"""Bounded binary/ZIP triage; evidence is distinct from confirmed crypto use."""
import hashlib
import io
import re
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import struct
import zipfile
from .binary_scanner import (scan_binary_data, calculate_shannon_entropy, AES_SBOX_PREFIX,
    AES_INVSBOX_PREFIX, DES_IP_TABLE, MD5_IV_LITTLE, SHA1_IV_BIG, SHA256_IV_BIG)

MAX_BYTES = 8 * 1024 * 1024


def sections(data):
    result = []
    if data.startswith(b'\x7fELF'):
        if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2):
            raise ValueError('Invalid ELF header')
        endian = '<' if data[5] == 1 else '>'
        is64 = data[4] == 2
        offset = struct.unpack_from(endian + ('Q' if is64 else 'I'), data, 40 if is64 else 32)[0]
        size, count, names_index = struct.unpack_from(endian + 'HHH', data, 58 if is64 else 46)
        if not count:
            return 'ELF', []
        if size < (64 if is64 else 40) or count > 4096 or offset + size * count > len(data) or names_index >= count:
            raise ValueError('Invalid ELF section table')
        entries = []
        for i in range(count):
            base = offset + i * size
            name, kind = struct.unpack_from(endian + 'II', data, base)
            start, length = struct.unpack_from(endian + ('QQ' if is64 else 'II'), data, base + (24 if is64 else 16))
            if kind != 8 and start + length > len(data):
                raise ValueError('ELF section outside file')
            entries.append((name, kind, start, length))
        _, _, start, length = entries[names_index]
        names = data[start:start + length]
        for name, kind, start, length in entries:
            if kind != 8:
                label = names[name:].split(b'\0', 1)[0].decode('utf-8', 'replace')
                result.append({'name': label, 'offset': start, 'size': length})
        return 'ELF', result
    if data.startswith(b'MZ'):
        if len(data) < 64:
            raise ValueError('Invalid PE header')
        pe = struct.unpack_from('<I', data, 60)[0]
        if pe + 24 > len(data) or data[pe:pe + 4] != b'PE\0\0':
            raise ValueError('Invalid PE signature')
        count = struct.unpack_from('<H', data, pe + 6)[0]
        optional_size = struct.unpack_from('<H', data, pe + 20)[0]
        table = pe + 24 + optional_size
        if count > 1024 or table + count * 40 > len(data):
            raise ValueError('Invalid PE section table')
        for i in range(count):
            base = table + i * 40
            label = data[base:base + 8].rstrip(b'\0').decode('ascii', 'replace')
            size, offset = struct.unpack_from('<II', data, base + 16)
            if offset + size > len(data):
                raise ValueError('PE section outside file')
            result.append({'name': label, 'offset': offset, 'size': size})
        return 'PE', result
    return 'raw', []


def scan_one(data, name):
    fmt, layout = sections(data)
    result = scan_binary_data(data, name)
    result.pop('hex_preview', None)  # Never return raw key-bearing bytes.
    # Repeat every signature match, including opposite word byte orders.
    signatures = [(AES_SBOX_PREFIX, 'AES S-box'), (AES_INVSBOX_PREFIX, 'AES inverse S-box'),
                  (DES_IP_TABLE, 'DES permutation table'), (MD5_IV_LITTLE, 'MD5 state constants'),
                  (SHA1_IV_BIG, 'SHA-1 state constants'), (SHA256_IV_BIG, 'SHA-256 state constants')]
    detections = []
    for signature, primitive in signatures:
        variants = [('table/native', signature)]
        if 'constants' in primitive:
            variants.append(('reversed-word-order', b''.join(signature[i:i + 4][::-1] for i in range(0, len(signature), 4))))
        for byte_order, pattern in variants:
            start = 0
            while True:
                pos = data.find(pattern, start)
                if pos < 0:
                    break
                detections.append({'primitive': primitive, 'offset': f'0x{pos:08X}', 'severity': 'MEDIUM' if primitive.startswith(('MD5', 'DES', 'SHA-1')) else 'LOW',
                    'confidence': 'MEDIUM', 'type': 'byte-signature', 'byte_order': byte_order,
                    'description': 'Matching constant bytes; presence does not prove execution or key size.'})
                start = pos + len(pattern)
                if len(detections) >= 10000:
                    raise ValueError('Detection limit exceeded')
    for match in re.finditer(rb'-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|PRIVATE KEY|CERTIFICATE)-----', data):
        label = match.group(1)
        end_marker = b'-----END ' + label + b'-----'
        end = data.find(end_marker, match.end())
        item = {'type': 'PEM marker', 'primitive': label.decode(), 'offset': f'0x{match.start():08X}',
                'confidence': 'LOW', 'severity': 'MEDIUM', 'description': 'PEM header found; material could not be parsed.'}
        if end >= 0 and end - match.start() <= 65536:
            pem = data[match.start():end + len(end_marker)]
            try:
                if label == b'CERTIFICATE':
                    x509.load_pem_x509_certificate(pem)
                    item.update(confidence='HIGH', severity='LOW', description='Parsed embedded certificate; its presence alone is not a vulnerability.')
                else:
                    load_pem_private_key(pem, password=None)
                    item.update(confidence='HIGH', severity='CRITICAL', description='Parsed unencrypted private key embedded in uploaded bytes. Key contents are not returned.')
            except (ValueError, TypeError):
                pass
        detections.append(item)
    for item in detections:
        offset = int(item['offset'], 16)
        item.update(file=name, section=next((s['name'] for s in layout if s['offset'] <= offset < s['offset'] + s['size']), None), source_hash=hashlib.sha256(data).hexdigest())
    # Cover the entire file with a bounded number of entropy windows.
    window = max(256, (len(data) + 255) // 256)

    from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
    evidence_list = []
    for item in detections:
        is_key = 'PRIVATE KEY' in item.get('primitive', '').upper()
        is_cert = 'CERTIFICATE' in item.get('primitive', '').upper()
        if is_key:
            level = EvidenceLevel.E3
            obs_type = ObservationType.BINARY_REFERENCE
            conf = 1.0 if item.get('confidence') == 'HIGH' else 0.75
        elif is_cert:
            level = EvidenceLevel.E3
            obs_type = ObservationType.X509_CERTIFICATE
            conf = 1.0 if item.get('confidence') == 'HIGH' else 0.80
        elif item.get('section'):
            level = EvidenceLevel.E2
            obs_type = ObservationType.BINARY_SIGNATURE
            conf = 0.85
        else:
            level = EvidenceLevel.E1
            obs_type = ObservationType.BINARY_SIGNATURE
            conf = 0.80

        ev = Evidence(
            state=EvidenceState.MEASURED,
            level=level,
            confidence=conf,
            source_engine="binary_deep",
            engine_version="4.0.0",
            rule_id=item.get('primitive'),
            rule_version="4.0.0",
            observation_type=obs_type,
            artifact_type="binary",
            symbol=item.get('primitive'),
            file_path=item.get('file'),
            byte_offset=item.get('offset'),
            description=item.get('description', 'Binary cryptographic indicator observed'),
            limitations=["Static signature/byte observation; execution path not traced dynamically."],
            raw_details={'section': item.get('section'), 'byte_order': item.get('byte_order'), 'severity': item.get('severity')},
            provenance=Provenance(
                input_hash=item.get('source_hash', ''),
                source_engine="binary_deep",
                engine_version="4.0.0",
                scan_id="",
                location=f"{item.get('file')}:{item.get('offset')}",
            )
        )
        evidence_list.append(ev.to_dict())

    result.update(detections=detections, total_detections=len(detections), format=fmt, sections=layout,
                  sha256=hashlib.sha256(data).hexdigest(),
                  critical_count=sum(d['severity'] == 'CRITICAL' for d in detections),
                  high_count=sum(d['severity'] == 'HIGH' for d in detections),
                  entropy_category='Byte distribution; encryption cannot be inferred',
                  entropy_map=[{'offset': f'0x{i:08X}', 'entropy': calculate_shannon_entropy(data[i:i + window]), 'status': 'Observed byte distribution'} for i in range(0, len(data), window)],
                  coverage={'bytes_scanned': len(data), 'entropy_window_bytes': window},
                  evidence=evidence_list)
    return result


def scan_upload(data, name):
    if not data or len(data) > MAX_BYTES:
        raise ValueError('File must contain 1 byte to 8 MiB')
    if zipfile.is_zipfile(io.BytesIO(data)):
        findings, members, total, evidence_all = [], [], 0, []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > 100:
                raise ValueError('Archive has more than 100 entries')
            for entry in entries:
                if entry.is_dir():
                    continue
                if entry.flag_bits & 1:
                    raise ValueError('Encrypted ZIP entries are unsupported')
                total += entry.file_size
                if total > MAX_BYTES or entry.file_size > MAX_BYTES:
                    raise ValueError('Expanded archive exceeds 8 MiB')
                # No extraction to disk and no nested archive expansion.
                with archive.open(entry) as stream:
                    content = stream.read(MAX_BYTES + 1)
                if len(content) != entry.file_size:
                    raise ValueError('Archive size mismatch')
                member = scan_one(content, f'{name}!/{entry.filename}')
                findings.extend(member['detections'])
                evidence_all.extend(member.get('evidence', []))
                members.append({'file': member['file_name'], 'sha256': member['sha256'], 'format': member['format'], 'coverage': member['coverage']})
        return {'file_name': name, 'file_size_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'format': 'ZIP', 'detections': findings, 'total_detections': len(findings),
                'critical_count': sum(d['severity'] == 'CRITICAL' for d in findings), 'high_count': sum(d['severity'] == 'HIGH' for d in findings), 'entropy_map': [], 'overall_entropy': calculate_shannon_entropy(data),
                'entropy_category': 'Archive', 'members': members,
                'evidence': evidence_all,
                'coverage': {'bytes_scanned': total, 'archive_depth': 1}, 'status': 'success'}
    result = scan_one(data, name)
    result['status'] = 'success'
    return result


def scan_binary_v4(data: bytes, name: str, project: str = "default", scan_id: str = "", asset_graph=None):
    from .binary.binary_pipeline import BinaryDiscoveryPipeline
    pipeline = BinaryDiscoveryPipeline(asset_graph=asset_graph)
    return pipeline.scan(data, name, project=project, scan_id=scan_id).to_dict()

