import base64
import io
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import app
from engine.binary_scanner import AES_SBOX_PREFIX, MD5_IV_LITTLE
from engine.binary_deep import scan_upload
from engine.source_scan import scan_sources
from engine.network_prober import clean_target_host, probe_tls_endpoint
from engine.scan_store import ScanStore


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('ECDAT_DB', str(tmp_path / 'scans.sqlite3'))
    monkeypatch.delenv('ECDAT_API_TOKEN', raising=False)
    with TestClient(app) as client:
        yield client


def finish(client, response, project='default'):
    assert response.status_code == 202, response.text
    scan_id = response.json()['id']
    for _ in range(1000):
        record = client.get(f'/api/scans/{scan_id}?project={project}').json()
        if record['status'] not in ('queued', 'running'):
            return record
        time.sleep(.02)
    pytest.fail('Job did not finish')


def test_empty_start_and_no_demo(client):
    assert client.get('/api/scans').json() == []
    assert client.get('/api/overview').json()['kpis']['total_findings'] == 0
    assert client.post('/api/demo/code').status_code == 404
    assert client.post('/api/scan/binary', json={}).status_code == 422
    assert client.post('/api/scan/binary', json={'raw_hex': 'NOT HEX'}).status_code == 422
    assert client.post('/api/scan/code', json={'source_code': 'x', 'language': 'ruby'}).status_code == 422


def test_ast_alias_multiline_and_cross_file_constants(client):
    response = client.post('/api/scan/sources?project=project_a', json={'files': [
        {'path': 'settings.py', 'content': 'BITS = 1024'},
        {'path': 'main.py', 'content': 'from cryptography.hazmat.primitives.asymmetric import rsa as r\nimport settings\nfrom hashlib import md5 as weak\nr.generate_private_key(\n public_exponent=65537,\n key_size=settings.BITS\n)\nweak(b"x")\n# hashlib.md5(x)\ns = "hashlib.md5(x)"'}]})
    record = finish(client, response, 'project_a')
    assert record['status'] == 'completed'
    findings = record['result']['findings']
    assert {f['primitive'] for f in findings} == {'RSA-1024', 'MD5'}
    assert len(findings) == 2
    assert all(f['file'] == 'main.py' for f in findings)
    assert client.get('/api/scans').json() == []
    assert client.get(f"/api/scans/{record['id']}").status_code == 404
    export = client.post('/api/export/cbom?project=project_a', json={'scan_ids': [record['id']]})
    assert export.status_code == 200
    assert len(export.json()['components']) == 2
    assert client.post('/api/export/cbom', json={'scan_ids': [record['id']]}).status_code == 422


def test_parse_and_coverage_not_clean_bill():
    result = scan_sources([{'path': 'bad.py', 'content': 'def ('}, {'path': 'a.rb', 'content': 'x'}])
    assert result['status'] == 'partial'
    assert [x['status'] for x in result['coverage']] == ['error', 'unsupported']


def test_binary_real_upload_and_zip(client):
    data = b'\x00' * 5000 + AES_SBOX_PREFIX + MD5_IV_LITTLE + MD5_IV_LITTLE
    record = finish(client, client.post('/api/scan/binary/upload', files={'file': ('real.bin', data)}))
    assert record['status'] == 'completed'
    result = record['result']
    assert result['file_size_bytes'] == len(data)
    assert len(result['detections']) == 3
    assert int(result['entropy_map'][-1]['offset'], 16) >= 4096
    assert {f['file'] for f in result['detections']} == {'real.bin'}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('member.bin', data)
    unpacked = scan_upload(archive.getvalue(), 'firmware.zip')
    assert len(unpacked['detections']) == 3
    assert unpacked['detections'][0]['file'] == 'firmware.zip!/member.bin'
    cbom = client.post('/api/export/cbom', json={'scan_ids': [record['id']]}).json()
    assert cbom['components'][0]['properties'][1]['value'] == 'binary'


def test_archive_limit():
    from engine.binary_deep import MAX_BYTES
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
        z.writestr('oversize.bin', b'0' * (MAX_BYTES + 1))
    with pytest.raises(ValueError, match='exceeds'):
        scan_upload(archive.getvalue(), 'bomb.zip')


def test_pe_sections():
    data = bytearray(512)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 64)
    data[64:68] = b'PE\0\0'
    struct.pack_into('<H', data, 70, 1)
    data[88:96] = b'.rdata\0\0'
    struct.pack_into('<II', data, 104, 256, 256)
    data[256:288] = AES_SBOX_PREFIX
    result = scan_upload(bytes(data), 'real.exe')
    assert result['format'] == 'PE'
    assert result['detections'][0]['section'] == '.rdata'


def test_auth_and_cors(client, monkeypatch):
    monkeypatch.setenv('ECDAT_API_TOKEN', 'test-secret')
    assert client.get('/api/scans').status_code == 401
    assert client.get('/api/scans', headers={'Authorization': 'Bearer test-secret'}).status_code == 200
    response = client.options('/api/scan/code', headers={'Origin': 'https://untrusted.example', 'Access-Control-Request-Method': 'POST'})
    assert 'access-control-allow-origin' not in response.headers


def test_cancel_and_persistence(tmp_path):
    path = str(tmp_path / 'jobs.db')
    store = ScanStore(path)
    gate = threading.Event()
    record = store.submit('a', 'code', {'x': 1}, lambda p: (gate.wait(2), {'findings': []})[1])
    store.cancel(record['id'], 'a')
    gate.set()
    store.close()
    restarted = ScanStore(path)
    assert restarted.get(record['id'], 'a')['status'] == 'cancelled'
    assert restarted.get(record['id'], 'b') is None
    restarted.close()


def test_target_parsing_and_private_scope(monkeypatch):
    assert clean_target_host('https://example.org:8443/path') == ('example.org', 8443)
    assert clean_target_host('[::1]:443') == ('::1', 443)
    monkeypatch.delenv('ECDAT_ALLOWED_CIDRS', raising=False)
    with pytest.raises(ValueError, match='allowlist'):
        probe_tls_endpoint('127.0.0.1')


@pytest.fixture
def tls_server(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.now(timezone.utc)-timedelta(days=2)).not_valid_after(datetime.now(timezone.utc)-timedelta(days=1)).sign(key, hashes.SHA256())
    cert_path, key_path = tmp_path/'cert.pem', tmp_path/'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_path, key_path)
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.1)
    done = threading.Event()
    def serve():
        while not done.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            conn.settimeout(.5)
            try:
                with context.wrap_socket(conn, server_side=True) as secure:
                    data = secure.recv(4096)
                    if data.startswith(b'HEAD / HTTP/1.1'):
                        secure.sendall(b'HTTP/1.1 302 Found\r\nServer: fixture\r\nCF-Ray: fixture-ray\r\nLocation: https://127.0.0.2/private\r\nSet-Cookie: secret=redacted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:
                conn.close()
    thread = threading.Thread(target=serve); thread.start()
    monkeypatch.setenv('ECDAT_ALLOWED_CIDRS', '127.0.0.0/8')
    yield listener.getsockname()[1]
    done.set(); thread.join(2); listener.close()


def test_tls_job_to_export(client, tls_server):
    record = finish(client, client.post('/api/scan/network', json={'target': f'https://127.0.0.1:{tls_server}/test'}))
    assert record['status'] == 'completed', record
    result = record['result']
    assert result['certificate']['expired'] is True
    assert result['certificate']['trust_validated'] is False
    assert result['post_quantum']['status'] in ('scanner_unavailable', 'tested_not_negotiated', 'hybrid_supported', 'inconclusive')
    assert result['post_quantum']['tests'][-1]['group'] == 'X25519'
    assert result['post_quantum']['tests'][-1]['status'] == 'negotiated'
    assert any(t['status'] == 'supported' for t in result['protocol_tests'])
    assert len(result['cipher_tests']) == 4
    cbom = client.post('/api/export/cbom', json={'scan_ids': [record['id']]}).json()
    assert len(cbom['components']) == 2
    schema = Path(__file__).parent/'bom-1.6.schema.json'
    from jsonschema import Draft7Validator
    Draft7Validator(json.loads(schema.read_text())).validate(cbom)


def test_handshake_failure_never_success(monkeypatch):
    import engine.network_prober as prober
    monkeypatch.setattr(prober, 'resolve_target', lambda *a: (socket.AF_INET, ('127.0.0.1', 443)))
    def fail(*args, **kwargs):
        raise ssl.SSLError('HANDSHAKE_FAILURE')
    monkeypatch.setattr(prober, '_handshake', fail)
    result = prober.probe_tls_endpoint('rc4.pq.example')
    assert result['status'] == 'error'
    assert result['certificate'] == {}
    assert result['pqc_status'] == 'Unknown / not measured'


def test_imported_constant_and_language_coverage():
    result = scan_sources([
        {'path': 'config.py', 'content': 'BITS = 1024'},
        {'path': 'app.py', 'content': 'from config import BITS\nfrom cryptography.hazmat.primitives.asymmetric import rsa\nrsa.generate_private_key(public_exponent=65537, key_size=BITS)'},
        {'path': 'App.java', 'content': '/* MessageDigest.getInstance("MD5") */\nMessageDigest.getInstance(\n"MD5"\n);'},
        {'path': 'a.c', 'content': 'MD5(data);'},
        {'path': 'a.go', 'content': 'md5.New()'},
        {'path': 'a.js', 'content': 'crypto.createHash("md5")'},
        {'path': 'requirements.txt', 'content': 'cryptography>=42'},
    ])
    assert len(result['findings']) == 5
    assert len(result['dependencies']) == 1
    assert len([f for f in result['findings'] if f['language'] == 'java']) == 1


def test_elf_sections():
    data = bytearray(400)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<Q', data, 40, 64)
    struct.pack_into('<HHH', data, 58, 64, 3, 1)
    names = b'\0.shstrtab\0.rodata\0'
    data[256:256 + len(names)] = names
    struct.pack_into('<II', data, 128, 1, 3)
    struct.pack_into('<QQ', data, 152, 256, len(names))
    struct.pack_into('<II', data, 192, 11, 1)
    struct.pack_into('<QQ', data, 216, 320, 32)
    data[320:352] = AES_SBOX_PREFIX
    result = scan_upload(bytes(data), 'test.elf')
    assert result['detections'][0]['section'] == '.rodata'


def test_export_schema_all_types(client):
    records = [finish(client, client.post('/api/scan/code', json={'source_code': 'import hashlib\nhashlib.md5(b"x")'})),
               finish(client, client.post('/api/scan/binary', json={'raw_hex': AES_SBOX_PREFIX.hex()}))]
    document = client.post('/api/export/cbom', json={'scan_ids': [r['id'] for r in records]}).json()
    from jsonschema import Draft7Validator
    schema = json.loads((Path(__file__).parent/'bom-1.6.schema.json').read_text())
    Draft7Validator(schema).validate(document)
    assert len(document['components']) == 2


def test_completed_scan_survives_restart(tmp_path):
    path = str(tmp_path/'store.sqlite')
    store = ScanStore(path)
    record = store.submit('a', 'code', {'source': 'x'}, lambda p: {'findings': []})
    store.close()
    store = ScanStore(path)
    assert store.get(record['id'], 'a')['status'] == 'completed'
    assert store.get(record['id'], 'a')['result'] == {'findings': []}
    store.close()


def test_real_private_key_and_marker_confidence():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    result = scan_upload(pem, 'embedded.bin')
    assert result['detections'][0]['confidence'] == 'HIGH'
    assert result['detections'][0]['severity'] == 'CRITICAL'
    assert 'MII' not in result['detections'][0]['description']
    fake = scan_upload(b'-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----', 'marker.bin')
    assert fake['detections'][0]['confidence'] == 'LOW'


def test_deployment_and_migration_pipeline(client, tls_server):
    site = finish(client, client.post('/api/scan/network?project=website', json={'target': f'https://127.0.0.1:{tls_server}/ignored'}), 'website')
    assert site['status'] == 'completed', site
    deployment = site['result']['deployment']
    assert deployment['status'] == 'observed'
    assert deployment['status_code'] == 302
    assert deployment['headers']['location'] == 'https://127.0.0.2/private'
    assert 'set-cookie' not in deployment['headers']
    assert deployment['hosting_hints'][0]['confidence'] == 'inferred'
    assert deployment['origin_provider'] is None
    source = finish(client, client.post('/api/scan/code?project=website', json={'source_code': 'import hashlib\nhashlib.md5(b"x")'}), 'website')
    response = client.post('/api/migration/plans?project=website', json={'scan_ids': [site['id'], source['id']], 'target_host': 'A new VPS', 'database': 'postgresql', 'data_gb': 90, 'transfer_mbps': 100,
        'traffic': {'source': 'Access log totals', 'start_date': '2025-01-01', 'end_date': '2025-01-10', 'total_requests': 1000, 'total_gb': 20}})
    assert response.status_code == 201, response.text
    plan = response.json()
    assert plan['traffic']['average_daily_requests'] == 100
    assert plan['traffic']['average_daily_gb'] == 2
    assert plan['estimate']['minimum_transfer_hours'] == 2
    assert plan['estimate']['downtime_minutes'] is None
    assert plan['evidence']['linked_findings'] == 1
    assert any('certificate trust' in p['title'] for p in plan['priorities'])
    assert {p['track'] for p in plan['phases']} == {'hosting', 'cryptography', 'shared'}
    assert client.get('/api/migration/plans?project=website').json()[0]['id'] == plan['id']
    assert client.get(f"/api/migration/plans/{plan['id']}?project=website").json() == plan
    assert client.get(f"/api/migration/plans/{plan['id']}").status_code == 404
    assert client.post('/api/migration/plans', json={'scan_ids': [site['id']]}).status_code == 422
    assert client.post('/api/migration/plans?project=website', json={'scan_ids': [source['id']]}).status_code == 422
    draft = client.post('/api/migration/plans?project=website', json={'scan_ids': [site['id']]}).json()
    assert draft['traffic']['status'] == 'unknown'
    assert draft['traffic']['average_daily_requests'] is None
    assert draft['estimate']['minimum_transfer_hours'] is None
    assert 'Traffic baseline' in draft['missing_inputs']


def test_plan_validation(client):
    base = {'scan_ids': ['missing'], 'traffic': {'source': 'logs', 'start_date': '2025-02-02', 'end_date': '2025-01-01', 'total_requests': 2}}
    assert client.post('/api/migration/plans', json=base).status_code == 422
    assert client.post('/api/migration/plans', json={'scan_ids': ['missing'], 'transfer_mbps': 0}).status_code == 422
    assert client.post('/api/migration/plans', json={'scan_ids': ['missing'], 'application_count': 0}).status_code == 422
    assert client.post('/api/migration/plans', json={'scan_ids': []}).status_code == 422


def test_http_header_bound_and_no_redirect_requests(monkeypatch):
    from engine.website_inspector import inspect_http
    calls = []
    class Connection:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def sendall(self, data): calls.append(data)
        def settimeout(self, value): pass
        def recv(self, size): return b'x' * size
    monkeypatch.setattr('engine.website_inspector._handshake', lambda *args: Connection())
    result = inspect_http('example.org', 443, (socket.AF_INET, ('1.1.1.1', 443)))
    assert result['status'] == 'unavailable'
    assert '16 KiB' in result['error']
    assert len(calls) == 1
    assert calls[0].startswith(b'HEAD / HTTP/1.1')


def test_plans_survive_restart(tmp_path):
    path = str(tmp_path / 'plans.db')
    store = ScanStore(path)
    plan = store.save_plan('a', {'target': 'example.org', 'created_at': '2025-01-01', 'traffic': {'status': 'unknown'}})
    store.close()
    restarted = ScanStore(path)
    assert restarted.get_plan(plan['id'], 'a') == plan
    assert restarted.list_plans('b') == []
    restarted.close()
