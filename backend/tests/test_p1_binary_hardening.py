"""
ECDAT V4 — P1.2 Hardening & Adversarial Acceptance Test Suite.

Validates the research-grade binary discovery engine across:
1. Research Axiom & Negative Controls (Non-crypto ELF, clean PE, natural language strings)
2. Presence vs Execution Axioms (Library links != execution, Imported symbols != execution)
3. Post-Quantum & NTT Precision Controls (Kyber NTT full match vs truncated/corrupted)
4. Secret Detection & Zero-Leakage Security (RSA/EC PEM masking, cert distinction, base64)
5. Firmware Traversal, Bomb Containment & Provenance (Zip slip, tar traversal, size limits, child lineage)
6. Optional Engine Health & Epistemic Separation (SCANNER_UNAVAILABLE, E1/E3/E4 mapping, never E5)
7. Graph Monotonicity & Asset Deduplication (Upgrades preserved, downgrades prevented, multi-evidence consolidation)
8. Cryptographic Normalization & Specificity Audit (RSA-2048, ML-KEM-768, AES-256-GCM)
9. Determinism & Robust Failure Containment (Malformed ELF/PE/archives, bit-exact reproducibility)
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
import sqlite3
import struct
import sys
import tarfile
from typing import Any, Callable, Dict, List, Tuple
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from engine.asset_graph import AssetGraphService, AssetType, RelationshipType
from engine.evidence_model import EvidenceLevel, EvidenceState, ObservationType
from engine.binary import (
    BinaryIdentifier,
    BinaryFormat,
    BinaryMetadataParser,
    BinarySymbolParser,
    SymbolInfo,
    SymbolType,
    SymbolBinding,
    BinaryImportParser,
    BinaryStringExtractor,
    BinarySignatureMatcher,
    FirmwareExtractor,
    GhidraEngine,
    AngrEngine,
    YaraEngine,
    get_available_engines,
    get_engine_health_report,
    BinaryNormalizer,
    BinaryEvidenceGenerator,
    BinaryDiscoveryPipeline,
)
from tests.test_p1_binary_discovery import create_synthetic_elf64, create_synthetic_pe32


def create_in_memory_graph() -> Tuple[AssetGraphService, sqlite3.Connection]:
    """Creates an isolated in-memory SQLite AssetGraphService for testing."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("""CREATE TABLE crypto_assets (
        id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT, asset_type TEXT NOT NULL,
        name TEXT NOT NULL, algorithm TEXT, variant TEXT, key_size INTEGER, library TEXT,
        version TEXT, artifact_id TEXT, status TEXT NOT NULL, fused_status TEXT NOT NULL,
        highest_evidence_level TEXT NOT NULL, confidence REAL NOT NULL, explanation TEXT,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE graph_edges (
        id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT, source_id TEXT NOT NULL,
        source_type TEXT NOT NULL, relationship TEXT NOT NULL, target_id TEXT NOT NULL,
        target_type TEXT NOT NULL, evidence_id TEXT, confidence REAL NOT NULL, created_at TEXT NOT NULL)""")
    conn.execute("""CREATE TABLE evidence (
        id TEXT PRIMARY KEY, asset_id TEXT, scan_id TEXT, project TEXT NOT NULL, state TEXT NOT NULL,
        level TEXT NOT NULL, confidence REAL NOT NULL, source_engine TEXT NOT NULL, engine_version TEXT NOT NULL,
        rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, observation_type TEXT NOT NULL, artifact_type TEXT NOT NULL,
        file_path TEXT, line_start INTEGER, line_end INTEGER, byte_offset TEXT, symbol TEXT,
        description TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL)""")

    def factory() -> sqlite3.Connection:
        return conn

    return AssetGraphService(factory), conn


# ==============================================================================
# SUITE 1: RESEARCH AXIOM & NEGATIVE CONTROLS
# ==============================================================================

def test_negative_control_pure_arithmetic_elf():
    """Negative control: ELF with only pure arithmetic logic produces 0 crypto assets."""
    arithmetic_text = bytes([
        0x55,                    # push rbp
        0x48, 0x89, 0xe5,        # mov rbp, rsp
        0x89, 0x7d, 0xfc,        # mov DWORD PTR [rbp-0x4], edi
        0x89, 0x75, 0xf8,        # mov DWORD PTR [rbp-0x8], esi
        0x8b, 0x55, 0xfc,        # mov edx, DWORD PTR [rbp-0x4]
        0x8b, 0x45, 0xf8,        # mov eax, DWORD PTR [rbp-0x8]
        0x01, 0xd0,              # add eax, edx
        0x5d,                    # pop rbp
        0xc3,                    # ret
    ])
    elf_data = create_synthetic_elf64(
        sections_data={
            ".text": arithmetic_text,
            ".rodata": b"Result computed successfully.\n",
        },
        symbols=[
            ("compute_sum", True, True, 0x401000, 16),
            ("main", True, True, 0x401020, 32),
        ],
        dt_needed=["libc.so.6", "libm.so.6"],
    )
    graph, _ = create_in_memory_graph()
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)
    result = pipeline.scan(elf_data, "pure_math.elf", project="test", scan_id="math_run_01")

    # Inspect assets in graph
    assets = graph.find_assets_by_project("test")
    crypto_algos = [a for a in assets if a.asset_type == AssetType.ALGORITHM]
    assert len(crypto_algos) == 0, f"Expected 0 crypto algorithm assets, found: {crypto_algos}"
    assert len(result.members) == 1
    assert result.members[0].identification.format == BinaryFormat.ELF


def test_negative_control_clean_pe():
    """Negative control: PE with non-crypto DLL imports produces 0 crypto references."""
    pe_data = create_synthetic_pe32(
        sections_data={
            ".text": b"\x90" * 64,
            ".rdata": b"Standard GUI Application String\0",
        },
        imported_dlls=["KERNEL32.dll", "USER32.dll", "SHELL32.dll"],
    )
    graph, _ = create_in_memory_graph()
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)
    result = pipeline.scan(pe_data, "clean_gui.exe", project="test", scan_id="clean_pe_run")

    assets = graph.find_assets_by_project("test")
    crypto_algos = [a for a in assets if a.asset_type == AssetType.ALGORITHM]
    assert len(crypto_algos) == 0
    crypto_libs = [a for a in assets if a.asset_type == AssetType.CRYPTO_LIBRARY]
    assert len(crypto_libs) == 0


def test_negative_control_non_crypto_strings():
    """Natural language comments and unrelated code words do not trigger false positive algorithms."""
    non_crypto_strings = (
        b"HashTable_Lookup_Key(hash_map_t *map, const char *key);\n"
        b"KeyboardEvent: KeyPressed and KeyReleased event handler.\n"
        b"CertificateAuthorityComment: user confirmed display settings.\n"
        b"Cipher disk not found in peripheral bay.\n"
    )
    strings = BinaryStringExtractor.extract_strings(non_crypto_strings, min_length=6)
    matched_algos = [s.algorithm for s in strings if s.category == "ALGORITHM_NAME"]
    assert "AES" not in matched_algos
    assert "RSA" not in matched_algos


# ==============================================================================
# SUITE 2: PRESENCE VS EXECUTION AXIOM
# ==============================================================================

def test_positive_control_elf_libcrypto_e2():
    """Shared library dependency on libcrypto produces E2 reference with explicit non-execution limitation."""
    elf_data = create_synthetic_elf64(
        sections_data={".text": b"\x90" * 32},
        dt_needed=["libcrypto.so.3", "libc.so.6"],
    )
    imports = BinaryImportParser.parse(elf_data, "app.elf")
    assert len(imports) == 2
    crypto_lib = next(i for i in imports if i.library_name == "libcrypto.so.3")
    assert crypto_lib.crypto_family == "OpenSSL"

    ev = BinaryEvidenceGenerator.from_import(crypto_lib, "app.elf", "hash123", "scan1")
    assert ev.level == EvidenceLevel.E2
    assert ev.state == EvidenceState.MEASURED
    assert any("cannot be confirmed from dependency declaration alone" in lim for lim in ev.limitations)
    assert ev.level != EvidenceLevel.E5


def test_positive_control_elf_imported_evp_e2():
    """Imported undefined EVP function produces E2 symbol evidence acknowledging lack of dynamic proof."""
    elf_data = create_synthetic_elf64(
        sections_data={".text": b"\x90" * 32},
        symbols=[("EVP_CIPHER_CTX_new", True, False, 0, 0)],
    )
    syms = BinarySymbolParser.parse(elf_data)
    assert len(syms) == 1
    sym = syms[0]
    assert not sym.is_defined
    assert sym.algorithm == "GenericCrypto"
    assert sym.is_crypto is True

    ev = BinaryEvidenceGenerator.from_symbol(sym, "app.elf", "hash123", "scan1")
    assert ev.level == EvidenceLevel.E2
    assert any("Dynamic reachability or runtime invocation path is not proven" in lim for lim in ev.limitations)



def test_positive_control_elf_defined_aes_e3():
    """Compiled defined AES function produces E3 symbol evidence."""
    elf_data = create_synthetic_elf64(
        sections_data={".text": b"\x90" * 64},
        symbols=[("AES_encrypt", True, True, 0x401000, 64)],
    )
    syms = BinarySymbolParser.parse(elf_data)
    assert len(syms) == 1
    sym = syms[0]
    assert sym.is_defined
    assert sym.algorithm == "AES"

    ev = BinaryEvidenceGenerator.from_symbol(sym, "app.elf", "hash123", "scan1")
    assert ev.level == EvidenceLevel.E3
    assert ev.state == EvidenceState.MEASURED


def test_positive_control_pe_bcrypt_import_e2():
    """PE importing bcrypt.dll and crypt32.dll produces E2 references."""
    pe_data = create_synthetic_pe32(
        sections_data={".text": b"\x90" * 32},
        imported_dlls=["bcrypt.dll", "crypt32.dll", "kernel32.dll"],
    )
    imports = BinaryImportParser.parse(pe_data, "sample.exe")
    crypto_imports = [i for i in imports if i.is_crypto]
    assert len(crypto_imports) == 2
    dll_names = [i.library_name.lower() for i in crypto_imports]
    assert "bcrypt.dll" in dll_names
    assert "crypt32.dll" in dll_names


def test_section_context_metadata_preservation():
    """Byte constant inside .rodata preserves section name and offset accurately in evidence."""
    aes_sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
    elf_data = create_synthetic_elf64(
        sections_data={
            ".text": b"\x90" * 32,
            ".rodata": b"\x00" * 16 + aes_sbox,
        }
    )
    meta = BinaryMetadataParser.parse(elf_data)
    matches = BinarySignatureMatcher.match(elf_data, sections=meta.sections)
    sbox_match = next((m for m in matches if "AES" in m.rule_id), None)
    assert sbox_match is not None
    assert sbox_match.section == ".rodata"
    assert sbox_match.offset > 0

    ev = BinaryEvidenceGenerator.from_signature_match(sbox_match, "app.elf", "hash123")
    assert ev.level == EvidenceLevel.E2
    assert ev.raw_details["section"] == ".rodata"


def test_der_oid_context_preservation():
    """ASN.1 DER OID for Ed25519 is recognized and preserves offset metadata."""
    ed25519_oid = bytes.fromhex("06032b6570")  # 1.3.101.112 id-Ed25519
    blob = b"CERTIFICATE_DATA_PADDING" + ed25519_oid + b"TRAILER_DATA"
    matches = BinarySignatureMatcher.match(blob)
    oid_match = next((m for m in matches if m.rule_id == "OID-ED25519"), None)
    assert oid_match is not None
    assert oid_match.algorithm == "Ed25519"
    assert oid_match.offset == len(b"CERTIFICATE_DATA_PADDING")


def test_stripped_elf_absence_of_symtab():
    """Stripped ELF without symbol table parses metadata safely without failing."""
    elf_data = create_synthetic_elf64(
        sections_data={".text": b"\x90" * 32},
        symbols=[],
    )
    meta = BinaryMetadataParser.parse(elf_data)
    assert meta.format == BinaryFormat.ELF
    symbols = BinarySymbolParser.parse(elf_data)
    assert len(symbols) == 0


# ==============================================================================
# SUITE 3: POST-QUANTUM & NTT TABLE CONTROLS
# ==============================================================================

# Kyber NTT zetas prefix from binary_crypto_signatures.yaml: "e3085a0aa8091b09d4068a054803f002"
KYBER_ZETAS_PREFIX = bytes.fromhex("e3085a0aa8091b09d4068a054803f002")


def test_pqc_kyber_ntt_full_sequence_match():
    """Valid Kyber NTT constant table prefix is detected with rule SIG-MLKEM-KYBER-ZETAS."""
    blob = b"\x00" * 64 + KYBER_ZETAS_PREFIX + b"\x00" * 32
    matches = BinarySignatureMatcher.match(blob)
    ntt = next((m for m in matches if m.rule_id == "SIG-MLKEM-KYBER-ZETAS"), None)
    assert ntt is not None
    assert ntt.category == "PQC"
    assert ntt.pqc_status == "PQC_STANDARDIZED"
    assert ntt.confidence >= 0.90


def test_pqc_kyber_ntt_truncated_sequence_rejected():
    """Truncated NTT sequence (first 8 bytes only) is rejected to avoid false positives."""
    truncated = KYBER_ZETAS_PREFIX[:8]
    blob = b"\x00" * 64 + truncated + b"\x00" * 32
    matches = BinarySignatureMatcher.match(blob)
    ntt_matches = [m for m in matches if m.rule_id == "SIG-MLKEM-KYBER-ZETAS"]
    assert len(ntt_matches) == 0


def test_pqc_kyber_ntt_corrupted_element_rejected():
    """NTT sequence with single corrupted byte does not match."""
    corrupted = bytearray(KYBER_ZETAS_PREFIX)
    corrupted[10] ^= 0xFF
    blob = b"\x00" * 32 + bytes(corrupted) + b"\x00" * 32
    matches = BinarySignatureMatcher.match(blob)
    ntt_matches = [m for m in matches if m.rule_id == "SIG-MLKEM-KYBER-ZETAS"]
    assert len(ntt_matches) == 0


def test_pqc_kyber_ntt_repeated_sequences_containment():
    """Repeated contiguous NTT sequences match cleanly without buffer overflow."""
    repeated = KYBER_ZETAS_PREFIX + b"\x00" * 8 + KYBER_ZETAS_PREFIX
    matches = BinarySignatureMatcher.match(repeated)
    ntt_matches = [m for m in matches if m.rule_id == "SIG-MLKEM-KYBER-ZETAS"]
    assert len(ntt_matches) == 2
    assert ntt_matches[0].offset != ntt_matches[1].offset


# ==============================================================================
# SUITE 4: SECRET DETECTION & ZERO-LEAKAGE SECURITY
# ==============================================================================

def test_secret_masking_rsa_private_key_zero_leakage():
    """RSA-2048 private key is detected, masked as SECRET_INDICATOR_DETECTED, with 0 bytes leaked."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    secrets = BinaryStringExtractor.extract_secrets(pem)
    assert len(secrets) == 1
    sec = secrets[0]
    assert sec.secret_type == "PEM_PRIVATE_KEY"
    assert sec.key_size == 2048
    assert sec.is_valid_pem is True
    assert sec.masked_indicator == "SECRET_INDICATOR_DETECTED"

    # Transform to evidence
    ev = BinaryEvidenceGenerator.from_secret(sec, "test.pem", "hash456", "scan2")
    assert ev.level == EvidenceLevel.E3
    assert ev.state == EvidenceState.MEASURED

    # Zero-leakage check: Assert no raw base64 or prime values in description, symbol, or raw_details
    pem_lines = [l for l in pem.decode().splitlines() if not l.startswith("---") and len(l) > 10]
    raw_payload_chunk = pem_lines[0]
    assert raw_payload_chunk not in ev.description
    assert raw_payload_chunk not in ev.symbol
    assert raw_payload_chunk not in str(ev.raw_details)
    assert "SECRET_INDICATOR_DETECTED" in ev.limitations[1]


def test_secret_masking_ec_private_key_zero_leakage():
    """EC SECP256R1 private key is detected and masked with zero key leakage."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    secrets = BinaryStringExtractor.extract_secrets(pem)
    assert len(secrets) == 1
    sec = secrets[0]
    assert sec.secret_type == "PEM_PRIVATE_KEY"
    assert sec.algorithm == "ECDSA"
    assert sec.key_size == 256

    ev = BinaryEvidenceGenerator.from_secret(sec, "ec.key", "hash789")
    pem_body = pem.decode().splitlines()[1]
    assert pem_body not in ev.description
    assert pem_body not in str(ev.raw_details)


def test_secret_masking_encrypted_private_key():
    """Encrypted PEM private key is flagged with is_encrypted=True and masked."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase123"),
    )
    secrets = BinaryStringExtractor.extract_secrets(pem)
    assert len(secrets) == 1
    sec = secrets[0]
    assert sec.is_encrypted is True
    assert sec.secret_type == "PEM_PRIVATE_KEY"


def test_secret_x509_cert_distinction():
    """X.509 certificate is detected as X509_CERTIFICATE observation, not as hardcoded private key."""
    cert_pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz3eY5e1j2k3l4m5n6o7p\n"
        b"-----END CERTIFICATE-----\n"
    )
    secrets = BinaryStringExtractor.extract_secrets(cert_pem)
    assert len(secrets) == 1
    sec = secrets[0]
    assert sec.secret_type == "PEM_CERTIFICATE"
    ev = BinaryEvidenceGenerator.from_secret(sec, "cert.crt", "cert_hash")
    assert ev.observation_type == ObservationType.X509_CERTIFICATE
    assert ev.observation_type != ObservationType.HARDCODED_KEY


def test_secret_random_base64_rejection():
    """Random base64 string without PEM headers is not classified as private key."""
    random_b64 = b"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwCg==" * 10
    secrets = BinaryStringExtractor.extract_secrets(random_b64)
    assert len(secrets) == 0


# ==============================================================================
# SUITE 5: FIRMWARE TRAVERSAL, BOMB CONTAINMENT & PROVENANCE
# ==============================================================================

def test_firmware_zip_slip_path_traversal_blocked():
    """Zip slip path traversal attack is blocked and file path sanitized."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash\n")
    res = FirmwareExtractor.extract(buf.getvalue(), "exploit.zip")
    for m in res.members:
        assert ".." not in m.virtual_path
        assert not m.virtual_path.startswith("/")
        assert not m.virtual_path.startswith("\\")


def test_firmware_tar_path_traversal_blocked():
    """Tar archive with directory traversal payload is safely neutralized."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        ti = tarfile.TarInfo(name="../../../../root/.ssh/id_rsa")
        content = b"fake_key_content"
        ti.size = len(content)
        t.addfile(ti, io.BytesIO(content))
    res = FirmwareExtractor.extract(buf.getvalue(), "traversal.tar")
    for m in res.members:
        assert ".." not in m.virtual_path
        assert not m.virtual_path.startswith("/")


def test_firmware_null_byte_in_filename_blocked():
    """Archive with embedded null byte in file name is handled safely without error."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("malicious\x00.exe", b"executable_payload")
    res = FirmwareExtractor.extract(buf.getvalue(), "null_byte.zip")
    for m in res.members:
        assert "\x00" not in m.virtual_path


def test_firmware_zip_bomb_expansion_limit():
    """Archive with uncompressed file exceeding 8MB ceiling is stopped."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.bin", b"0" * (8 * 1024 * 1024 + 10))

    with pytest.raises(ValueError, match="exceeds"):
        FirmwareExtractor.extract(buf.getvalue(), "bomb.zip")


def test_firmware_child_provenance_chain():
    """Extracted firmware artifacts preserve parent hash, container path, and child hash."""
    buf = io.BytesIO()
    inner_payload = b"inner_kernel_payload_12345"
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("boot/vmlinuz", inner_payload)

    container_bytes = buf.getvalue()
    parent_hash = hashlib.sha256(container_bytes).hexdigest()
    child_expected_hash = hashlib.sha256(inner_payload).hexdigest()

    res = FirmwareExtractor.extract(container_bytes, "firmware.bin")
    assert len(res.members) == 1
    m = res.members[0]
    assert m.parent_hash == parent_hash
    assert m.container_path == "firmware.bin"
    assert m.extraction_method == "zip"
    assert m.sha256 == child_expected_hash


def test_firmware_graph_containment_edges():
    """BinaryDiscoveryPipeline builds CONTAINS edges linking container to child files."""
    buf = io.BytesIO()
    child_elf = create_synthetic_elf64(
        sections_data={".text": b"\x90" * 16},
        symbols=[("AES_set_encrypt_key", True, True, 0x401000, 16)],
    )
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("bin/crypt_tool", child_elf)

    graph, _ = create_in_memory_graph()
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)
    result = pipeline.scan(buf.getvalue(), "firmware_pack.zip", project="fw_test", scan_id="fw_01")

    # Verify relationships in graph
    rels = graph.get_relationships(project="fw_test")
    contains_rels = [r for r in rels if r.get("relationship") == RelationshipType.CONTAINS.value]
    assert len(contains_rels) >= 1
    # Child crypto algorithm linked
    assets = graph.find_assets_by_project("fw_test")
    algo_assets = [a for a in assets if a.asset_type == AssetType.ALGORITHM]
    assert len(algo_assets) >= 1
    assert any("AES" in a.name for a in algo_assets)


# ==============================================================================
# SUITE 6: OPTIONAL ENGINE HEALTH & EPISTEMIC SEPARATION
# ==============================================================================

def test_optional_engine_health_reporting():
    """Ghidra, angr, YARA engines report SCANNER_UNAVAILABLE when not present with helpful messages."""
    health_reports = get_engine_health_report()
    assert len(health_reports) == 3
    engine_names = [h["engine_name"] for h in health_reports]
    assert "Ghidra" in engine_names
    assert "angr" in engine_names
    assert "YARA" in engine_names

    for h in health_reports:
        assert h["status"] in ("AVAILABLE", "SCANNER_UNAVAILABLE", "DEGRADED")
        assert len(h["message"]) > 0


def test_optional_engine_analyze_graceful_containment():
    """Calling analyze() on unavailable plugins returns SCANNER_UNAVAILABLE and empty findings without error."""
    engines = get_available_engines()
    dummy_elf = create_synthetic_elf64()
    for engine in engines:
        res = engine.analyze(dummy_elf, BinaryFormat.ELF)
        assert "engine" in res
        assert "status" in res
        assert "findings" in res
        if res["status"] == "SCANNER_UNAVAILABLE":
            assert res["findings"] == []


def test_deep_re_evidence_mapping_epistemic_separation():
    """Deep RE findings map to E1..E4 evidence, all MEASURED, NEVER E5 (Live Execution)."""
    # Ghidra -> E3
    ghidra_ev = BinaryEvidenceGenerator.from_deep_re_finding(
        engine_name="Ghidra",
        finding={"symbol": "crypto_box_curve25519xsalsa20poly1305", "offset": 0x401000},
        file_path="libfoo.so",
        file_hash="hash_ghidra",
    )
    assert ghidra_ev.level == EvidenceLevel.E3
    assert ghidra_ev.state == EvidenceState.MEASURED
    assert ghidra_ev.level != EvidenceLevel.E5

    # angr -> E4
    angr_ev = BinaryEvidenceGenerator.from_deep_re_finding(
        engine_name="angr",
        finding={"symbol": "reachable_path_to_aes", "offset": 0x401200},
        file_path="libfoo.so",
        file_hash="hash_angr",
    )
    assert angr_ev.level == EvidenceLevel.E4
    assert angr_ev.state == EvidenceState.MEASURED
    assert angr_ev.level != EvidenceLevel.E5

    # YARA -> E1
    yara_ev = BinaryEvidenceGenerator.from_deep_re_finding(
        engine_name="YARA",
        finding={"rule_name": "crypto_constants_detector", "offset": 0x401400},
        file_path="libfoo.so",
        file_hash="hash_yara",
    )
    assert yara_ev.level == EvidenceLevel.E1
    assert yara_ev.state == EvidenceState.MEASURED
    assert yara_ev.level != EvidenceLevel.E5


# ==============================================================================
# SUITE 7: GRAPH MONOTONICITY & ASSET DEDUPLICATION
# ==============================================================================

def test_asset_graph_monotonicity_protection():
    """Updating an existing E3 asset with an E1 observation preserves E3 level and max confidence."""
    graph, _ = create_in_memory_graph()
    asset = graph.create_asset(
        project="test_proj",
        asset_type=AssetType.ALGORITHM,
        name="AES",
        highest_evidence_level="E3",
        confidence=0.88,
    )
    asset_id = asset.id

    # Attempt to update with weaker E1 evidence
    graph.update_asset(
        asset_id=asset_id,
        highest_evidence_level="E1",
        confidence=0.50,
    )
    updated = graph.get_asset(asset_id, "test_proj")
    assert updated.highest_evidence_level == "E3"
    assert updated.confidence == 0.88

    # Now upgrade with stronger E4 evidence
    graph.update_asset(
        asset_id=asset_id,
        highest_evidence_level="E4",
        confidence=0.95,
    )
    upgraded = graph.get_asset(asset_id, "test_proj")
    assert upgraded.highest_evidence_level == "E4"
    assert upgraded.confidence == 0.95


def test_asset_deduplication_multi_source():
    """An algorithm detected via symbol, string, and byte signature consolidates into one asset with multiple evidence links."""
    aes_sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
    elf_data = create_synthetic_elf64(
        sections_data={
            ".text": b"\x90" * 32,
            ".rodata": aes_sbox + b"\0AES_CBC_ENCRYPT_MODE\0",
        },
        symbols=[("aes_encrypt", True, True, 0x401000, 32)],
    )
    graph, _ = create_in_memory_graph()
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)
    result = pipeline.scan(elf_data, "crypto_bundle.elf", project="dedup_proj", scan_id="dedup_scan")

    assets = graph.find_assets_by_project("dedup_proj")
    aes_assets = [a for a in assets if a.name == "AES" and a.asset_type == AssetType.ALGORITHM]
    # Exactly one canonical AES algorithm asset node
    assert len(aes_assets) == 1
    # Supporting evidence items generated
    assert len(result.evidence) >= 2


# ==============================================================================
# SUITE 8: CRYPTOGRAPHIC NORMALIZATION & SPECIFICITY AUDIT
# ==============================================================================

def test_normalization_canonical_specificity_preservation():
    """RSA-2048, ML-KEM-768, AES-256-GCM preserve parameter specificity when requested."""
    name, cat, stat = BinaryNormalizer.normalize_canonical("RSA_2048")
    assert name == "RSA-2048"
    assert cat == "ASYMMETRIC"
    assert stat == "QUANTUM_VULNERABLE"

    name, cat, stat = BinaryNormalizer.normalize_canonical("crystals_kyber768")
    assert name == "ML-KEM-768"
    assert cat == "PQC"
    assert stat == "PQC_STANDARDIZED"

    name, cat, stat = BinaryNormalizer.normalize_canonical("aes_256_gcm")
    assert name == "AES-256-GCM"
    assert cat == "SYMMETRIC"

    name, cat, stat = BinaryNormalizer.normalize_canonical("dilithium65")
    assert name == "ML-DSA-65"
    assert cat == "PQC"


def test_normalization_coarse_backward_compatibility():
    """Coarse normalize_algorithm remains backward compatible by default."""
    name, cat, stat = BinaryNormalizer.normalize_algorithm("aes_128_gcm")
    assert name == "AES"
    assert cat == "SYMMETRIC"

    name, cat, stat = BinaryNormalizer.normalize_algorithm("crystals_kyber768")
    assert name == "ML-KEM"
    assert cat == "PQC"


def test_normalization_entity_audit():
    """normalize_entity produces structured dictionary with specificity audit."""
    ent = BinaryNormalizer.normalize_entity("RSA_4096")
    assert ent["canonical_family"] == "RSA"
    assert ent["canonical_name"] == "RSA-4096"
    assert ent["key_size"] == 4096
    assert ent["specificity_preserved"] is True

    ent_aes = BinaryNormalizer.normalize_entity("AES_256_CBC")
    assert ent_aes["canonical_name"] == "AES-256-CBC"
    assert ent_aes["mode"] == "CBC"
    assert ent_aes["key_size"] == 256


# ==============================================================================
# SUITE 9: DETERMINISM & ROBUST FAILURE CONTAINMENT
# ==============================================================================

def test_pipeline_reproducibility_determinism():
    """Repeated execution over identical input produces identical asset count and evidence count."""
    elf_data = create_synthetic_elf64(
        sections_data={".text": b"\x90" * 32},
        symbols=[("sha256_transform", True, True, 0x401000, 32)],
    )
    graph1, _ = create_in_memory_graph()
    res1 = BinaryDiscoveryPipeline(asset_graph=graph1).scan(elf_data, "sample.elf", "scan_1")

    graph2, _ = create_in_memory_graph()
    res2 = BinaryDiscoveryPipeline(asset_graph=graph2).scan(elf_data, "sample.elf", "scan_2")

    assert len(res1.members) == len(res2.members)
    assert len(res1.evidence) == len(res2.evidence)
    assert res1.members[0].symbols[0].name == res2.members[0].symbols[0].name


def test_malformed_elf_header_containment():
    """ELF with corrupted section header offsets is contained without raising unhandled exception."""
    elf_corrupted = bytearray(create_synthetic_elf64())
    struct.pack_into("<Q", elf_corrupted, 40, 0xFFFFFFFFFFFF)

    graph, _ = create_in_memory_graph()
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)
    res = pipeline.scan(bytes(elf_corrupted), "corrupted.elf", project="test", scan_id="scan_corrupt")
    assert len(res.members) == 1
    assert res.members[0].identification.format == BinaryFormat.ELF


def test_malformed_pe_header_containment():
    """PE with invalid e_lfanew pointer is contained gracefully."""
    pe_corrupted = bytearray(create_synthetic_pe32())
    struct.pack_into("<I", pe_corrupted, 60, len(pe_corrupted) + 1000)

    graph, _ = create_in_memory_graph()
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)
    res = pipeline.scan(bytes(pe_corrupted), "corrupted.exe", project="test", scan_id="scan_corrupt_pe")
    assert len(res.members) == 1


def test_malformed_archive_containment():
    """Truncated archive data is handled gracefully by FirmwareExtractor."""
    truncated_zip = b"PK\x03\x04" + b"\x00" * 10
    res = FirmwareExtractor.extract(truncated_zip, "truncated.zip")
    assert res.members == []
    assert len(res.errors) >= 1
