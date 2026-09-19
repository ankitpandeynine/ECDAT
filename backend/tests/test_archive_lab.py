"""
Tests for ECDAT Phase 20-23: Secure Archive Lab, ECVault Repackaging & Verification.
"""
import io
import zipfile
import pytest
from engine.scan_store import ScanStore
from engine.archive_lab import SecureArchiveLab, detect_archive_format
from engine.ecvault import ECVaultEngine, VaultProtectionMode


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_arch.sqlite3")
    return ScanStore(db_path)


def test_detect_archive_formats():
    assert detect_archive_format(b"PK\x03\x04\x14\x00...") == "ZIP"
    assert detect_archive_format(b"7z\xbc\xaf\x27\x1c...") == "7z"
    assert detect_archive_format(b"\x1f\x8b\x08\x00...") == "GZIP"
    assert detect_archive_format(b"RANDOM_NON_ARCHIVE_DATA") == "UNKNOWN"


def test_password_vault_creation_and_verification():
    secret_data = b"CONFIDENTIAL FINANCIAL RECORD: ACCT-9918239102-SECRET"
    password = "MasterVaultPassword2026!"

    # 1. Create Password Vault container
    container = ECVaultEngine.create_password_vault(
        payload_bytes=secret_data,
        password=password,
        vault_name="q3_financials.ecvault",
        project_id="default"
    )

    assert container["format"] == "ECVAULT"
    assert container["mode"] == VaultProtectionMode.PASSWORD_VAULT.value
    assert container["manifest"]["bulk_cipher"] == "AES-256-GCM"
    assert container["manifest"]["kdf"] == "PBKDF2-HMAC-SHA256"

    # 2. Verify with correct password -> PASS
    res_valid = ECVaultEngine.verify_vault(container, password=password)
    assert res_valid["status"] == "VERIFIED"
    assert all(c["status"] == "PASS" for c in res_valid["checks"])

    # 3. Verify with wrong password -> FAILED
    res_invalid = ECVaultEngine.verify_vault(container, password="WrongPassword!")
    assert res_invalid["status"] == "FAILED"

    # 4. Verify with no password -> INCONCLUSIVE
    res_no_pwd = ECVaultEngine.verify_vault(container, password=None)
    assert res_no_pwd["status"] == "INCONCLUSIVE"


def test_pqc_hybrid_vault():
    secret_data = b"QUANTUM CLASSIFIED COMMUNICATIONS TELEMETRY"
    container = ECVaultEngine.create_pqc_hybrid_vault(
        payload_bytes=secret_data,
        vault_name="quantum_satellite.ecvault",
        project_id="default"
    )

    assert container["mode"] == VaultProtectionMode.PQC_HYBRID_VAULT.value
    assert container["manifest"]["key_encapsulation"] == "X25519-ML-KEM-768-Hybrid"

    # Verify PQC hybrid vault
    res = ECVaultEngine.verify_vault(container)
    assert res["status"] == "VERIFIED"


def test_archive_analysis_and_internal_discovery(store):
    # Create synthetic test ZIP containing source code and a certificate
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w') as zf:
        zf.writestr('core_auth.py', 'from cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(65537, 2048)')
        zf.writestr('server.crt', '-----BEGIN CERTIFICATE-----\nMIIBkDCB+wIJAKHH0...')
    raw_zip = bio.getvalue()

    lab = SecureArchiveLab(store)
    report = lab.analyze_archive(raw_zip, filename="test_bundle.zip", project_id="default")

    assert report["format"] == "ZIP"
    assert report["file_count"] == 2
    assert report["content_status"] in ("ANALYZED_UNENCRYPTED", "SUCCESSFULLY_DECRYPTED_AND_ANALYZED")
    assert len(report["discovered_assets"]) >= 1
    # Check that discovered asset captured the RSA usage inside the archive
    algo_names = [a.get("algorithm") for a in report["discovered_assets"]]
    assert any("RSA" in a or "ASYMMETRIC" in a for a in algo_names)


def test_zip_slip_path_traversal_protection(store):
    # Create malicious ZIP attempting path traversal
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, 'w') as zf:
        zf.writestr('../../etc/shadow_exploit.txt', 'MALICIOUS_PAYLOAD')
        zf.writestr('legit.txt', 'SAFE_CONTENT')
    raw_zip = bio.getvalue()

    lab = SecureArchiveLab(store)
    report = lab.analyze_archive(raw_zip, filename="exploit.zip", project_id="default")

    # The traversal file must be ignored and not extracted outside sandbox
    assert report["format"] == "ZIP"
    assert report["content_status"] in ("ANALYZED_UNENCRYPTED", "SUCCESSFULLY_DECRYPTED_AND_ANALYZED")
