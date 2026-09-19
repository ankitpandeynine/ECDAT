import pytest
from engine.evidence_model import (
    AssetType,
    ConfidenceLevel,
    CryptographicRole,
    EvidenceRecord,
    EvidenceType,
    SourceSurface,
)
from engine.verifier import ClosedLoopVerifier, VerificationVerdict
from fastapi.testclient import TestClient
from main import app


def create_mock_evidence(algo: str, role: CryptographicRole, surface: SourceSurface, location: str, severity: str = "LOW") -> EvidenceRecord:
    return EvidenceRecord(
        asset_id=EvidenceRecord.generate_asset_id(surface.value, location, algo),
        asset_type=AssetType.ALGORITHM,
        algorithm=algo,
        cryptographic_role=role,
        source_surface=surface,
        evidence_type=EvidenceType.STATIC_INFERRED,
        location_endpoint=location,
        confidence=ConfidenceLevel.CONFIRMED,
        severity=severity
    )


def test_closed_loop_verifier_verified():
    baseline = [
        create_mock_evidence("MD5", CryptographicRole.HASH_INTEGRITY, SourceSurface.SOURCE_CODE, "src/auth.py:10", "CRITICAL"),
        create_mock_evidence("RSA-1024", CryptographicRole.KEY_EXCHANGE, SourceSurface.SOURCE_CODE, "src/keys.py:20", "CRITICAL")
    ]
    post_migration = [
        create_mock_evidence("SHA-256", CryptographicRole.HASH_INTEGRITY, SourceSurface.SOURCE_CODE, "src/auth.py:10", "LOW"),
        create_mock_evidence("ML-KEM-768", CryptographicRole.KEY_EXCHANGE, SourceSurface.SOURCE_CODE, "src/keys.py:20", "LOW")
    ]

    report = ClosedLoopVerifier.verify(baseline, post_migration)
    assert report.verdict == VerificationVerdict.VERIFIED
    assert len(report.retired_weaknesses) == 2
    assert len(report.introduced_protections) == 2
    assert len(report.persisting_risks) == 0
    assert report.summary["risk_reduction_percentage"] == 100.0


def test_closed_loop_verifier_persisting_risk():
    baseline = [
        create_mock_evidence("MD5", CryptographicRole.HASH_INTEGRITY, SourceSurface.SOURCE_CODE, "src/auth.py:10", "CRITICAL")
    ]
    post_migration = [
        create_mock_evidence("MD5", CryptographicRole.HASH_INTEGRITY, SourceSurface.SOURCE_CODE, "src/auth.py:10", "CRITICAL")
    ]

    report = ClosedLoopVerifier.verify(baseline, post_migration)
    assert report.verdict == VerificationVerdict.NOT_VERIFIED
    assert len(report.persisting_risks) == 1
    assert len(report.retired_weaknesses) == 0


def test_closed_loop_verifier_regression():
    baseline = [
        create_mock_evidence("SHA-256", CryptographicRole.HASH_INTEGRITY, SourceSurface.SOURCE_CODE, "src/auth.py:10", "LOW")
    ]
    post_migration = [
        create_mock_evidence("SHA-256", CryptographicRole.HASH_INTEGRITY, SourceSurface.SOURCE_CODE, "src/auth.py:10", "LOW"),
        create_mock_evidence("DES", CryptographicRole.BULK_ENCRYPTION, SourceSurface.SOURCE_CODE, "src/legacy.py:5", "CRITICAL")
    ]

    report = ClosedLoopVerifier.verify(baseline, post_migration)
    assert report.verdict == VerificationVerdict.NOT_VERIFIED
    assert len(report.regressions) == 1


def test_verify_api_endpoint(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_DB", str(tmp_path / "scans.sqlite3"))
    monkeypatch.delenv("ECDAT_API_TOKEN", raising=False)

    with TestClient(app) as client:
        # Scan 1: Baseline (MD5)
        resp1 = client.post("/api/scan/code?project=test_verify", json={
            "source_code": "import hashlib\ndef a(): return hashlib.md5(b'1').digest()",
            "language": "python"
        })
        scan1_id = resp1.json()["id"]

        # Scan 2: Post-Migration (SHA-256)
        resp2 = client.post("/api/scan/code?project=test_verify", json={
            "source_code": "import hashlib\ndef a(): return hashlib.sha256(b'1').digest()",
            "language": "python"
        })
        scan2_id = resp2.json()["id"]

        import time
        for _ in range(100):
            r1 = client.get(f"/api/scans/{scan1_id}?project=test_verify").json()
            r2 = client.get(f"/api/scans/{scan2_id}?project=test_verify").json()
            if r1["status"] == "completed" and r2["status"] == "completed":
                break
            time.sleep(0.02)

        # Call verify endpoint
        verify_resp = client.post("/api/verify?project=test_verify", json={
            "baseline_scan_ids": [scan1_id],
            "post_migration_scan_ids": [scan2_id]
        })
        assert verify_resp.status_code == 200
        report = verify_resp.json()
        assert report["verdict"] == "VERIFIED"
        assert len(report["retired_weaknesses"]) >= 1
