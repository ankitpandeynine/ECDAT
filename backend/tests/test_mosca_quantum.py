"""
Tests for Mosca's Theorem Engine and Quantum API endpoints.
Verifies:
- Published research values (Gidney & Ekerå 2021, NIST IR 8547 2024)
- Mosca's Theorem logic: (X + Y > Z) implies Harvest-Now-Decrypt-Later exposure
- Empty project returns informative message
- Assets in project yield sorted Mosca results
- Timeline summary returns per-algorithm Z horizons
"""
import pytest
from fastapi.testclient import TestClient
from main import app
from engine.mosca import (
    QUANTUM_BREAK_YEARS,
    lookup_quantum_break_years,
    mosca_assess,
    assess_project_assets,
    get_timeline_summary,
)


def test_quantum_break_years_literature_constants():
    """Ensure hardcoded constants match published research."""
    # RSA-2048 from Gidney & Ekerå 2021 (~20M physical qubits, 8 hours)
    assert QUANTUM_BREAK_YEARS[("RSA", 2048)] == 9.0
    # ECDSA-256 from Roetteler et al. 2017 (~2330 logical qubits)
    assert QUANTUM_BREAK_YEARS[("ECDSA", 256)] == 7.0
    # AES-256 is quantum-safe (Grover leaves 128-bit security)
    assert QUANTUM_BREAK_YEARS[("AES", 256)] == 60.0
    # NIST FIPS 203 PQC
    assert QUANTUM_BREAK_YEARS[("ML-KEM", 768)] == 100.0


def test_mosca_assess_rsa_2048():
    """
    Test Mosca assessment on RSA-2048:
    X = 10, Y = 3 -> X + Y = 13.
    Z = 9.0 (RSA-2048).
    Deficit = 13 - 9 = 4.0 years.
    Harvest-now-decrypt-later risk is TRUE.
    """
    result = mosca_assess("RSA", 2048, data_sensitivity_years=10.0, migration_time_years=3.0)
    assert "RSA" in result.algorithm
    assert result.key_size == 2048
    assert result.x_sensitivity_years == 10.0
    assert result.y_migration_years == 3.0
    assert result.z_threat_horizon_years == 9.0
    assert result.quantum_deficit_years == 4.0
    assert result.harvest_now_risk is True
    assert result.risk_level in ["CRITICAL", "HIGH"]
    assert "Gidney" in result.literature_reference or "NIST" in result.literature_reference


def test_mosca_assess_quantum_safe_pqc():
    """
    ML-KEM-768 has Z=100.0.
    With X=10, Y=3 (13 <= 100), quantum deficit is negative (safety margin), harvest_now_risk is False, risk_level is SAFE.
    """
    result = mosca_assess("ML-KEM", 768, data_sensitivity_years=10.0, migration_time_years=3.0)
    assert result.z_threat_horizon_years == 100.0
    assert result.quantum_deficit_years < 0.0  # Safe margin
    assert result.harvest_now_risk is False
    assert result.risk_level == "SAFE"


def test_mosca_api_empty_project():
    """If project has no assets: return {results: [], message: 'No assets discovered yet. Run a scan.'}"""
    with TestClient(app) as client:
        resp = client.post(
            "/api/quantum/mosca-project-scan",
            json={"project_id": "nonexistent-empty-project-id", "data_sensitivity_years": 10.0, "migration_time_years": 3.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["results"] == []
        assert "No assets discovered yet" in data["message"]


def test_mosca_api_and_timeline_with_assets():
    """Create a temporary project with assets and test both endpoints."""
    with TestClient(app) as client:
        store = app.state.store
        test_proj = "test-mosca-proj-123"

        with store.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO projects (id, name, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))",
                (test_proj, "Mosca Test Project"),
            )
            # Clean existing assets
            db.execute("DELETE FROM crypto_assets WHERE project = ?", (test_proj,))
            # Insert RSA-2048 and AES-256 assets
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("asset-1", test_proj, "jwt_signer", "RSA", 2048, "key"),
            )
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("asset-2", test_proj, "tls_cert", "RSA", 2048, "certificate"),
            )
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("asset-3", test_proj, "db_encryption", "AES", 256, "cipher"),
            )
            db.commit()

        # Test POST /api/quantum/mosca-project-scan
        resp = client.post(
            "/api/quantum/mosca-project-scan",
            json={"project_id": test_proj, "data_sensitivity_years": 10.0, "migration_time_years": 3.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["results"]) == 2  # RSA-2048 and AES-256
        # Sorted by risk_score descending -> RSA-2048 should be first
        assert data["results"][0]["algorithm"] == "RSA-2048"
        assert data["results"][0]["key_size"] == 2048
        assert data["results"][0]["asset_count"] == 2
        assert data["results"][0]["harvest_now_risk"] is True

        assert data["results"][1]["algorithm"] == "AES-256"
        assert data["results"][1]["key_size"] == 256
        assert data["results"][1]["asset_count"] == 1
        assert data["results"][1]["harvest_now_risk"] is False

        # Test GET /api/quantum/timeline-summary?project={test_proj}
        resp_timeline = client.get(f"/api/quantum/timeline-summary?project={test_proj}")
        assert resp_timeline.status_code == 200
        tdata = resp_timeline.json()
        assert len(tdata) == 2
        # Check shape
        item = next(i for i in tdata if i["algorithm"] == "RSA-2048")
        assert item["z_years"] == 9.0
        assert item["asset_count"] == 2
        assert item["risk_level"] in ["CRITICAL", "HIGH", "AT_RISK"]

        # Cleanup
        with store.connect() as db:
            db.execute("DELETE FROM crypto_assets WHERE project = ?", (test_proj,))
            db.execute("DELETE FROM projects WHERE id = ?", (test_proj,))
            db.commit()


def test_quantum_risk_summary_and_dependency_filtering():
    """Verify /api/quantum/risk-summary returns accurate counts and excludes npm runtime packages."""
    with TestClient(app) as client:
        store = app.state.store
        test_proj = "test-quantum-summary-proj"

        with store.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO projects (id, name, created_at, updated_at) VALUES (?, ?, datetime('now'), datetime('now'))",
                (test_proj, "Summary Test"),
            )
            db.execute("DELETE FROM crypto_assets WHERE project = ?", (test_proj,))

            # Insert a mix of assets:
            # 1. Broken NOW: MD5
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("a-md5", test_proj, "md5_hash", "MD5", None, "hash"),
            )
            # 2. Quantum Critical (Shor): RSA-2048
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("a-rsa", test_proj, "rsa_key", "RSA", 2048, "key"),
            )
            # 3. Quantum Safe: ML-KEM-768
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("a-mlkem", test_proj, "kem_key", "ML-KEM-768", 768, "kem"),
            )
            # 4. Noise packages (should be filtered out completely)
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("a-zod", test_proj, "zod-validation-error", "zod-validation-error", None, "DEPENDENCY"),
            )
            db.execute(
                """
                INSERT INTO crypto_assets (id, project, name, algorithm, key_size, asset_type, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', datetime('now'), datetime('now'))
                """,
                ("a-colors", test_proj, "yoctocolors", "yoctocolors", None, "PACKAGE"),
            )
            db.commit()

        # Test risk summary
        resp = client.get(f"/api/quantum/risk-summary?project={test_proj}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["broken_now"] == 1        # MD5
        assert data["quantum_critical"] == 1   # RSA-2048
        assert data["quantum_safe"] == 1       # ML-KEM-768
        assert data["mosca_at_risk"] >= 1      # RSA and/or MD5
        assert data["total_assets"] == 3       # zod and yoctocolors filtered out!

        # Test timeline summary also excludes noise and has mosca_verdict
        resp_tl = client.get(f"/api/quantum/timeline-summary?project={test_proj}")
        assert resp_tl.status_code == 200
        tl_data = resp_tl.json()
        algos = [t["algorithm"] for t in tl_data]
        assert not any("zod" in a.lower() or "color" in a.lower() for a in algos)
        assert any("RSA" in a for a in algos)
        assert all("mosca_verdict" in t for t in tl_data)

        # Cleanup
        with store.connect() as db:
            db.execute("DELETE FROM crypto_assets WHERE project = ?", (test_proj,))
            db.execute("DELETE FROM projects WHERE id = ?", (test_proj,))
            db.commit()

