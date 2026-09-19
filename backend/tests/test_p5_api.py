"""
ECDAT V4 P5 REST API Endpoint Tests.
"""
from pathlib import Path
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import app
from engine.scan_store import ScanStore


@pytest.fixture
def client_with_data():
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        db_path = f.name

    store = ScanStore(path=db_path)
    app.state.store = store

    with store.connect() as db:
        db.execute("INSERT OR IGNORE INTO scans (id, project, kind, status, created_at, input_hash) VALUES ('scan-alpha', 'proj-api', 'source', 'completed', '2026-09-18T00:00:00Z', 'h1')")
        db.execute("INSERT OR IGNORE INTO scans (id, project, kind, status, created_at, input_hash) VALUES ('scan-beta', 'proj-api', 'source', 'completed', '2026-09-18T01:00:00Z', 'h2')")

    a1 = store.graph.create_asset(
        project="proj-api",
        asset_type="ALGORITHM",
        name="AES-256-API",
        scan_id="scan-alpha",
        algorithm="AES",
        key_size=256,
        asset_id="asset-api-1",
    )
    a2 = store.graph.create_asset(
        project="proj-api",
        asset_type="ALGORITHM",
        name="ML-KEM-API",
        scan_id="scan-beta",
        algorithm="ML-KEM",
        key_size=768,
        asset_id="asset-api-2",
    )

    client = TestClient(app)
    yield client, a1.id, a2.id
    store.close()


def test_api_asset_timeline(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/timeline?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "events" in data
    assert data["asset_id"] == a1_id


def test_api_asset_changes(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/changes?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert data["asset_id"] == a1_id
    assert "change_events" in data


def test_api_asset_posture(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/posture?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "dimensions" in data
    assert "CRYPTO_INVENTORY" in data["dimensions"]


def test_api_asset_posture_history(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/posture/history?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "history" in data


def test_api_temporal_risk(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/temporal-risk?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "temporal_risk_change" in data


def test_api_temporal_pqc(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/temporal-pqc?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "temporal_pqc_change" in data


def test_api_temporal_agility(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/temporal-agility?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "temporal_agility_change" in data


def test_api_temporal_migration(client_with_data):
    client, a1_id, _ = client_with_data
    res = client.get(f"/api/assets/{a1_id}/temporal-migration?project=proj-api")
    assert res.status_code == 200
    data = res.json()
    assert "temporal_migration_change" in data


def test_api_temporal_compare(client_with_data):
    client, _, _ = client_with_data
    payload = {
        "project": "proj-api",
        "base_scan_id": "scan-alpha",
        "target_scan_id": "scan-beta",
    }
    res = client.post("/api/temporal/compare", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "comparison_id" in data
    assert "temporal_hash" in data
    assert data["base_scan_id"] == "scan-alpha"
    assert data["target_scan_id"] == "scan-beta"


def test_api_posture_evaluate_scan_and_change(client_with_data):
    client, _, _ = client_with_data
    # 1. Single scan evaluation
    payload_scan = {
        "project": "proj-api",
        "scan_id": "scan-alpha",
    }
    res = client.post("/api/posture/evaluate", json=payload_scan)
    assert res.status_code == 200
    data = res.json()
    assert "dimensions" in data

    # 2. Continuous change between two scans
    payload_change = {
        "project": "proj-api",
        "scan_id": "scan-beta",
        "base_scan_id": "scan-alpha",
        "target_scan_id": "scan-beta",
    }
    res_change = client.post("/api/posture/evaluate", json=payload_change)
    assert res_change.status_code == 200
    data_change = res_change.json()
    assert "overall_trend" in data_change
