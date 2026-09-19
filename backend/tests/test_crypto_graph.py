import uuid
import pytest
from fastapi.testclient import TestClient
from main import app
from engine.scan_store import ScanStore


@pytest.fixture
def client(tmp_path):
    db_file = tmp_path / "test_graph.sqlite3"
    app.state.store = ScanStore(str(db_file))
    with TestClient(app) as test_client:
        yield test_client
    app.state.store.close()


def test_empty_project_graph(client):
    """
    Rule 1 & Task Item 1:
    Empty project must return {"nodes": [], "edges": []}, strictly 0 nodes and 0 edges.
    """
    p_id = f"empty-{uuid.uuid4().hex[:6]}"
    resp = client.get(f"/api/graph?project={p_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["nodes"] == []
    assert data["edges"] == []


def test_orphan_edges_filtered_out(client):
    """
    Task Item 1:
    If graph_edges reference node IDs not in the nodes array: filter those edges OUT before returning.
    """
    p_id = f"orphan-{uuid.uuid4().hex[:6]}"
    node_id = f"node-{uuid.uuid4().hex[:6]}"
    store = app.state.store

    # Insert one valid node into graph_nodes
    with store.connect() as db:
        db.execute("""
            INSERT INTO graph_nodes (id, project, label, type, risk_level, evidence_count, blast_radius_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        """, (node_id, p_id, "AES-256", "algorithm", "low", 1, 0))

        # Insert one orphan edge referencing non-existent target node
        db.execute("""
            INSERT INTO graph_edges (id, project, source_id, source_type, relationship, target_id, target_type, confidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (f"edge-{uuid.uuid4().hex[:6]}", p_id, node_id, "algorithm", "uses", "non-existent-node-999", "service", 0.9))

    resp = client.get(f"/api/graph?project={p_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["nodes"]) == 1
    assert data["nodes"][0]["id"] == node_id
    # Orphan edge must be filtered out
    assert len(data["edges"]) == 0


def test_source_scan_populates_graph_nodes(client):
    """
    Task Item 2:
    Verify that after a source scan completes and assets are saved to crypto_assets table,
    the knowledge_graph is called to create corresponding graph_nodes for each new asset.
    """
    p_id = f"scan-graph-{uuid.uuid4().hex[:6]}"
    code = """
import hashlib
from Crypto.Cipher import AES

def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt(data)

def weak_hash(data):
    return hashlib.md5(data).hexdigest()
"""
    scan_resp = client.post(
        f"/api/scan/code?project={p_id}",
        json={"source_code": code, "language": "python"}
    )
    assert scan_resp.status_code == 202
    job_id = scan_resp.json()["id"]

    # Wait for scan job completion
    import time
    for _ in range(20):
        check = client.get(f"/api/scans/{job_id}?project={p_id}").json()
        if check["status"] in ("completed", "failed"):
            break
        time.sleep(0.1)

    assert check["status"] == "completed"

    # Query graph
    graph_resp = client.get(f"/api/graph?project={p_id}")
    assert graph_resp.status_code == 200
    g_data = graph_resp.json()

    assert len(g_data["nodes"]) >= 2
    # Verify exact shape
    for node in g_data["nodes"]:
        assert "id" in node
        assert "label" in node
        assert "type" in node
        assert "risk_level" in node
        assert "evidence_count" in node
        assert "blast_radius_count" in node

    node_ids = {n["id"] for n in g_data["nodes"]}
    for edge in g_data["edges"]:
        assert "source" in edge
        assert "target" in edge
        assert "relationship" in edge
        assert "confidence" in edge
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids


def test_demo_seed_populates_graph_properly(client):
    """
    Verifies demo data seeding creates valid graph_nodes and graph_edges with zero orphan edges.
    """
    p_id = f"demo-seed-{uuid.uuid4().hex[:6]}"
    seed_resp = client.post(f"/api/projects/{p_id}/demo/seed")
    assert seed_resp.status_code == 200

    graph_resp = client.get(f"/api/graph?project={p_id}")
    assert graph_resp.status_code == 200
    g_data = graph_resp.json()

    assert len(g_data["nodes"]) >= 3
    node_ids = {n["id"] for n in g_data["nodes"]}

    for edge in g_data["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
