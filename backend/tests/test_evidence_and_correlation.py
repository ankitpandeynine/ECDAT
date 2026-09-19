import pytest
from engine.evidence_model import (
    AssetType,
    ConfidenceLevel,
    CryptographicRole,
    EvidenceRecord,
    EvidenceType,
    SourceSurface,
    normalize_source_finding,
    normalize_binary_detection,
    normalize_network_scan,
    is_quantum_vulnerable,
)
from engine.correlator import CrossSurfaceCorrelator
from engine.knowledge_graph import CryptoKnowledgeGraph
from fastapi.testclient import TestClient
from main import app


def test_evidence_record_generation_and_unknowns():
    aid = EvidenceRecord.generate_asset_id("source_code", "src/auth.py:45", "MD5")
    assert aid.startswith("asset_")

    rec = EvidenceRecord(
        asset_id=aid,
        asset_type=AssetType.ALGORITHM,
        algorithm="MD5",
        cryptographic_role=CryptographicRole.HASH_INTEGRITY,
        source_surface=SourceSurface.SOURCE_CODE,
        evidence_type=EvidenceType.STATIC_INFERRED,
        location_endpoint="src/auth.py:45",
        confidence=ConfidenceLevel.HIGH,
        is_unknown=False
    )
    assert rec.algorithm == "MD5"
    assert rec.is_unknown is False


def test_quantum_vulnerability_mapping():
    assert is_quantum_vulnerable("RSA-2048") is True
    assert is_quantum_vulnerable("ECDSA-P256") is True
    assert is_quantum_vulnerable("ML-KEM-768") is False
    assert is_quantum_vulnerable("ML-DSA-65") is False
    assert is_quantum_vulnerable("AES-256-GCM") is False
    assert is_quantum_vulnerable("DES") is True


def test_cross_surface_correlator_and_graph():
    correlator = CrossSurfaceCorrelator()

    # Ingest synthetic records across surfaces
    source_finding = {
        "primitive": "RSA-1024",
        "file": "src/crypto/keys.py",
        "line": 42,
        "category": "Asymmetric Key",
        "severity": "CRITICAL",
        "issue": "Weak key size"
    }
    rec1 = normalize_source_finding(source_finding, input_hash="hash1")
    correlator.ingest_records([rec1])

    network_result = {
        "target": "api.bank.com:443",
        "host": "api.bank.com",
        "port": 443,
        "cipher_name": "TLS_AES_256_GCM_SHA384",
        "protocol": "TLSv1.3",
        "quantum_vulnerable": False,
        "hndl_risk": "LOW",
        "post_quantum": {
            "tests": [{"status": "negotiated", "group": "X25519MLKEM768", "evidence": "TLS 1.3 negotiated"}]
        },
        "certificate": {
            "subject": "CN=api.bank.com",
            "issuer": "CN=DigiCert Global CA",
            "public_key": "RSA-2048",
            "expired": False
        }
    }
    net_recs = normalize_network_scan(network_result, "scan_net_1", input_hash="hash2")
    correlator.ingest_records(net_recs)

    topology = correlator.correlate(default_app_name="PaymentService")
    assert topology.total_assets >= 4
    assert len(topology.links) >= 3

    # Verify relationships
    rels = {l.relationship for l in topology.links}
    assert "uses" in rels or "implements" in rels or "serves" in rels

    # Build CryptoKnowledgeGraph from topology
    kg = CryptoKnowledgeGraph()
    kg.load_from_topology(topology)
    exported = kg.export_for_ui()
    assert len(exported["nodes"]) >= 4
    assert len(exported["links"]) >= 3

    # Check blast radius computation
    rsa_node = next((n for n in exported["nodes"] if "rsa" in n["id"].lower()), None)
    if rsa_node:
        assert isinstance(rsa_node["blast_radius"], list)


def test_api_evidence_and_topology_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_DB", str(tmp_path / "scans.sqlite3"))
    monkeypatch.delenv("ECDAT_API_TOKEN", raising=False)

    with TestClient(app) as client:
        # Submit a code scan
        code_resp = client.post("/api/scan/code?project=test_proj", json={
            "source_code": "import hashlib\ndef h(p): return hashlib.md5(p).hexdigest()",
            "language": "python"
        })
        assert code_resp.status_code == 202
        scan_id = code_resp.json()["id"]

        import time
        for _ in range(100):
            res = client.get(f"/api/scans/{scan_id}?project=test_proj").json()
            if res["status"] == "completed":
                break
            time.sleep(0.02)

        # Query evidence records
        ev_resp = client.get("/api/evidence/records?project=test_proj")
        assert ev_resp.status_code == 200
        records = ev_resp.json()
        assert len(records) >= 1
        assert any(r["algorithm"] == "MD5" for r in records)

        # Query correlated topology
        topo_resp = client.get("/api/correlate?project=test_proj")
        assert topo_resp.status_code == 200
        topo = topo_resp.json()
        assert topo["total_assets"] >= 1

        # Query graph
        graph_resp = client.get("/api/graph?project=test_proj")
        assert graph_resp.status_code == 200
        assert "nodes" in graph_resp.json()
