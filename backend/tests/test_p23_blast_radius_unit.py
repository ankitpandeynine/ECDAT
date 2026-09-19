"""
ECDAT V4 P2.3 Blast Radius Unit Tests.

Verifies:
1. Strongly typed enums & assessment dataclasses
2. Graph normalization, edge canonicalization, and SHA-256 graph hashing
3. Dependency path reconstruction and multi-path detection
4. Bounded graph traversal and cycle pruning (A -> B -> A)
5. Architectural criticality assessment (production, sensitive data, external ingress)
6. Blast radius state and impact category classification
7. Evidence correlation and contradiction detection
8. Explainability reason chain generation
9. AssetGraphService and ScanStore SQLite persistence
10. REST API endpoints (GET /blast-radius, /why, /paths, /criticality, POST /blast-radius/evaluate)
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.asset_graph import AssetGraphService, CryptoAsset
from engine.blast_radius import (
    BlastRadiusAssessment,
    BlastRadiusReason,
    BlastRadiusState,
    CriticalityLevel,
    DependencyPath,
    GraphConfidence,
    ImpactCategory,
    build_blast_radius_explainability_report,
    evaluate_blast_radius,
)
from engine.blast_radius.criticality import assess_architectural_criticality
from engine.blast_radius.dependency_paths import (
    build_dependency_path,
    extract_multi_paths,
    has_independent_multi_paths,
)
from engine.blast_radius.evidence import (
    compute_evidence_hash,
    correlate_path_evidence,
)
from engine.blast_radius.explainability import generate_blast_radius_reason_chain
from engine.blast_radius.graph_analyzer import BoundedGraphAnalyzer
from engine.blast_radius.impact_classifier import (
    classify_blast_radius_state,
    classify_impact_category,
)
from engine.blast_radius.normalizer import (
    compute_canonical_graph_hash,
    is_relevant_relationship,
    normalize_edge,
    normalize_node,
    normalize_relationship,
)
from main import app


# ---------------------------------------------------------------------------
# 1. Models & Normalizer Tests
# ---------------------------------------------------------------------------

def test_p23_models_serialization():
    dp = build_dependency_path(
        source_id="service-a",
        target_id="crypto-primitive",
        node_sequence=["service-a", "crypto-primitive"],
        relationship_sequence=["USES"],
        evidence_refs=["ev-101"],
    )
    d = dp.to_dict()
    assert d["source_asset"] == "service-a"
    assert d["target_asset"] == "crypto-primitive"
    assert d["path_length"] == 1
    assert d["direct_or_transitive"] == "DIRECT"

    dp_restored = DependencyPath.from_dict(d)
    assert dp_restored.path_id == dp.path_id
    assert dp_restored.node_sequence == dp.node_sequence


def test_p23_normalizer_and_hashing():
    assert is_relevant_relationship("USES") is True
    assert is_relevant_relationship("DEPENDS_ON") is True
    assert is_relevant_relationship("EVIDENCED_BY") is False

    node = normalize_node({"id": "node-1", "type": "ALGORITHM", "name": "RSA-1024"})
    assert node["asset_type"] == "ALGORITHM"

    edge = normalize_edge({"source": "app-1", "target": "node-1", "rel": "uses"})
    assert edge["relationship"] == "USES"

    h1 = compute_canonical_graph_hash([node], [edge])
    h2 = compute_canonical_graph_hash([node], [edge])
    assert h1 == h2
    assert len(h1) == 64


# ---------------------------------------------------------------------------
# 2. Dependency Paths & Multi-Path Detection
# ---------------------------------------------------------------------------

def test_p23_dependency_paths_and_multi_paths():
    p1 = build_dependency_path(
        source_id="frontend",
        target_id="primitive",
        node_sequence=["frontend", "primitive"],
        relationship_sequence=["USES"],
    )
    p2 = build_dependency_path(
        source_id="frontend",
        target_id="primitive",
        node_sequence=["frontend", "middleware", "primitive"],
        relationship_sequence=["CALLS", "USES"],
    )

    assert p1.direct_or_transitive == "DIRECT"
    assert p2.direct_or_transitive == "TRANSITIVE"

    paths = [p1, p2]
    grouped = extract_multi_paths(paths)
    assert ("frontend", "primitive") in grouped
    assert len(grouped[("frontend", "primitive")]) == 2
    assert has_independent_multi_paths(paths) is True


# ---------------------------------------------------------------------------
# 3. Bounded Graph Traversal & Cycle Pruning
# ---------------------------------------------------------------------------

def test_p23_graph_analyzer_linear_chain():
    # S1 -> S2 -> S3 -> Target
    edges = [
        {"source_id": "s3", "target_id": "target", "relationship": "USES"},
        {"source_id": "s2", "target_id": "s3", "relationship": "CALLS"},
        {"source_id": "s1", "target_id": "s2", "relationship": "CALLS"},
    ]
    analyzer = BoundedGraphAnalyzer(max_depth=5)
    res = analyzer.analyze_blast_radius("target", raw_edges=edges)

    assert res["target_node_id"] == "target"
    assert res["total_impacted_count"] == 3
    assert res["direct_dependents"] == ["s3"]
    assert sorted(res["transitive_dependents"]) == ["s1", "s2"]
    assert res["partial_result"] is False
    assert len(res["limitations"]) == 0


def test_p23_graph_analyzer_cycle_pruning():
    # S1 -> S2 -> S1 -> Target (Cyclic loop)
    edges = [
        {"source_id": "s1", "target_id": "target", "relationship": "USES"},
        {"source_id": "s2", "target_id": "s1", "relationship": "CALLS"},
        {"source_id": "s1", "target_id": "s2", "relationship": "CALLS"},
    ]
    analyzer = BoundedGraphAnalyzer(max_depth=5)
    res = analyzer.analyze_blast_radius("target", raw_edges=edges)

    assert res["total_impacted_count"] == 2
    assert "CYCLE_DETECTED_AND_PRUNED" in res["limitations"]


def test_p23_graph_analyzer_depth_bound():
    # Chain of 6 nodes with max_depth=3
    edges = [
        {"source_id": "n1", "target_id": "target", "relationship": "USES"},
        {"source_id": "n2", "target_id": "n1", "relationship": "CALLS"},
        {"source_id": "n3", "target_id": "n2", "relationship": "CALLS"},
        {"source_id": "n4", "target_id": "n3", "relationship": "CALLS"},
        {"source_id": "n5", "target_id": "n4", "relationship": "CALLS"},
    ]
    analyzer = BoundedGraphAnalyzer(max_depth=3)
    res = analyzer.analyze_blast_radius("target", raw_edges=edges)

    assert res["partial_result"] is True
    assert "MAX_DEPTH_REACHED" in res["limitations"]
    assert len(res["dependency_paths"]) <= 3


# ---------------------------------------------------------------------------
# 4. Architectural Criticality
# ---------------------------------------------------------------------------

def test_p23_architectural_criticality_production():
    target = {"id": "asset-1", "is_production": True}
    impacted = [{"id": "svc-1", "asset_type": "SERVICE"}]
    crit, factors, lims = assess_architectural_criticality(target, impacted)
    assert crit == CriticalityLevel.CRITICAL
    assert any("production" in f.lower() for f in factors)


def test_p23_architectural_criticality_data_protection():
    target = {"id": "asset-2", "is_production": False}
    impacted = [{"id": "db-1", "asset_type": "DATA_ASSET"}]
    crit, factors, lims = assess_architectural_criticality(target, impacted)
    assert crit == CriticalityLevel.HIGH
    assert any("data" in f.lower() for f in factors)


def test_p23_architectural_criticality_external_exposure():
    target = {"id": "asset-3", "is_externally_exposed": True}
    impacted = [{"id": "gateway-1", "asset_type": "GATEWAY"}]
    crit, factors, lims = assess_architectural_criticality(target, impacted)
    assert crit == CriticalityLevel.HIGH
    assert any("exposed" in f.lower() for f in factors)


def test_p23_architectural_criticality_unknown_when_unspecified():
    target = {"id": "asset-4"}
    impacted = [{"id": "mod-1", "asset_type": "UNKNOWN"}]
    crit, factors, lims = assess_architectural_criticality(target, impacted)
    assert crit == CriticalityLevel.UNKNOWN


# ---------------------------------------------------------------------------
# 5. State & Impact Classifier
# ---------------------------------------------------------------------------

def test_p23_classifier_no_dependents():
    state, s_rat = classify_blast_radius_state([], [])
    assert state == BlastRadiusState.NO_DEPENDENTS_OBSERVED

    cat, c_rat = classify_impact_category([], [])
    assert cat == ImpactCategory.NONE_OBSERVED


def test_p23_classifier_direct_only():
    p = build_dependency_path("caller", "target", ["caller", "target"], ["USES"])
    state, s_rat = classify_blast_radius_state([p], [{"id": "caller"}])
    assert state == BlastRadiusState.DIRECT_ONLY

    cat, c_rat = classify_impact_category([p], [{"id": "caller"}])
    assert cat == ImpactCategory.DIRECT


def test_p23_classifier_multi_service():
    p1 = build_dependency_path("svc-1", "target", ["svc-1", "target"], ["USES"])
    p2 = build_dependency_path("svc-2", "target", ["svc-2", "target"], ["USES"])
    impacted = [
        {"id": "svc-1", "asset_type": "SERVICE"},
        {"id": "svc-2", "asset_type": "SERVICE"},
    ]
    cat, c_rat = classify_impact_category([p1, p2], impacted)
    assert cat == ImpactCategory.MULTI_SERVICE


# ---------------------------------------------------------------------------
# 6. Evidence Correlation & Contradictions
# ---------------------------------------------------------------------------

def test_p23_evidence_correlation_and_contradiction():
    p = build_dependency_path("caller", "target", ["caller", "target"], ["USES"], evidence_refs=["ev-1"])
    ev_item1 = {"id": "ev-1", "description": "Verified AST call", "level": "E3", "state": "MEASURED"}
    ev_item2 = {"id": "ev-2", "description": "unlinked dead_code", "state": "CONTRADICTED"}

    refs, sup, contra, has_contra = correlate_path_evidence([p], [ev_item1, ev_item2])
    assert "ev-1" in refs
    assert "ev-2" in refs
    assert has_contra is True
    assert len(contra) > 0

    state, rat = classify_blast_radius_state([p], [{"id": "caller"}], has_contradiction=has_contra)
    assert state == BlastRadiusState.INCONCLUSIVE


# ---------------------------------------------------------------------------
# 7. Master Pipeline & Explainability
# ---------------------------------------------------------------------------

def test_p23_evaluate_blast_radius_pipeline():
    edges = [
        {"source_id": "gateway", "target_id": "auth_lib", "relationship": "USES"},
        {"source_id": "auth_lib", "target_id": "crypto_core", "relationship": "USES"},
    ]
    nodes = [
        {"id": "crypto_core", "asset_type": "ALGORITHM", "name": "RSA-1024", "is_production": True},
        {"id": "auth_lib", "asset_type": "CRYPTO_LIBRARY", "name": "libauth.so"},
        {"id": "gateway", "asset_type": "SERVICE", "name": "api-gateway", "is_externally_exposed": True},
    ]
    assessment = evaluate_blast_radius(
        target_asset=nodes[0],
        raw_edges=edges,
        raw_nodes=nodes,
    )

    assert assessment.asset_id == "crypto_core"
    assert assessment.criticality == CriticalityLevel.CRITICAL
    assert assessment.state in (BlastRadiusState.TRANSITIVE, BlastRadiusState.CONTAINED)
    assert len(assessment.dependency_paths) == 2
    assert len(assessment.reason_chain) >= 4
    assert len(assessment.graph_hash) == 64

    # Build explainability report
    report = build_blast_radius_explainability_report(assessment)
    assert report["asset_id"] == "crypto_core"
    assert "reason_chain" in report
    assert "provenance" in report
    assert report["provenance"]["graph_hash"] == assessment.graph_hash


# ---------------------------------------------------------------------------
# 8. SQLite Persistence in AssetGraphService
# ---------------------------------------------------------------------------

def test_p23_sqlite_persistence():
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as tf:
        db_path = tf.name

    try:
        from engine.scan_store import ScanStore
        store = ScanStore(path=db_path)
        service = store.graph
        # Register an asset
        asset = service.create_asset(
            project="test_proj",
            asset_type="ALGORITHM",
            name="RSA-2048",
            algorithm="RSA",
            highest_evidence_level="E3",
            fused_status="CORROBORATED",
            confidence=0.95,
            explanation="Test RSA asset",
            asset_id="crypto-prim-1",
        )

        # Create caller and edge
        caller = service.create_asset(
            project="test_proj",
            asset_type="SERVICE",
            name="Core Banking",
            highest_evidence_level="E3",
            fused_status="CORROBORATED",
            confidence=0.95,
            explanation="Core service",
            asset_id="service-core",
        )
        service.add_relationship(
            project="test_proj",
            source_id="service-core",
            source_type="SERVICE",
            relationship="USES",
            target_id="crypto-prim-1",
            target_type="ALGORITHM",
        )

        # Evaluate and save blast radius
        eval_res = evaluate_blast_radius(asset.to_dict(), graph_service=service)
        aid = service.save_blast_radius_assessment(eval_res)
        assert aid == eval_res.assessment_id

        # Query back
        loaded = service.get_blast_radius_assessment("crypto-prim-1")
        assert loaded is not None
        assert loaded["assessment_id"] == eval_res.assessment_id
        assert loaded["direct_dependents"] == ["service-core"]

        all_records = service.get_all_blast_radius_assessments("crypto-prim-1")
        assert len(all_records) == 1

        why = service.get_why_blast_radius("crypto-prim-1", project="test_proj")
        assert why is not None
        assert why["asset_id"] == "crypto-prim-1"
        assert len(why["reason_chain"]) > 0

    finally:
        store.close()
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 9. REST Endpoints
# ---------------------------------------------------------------------------

def test_p23_api_endpoints():
    with TestClient(app) as client:
        # 1. Non-existent asset 404
        resp = client.get("/api/assets/non-existent-xyz/blast-radius")
        assert resp.status_code == 404

        resp = client.get("/api/assets/non-existent-xyz/blast-radius/why")
        assert resp.status_code == 404

        resp = client.get("/api/assets/non-existent-xyz/blast-radius/paths")
        assert resp.status_code == 404

        resp = client.get("/api/assets/non-existent-xyz/blast-radius/criticality")
        assert resp.status_code == 404

        # 2. Direct evaluation endpoint POST /api/blast-radius/evaluate
        payload = {
            "asset": {"id": "ecdsa-secp256k1", "asset_type": "ALGORITHM", "name": "ECDSA", "is_production": True},
            "edges": [
                {"source_id": "signer_service", "target_id": "ecdsa-secp256k1", "relationship": "USES"},
                {"source_id": "wallet_app", "target_id": "signer_service", "relationship": "CALLS"},
            ],
            "nodes": [
                {"id": "signer_service", "asset_type": "SERVICE", "name": "Transaction Signer"},
                {"id": "wallet_app", "asset_type": "APPLICATION", "name": "Mobile Wallet"},
            ],
            "context": {"environment": "production"},
        }
        resp = client.post("/api/blast-radius/evaluate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["asset_id"] == "ecdsa-secp256k1"
        assert data["criticality"] == "CRITICAL"
        assert "signer_service" in data["direct_dependents"]
        assert "wallet_app" in data["transitive_dependents"]
        assert len(data["dependency_paths"]) == 2

