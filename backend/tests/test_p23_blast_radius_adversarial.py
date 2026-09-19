"""
ECDAT V4 P2.3 Blast Radius Adversarial & Axiom Test Suite.

Rigorously enforces the mathematical and domain axioms:
- Axioms 1-10: Orthogonality (Blast Radius != Risk != Agility != Centrality != Migration Priority)
- Axioms 11-20: Graph Topology & Traversal (Direct != Transitive, Multi-path distinction, Cycle bounds)
- Axioms 21-30: Evidence & Contradiction (Provenances, Contradictions -> INCONCLUSIVE, Hashes)
- Axioms 31-40: Architectural Criticality & Bounds (Metadata-driven, Bounded limits, Safety flags)
- Integration Fixtures A - F:
  Fixture A: Isolated primitive with zero consumers -> NO_DEPENDENTS_OBSERVED
  Fixture B: Direct single service caller -> DIRECT_ONLY / LOCAL
  Fixture C: Multi-tier banking architecture -> MULTI_SERVICE / TRANSITIVE
  Fixture D: Cyclic microservice loop -> CYCLE_DETECTED_AND_PRUNED
  Fixture E: High-degree shared crypto library (Diamond DAG) -> MULTI_PATH / WIDESPREAD
  Fixture F: Conflicting/contradictory evidence -> INCONCLUSIVE / CONTRADICTED
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

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
)


# ===========================================================================
# GROUP 1: ORTHOGONALITY AXIOMS (Axioms 1 - 10)
# ===========================================================================

def test_axiom_01_blast_radius_is_not_cryptographic_risk():
    """Axiom 1: A deprecated cipher (e.g. MD5) with zero dependents has low blast radius."""
    target = {"id": "deprecated-md5", "algorithm": "MD5", "asset_type": "ALGORITHM"}
    res = evaluate_blast_radius(target, raw_edges=[], raw_nodes=[])
    assert res.state == BlastRadiusState.NO_DEPENDENTS_OBSERVED
    assert res.impact_category == ImpactCategory.NONE_OBSERVED
    assert len(res.direct_dependents) == 0


def test_axiom_02_blast_radius_is_not_crypto_agility():
    """Axiom 2: Highly agile algorithm can still have widespread blast radius if widely used."""
    target = {"id": "agile-aes", "algorithm": "AES-256", "asset_type": "ALGORITHM"}
    edges = [{"source_id": f"svc-{i}", "target_id": "agile-aes", "relationship": "USES"} for i in range(15)]
    nodes = [{"id": f"svc-{i}", "asset_type": "SERVICE"} for i in range(15)]
    res = evaluate_blast_radius(target, raw_edges=edges, raw_nodes=nodes)
    assert res.state == BlastRadiusState.WIDESPREAD
    assert res.impact_category == ImpactCategory.WIDESPREAD


def test_axiom_03_no_composite_score_mixing():
    """Axiom 3: BlastRadiusAssessment contains no blended numerical risk-agility-blast score."""
    target = {"id": "asset-clean", "algorithm": "RSA-2048"}
    res = evaluate_blast_radius(target, raw_edges=[], raw_nodes=[])
    data = res.to_dict()
    assert "composite_score" not in data
    assert "blended_score" not in data
    assert "risk_score" not in data


def test_axiom_04_zero_dependents_distinct_from_scanner_failure():
    """Axiom 4: NO_DEPENDENTS_OBSERVED != SCANNER_UNAVAILABLE."""
    target = {"id": "isolated-prim"}
    normal_res = evaluate_blast_radius(target, raw_edges=[], raw_nodes=[])
    failed_res = evaluate_blast_radius(target, context={"scanner_unavailable": True})
    assert normal_res.state == BlastRadiusState.NO_DEPENDENTS_OBSERVED
    assert failed_res.state == BlastRadiusState.SCANNER_UNAVAILABLE
    assert normal_res.state != failed_res.state


def test_axiom_05_criticality_not_inferred_from_dependent_count():
    """Axiom 5: An internal dev test harness with 50 mock dependents remains LOW/MEDIUM, not CRITICAL."""
    target = {"id": "test-mock-util", "environment": "dev"}
    edges = [{"source_id": f"mock-{i}", "target_id": "test-mock-util", "relationship": "USES"} for i in range(30)]
    nodes = [{"id": f"mock-{i}", "asset_type": "MODULE", "environment": "dev"} for i in range(30)]
    res = evaluate_blast_radius(target, raw_edges=edges, raw_nodes=nodes)
    assert res.criticality == CriticalityLevel.LOW
    assert any("dependent count" in lim.lower() for lim in res.limitations)


def test_axiom_06_blast_radius_does_not_mutate_graph_service():
    """Axiom 6: Evaluating blast radius is strictly read-only on the underlying graph."""
    edges = [{"source_id": "app", "target_id": "lib", "relationship": "USES"}]
    initial_len = len(edges)
    _ = evaluate_blast_radius({"id": "lib"}, raw_edges=edges)
    assert len(edges) == initial_len


def test_axiom_07_directionality_is_reverse_upstream():
    """Axiom 7: Traversal queries incoming edges (who depends on target), not outgoing dependencies."""
    # Target USES SubModule; App USES Target
    edges = [
        {"source_id": "target", "target_id": "submodule", "relationship": "USES"},
        {"source_id": "app", "target_id": "target", "relationship": "USES"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert "app" in res.direct_dependents
    assert "submodule" not in res.direct_dependents


def test_axiom_08_migration_priority_not_conflated():
    """Axiom 8: Blast radius output leaves migration ordering to migration planning layer."""
    res = evaluate_blast_radius({"id": "target"}, raw_edges=[])
    data = res.to_dict()
    assert "migration_wave" not in data
    assert "priority_rank" not in data


def test_axiom_09_graph_confidence_distinct_from_evidence_level():
    """Axiom 9: Graph confidence (MEASURED, INFERRED, CONTRADICTED) is strictly about topological links."""
    p = build_dependency_path("s", "t", ["s", "t"], ["USES"], confidence=GraphConfidence.MEASURED.value)
    assert p.confidence == "MEASURED"


def test_axiom_10_centrality_metric_exclusion():
    """Axiom 10: PageRank/Betweenness centrality is not used as a proxy for operational impact."""
    res = evaluate_blast_radius({"id": "target"}, raw_edges=[])
    assert "pagerank" not in res.to_dict()


# ===========================================================================
# GROUP 2: GRAPH TOPOLOGY & TRAVERSAL AXIOMS (Axioms 11 - 20)
# ===========================================================================

def test_axiom_11_direct_dependents_path_length_one():
    """Axiom 11: Direct dependents strictly have path_length == 1."""
    edges = [
        {"source_id": "d1", "target_id": "target", "relationship": "USES"},
        {"source_id": "t1", "target_id": "d1", "relationship": "USES"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert res.direct_dependents == ["d1"]
    for p in res.dependency_paths:
        if p.source_asset in res.direct_dependents:
            assert p.path_length == 1
            assert p.direct_or_transitive == "DIRECT"


def test_axiom_12_transitive_dependents_path_length_greater_than_one():
    """Axiom 12: Transitive dependents have path_length > 1."""
    edges = [
        {"source_id": "d1", "target_id": "target", "relationship": "USES"},
        {"source_id": "t1", "target_id": "d1", "relationship": "USES"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert res.transitive_dependents == ["t1"]
    for p in res.dependency_paths:
        if p.source_asset in res.transitive_dependents:
            assert p.path_length > 1
            assert p.direct_or_transitive == "TRANSITIVE"


def test_axiom_13_disjoint_direct_and_transitive_sets():
    """Axiom 13: An asset that is only transitive is never listed as direct."""
    edges = [
        {"source_id": "mid", "target_id": "target", "relationship": "USES"},
        {"source_id": "root", "target_id": "mid", "relationship": "CALLS"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert "root" in res.transitive_dependents
    assert "root" not in res.direct_dependents


def test_axiom_14_multi_path_asset_in_both_retains_concrete_paths():
    """Axiom 14: If caller connects directly AND transitively, both concrete paths are preserved."""
    edges = [
        {"source_id": "caller", "target_id": "target", "relationship": "USES"},
        {"source_id": "caller", "target_id": "helper", "relationship": "CALLS"},
        {"source_id": "helper", "target_id": "target", "relationship": "USES"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert "caller" in res.direct_dependents
    assert "caller" in res.transitive_dependents
    caller_paths = [p for p in res.dependency_paths if p.source_asset == "caller"]
    assert len(caller_paths) == 2
    assert {p.path_length for p in caller_paths} == {1, 2}


def test_axiom_15_cycle_loop_pruned_without_hang():
    """Axiom 15: Cyclic loop (A -> B -> C -> A) is pruned with explicit cycle limitation code."""
    edges = [
        {"source_id": "a", "target_id": "target", "relationship": "USES"},
        {"source_id": "b", "target_id": "a", "relationship": "USES"},
        {"source_id": "c", "target_id": "b", "relationship": "USES"},
        {"source_id": "a", "target_id": "c", "relationship": "USES"},  # cycle
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert "CYCLE_DETECTED_AND_PRUNED" in res.limitations
    assert len(res.dependency_paths) > 0


def test_axiom_16_max_depth_enforced():
    """Axiom 16: Max depth limit truncates deep chains with MAX_DEPTH_REACHED limitation."""
    edges = [{"source_id": f"n{i+1}", "target_id": f"n{i}", "relationship": "CALLS"} for i in range(12)]
    res = evaluate_blast_radius({"id": "n0"}, raw_edges=edges, max_depth=4)
    assert res.partial_result is True
    assert "MAX_DEPTH_REACHED" in res.limitations
    assert max(p.path_length for p in res.dependency_paths) <= 4


def test_axiom_17_max_paths_enforced():
    """Axiom 17: Max paths limit truncates fan-out with MAX_PATHS_REACHED limitation."""
    edges = [{"source_id": f"caller-{i}", "target_id": "target", "relationship": "USES"} for i in range(25)]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges, max_paths=10)
    assert res.partial_result is True
    assert "MAX_PATHS_REACHED" in res.limitations
    assert len(res.dependency_paths) <= 10


def test_axiom_18_irrelevant_edges_filtered_out():
    """Axiom 18: Audit/Metadata edges (EVIDENCED_BY, OBSERVED_BY) are not traversed as dependency paths."""
    edges = [
        {"source_id": "scanner-evidence-1", "target_id": "target", "relationship": "EVIDENCED_BY"},
        {"source_id": "real-caller", "target_id": "target", "relationship": "USES"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert res.direct_dependents == ["real-caller"]
    assert "scanner-evidence-1" not in res.direct_dependents


def test_axiom_19_complete_node_sequence_preserved():
    """Axiom 19: DependencyPath contains unbroken contiguous sequence of intermediate nodes."""
    edges = [
        {"source_id": "l3", "target_id": "l2", "relationship": "CALLS"},
        {"source_id": "l2", "target_id": "l1", "relationship": "CALLS"},
        {"source_id": "l1", "target_id": "target", "relationship": "USES"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    l3_paths = [p for p in res.dependency_paths if p.source_asset == "l3"]
    assert len(l3_paths) == 1
    assert l3_paths[0].node_sequence == ["l3", "l2", "l1", "target"]
    assert l3_paths[0].relationship_sequence == ["CALLS", "CALLS", "USES"]


def test_axiom_20_diamond_dag_traversal_integrity():
    """Axiom 20: Diamond DAG (A -> B -> Target, A -> C -> Target) discovers both distinct paths."""
    edges = [
        {"source_id": "b", "target_id": "target", "relationship": "USES"},
        {"source_id": "c", "target_id": "target", "relationship": "USES"},
        {"source_id": "a", "target_id": "b", "relationship": "CALLS"},
        {"source_id": "a", "target_id": "c", "relationship": "CALLS"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    a_paths = [p for p in res.dependency_paths if p.source_asset == "a"]
    assert len(a_paths) == 2
    assert res.state == BlastRadiusState.MULTI_PATH


# ===========================================================================
# GROUP 3: EVIDENCE & CONTRADICTION AXIOMS (Axioms 21 - 30)
# ===========================================================================

def test_axiom_21_contradictory_evidence_forces_inconclusive():
    """Axiom 21: Contradictory evidence (e.g. unlinked dead-code) forces state to INCONCLUSIVE."""
    edges = [{"source_id": "caller", "target_id": "target", "relationship": "USES"}]
    ev = [{"id": "ev-contra", "description": "unlinked dead_code", "state": "CONTRADICTED"}]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges, evidence_items=ev)
    assert res.state == BlastRadiusState.INCONCLUSIVE
    assert res.confidence == GraphConfidence.CONTRADICTED
    assert len(res.contradicting_evidence) > 0


def test_axiom_22_canonical_graph_hash_deterministic():
    """Axiom 22: Graph hash is strictly reproducible regardless of node insertion ordering."""
    nodes_a = [{"id": "n1", "name": "A", "asset_type": "SERVICE"}, {"id": "n2", "name": "B", "asset_type": "SERVICE"}]
    nodes_b = [{"id": "n2", "name": "B", "asset_type": "SERVICE"}, {"id": "n1", "name": "A", "asset_type": "SERVICE"}]
    edges = [{"source_id": "n1", "target_id": "n2", "relationship": "USES"}]

    h1 = compute_canonical_graph_hash(nodes_a, edges)
    h2 = compute_canonical_graph_hash(nodes_b, edges)
    assert h1 == h2


def test_axiom_23_evidence_hash_deterministic():
    """Axiom 23: Evidence hash is identical for same set of evidence references."""
    h1 = compute_evidence_hash(["ev-2", "ev-1", "ev-3"])
    h2 = compute_evidence_hash(["ev-1", "ev-3", "ev-2"])
    assert h1 == h2


def test_axiom_24_measured_confidence_requires_all_measured():
    """Axiom 24: MEASURED confidence is assigned only if all traversed edges are verified measured."""
    edges = [{"source_id": "c1", "target_id": "target", "relationship": "USES", "confidence": 1.0}]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert res.confidence == GraphConfidence.MEASURED


def test_axiom_25_inferred_confidence_when_probabilistic_edges():
    """Axiom 25: Low confidence edges produce INFERRED graph confidence."""
    edges = [{"source_id": "c1", "target_id": "target", "relationship": "USES", "confidence": 0.5}]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert res.confidence == GraphConfidence.INFERRED


def test_axiom_26_evidence_references_propagated_to_paths():
    """Axiom 26: DependencyPath includes evidence_id attached to edge."""
    edges = [{"source_id": "c1", "target_id": "target", "relationship": "USES", "evidence_id": "ev-ast-99"}]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges)
    assert "ev-ast-99" in res.evidence_refs
    assert "ev-ast-99" in res.dependency_paths[0].evidence_refs


def test_axiom_27_unknown_graph_data_state():
    """Axiom 27: Explicit context flag missing_graph_data results in UNKNOWN state."""
    res = evaluate_blast_radius({"id": "target"}, context={"missing_graph_data": True})
    assert res.state == BlastRadiusState.UNKNOWN


def test_axiom_28_configuration_hash_captures_limits():
    """Axiom 28: Configuration hash changes if traversal limits differ."""
    target = {"id": "target"}
    res1 = evaluate_blast_radius(target, max_depth=5)
    res2 = evaluate_blast_radius(target, max_depth=10)
    assert res1.configuration_hash != res2.configuration_hash


def test_axiom_29_knowledge_base_version_tracked():
    """Axiom 29: Assessment provenance specifies rule knowledge base version."""
    res = evaluate_blast_radius({"id": "target"})
    assert res.knowledge_base_version == "2024.1"


def test_axiom_30_explainability_reason_chain_generated():
    """Axiom 30: BlastRadiusAssessment contains structured reason chain explaining impact."""
    edges = [{"source_id": "auth", "target_id": "rsa", "relationship": "USES"}]
    res = evaluate_blast_radius({"id": "rsa"}, raw_edges=edges)
    assert len(res.reason_chain) >= 3
    steps = [r.step for r in res.reason_chain]
    assert "DIRECT_DEPENDENCY_IDENTIFICATION" in steps
    assert "IMPACT_SCOPE_CLASSIFICATION" in steps


# ===========================================================================
# GROUP 4: ARCHITECTURAL CRITICALITY & SCOPE AXIOMS (Axioms 31 - 40)
# ===========================================================================

def test_axiom_31_production_target_is_critical():
    """Axiom 31: If target asset is in production, architectural criticality is CRITICAL."""
    res = evaluate_blast_radius({"id": "target", "is_production": True})
    assert res.criticality == CriticalityLevel.CRITICAL


def test_axiom_32_production_consumer_elevates_to_critical():
    """Axiom 32: If any downstream impacted consumer is production, criticality is CRITICAL."""
    edges = [{"source_id": "prod_service", "target_id": "target", "relationship": "USES"}]
    nodes = [{"id": "prod_service", "asset_type": "SERVICE", "is_production": True}]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges, raw_nodes=nodes)
    assert res.criticality == CriticalityLevel.CRITICAL


def test_axiom_33_data_protection_is_high_criticality():
    """Axiom 33: Assets protecting persistent data assets have HIGH criticality."""
    edges = [{"source_id": "database_vault", "target_id": "target", "relationship": "USES"}]
    nodes = [{"id": "database_vault", "asset_type": "DATA_ASSET", "name": "Customer DB"}]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges, raw_nodes=nodes)
    assert res.criticality == CriticalityLevel.HIGH


def test_axiom_34_external_exposure_is_high_criticality():
    """Axiom 34: Externally exposed ingress endpoints have HIGH criticality."""
    res = evaluate_blast_radius({"id": "target", "is_externally_exposed": True})
    assert res.criticality == CriticalityLevel.HIGH


def test_axiom_35_dev_environment_is_low_criticality():
    """Axiom 35: Ephemeral dev/test assets default to LOW criticality."""
    res = evaluate_blast_radius({"id": "target", "environment": "dev"})
    assert res.criticality == CriticalityLevel.LOW


def test_axiom_36_multi_service_impact_classification():
    """Axiom 36: Impact on 2+ independent microservices classifies as MULTI_SERVICE."""
    edges = [
        {"source_id": "svc-order", "target_id": "crypto-core", "relationship": "USES"},
        {"source_id": "svc-payment", "target_id": "crypto-core", "relationship": "USES"},
    ]
    nodes = [
        {"id": "svc-order", "asset_type": "SERVICE"},
        {"id": "svc-payment", "asset_type": "SERVICE"},
    ]
    res = evaluate_blast_radius({"id": "crypto-core"}, raw_edges=edges, raw_nodes=nodes)
    assert res.impact_category == ImpactCategory.MULTI_SERVICE


def test_axiom_37_cross_deployment_impact_classification():
    """Axiom 37: Impact spanning 2+ independent deployment units classifies as CROSS_DEPLOYMENT."""
    edges = [
        {"source_id": "deploy-us-east", "target_id": "root-ca", "relationship": "USES"},
        {"source_id": "deploy-eu-west", "target_id": "root-ca", "relationship": "USES"},
    ]
    nodes = [
        {"id": "deploy-us-east", "asset_type": "DEPLOYMENT"},
        {"id": "deploy-eu-west", "asset_type": "DEPLOYMENT"},
    ]
    res = evaluate_blast_radius({"id": "root-ca"}, raw_edges=edges, raw_nodes=nodes)
    assert res.impact_category == ImpactCategory.CROSS_DEPLOYMENT


def test_axiom_38_contained_transitive_impact():
    """Axiom 38: Transitive propagation within a small localized boundary is CONTAINED."""
    edges = [
        {"source_id": "fn_inner", "target_id": "target", "relationship": "USES"},
        {"source_id": "fn_outer", "target_id": "fn_inner", "relationship": "CALLS"},
    ]
    nodes = [
        {"id": "fn_inner", "asset_type": "FUNCTION", "module": "auth_mod"},
        {"id": "fn_outer", "asset_type": "FUNCTION", "module": "auth_mod"},
    ]
    res = evaluate_blast_radius({"id": "target"}, raw_edges=edges, raw_nodes=nodes)
    assert res.state == BlastRadiusState.CONTAINED


def test_axiom_39_widespread_impact_threshold():
    """Axiom 39: 5+ services or 20+ assets classifies as WIDESPREAD."""
    edges = [{"source_id": f"svc-{i}", "target_id": "shared-core", "relationship": "USES"} for i in range(6)]
    nodes = [{"id": f"svc-{i}", "asset_type": "SERVICE"} for i in range(6)]
    res = evaluate_blast_radius({"id": "shared-core"}, raw_edges=edges, raw_nodes=nodes)
    assert res.impact_category == ImpactCategory.WIDESPREAD


def test_axiom_40_serialization_round_trip():
    """Axiom 40: BlastRadiusAssessment serialization round trip to/from dict is lossless."""
    target = {"id": "target-asset", "is_production": True}
    edges = [{"source_id": "caller", "target_id": "target-asset", "relationship": "USES"}]
    orig = evaluate_blast_radius(target, raw_edges=edges)
    d = orig.to_dict()
    restored = BlastRadiusAssessment.from_dict(d)
    assert restored.assessment_id == orig.assessment_id
    assert restored.asset_id == orig.asset_id
    assert restored.state == orig.state
    assert restored.impact_category == orig.impact_category
    assert restored.criticality == orig.criticality
    assert restored.direct_dependents == orig.direct_dependents


# ===========================================================================
# INTEGRATION FIXTURES A - F
# ===========================================================================

def test_fixture_a_isolated_primitive():
    """Fixture A: Isolated cryptographic primitive with no callers."""
    target = {"id": "isolated-des", "algorithm": "DES", "asset_type": "ALGORITHM"}
    res = evaluate_blast_radius(target, raw_edges=[], raw_nodes=[])
    assert res.state == BlastRadiusState.NO_DEPENDENTS_OBSERVED
    assert res.impact_category == ImpactCategory.NONE_OBSERVED
    assert len(res.direct_dependents) == 0
    assert len(res.transitive_dependents) == 0
    assert len(res.dependency_paths) == 0


def test_fixture_b_direct_single_caller():
    """Fixture B: Primitive consumed by exactly one direct application."""
    edges = [{"source_id": "user-portal", "target_id": "rsa-key", "relationship": "USES"}]
    nodes = [
        {"id": "rsa-key", "asset_type": "KEY"},
        {"id": "user-portal", "asset_type": "APPLICATION", "module": "frontend_app"},
    ]
    res = evaluate_blast_radius(nodes[0], raw_edges=edges, raw_nodes=nodes)
    assert res.state == BlastRadiusState.DIRECT_ONLY
    assert res.impact_category in (ImpactCategory.DIRECT, ImpactCategory.LOCAL)
    assert res.direct_dependents == ["user-portal"]
    assert len(res.transitive_dependents) == 0


def test_fixture_c_multi_tier_banking():
    """Fixture C: Multi-tier banking architecture (Web Gateway -> API Layer -> Crypto Module)."""
    edges = [
        {"source_id": "core-crypto", "target_id": "hsm-driver", "relationship": "USES"},
        {"source_id": "payment-api", "target_id": "core-crypto", "relationship": "USES"},
        {"source_id": "web-gateway", "target_id": "payment-api", "relationship": "CALLS"},
    ]
    nodes = [
        {"id": "hsm-driver", "asset_type": "ALGORITHM", "is_production": True},
        {"id": "core-crypto", "asset_type": "CRYPTO_LIBRARY"},
        {"id": "payment-api", "asset_type": "SERVICE"},
        {"id": "web-gateway", "asset_type": "SERVICE", "is_externally_exposed": True},
    ]
    res = evaluate_blast_radius(nodes[0], raw_edges=edges, raw_nodes=nodes)
    assert res.criticality == CriticalityLevel.CRITICAL
    assert res.direct_dependents == ["core-crypto"]
    assert sorted(res.transitive_dependents) == ["payment-api", "web-gateway"]
    assert res.impact_category in (ImpactCategory.MULTI_SERVICE, ImpactCategory.TRANSITIVE)


def test_fixture_d_cyclic_microservice_loop():
    """Fixture D: Microservice mesh with cyclic dependency loop."""
    edges = [
        {"source_id": "svc-a", "target_id": "auth-primitive", "relationship": "USES"},
        {"source_id": "svc-b", "target_id": "svc-a", "relationship": "CALLS"},
        {"source_id": "svc-c", "target_id": "svc-b", "relationship": "CALLS"},
        {"source_id": "svc-a", "target_id": "svc-c", "relationship": "CALLS"},  # cycle back to a
    ]
    nodes = [
        {"id": "auth-primitive", "asset_type": "ALGORITHM"},
        {"id": "svc-a", "asset_type": "SERVICE"},
        {"id": "svc-b", "asset_type": "SERVICE"},
        {"id": "svc-c", "asset_type": "SERVICE"},
    ]
    res = evaluate_blast_radius(nodes[0], raw_edges=edges, raw_nodes=nodes)
    assert "CYCLE_DETECTED_AND_PRUNED" in res.limitations
    assert "svc-a" in res.direct_dependents
    assert "svc-b" in res.transitive_dependents
    assert "svc-c" in res.transitive_dependents


def test_fixture_e_diamond_dag_shared_library():
    """Fixture E: Diamond DAG shared library with multiple distinct paths."""
    edges = [
        {"source_id": "lib-sec", "target_id": "openssl-core", "relationship": "USES"},
        {"source_id": "lib-tls", "target_id": "openssl-core", "relationship": "USES"},
        {"source_id": "gateway", "target_id": "lib-sec", "relationship": "CALLS"},
        {"source_id": "gateway", "target_id": "lib-tls", "relationship": "CALLS"},
    ]
    nodes = [
        {"id": "openssl-core", "asset_type": "CRYPTO_LIBRARY"},
        {"id": "lib-sec", "asset_type": "DEPENDENCY"},
        {"id": "lib-tls", "asset_type": "DEPENDENCY"},
        {"id": "gateway", "asset_type": "SERVICE"},
    ]
    res = evaluate_blast_radius(nodes[0], raw_edges=edges, raw_nodes=nodes)
    assert res.state == BlastRadiusState.MULTI_PATH
    gateway_paths = [p for p in res.dependency_paths if p.source_asset == "gateway"]
    assert len(gateway_paths) == 2


def test_fixture_f_conflicting_contradictory_evidence():
    """Fixture F: Conflicting graph evidence triggering INCONCLUSIVE state."""
    edges = [{"source_id": "legacy-service", "target_id": "rc4-cipher", "relationship": "USES"}]
    nodes = [
        {"id": "rc4-cipher", "asset_type": "ALGORITHM"},
        {"id": "legacy-service", "asset_type": "SERVICE"},
    ]
    ev = [{"id": "ev-removal", "description": "dependency_removed during v4 refactor", "state": "CONTRADICTED"}]
    res = evaluate_blast_radius(nodes[0], raw_edges=edges, raw_nodes=nodes, evidence_items=ev)
    assert res.state == BlastRadiusState.INCONCLUSIVE
    assert res.confidence == GraphConfidence.CONTRADICTED
    assert len(res.contradicting_evidence) > 0
