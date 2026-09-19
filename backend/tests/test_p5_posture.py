"""
ECDAT V4 P5.3 Continuous Crypto Posture Unit Tests.
"""
from pathlib import Path
import sys
import tempfile
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.posture.models import (
    PostureDimension,
    PostureTrend,
    QuantumRiskState,
    PQCReadinessState,
    CryptoAgilityState,
    BlastRadiusState,
    MigrationStatusState,
    EvidenceQualityState,
)
from engine.posture.posture_classifier import (
    classify_inventory_posture,
    classify_quantum_risk_posture,
    classify_pqc_readiness_posture,
    classify_crypto_agility_posture,
    classify_blast_radius_posture,
    classify_migration_status_posture,
    classify_evidence_quality_posture,
    evaluate_posture,
)
from engine.posture.posture_changes import evaluate_posture_change
from engine.posture.posture_summary import summarize_posture
from engine.posture.explainability import (
    build_posture_explainability,
    build_posture_change_explainability,
)
from engine.posture.pipeline import PosturePipeline
from engine.scan_store import ScanStore


def test_posture_multi_dimensionality_and_no_scalar_score():
    assets = [
        {"id": "a1", "name": "AES-256", "algorithm": "AES-256", "fused_status": "CORROBORATED"},
    ]
    assessment = evaluate_posture(project="proj-1", scan_id="s1", assets=assets)
    d = assessment.to_dict()

    # Must contain all 7 dimensions
    for dim in PostureDimension:
        assert dim.value in d["dimensions"]

    # Must NOT have a top-level single score collapsing everything
    assert "single_score" not in d
    assert "posture_score" not in d
    assert "composite_score" not in d


def test_inventory_posture_classification():
    empty_dim = classify_inventory_posture([])
    assert empty_dim.state == "EMPTY"

    full_dim = classify_inventory_posture([{"id": "1"}, {"id": "2"}])
    assert full_dim.state == "CATALOGED"
    assert full_dim.numeric_value == 2.0


def test_quantum_risk_posture_classification():
    dim_crit = classify_quantum_risk_posture([{"risk_level": "CRITICAL", "risk_score": 9.5}])
    assert dim_crit.state == QuantumRiskState.CRITICAL.value

    dim_high = classify_quantum_risk_posture([{"risk_level": "HIGH", "risk_score": 7.5}])
    assert dim_high.state == QuantumRiskState.HIGH.value

    dim_low = classify_quantum_risk_posture([{"risk_level": "LOW", "risk_score": 1.5}])
    assert dim_low.state == QuantumRiskState.LOW.value


def test_pqc_readiness_posture_classification():
    # 100% PQC -> COMPLIANT
    assets_pqc = [{"algorithm": "ML-KEM-768"}, {"algorithm": "ML-DSA-65"}]
    dim_pqc = classify_pqc_readiness_posture([], assets_pqc)
    assert dim_pqc.state == PQCReadinessState.COMPLIANT.value

    # Hybrid / partial -> PQC_READY or HYBRID_TRANSITION
    assets_mix = [{"algorithm": "ML-KEM-768"}, {"algorithm": "RSA-2048"}]
    dim_mix = classify_pqc_readiness_posture([], assets_mix)
    assert dim_mix.state == PQCReadinessState.PQC_READY.value

    # Zero PQC -> NON_COMPLIANT
    assets_classical = [{"algorithm": "RSA-2048"}]
    dim_class = classify_pqc_readiness_posture([], assets_classical)
    assert dim_class.state == PQCReadinessState.NON_COMPLIANT.value


def test_crypto_agility_posture_classification():
    dim_agile = classify_crypto_agility_posture([{"overall_score": 0.85}])
    assert dim_agile.state == CryptoAgilityState.HIGHLY_AGILE.value

    dim_mid = classify_crypto_agility_posture([{"overall_score": 0.5}])
    assert dim_mid.state == CryptoAgilityState.PARTIALLY_AGILE.value

    dim_rigid = classify_crypto_agility_posture([{"overall_score": 0.1}])
    assert dim_rigid.state == CryptoAgilityState.RIGID.value


def test_blast_radius_posture_classification():
    dim_unbounded = classify_blast_radius_posture([{"transitive_dependents_count": 25}])
    assert dim_unbounded.state == BlastRadiusState.UNBOUNDED.value

    dim_contained = classify_blast_radius_posture([{"transitive_dependents_count": 5}])
    assert dim_contained.state == BlastRadiusState.CONTAINED.value

    dim_isolated = classify_blast_radius_posture([{"transitive_dependents_count": 1}])
    assert dim_isolated.state == BlastRadiusState.ISOLATED.value


def test_migration_status_posture_classification():
    dim_ver = classify_migration_status_posture([{"verification_state": "VERIFIED"}], [])
    assert dim_ver.state == MigrationStatusState.VERIFIED.value

    dim_prog = classify_migration_status_posture([{"verification_state": "IN_PROGRESS"}], [])
    assert dim_prog.state == MigrationStatusState.IN_PROGRESS.value

    dim_plan = classify_migration_status_posture([], [{"plan_id": "p1"}])
    assert dim_plan.state == MigrationStatusState.PLANNED.value


def test_evidence_quality_posture_classification():
    dim_corrob = classify_evidence_quality_posture([{"fused_status": "CORROBORATED"}], [])
    assert dim_corrob.state == EvidenceQualityState.CORROBORATED.value


def test_posture_change_single_scan_not_enough_history():
    posture_1 = evaluate_posture("proj-1", "s1", [{"id": "a1", "algorithm": "AES"}])
    change = evaluate_posture_change(posture_1, None)
    assert change.overall_trend == PostureTrend.NOT_ENOUGH_HISTORY
    assert "not enough historical scans" in change.summary


def test_posture_change_trend_improved():
    # Base: High risk, classical
    p_base = evaluate_posture(
        "proj-1", "s1",
        assets=[{"algorithm": "RSA-1024"}],
        risks=[{"risk_level": "HIGH", "risk_score": 8.0}],
    )
    # Target: Low risk, PQC compliant
    p_target = evaluate_posture(
        "proj-1", "s2",
        assets=[{"algorithm": "ML-KEM-768"}],
        risks=[{"risk_level": "LOW", "risk_score": 1.0}],
    )

    change = evaluate_posture_change(p_base, p_target)
    assert change.overall_trend == PostureTrend.IMPROVED
    assert change.dimension_transitions[PostureDimension.QUANTUM_RISK.value].trend == PostureTrend.IMPROVED
    assert change.dimension_transitions[PostureDimension.PQC_READINESS.value].trend == PostureTrend.IMPROVED


def test_posture_change_trend_degraded():
    p_base = evaluate_posture(
        "proj-1", "s1",
        assets=[{"algorithm": "ML-KEM-768"}],
        risks=[{"risk_level": "LOW", "risk_score": 1.0}],
    )
    # Target: Regressed to high risk classical
    p_target = evaluate_posture(
        "proj-1", "s2",
        assets=[{"algorithm": "RSA-1024"}],
        risks=[{"risk_level": "HIGH", "risk_score": 8.5}],
    )

    change = evaluate_posture_change(p_base, p_target)
    assert change.overall_trend == PostureTrend.DEGRADED


def test_posture_summary_and_explainability():
    assessment = evaluate_posture(
        "proj-1", "s1",
        assets=[{"algorithm": "ML-KEM-768"}],
        risks=[{"risk_level": "LOW", "risk_score": 1.0}],
        agilities=[{"overall_score": 0.85}],
    )
    summary = summarize_posture(assessment)
    assert "executive_highlights" in summary
    assert "status_matrix" in summary

    expl = build_posture_explainability(assessment)
    assert "dimensions" in expl
    assert expl["dimensions"][PostureDimension.QUANTUM_RISK.value]["state"] == "LOW"


def test_posture_pipeline_persistence():
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        db_path = f.name

    store = ScanStore(path=db_path)
    with store.connect() as db:
        db.execute("INSERT OR IGNORE INTO scans (id, project, kind, status, created_at, input_hash) VALUES ('s1', 'proj-test', 'source', 'completed', '2026-09-18T00:00:00Z', 'hash1')")

    pipeline = PosturePipeline(store)

    store.graph.upsert_asset("proj-test", "ALGORITHM", "AES-256", scan_id="s1", algorithm="AES-256")
    res = pipeline.evaluate_scan_posture("proj-test", "s1")
    assert "assessment_id" in res
    assert res["project_id"] == "proj-test"

    # Fetch cached
    cached = store.get_posture_assessment("s1", project="proj-test")
    assert cached is not None
    assert cached["assessment_id"] == res["assessment_id"]

    store.close()
