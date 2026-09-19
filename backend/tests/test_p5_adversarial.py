"""
ECDAT V4 P5 Adversarial Axiom Verification Suite.
Validates all 40 mandatory temporal and continuous posture axioms.
"""
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import random
import sys
import uuid
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
from engine.evidence_fusion import (
    CorroborationEngine,
    CorroborationStatus,
    EvidenceFreshness,
)
from engine.temporal.models import (
    ChangeCategory,
    RiskChange,
    PQCChange,
    AgilityChange,
    MigrationChange,
    TimelineEventType,
)
from engine.temporal.normalizer import compute_asset_key
from engine.temporal.comparator import compare_scans
from engine.temporal.temporal_risk import evaluate_temporal_risk
from engine.temporal.temporal_pqc import evaluate_temporal_pqc
from engine.temporal.temporal_agility import evaluate_temporal_agility
from engine.temporal.temporal_migration import evaluate_temporal_migration
from engine.temporal.evidence_timeline import build_asset_timeline
from engine.posture.models import (
    PostureDimension,
    PostureTrend,
    QuantumRiskState,
    BlastRadiusState,
)
from engine.posture.posture_classifier import evaluate_posture
from engine.posture.posture_changes import evaluate_posture_change


def make_evidence(
    source_engine="source",
    level=EvidenceLevel.E2,
    state=EvidenceState.MEASURED,
    observation_type=ObservationType.SOURCE_API_USE,
    confidence=0.8,
    symbol="AES",
    description="AES observation",
    timestamp=None,
    scan_id="s1",
):
    ts = timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()
    prov = Provenance(
        input_hash="hash",
        source_engine=source_engine,
        scan_id=scan_id,
        timestamp=ts,
    )
    return Evidence(
        id=str(uuid.uuid4()),
        state=state,
        level=level,
        confidence=confidence,
        source_engine=source_engine,
        observation_type=observation_type,
        artifact_type="SOURCE_FILE",
        description=description,
        symbol=symbol,
        provenance=prov,
        timestamp=ts,
    )


# Axiom 1: Multi-scan evidence accumulation without confidence inflation (c <= 1.0)
def test_axiom_01_multiscan_evidence_accumulation_no_confidence_inflation():
    engine = CorroborationEngine()
    evs = [
        make_evidence(
            source_engine=f"engine_{i}",
            level=EvidenceLevel.E3,
            state=EvidenceState.MEASURED,
            observation_type=ObservationType.SOURCE_API_USE,
            confidence=0.99,
            symbol="AES",
            description="AES observation",
        )
        for i in range(10)
    ]
    scans = [{"scan_id": f"s{i}", "evidence": [evs[i]]} for i in range(10)]
    res = engine.corroborate_multi_scan("p", "AES", scans)
    assert res.combined_confidence <= 1.0
    assert res.combined_confidence > 0.99


# Axiom 2: Staleness detection with TTL expiration
def test_axiom_02_staleness_detection_with_ttl_expiration():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev_stale = make_evidence(
        source_engine="eng",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.8,
        symbol="RSA",
        description="Old RSA",
        timestamp=(now - timedelta(days=91)).isoformat(),
    )
    ev_fresh = make_evidence(
        source_engine="eng",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.8,
        symbol="RSA",
        description="Recent RSA",
        timestamp=(now - timedelta(days=30)).isoformat(),
    )
    assert engine.evaluate_freshness(ev_stale, as_of_time=now, ttl_days=90) == EvidenceFreshness.STALE
    assert engine.evaluate_freshness(ev_fresh, as_of_time=now, ttl_days=90) == EvidenceFreshness.CURRENT


# Axiom 3: Superseded evidence exclusion from current state
def test_axiom_03_superseded_evidence_exclusion_from_current_state():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev_old = make_evidence(
        source_engine="eng",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.5,
        symbol="MD5",
        description="MD5 in code",
        timestamp=(now - timedelta(days=5)).isoformat(),
    )
    ev_new = make_evidence(
        source_engine="eng",
        level=EvidenceLevel.E3,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.9,
        symbol="SHA-256",
        description="SHA-256 in code",
        timestamp=now.isoformat(),
    )
    engine.track_supersession(ev_old, ev_new)
    scans = [{"scan_id": "s1", "evidence": [ev_old, ev_new]}]
    res = engine.corroborate_multi_scan("p", "code", scans)
    assert res.superseded_evidence_count == 1
    assert res.active_evidence_count == 1


# Axiom 4: Contradiction preservation across scans (never silently overwrite)
def test_axiom_04_contradiction_preservation_across_scans():
    engine = CorroborationEngine()
    ev1 = make_evidence(
        source_engine="source",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.8,
        symbol="RSA",
        description="Configured RSA",
    )
    ev2 = make_evidence(
        source_engine="network",
        level=EvidenceLevel.E5,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.TLS_NEGOTIATION,
        confidence=0.95,
        symbol="ECDSA",
        description="Live ECDSA",
    )
    res = engine.corroborate_multi_scan("p", "RSA", [{"scan_id": "s1", "evidence": [ev1]}, {"scan_id": "s2", "evidence": [ev2]}])
    assert res.fused_status == CorroborationStatus.CONTRADICTED or len(res.contradictions) > 0


# Axiom 5: Evidence level preservation across temporal gap
def test_axiom_05_evidence_level_preservation_across_temporal_gap():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev = make_evidence(
        source_engine="network",
        level=EvidenceLevel.E5,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.TLS_NEGOTIATION,
        confidence=0.9,
        symbol="AES",
        description="Observed TLS",
        timestamp=(now - timedelta(days=120)).isoformat(),
    )
    scans = [{"scan_id": "s1", "evidence": [ev]}]
    res = engine.corroborate_multi_scan("p", "AES", scans, as_of_time=now, ttl_days=90)
    assert res.highest_level == EvidenceLevel.E5
    assert res.freshness == EvidenceFreshness.STALE


# Axiom 6: Deterministic asset key generation (same inputs = identical key)
def test_axiom_06_deterministic_asset_key_generation():
    k1 = compute_asset_key({"asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256})
    k2 = compute_asset_key({"asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256})
    assert k1 == k2


# Axiom 7: Deterministic asset key collision resistance
def test_axiom_07_deterministic_asset_key_collision_resistance():
    k1 = compute_asset_key({"asset_type": "ALGORITHM", "name": "AES-128", "algorithm": "AES", "key_size": 128})
    k2 = compute_asset_key({"asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256})
    assert k1 != k2


# Axiom 8: Temporal comparison reproducibility (same scans = identical comparison hash)
def test_axiom_08_temporal_comparison_reproducibility():
    assets1 = [{"id": "1", "asset_type": "ALGORITHM", "name": "AES", "algorithm": "AES"}]
    assets2 = [{"id": "2", "asset_type": "ALGORITHM", "name": "ML-KEM", "algorithm": "ML-KEM"}]
    c1 = compare_scans("p", "s1", "s2", assets1, assets2)
    c2 = compare_scans("p", "s1", "s2", assets1, assets2)
    assert c1.temporal_hash == c2.temporal_hash


# Axiom 9: New asset detection (in target, not in base)
def test_axiom_09_new_asset_detection():
    c = compare_scans("p", "s1", "s2", [], [{"id": "1", "asset_type": "ALGORITHM", "name": "AES", "algorithm": "AES"}])
    assert c.added_count == 1
    assert c.asset_changes[0].category == ChangeCategory.NEW


# Axiom 10: Removed asset detection (in base, not in target)
def test_axiom_10_removed_asset_detection():
    c = compare_scans("p", "s1", "s2", [{"id": "1", "asset_type": "ALGORITHM", "name": "DES", "algorithm": "DES"}], [])
    assert c.removed_count == 1
    assert c.asset_changes[0].category == ChangeCategory.REMOVED


# Axiom 11: Changed asset property detection (algorithm change)
def test_axiom_11_changed_asset_property_detection_algorithm():
    b = [{"id": "1", "asset_type": "PROTOCOL", "name": "TLS_CIPHER", "algorithm": "RSA"}]
    t = [{"id": "1", "asset_type": "PROTOCOL", "name": "TLS_CIPHER", "algorithm": "ML-KEM"}]
    c = compare_scans("p", "s1", "s2", b, t)
    assert c.changed_count == 1
    assert "algorithm" in c.asset_changes[0].diff_summary["changed_properties"]


# Axiom 12: Changed asset property detection (key size change)
def test_axiom_12_changed_asset_property_detection_keysize():
    b = [{"id": "1", "asset_type": "ALGORITHM", "name": "RSA", "algorithm": "RSA", "key_size": 1024}]
    t = [{"id": "1", "asset_type": "ALGORITHM", "name": "RSA", "algorithm": "RSA", "key_size": 2048}]
    c = compare_scans("p", "s1", "s2", b, t)
    assert c.changed_count == 1
    assert "key_size" in c.asset_changes[0].diff_summary["changed_properties"]


# Axiom 13: Changed asset property detection (version bump)
def test_axiom_13_changed_asset_property_detection_version():
    b = [{"id": "1", "asset_type": "DEPENDENCY", "name": "openssl", "algorithm": "AES", "version": "1.1.1"}]
    t = [{"id": "1", "asset_type": "DEPENDENCY", "name": "openssl", "algorithm": "AES", "version": "3.2.0"}]
    c = compare_scans("p", "s1", "s2", b, t)
    assert c.changed_count == 1
    assert "version" in c.asset_changes[0].diff_summary["changed_properties"]


# Axiom 14: Unchanged asset identity preservation
def test_axiom_14_unchanged_asset_identity_preservation():
    a = [{"id": "1", "asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256}]
    c = compare_scans("p", "s1", "s2", a, a)
    assert c.unchanged_count == 1
    assert c.changed_count == 0
    assert c.asset_changes[0].category == ChangeCategory.UNCHANGED


# Axiom 15: Quantum risk escalation detection
def test_axiom_15_quantum_risk_escalation_detection():
    rc, _ = evaluate_temporal_risk({"risk_level": "LOW", "risk_score": 1.0}, {"risk_level": "CRITICAL", "risk_score": 9.5})
    assert rc == RiskChange.RISK_INCREASED


# Axiom 16: Quantum risk reduction detection
def test_axiom_16_quantum_risk_reduction_detection():
    rc, _ = evaluate_temporal_risk({"risk_level": "HIGH", "risk_score": 8.0}, {"risk_level": "LOW", "risk_score": 1.0})
    assert rc == RiskChange.RISK_DECREASED


# Axiom 17: PQC introduction detection (classical -> PQC)
def test_axiom_17_pqc_introduction_detection():
    rc, _ = evaluate_temporal_pqc(None, None, {"algorithm": "RSA-2048"}, {"algorithm": "ML-KEM-768"})
    assert rc == PQCChange.PQC_INTRODUCED


# Axiom 18: PQC removal detection (PQC -> classical rollback)
def test_axiom_18_pqc_removal_detection():
    rc, _ = evaluate_temporal_pqc(None, None, {"algorithm": "ML-KEM-768"}, {"algorithm": "RSA-2048"})
    assert rc == PQCChange.PQC_REMOVED


# Axiom 19: PQC upgrade detection (Round 3 -> FIPS 203/204)
def test_axiom_19_pqc_upgrade_detection():
    rc, _ = evaluate_temporal_pqc(None, None, {"algorithm": "Kyber-768"}, {"algorithm": "ML-KEM-768"})
    assert rc == PQCChange.PQC_UPGRADED


# Axiom 20: Crypto agility increase detection
def test_axiom_20_crypto_agility_increase_detection():
    ac, _ = evaluate_temporal_agility({"overall_score": 0.25}, {"overall_score": 0.85})
    assert ac == AgilityChange.AGILITY_INCREASED


# Axiom 21: Crypto agility decrease detection
def test_axiom_21_crypto_agility_decrease_detection():
    ac, _ = evaluate_temporal_agility({"overall_score": 0.85}, {"overall_score": 0.35})
    assert ac == AgilityChange.AGILITY_DECREASED


# Axiom 22: Migration progress tracking (PLANNED -> VERIFIED)
def test_axiom_22_migration_progress_tracking():
    mc, _ = evaluate_temporal_migration({"status": "PLANNED"}, {"verification_state": "VERIFIED"})
    assert mc == MigrationChange.MIGRATION_VERIFIED


# Axiom 23: Migration regression detection (VERIFIED -> FAILED/ROLLBACK)
def test_axiom_23_migration_regression_detection():
    mc, _ = evaluate_temporal_migration({"verification_state": "VERIFIED"}, {"verification_state": "FAILED"})
    assert mc == MigrationChange.MIGRATION_FAILED


# Axiom 24: Timeline chronological ordering
def test_axiom_24_timeline_chronological_ordering():
    now = datetime.now(timezone.utc)
    ev1 = make_evidence(source_engine="e", level=EvidenceLevel.E2, state=EvidenceState.MEASURED, observation_type=ObservationType.SOURCE_API_USE, confidence=0.8, symbol="A", description="A", timestamp=(now - timedelta(days=10)).isoformat())
    ev2 = make_evidence(source_engine="e", level=EvidenceLevel.E2, state=EvidenceState.MEASURED, observation_type=ObservationType.SOURCE_API_USE, confidence=0.8, symbol="A", description="A", timestamp=now.isoformat())
    scans = [
        {"scan_id": "s2", "timestamp": now.isoformat(), "evidence": [ev2]},
        {"scan_id": "s1", "timestamp": (now - timedelta(days=10)).isoformat(), "evidence": [ev1]},
    ]
    tl = build_asset_timeline("p", "A", scans)
    assert tl.events[0].scan_id == "s1"
    assert tl.events[1].scan_id == "s2"


# Axiom 25: Timeline event gap detection (unobserved scans)
def test_axiom_25_timeline_event_gap_detection():
    now = datetime.now(timezone.utc)
    ev1 = make_evidence(source_engine="e", level=EvidenceLevel.E2, state=EvidenceState.MEASURED, observation_type=ObservationType.SOURCE_API_USE, confidence=0.8, symbol="A", description="A")
    scans = [
        {"scan_id": "s1", "timestamp": (now - timedelta(days=20)).isoformat(), "evidence": [ev1]},
        {"scan_id": "s2", "timestamp": (now - timedelta(days=10)).isoformat(), "evidence": []},
        {"scan_id": "s3", "timestamp": now.isoformat(), "evidence": [ev1]},
    ]
    tl = build_asset_timeline("p", "A", scans)
    assert any(e.event_type == TimelineEventType.UNOBSERVED for e in tl.events)


# Axiom 26: Posture assessment multi-dimensionality (all 7 dimensions present)
def test_axiom_26_posture_assessment_multidimensionality():
    posture = evaluate_posture("p", "s1", [{"algorithm": "AES"}])
    for dim in PostureDimension:
        assert dim.value in posture.dimensions


# Axiom 27: Posture assessment no single scalar score
def test_axiom_27_posture_assessment_no_single_scalar_score():
    posture = evaluate_posture("p", "s1", [{"algorithm": "AES"}])
    p_dict = posture.to_dict()
    assert "score" not in p_dict
    assert "single_score" not in p_dict
    assert isinstance(p_dict["dimensions"], dict)


# Axiom 28: Posture change trend evaluation (IMPROVED)
def test_axiom_28_posture_change_trend_improved():
    p1 = evaluate_posture("p", "s1", [{"algorithm": "RSA"}], risks=[{"risk_level": "HIGH"}])
    p2 = evaluate_posture("p", "s2", [{"algorithm": "ML-KEM"}], risks=[{"risk_level": "LOW"}])
    change = evaluate_posture_change(p1, p2)
    assert change.overall_trend == PostureTrend.IMPROVED


# Axiom 29: Posture change trend evaluation (DEGRADED)
def test_axiom_29_posture_change_trend_degraded():
    p1 = evaluate_posture("p", "s1", [{"algorithm": "ML-KEM"}], risks=[{"risk_level": "LOW"}])
    p2 = evaluate_posture("p", "s2", [{"algorithm": "RSA"}], risks=[{"risk_level": "HIGH"}])
    change = evaluate_posture_change(p1, p2)
    assert change.overall_trend == PostureTrend.DEGRADED


# Axiom 30: Posture change trend evaluation (UNCHANGED)
def test_axiom_30_posture_change_trend_unchanged():
    p = evaluate_posture("p", "s1", [{"algorithm": "AES"}])
    change = evaluate_posture_change(p, p)
    assert change.overall_trend == PostureTrend.UNCHANGED


# Axiom 31: Single scan history evaluation yields NOT_ENOUGH_HISTORY
def test_axiom_31_single_scan_history_evaluation_yields_not_enough_history():
    p = evaluate_posture("p", "s1", [{"algorithm": "AES"}])
    change = evaluate_posture_change(p, None)
    assert change.overall_trend == PostureTrend.NOT_ENOUGH_HISTORY


# Axiom 32: Failure to observe != asset removed (explicit distinction)
def test_axiom_32_failure_to_observe_not_equal_to_asset_removed():
    now = datetime.now(timezone.utc)
    ev = make_evidence(source_engine="e", level=EvidenceLevel.E2, state=EvidenceState.MEASURED, observation_type=ObservationType.SOURCE_API_USE, confidence=0.8, symbol="A", description="A")
    scans = [
        {"scan_id": "s1", "timestamp": (now - timedelta(days=5)).isoformat(), "evidence": [ev]},
        {"scan_id": "s2", "timestamp": now.isoformat(), "evidence": []},
    ]
    tl = build_asset_timeline("p", "A", scans)
    unobs = [e for e in tl.events if e.event_type == TimelineEventType.UNOBSERVED]
    assert len(unobs) == 1
    assert "not observed" in unobs[0].description.lower()


# Axiom 33: Cross-project temporal isolation
def test_axiom_33_cross_project_temporal_isolation():
    c_p1 = compare_scans("proj_a", "s1", "s2", [{"algorithm": "AES"}], [{"algorithm": "AES"}])
    c_p2 = compare_scans("proj_b", "s1", "s2", [{"algorithm": "RSA"}], [{"algorithm": "RSA"}])
    assert c_p1.project_id == "proj_a"
    assert c_p2.project_id == "proj_b"
    assert c_p1.temporal_hash != c_p2.temporal_hash


# Axiom 34: Blast radius temporal evolution tracking
def test_axiom_34_blast_radius_temporal_evolution_tracking():
    p_contained = evaluate_posture("p", "s1", assets=[{"algorithm": "AES"}], blast_radii=[{"transitive_dependents_count": 2}])
    p_unbounded = evaluate_posture("p", "s2", assets=[{"algorithm": "AES"}], blast_radii=[{"transitive_dependents_count": 35}])
    assert p_contained.dimensions[PostureDimension.BLAST_RADIUS.value].state == BlastRadiusState.ISOLATED.value
    assert p_unbounded.dimensions[PostureDimension.BLAST_RADIUS.value].state == BlastRadiusState.UNBOUNDED.value
    change = evaluate_posture_change(p_contained, p_unbounded)
    assert change.dimension_transitions[PostureDimension.BLAST_RADIUS.value].trend == PostureTrend.DEGRADED


# Axiom 35: Re-scan of identical codebase yields UNCHANGED across all dimensions
def test_axiom_35_rescan_of_identical_codebase_yields_unchanged():
    assets = [{"id": "1", "asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256}]
    comp = compare_scans("p", "s1", "s2", assets, assets)
    assert comp.added_count == 0
    assert comp.removed_count == 0
    assert comp.changed_count == 0
    assert comp.unchanged_count == 1


# Axiom 36: Scan order independence in multi-scan timeline construction
def test_axiom_36_scan_order_independence_in_multiscan_timeline():
    now = datetime.now(timezone.utc)
    evs = [
        make_evidence(source_engine="e", level=EvidenceLevel.E2, state=EvidenceState.MEASURED, observation_type=ObservationType.SOURCE_API_USE, confidence=0.8, symbol="A", description="A", timestamp=(now - timedelta(days=i*10)).isoformat())
        for i in range(5)
    ]
    scans = [{"scan_id": f"s{i}", "timestamp": (now - timedelta(days=i*10)).isoformat(), "evidence": [evs[i]]} for i in range(5)]
    shuffled = list(scans)
    random.seed(42)
    random.shuffle(shuffled)

    tl1 = build_asset_timeline("p", "A", scans)
    tl2 = build_asset_timeline("p", "A", shuffled)
    assert [e.timestamp for e in tl1.events] == [e.timestamp for e in tl2.events]


# Axiom 37: Empty scan handling (0 assets to N assets = all NEW)
def test_axiom_37_empty_scan_handling():
    assets = [{"id": f"{i}", "asset_type": "ALGORITHM", "name": f"A{i}", "algorithm": "AES"} for i in range(5)]
    comp = compare_scans("p", "s1", "s2", [], assets)
    assert comp.added_count == 5
    assert comp.removed_count == 0
    assert all(c.category == ChangeCategory.NEW for c in comp.asset_changes)


# Axiom 38: Vanishing inventory handling (N assets to 0 assets = all REMOVED)
def test_axiom_38_vanishing_inventory_handling():
    assets = [{"id": f"{i}", "asset_type": "ALGORITHM", "name": f"A{i}", "algorithm": "AES"} for i in range(5)]
    comp = compare_scans("p", "s1", "s2", assets, [])
    assert comp.removed_count == 5
    assert comp.added_count == 0
    assert all(c.category == ChangeCategory.REMOVED for c in comp.asset_changes)


# Axiom 39: High-frequency scan noise resistance (rapid successive scans)
def test_axiom_39_high_frequency_scan_noise_resistance():
    now = datetime.now(timezone.utc)
    ev = make_evidence(source_engine="e", level=EvidenceLevel.E2, state=EvidenceState.MEASURED, observation_type=ObservationType.SOURCE_API_USE, confidence=0.8, symbol="A", description="A")
    scans = [{"scan_id": f"s{i}", "timestamp": (now + timedelta(seconds=i)).isoformat(), "evidence": [ev]} for i in range(5)]
    tl = build_asset_timeline("p", "A", scans, ttl_days=90)
    assert not any(e.event_type == TimelineEventType.STALE for e in tl.events)


# Axiom 40: Hash verification of temporal comparison and posture assessment
def test_axiom_40_hash_verification_of_temporal_comparison_and_posture():
    assets = [{"id": "1", "asset_type": "ALGORITHM", "name": "AES", "algorithm": "AES"}]
    comp = compare_scans("p", "s1", "s2", assets, assets)
    posture = evaluate_posture("p", "s1", assets)

    assert len(comp.temporal_hash) == 64
    assert len(posture.posture_hash) == 64
    assert int(comp.temporal_hash, 16) > 0
    assert int(posture.posture_hash, 16) > 0
