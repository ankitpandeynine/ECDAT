"""
ECDAT V4 P5.2 Temporal Crypto Intelligence Unit Tests.
"""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import uuid
import pytest
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.temporal.models import (
    ChangeCategory,
    RiskChange,
    PQCChange,
    AgilityChange,
    MigrationChange,
    TimelineEventType,
)
from engine.temporal.normalizer import compute_asset_key, normalize_asset
from engine.temporal.change_detector import detect_property_changes
from engine.temporal.comparator import compare_scans
from engine.temporal.temporal_risk import evaluate_temporal_risk
from engine.temporal.temporal_pqc import evaluate_temporal_pqc
from engine.temporal.temporal_agility import evaluate_temporal_agility
from engine.temporal.temporal_migration import evaluate_temporal_migration
from engine.temporal.evidence_timeline import build_asset_timeline
from engine.temporal.explainability import build_temporal_explainability
from engine.temporal.pipeline import TemporalPipeline
from engine.scan_store import ScanStore
from engine.evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance


def make_evidence(
    source_engine="source_analyzer",
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


def test_deterministic_asset_key_generation():
    asset1 = {
        "id": "random-uuid-1",
        "asset_type": "ALGORITHM",
        "name": "AES-256",
        "algorithm": "AES",
        "key_size": 256,
        "library": "cryptography",
    }
    asset2 = {
        "id": "random-uuid-2",
        "asset_type": "ALGORITHM",
        "name": "AES-256",
        "algorithm": "AES",
        "key_size": 256,
        "library": "cryptography",
    }
    k1 = compute_asset_key(asset1)
    k2 = compute_asset_key(asset2)
    assert k1 == k2
    assert "algorithm:aes:" in k1


def test_deterministic_asset_key_collision_resistance():
    asset_aes = {"asset_type": "ALGORITHM", "name": "AES-128", "algorithm": "AES", "key_size": 128}
    asset_rsa = {"asset_type": "ALGORITHM", "name": "RSA-2048", "algorithm": "RSA", "key_size": 2048}
    assert compute_asset_key(asset_aes) != compute_asset_key(asset_rsa)


def test_compare_scans_new_and_removed():
    base_assets = [
        {"id": "a1", "asset_type": "ALGORITHM", "name": "DES", "algorithm": "DES", "key_size": 56},
        {"id": "a2", "asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256},
    ]
    target_assets = [
        {"id": "a2_new", "asset_type": "ALGORITHM", "name": "AES-256", "algorithm": "AES", "key_size": 256},
        {"id": "a3", "asset_type": "ALGORITHM", "name": "ML-KEM-768", "algorithm": "ML-KEM", "key_size": 768},
    ]

    comp = compare_scans(
        project="proj-1",
        base_scan_id="s1",
        target_scan_id="s2",
        base_assets=base_assets,
        target_assets=target_assets,
    )

    assert comp.added_count == 1
    assert comp.removed_count == 1
    assert comp.unchanged_count == 1
    assert comp.changed_count == 0

    new_change = next(c for c in comp.asset_changes if c.category == ChangeCategory.NEW)
    assert "ML-KEM" in new_change.name or "ML-KEM" in new_change.asset_key

    removed_change = next(c for c in comp.asset_changes if c.category == ChangeCategory.REMOVED)
    assert "DES" in removed_change.name or "DES" in removed_change.asset_key


def test_compare_scans_changed_properties():
    b_item = {"id": "a1", "asset_type": "ALGORITHM", "name": "RSA", "algorithm": "RSA", "key_size": 1024, "version": "1.0"}
    t_item = {"id": "a1", "asset_type": "ALGORITHM", "name": "RSA", "algorithm": "RSA", "key_size": 2048, "version": "2.0"}

    comp = compare_scans(
        project="proj-1",
        base_scan_id="s1",
        target_scan_id="s2",
        base_assets=[b_item],
        target_assets=[t_item],
    )

    assert comp.changed_count == 1
    assert comp.unchanged_count == 0
    change = comp.asset_changes[0]
    assert change.category == ChangeCategory.CHANGED
    assert "key_size" in change.diff_summary["changed_properties"]
    assert "version" in change.diff_summary["changed_properties"]


def test_temporal_risk_evaluation():
    # New risk
    rc, _ = evaluate_temporal_risk(None, {"risk_level": "HIGH", "risk_score": 8.0})
    assert rc == RiskChange.RISK_NEW

    # Escalated risk
    rc, _ = evaluate_temporal_risk({"risk_level": "LOW", "risk_score": 2.0}, {"risk_level": "HIGH", "risk_score": 8.5})
    assert rc == RiskChange.RISK_INCREASED

    # Decreased risk
    rc, _ = evaluate_temporal_risk({"risk_level": "HIGH", "risk_score": 8.5}, {"risk_level": "LOW", "risk_score": 2.0})
    assert rc == RiskChange.RISK_DECREASED

    # Unchanged risk
    rc, _ = evaluate_temporal_risk({"risk_level": "LOW", "risk_score": 2.0}, {"risk_level": "LOW", "risk_score": 2.0})
    assert rc == RiskChange.RISK_UNCHANGED


def test_temporal_pqc_evaluation():
    # Classical to PQC introduction
    rc, _ = evaluate_temporal_pqc(None, None, {"algorithm": "RSA-2048"}, {"algorithm": "ML-KEM-768"})
    assert rc == PQCChange.PQC_INTRODUCED

    # PQC rollback
    rc, _ = evaluate_temporal_pqc(None, None, {"algorithm": "ML-KEM-768"}, {"algorithm": "RSA-2048"})
    assert rc == PQCChange.PQC_REMOVED

    # Round-3 to FIPS upgrade
    rc, _ = evaluate_temporal_pqc(None, None, {"algorithm": "Kyber-768"}, {"algorithm": "ML-KEM-768"})
    assert rc == PQCChange.PQC_UPGRADED


def test_temporal_agility_evaluation():
    # Improved agility
    ac, _ = evaluate_temporal_agility({"overall_score": 0.3}, {"overall_score": 0.8})
    assert ac == AgilityChange.AGILITY_INCREASED

    # Degraded agility
    ac, _ = evaluate_temporal_agility({"overall_score": 0.75}, {"overall_score": 0.4})
    assert ac == AgilityChange.AGILITY_DECREASED

    # Unchanged
    ac, _ = evaluate_temporal_agility({"overall_score": 0.5}, {"overall_score": 0.51})
    assert ac == AgilityChange.AGILITY_UNCHANGED


def test_temporal_migration_evaluation():
    mc, _ = evaluate_temporal_migration(None, {"verification_state": "VERIFIED"})
    assert mc == MigrationChange.MIGRATION_VERIFIED

    mc, _ = evaluate_temporal_migration({"status": "PLANNED"}, {"verification_state": "IN_PROGRESS"})
    assert mc == MigrationChange.MIGRATION_PROGRESSING

    mc, _ = evaluate_temporal_migration({"status": "IN_PROGRESS"}, {"verification_state": "FAILED"})
    assert mc == MigrationChange.MIGRATION_FAILED


def test_build_asset_timeline_ordered_events():
    now = datetime.now(timezone.utc)
    ev1 = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.8,
        symbol="AES",
        description="AES in source",
        timestamp=(now - timedelta(days=200)).isoformat(),
    )
    ev2 = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E3,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.9,
        symbol="AES",
        description="AES in build file",
        timestamp=now.isoformat(),
    )

    scans = [
        {"scan_id": "s1", "timestamp": (now - timedelta(days=200)).isoformat(), "evidence": [ev1]},
        {"scan_id": "s2", "timestamp": now.isoformat(), "evidence": [ev2]},
    ]

    timeline = build_asset_timeline("proj-1", "AES", scans, ttl_days=90)
    assert timeline.observation_count >= 1
    assert len(timeline.events) >= 2
    assert timeline.events[0].event_type == TimelineEventType.FIRST_OBSERVED
    assert any(e.event_type == TimelineEventType.STALE for e in timeline.events)


def test_explainability_report_generation():
    base_assets = [{"id": "a1", "asset_type": "ALGORITHM", "name": "RSA", "algorithm": "RSA"}]
    target_assets = [{"id": "a2", "asset_type": "ALGORITHM", "name": "ML-KEM", "algorithm": "ML-KEM"}]

    comp = compare_scans("proj-1", "s1", "s2", base_assets, target_assets)
    report = build_temporal_explainability(comp)

    assert "comparison_id" in report
    assert "narrative" in report
    assert report["inventory_delta"]["added"] == 1
    assert report["inventory_delta"]["removed"] == 1
    assert "critical_findings" in report
    assert "recommendations" in report


def test_temporal_pipeline_persistence():
    with tempfile.NamedTemporaryFile(suffix=".sqlite3", delete=False) as f:
        db_path = f.name

    store = ScanStore(path=db_path)
    with store.connect() as db:
        db.execute("INSERT OR IGNORE INTO scans (id, project, kind, status, created_at, input_hash) VALUES ('s1', 'proj-x', 'source', 'completed', '2026-09-18T00:00:00Z', 'hash1')")
        db.execute("INSERT OR IGNORE INTO scans (id, project, kind, status, created_at, input_hash) VALUES ('s2', 'proj-x', 'source', 'completed', '2026-09-18T01:00:00Z', 'hash2')")

    pipeline = TemporalPipeline(store)

    a1 = store.graph.upsert_asset("proj-x", "ALGORITHM", "AES", scan_id="s1", algorithm="AES")
    a2 = store.graph.upsert_asset("proj-x", "ALGORITHM", "AES", scan_id="s2", algorithm="AES")

    comp_dict = pipeline.run_comparison("proj-x", "s1", "s2")
    assert "comparison_id" in comp_dict
    assert comp_dict["base_scan_id"] == "s1"
    assert comp_dict["target_scan_id"] == "s2"

    cached = store.get_temporal_comparison("proj-x", "s1", "s2")
    assert cached is not None
    assert cached["comparison_id"] == comp_dict["comparison_id"]

    tl = pipeline.get_asset_timeline("proj-x", a1.id)
    assert tl is not None
    assert tl["asset_id"] == a1.id

    store.close()
