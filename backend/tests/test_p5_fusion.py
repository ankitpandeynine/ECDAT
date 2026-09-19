"""
ECDAT V4 P5.1 Advanced Evidence Fusion Unit Tests.
"""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import sys
import uuid
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
from engine.evidence_fusion import (
    CorroborationEngine,
    EvidenceFusionEngine,
    CorroborationStatus,
    EvidenceFreshness,
    EvidenceLineage,
    MultiScanCorroboration,
)


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


def test_freshness_enum_and_lineage_serialization():
    assert EvidenceFreshness.CURRENT.value == "CURRENT"
    assert EvidenceFreshness.STALE.value == "STALE"
    assert EvidenceFreshness.SUPERSEDED.value == "SUPERSEDED"
    assert EvidenceFreshness.UNKNOWN.value == "UNKNOWN"

    lineage = EvidenceLineage(
        scan_id="scan-001",
        parent_evidence_id="ev-001",
        superseded_by_id="ev-002",
        superseded_at="2026-09-18T12:00:00Z",
    )
    d = lineage.to_dict()
    assert d["scan_id"] == "scan-001"
    assert d["parent_evidence_id"] == "ev-001"
    assert d["superseded_by_id"] == "ev-002"


def test_corroboration_engine_alias():
    assert CorroborationEngine is EvidenceFusionEngine
    engine = CorroborationEngine()
    assert hasattr(engine, "evaluate_freshness")
    assert hasattr(engine, "track_supersession")
    assert hasattr(engine, "corroborate_multi_scan")


def test_freshness_evaluation_current():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.9,
        symbol="AES-256",
        description="AES-256 in source",
        timestamp=now.isoformat(),
    )
    freshness = engine.evaluate_freshness(ev, as_of_time=now, ttl_days=90)
    assert freshness == EvidenceFreshness.CURRENT
    # Immutability assertion
    assert ev.state == EvidenceState.MEASURED


def test_freshness_evaluation_stale():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    past_date = now - timedelta(days=120)
    ev = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.85,
        symbol="RSA-2048",
        description="RSA-2048 in config",
        timestamp=past_date.isoformat(),
    )
    freshness = engine.evaluate_freshness(ev, as_of_time=now, ttl_days=90)
    assert freshness == EvidenceFreshness.STALE
    # State must remain MEASURED!
    assert ev.state == EvidenceState.MEASURED


def test_freshness_evaluation_unknown_timestamp():
    engine = CorroborationEngine()
    ev = make_evidence(
        source_engine="manual",
        level=EvidenceLevel.E1,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_PATTERN,
        confidence=0.5,
        symbol="UNKNOWN",
        description="No timestamp evidence",
    )
    ev.timestamp = ""
    freshness = engine.evaluate_freshness(ev)
    assert freshness == EvidenceFreshness.UNKNOWN


def test_track_supersession_lineage_and_immutability():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    old_ev = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.8,
        symbol="SHA-1",
        description="Old SHA-1 observation",
        timestamp=(now - timedelta(days=10)).isoformat(),
    )
    new_ev = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E3,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.95,
        symbol="SHA-256",
        description="Updated SHA-256 observation",
        timestamp=now.isoformat(),
    )

    lineage = engine.track_supersession(old_ev, new_ev)
    assert lineage.parent_evidence_id == old_ev.id
    assert lineage.superseded_by_id == new_ev.id
    assert old_ev.raw_details.get("superseded_by") == new_ev.id

    # Check that evaluate_freshness now treats old_ev as SUPERSEDED
    assert engine.evaluate_freshness(old_ev) == EvidenceFreshness.SUPERSEDED
    # Crucial: state must NOT be mutated from MEASURED
    assert old_ev.state == EvidenceState.MEASURED


def test_corroborate_multi_scan_accumulation():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev1 = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.7,
        symbol="AES-GCM",
        description="AES-GCM in crypto.py",
        timestamp=(now - timedelta(days=5)).isoformat(),
    )
    ev2 = make_evidence(
        source_engine="dependency_analyzer",
        level=EvidenceLevel.E3,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.DEPENDENCY_DECLARATION,
        confidence=0.8,
        symbol="AES-GCM",
        description="AES-GCM in requirements.txt",
        timestamp=now.isoformat(),
    )

    scans = [
        {"scan_id": "scan-1", "evidence": [ev1]},
        {"scan_id": "scan-2", "evidence": [ev2]},
    ]

    res = engine.corroborate_multi_scan("test_proj", "AES-GCM", scans, as_of_time=now)
    assert res.scan_count == 2
    assert "scan-1" in res.scans_observed and "scan-2" in res.scans_observed
    assert res.fused_status == CorroborationStatus.CORROBORATED
    assert res.highest_level == EvidenceLevel.E3
    assert res.combined_confidence > 0.8
    assert res.combined_confidence <= 1.0
    assert res.freshness == EvidenceFreshness.CURRENT
    assert res.active_evidence_count == 2


def test_corroborate_multi_scan_with_supersession():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev_old = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.6,
        symbol="RSA-1024",
        description="RSA-1024 in legacy code",
        timestamp=(now - timedelta(days=20)).isoformat(),
    )
    ev_new = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E3,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.9,
        symbol="RSA-2048",
        description="RSA-2048 in upgraded code",
        timestamp=now.isoformat(),
    )

    engine.track_supersession(ev_old, ev_new)

    scans = [
        {"scan_id": "scan-1", "evidence": [ev_old]},
        {"scan_id": "scan-2", "evidence": [ev_new]},
    ]

    res = engine.corroborate_multi_scan("test_proj", "RSA", scans, as_of_time=now)
    assert res.superseded_evidence_count == 1
    assert res.active_evidence_count == 1
    assert res.freshness == EvidenceFreshness.CURRENT


def test_corroborate_multi_scan_empty():
    engine = CorroborationEngine()
    res = engine.corroborate_multi_scan("test_proj", "NON_EXISTENT", [])
    assert res.scan_count == 0
    assert res.freshness == EvidenceFreshness.UNKNOWN
    assert res.fused_status == CorroborationStatus.INCONCLUSIVE
    assert res.active_evidence_count == 0


def test_corroboration_contradiction_multi_scan():
    engine = CorroborationEngine()
    now = datetime.now(timezone.utc)
    ev_static = make_evidence(
        source_engine="source_analyzer",
        level=EvidenceLevel.E2,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.SOURCE_API_USE,
        confidence=0.8,
        symbol="RSA",
        description="RSA statically referenced",
        timestamp=now.isoformat(),
    )
    ev_dynamic = make_evidence(
        source_engine="tls_analyzer",
        level=EvidenceLevel.E5,
        state=EvidenceState.MEASURED,
        observation_type=ObservationType.TLS_NEGOTIATION,
        confidence=0.95,
        symbol="ECDSA",
        description="ECDSA negotiated at live TLS endpoint",
        timestamp=now.isoformat(),
    )

    scans = [
        {"scan_id": "scan-1", "evidence": [ev_static, ev_dynamic]},
    ]
    res = engine.corroborate_multi_scan("test_proj", "RSA", scans, as_of_time=now)
    assert res.fused_status == CorroborationStatus.CONTRADICTED or len(res.contradictions) > 0
