"""
ECDAT V4 P2.1 Evidence Context Utility.

Derives RiskConfidence from P0 Evidence items.
NO second evidence system is invented. Uses existing EvidenceLevel, EvidenceState.

AXIOM: UNKNOWN confidence is a valid result when evidence is absent or E0-only.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .models import RiskConfidence


def derive_confidence_from_evidence(evidence_items: List[Dict[str, Any]]) -> RiskConfidence:
    """
    Compute RiskConfidence from a list of P0 Evidence dicts.

    Rules (in priority order):
    1. If any item has contradicting IDs populated -> CONTRADICTED.
    2. If multiple independent E3+ items agree -> CORROBORATED.
    3. If at least one E3+ item exists -> MEASURED.
    4. If E1/E2 items exist -> INFERRED.
    5. If only E0 or no items -> UNKNOWN.
    """
    if not evidence_items:
        return RiskConfidence.UNKNOWN

    # 1. Explicit contradiction in evidence or state
    for ev in evidence_items:
        state = str(ev.get("state", "")).upper()
        fused = str(ev.get("fused_status", "")).upper()
        if ev.get("contradicting") or state == "CONTRADICTED" or fused == "CONTRADICTED":
            return RiskConfidence.CONTRADICTED

    # 2. Corroborated state from fusion or explicit flag
    for ev in evidence_items:
        state = str(ev.get("state", "")).upper()
        fused = str(ev.get("fused_status", "")).upper()
        if state == "CORROBORATED" or fused == "CORROBORATED":
            return RiskConfidence.CORROBORATED

    levels = [ev.get("level", "E0") for ev in evidence_items]
    ranks = [_level_rank(l) for l in levels]

    high_quality = [r for r in ranks if r >= 3]  # E3, E4, E5
    medium_quality = [r for r in ranks if r >= 1]  # E1+

    if len(high_quality) >= 2:
        return RiskConfidence.CORROBORATED
    if len(high_quality) >= 1:
        return RiskConfidence.MEASURED
    if len(medium_quality) >= 1:
        return RiskConfidence.INFERRED

    return RiskConfidence.UNKNOWN


def _level_rank(level_str: str) -> int:
    mapping = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}
    return mapping.get(str(level_str).upper(), 0)


def evidence_to_ref(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a P0 evidence dict to a lightweight EvidenceReference dict."""
    return {
        "evidence_id": ev.get("id", ""),
        "level": ev.get("level", "E0"),
        "state": ev.get("state", "UNMEASURED"),
        "observation_type": ev.get("observation_type", ""),
        "source_engine": ev.get("source_engine", ""),
        "location": ev.get("location") or ev.get("file_path"),
    }


def filter_evidence_by_observation(
    evidence_items: List[Dict[str, Any]],
    observation_types: List[str],
) -> List[Dict[str, Any]]:
    """Return evidence items matching any of the given observation types."""
    types_upper = {t.upper() for t in observation_types}
    return [
        ev for ev in evidence_items
        if str(ev.get("observation_type", "")).upper() in types_upper
    ]
