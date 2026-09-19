"""
ECDAT V4 Posture Change & Transition Engine.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
import uuid

from .models import (
    PostureDimension,
    PostureTrend,
    PostureDimensionTransition,
    PostureAssessment,
    PostureChangeAssessment,
)

# Orderings where higher index is strictly better (progression)
PQC_ORDER = ["NON_COMPLIANT", "PLANNING", "HYBRID_TRANSITION", "PQC_READY", "COMPLIANT"]
AGILITY_ORDER = ["RIGID", "FRAGILE", "PARTIALLY_AGILE", "AGILE", "HIGHLY_AGILE"]
EVIDENCE_ORDER = ["SPECULATIVE", "HEURISTIC", "VERIFIED_STATIC", "VERIFIED_RUNTIME", "CORROBORATED"]
MIGRATION_ORDER = ["NOT_STARTED", "PLANNED", "IN_PROGRESS", "VERIFIED"]

# Orderings where lower index is strictly better (less risk / less blast radius)
RISK_ORDER = ["LOW", "MODERATE", "ELEVATED", "HIGH", "CRITICAL"]
BLAST_ORDER = ["MINIMAL", "ISOLATED", "CONTAINED", "BROAD", "UNBOUNDED"]


def _rank_trend(base_state: str, target_state: str, order: list[str], reverse: bool = False) -> PostureTrend:
    if base_state == target_state:
        return PostureTrend.UNCHANGED
    if base_state not in order or target_state not in order:
        return PostureTrend.UNKNOWN

    b_idx = order.index(base_state)
    t_idx = order.index(target_state)

    if not reverse:
        # Higher is better
        return PostureTrend.IMPROVED if t_idx > b_idx else PostureTrend.DEGRADED
    else:
        # Lower is better (e.g. risk, blast radius)
        return PostureTrend.IMPROVED if t_idx < b_idx else PostureTrend.DEGRADED


def evaluate_posture_change(
    base: Optional[PostureAssessment | Dict[str, Any]],
    target: Optional[PostureAssessment | Dict[str, Any]],
    project: str = "default",
    asset_id: Optional[str] = None,
) -> PostureChangeAssessment:
    """
    Evaluates continuous posture change between two assessments.
    Enforces rule: single scan history yields NOT_ENOUGH_HISTORY.
    """
    if base is None or target is None:
        return PostureChangeAssessment(
            change_id=f"pchange-{uuid.uuid4().hex[:12]}",
            project_id=project,
            base_assessment_id=base.get("assessment_id", "") if isinstance(base, dict) else (base.assessment_id if base else ""),
            target_assessment_id=target.get("assessment_id", "") if isinstance(target, dict) else (target.assessment_id if target else ""),
            asset_id=asset_id,
            overall_trend=PostureTrend.NOT_ENOUGH_HISTORY,
            dimension_transitions={},
            summary="Single scan baseline; not enough historical scans to compute continuous posture delta.",
        )

    base_dict = base.to_dict() if hasattr(base, "to_dict") else dict(base)
    target_dict = target.to_dict() if hasattr(target, "to_dict") else dict(target)

    b_dims = base_dict.get("dimensions", {})
    t_dims = target_dict.get("dimensions", {})

    transitions: Dict[str, PostureDimensionTransition] = {}
    improved_count = 0
    degraded_count = 0

    for dim in PostureDimension:
        d_key = dim.value
        b_d = b_dims.get(d_key, {})
        t_d = t_dims.get(d_key, {})

        b_state = b_d.get("state", "UNKNOWN")
        t_state = t_d.get("state", "UNKNOWN")

        if dim == PostureDimension.QUANTUM_RISK:
            trend = _rank_trend(b_state, t_state, RISK_ORDER, reverse=True)
        elif dim == PostureDimension.BLAST_RADIUS:
            trend = _rank_trend(b_state, t_state, BLAST_ORDER, reverse=True)
        elif dim == PostureDimension.PQC_READINESS:
            trend = _rank_trend(b_state, t_state, PQC_ORDER)
        elif dim == PostureDimension.CRYPTO_AGILITY:
            trend = _rank_trend(b_state, t_state, AGILITY_ORDER)
        elif dim == PostureDimension.EVIDENCE_QUALITY:
            trend = _rank_trend(b_state, t_state, EVIDENCE_ORDER)
        elif dim == PostureDimension.MIGRATION_STATUS:
            if t_state == "BLOCKED" and b_state != "BLOCKED":
                trend = PostureTrend.DEGRADED
            else:
                trend = _rank_trend(b_state, t_state, MIGRATION_ORDER)
        else:
            # Inventory
            trend = PostureTrend.UNCHANGED if b_state == t_state else PostureTrend.IMPROVED

        if trend == PostureTrend.IMPROVED:
            improved_count += 1
            expl = f"{dim.value} improved from {b_state} to {t_state}."
        elif trend == PostureTrend.DEGRADED:
            degraded_count += 1
            expl = f"⚠️ {dim.value} degraded from {b_state} to {t_state}."
        else:
            expl = f"{dim.value} remained stable at {t_state}."

        transitions[d_key] = PostureDimensionTransition(
            dimension=dim,
            base_state=b_state,
            target_state=t_state,
            trend=trend,
            explanation=expl,
        )

    # Determine overall trend
    if degraded_count > 0 and improved_count == 0:
        overall_trend = PostureTrend.DEGRADED
    elif improved_count > 0 and degraded_count == 0:
        overall_trend = PostureTrend.IMPROVED
    elif improved_count > 0 and degraded_count > 0:
        # If risk degraded or PQC reverted, overall is DEGRADED
        risk_trend = transitions.get(PostureDimension.QUANTUM_RISK.value, {}).trend if transitions.get(PostureDimension.QUANTUM_RISK.value) else PostureTrend.UNCHANGED
        if risk_trend == PostureTrend.DEGRADED:
            overall_trend = PostureTrend.DEGRADED
        else:
            overall_trend = PostureTrend.IMPROVED
    else:
        overall_trend = PostureTrend.UNCHANGED

    summary_text = (
        f"Continuous Posture Assessment: Overall trend is {overall_trend.value} "
        f"({improved_count} dimension(s) improved, {degraded_count} dimension(s) degraded)."
    )

    return PostureChangeAssessment(
        change_id=f"pchange-{uuid.uuid4().hex[:12]}",
        project_id=project,
        base_assessment_id=base_dict.get("assessment_id", ""),
        target_assessment_id=target_dict.get("assessment_id", ""),
        asset_id=asset_id,
        overall_trend=overall_trend,
        dimension_transitions=transitions,
        summary=summary_text,
    )
