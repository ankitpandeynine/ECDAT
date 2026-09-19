"""
ECDAT V4 Posture Explainability Generator.
"""
from __future__ import annotations

from typing import Any, Dict, List
from .models import PostureAssessment, PostureChangeAssessment, PostureTrend


def build_posture_explainability(assessment: PostureAssessment) -> Dict[str, Any]:
    """Generates detailed, deterministic explainability rationale for a posture assessment."""
    dim_explanations: Dict[str, Any] = {}
    for d_name, dim in assessment.dimensions.items():
        dim_explanations[d_name] = {
            "state": dim.state,
            "metric": dim.numeric_value,
            "rationale": dim.summary,
            "evidence_count": dim.evidence_count,
            "evidence_details": dim.details,
        }

    return {
        "assessment_id": assessment.assessment_id,
        "project_id": assessment.project_id,
        "scan_id": assessment.scan_id,
        "posture_hash": assessment.posture_hash,
        "summary": assessment.summary,
        "dimensions": dim_explanations,
    }


def build_posture_change_explainability(change: PostureChangeAssessment) -> Dict[str, Any]:
    """Generates detailed, deterministic explainability rationale for posture transitions."""
    improved_dims: List[str] = []
    degraded_dims: List[str] = []
    stable_dims: List[str] = []

    for d_name, trans in change.dimension_transitions.items():
        if trans.trend == PostureTrend.IMPROVED:
            improved_dims.append(trans.explanation)
        elif trans.trend == PostureTrend.DEGRADED:
            degraded_dims.append(trans.explanation)
        else:
            stable_dims.append(trans.explanation)

    actionable_remediation: List[str] = []
    if degraded_dims:
        actionable_remediation.append("Investigate root cause of degraded cryptographic posture dimensions.")
    if change.overall_trend == PostureTrend.NOT_ENOUGH_HISTORY:
        actionable_remediation.append("Perform a subsequent scan to establish longitudinal temporal comparison.")

    return {
        "change_id": change.change_id,
        "base_assessment_id": change.base_assessment_id,
        "target_assessment_id": change.target_assessment_id,
        "overall_trend": change.overall_trend.value if hasattr(change.overall_trend, "value") else str(change.overall_trend),
        "summary": change.summary,
        "improved_dimensions": improved_dims,
        "degraded_dimensions": degraded_dims,
        "stable_dimensions": stable_dims,
        "actionable_remediation": actionable_remediation,
    }
