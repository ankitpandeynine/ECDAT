"""
ECDAT V4 Agility Explainability Engine.

Synthesizes machine-readable reason chains answering "WHY?" for each dimension
and the aggregate agility assessment.
"""
from __future__ import annotations

from typing import Any, Dict, List
from .models import AgilityAssessment, AgilityDimension, AgilityReason, DimensionalAgility


def build_agility_explainability_report(assessment: AgilityAssessment) -> Dict[str, Any]:
    """Generates an audit-ready explainability report from an AgilityAssessment."""
    reasons_by_dim: Dict[str, List[Dict[str, Any]]] = {}
    evidence_links: List[str] = []

    for dim_key, dim_val in assessment.dimensions.items():
        dim_reasons = []
        for r in dim_val.reason_chain:
            dim_reasons.append(r.to_dict() if hasattr(r, "to_dict") else r)
            evidence_links.extend(r.evidence_refs)
        reasons_by_dim[dim_key] = dim_reasons

    # High-level summary
    dimension_summaries = {}
    for dim_key, dim_val in assessment.dimensions.items():
        dimension_summaries[dim_key] = {
            "state": dim_val.state.value,
            "confidence": dim_val.confidence.value,
            "derived_score": dim_val.derived_score,
            "supporting_count": len(dim_val.supporting_evidence),
            "contradicting_count": len(dim_val.contradicting_evidence),
            "unknowns_count": len(dim_val.unknowns),
        }

    return {
        "assessment_id": assessment.assessment_id,
        "asset_id": assessment.asset_id,
        "overall_state": assessment.overall_state.value,
        "composite_score": assessment.composite_score,
        "derived_score_metadata": assessment.derived_score_metadata,
        "dimension_summaries": dimension_summaries,
        "reasons_by_dimension": reasons_by_dim,
        "all_reasons": [r.to_dict() if hasattr(r, "to_dict") else r for r in assessment.reasons],
        "evidence_refs": sorted(list(set(evidence_links))),
        "unknowns": assessment.unknowns,
        "limitations": assessment.limitations,
        "provenance": {
            "evidence_hash": assessment.evidence_hash,
            "configuration_hash": assessment.configuration_hash,
            "knowledge_base_version": assessment.knowledge_base_version,
            "engine_version": assessment.engine_version,
            "created_at": assessment.created_at,
        },
    }
