"""
ECDAT V4 P2.3 Blast Radius Explainability & Audit Reports.

Generates transparent, machine-readable reason chains detailing each step of
dependency propagation and impact reasoning.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import BlastRadiusAssessment, BlastRadiusReason


def generate_blast_radius_reason_chain(
    assessment_data: Dict[str, Any],
    direct_dependents: List[str],
    transitive_dependents: List[str],
    dependency_paths: List[Any],
    impact_rationale: List[str],
    criticality_factors: List[str],
    limitations: List[str],
) -> List[BlastRadiusReason]:
    """Builds a sequence of structured reason steps explaining the blast radius."""
    reasons: List[BlastRadiusReason] = []
    asset_id = assessment_data.get("asset_id", "Unknown")

    # Step 1: Direct dependency analysis
    if direct_dependents:
        reasons.append(
            BlastRadiusReason(
                step="DIRECT_DEPENDENCY_IDENTIFICATION",
                claim=f"Direct consumption observed: {len(direct_dependents)} immediate caller(s)/consumer(s) link to {asset_id}.",
                rule_id="BLST-PTH-001",
                rule_version="1.0",
                supporting=[f"Direct dependent: {d}" for d in direct_dependents[:5]],
                limitations=[],
            )
        )
    else:
        reasons.append(
            BlastRadiusReason(
                step="DIRECT_DEPENDENCY_IDENTIFICATION",
                claim=f"No immediate direct callers or consumers were observed for {asset_id} in the analyzed graph.",
                rule_id="BLST-IMP-001",
                rule_version="1.0",
                limitations=["Absence of observed callers within scan boundary does not guarantee dead code."],
            )
        )

    # Step 2: Transitive path propagation
    if transitive_dependents:
        reasons.append(
            BlastRadiusReason(
                step="TRANSITIVE_PROPAGATION_ANALYSIS",
                claim=f"Transitive propagation observed: {len(transitive_dependents)} indirect asset(s) depend via intermediate links.",
                rule_id="BLST-PTH-002",
                rule_version="1.0",
                supporting=[f"Transitive dependent: {t}" for t in transitive_dependents[:5]],
                limitations=[],
            )
        )

    # Step 3: Impact scope classification
    reasons.append(
        BlastRadiusReason(
            step="IMPACT_SCOPE_CLASSIFICATION",
            claim=f"Impact categorized as {assessment_data.get('impact_category', 'UNKNOWN')} with state {assessment_data.get('state', 'UNKNOWN')}.",
            rule_id="BLST-IMP-005" if "MULTI_SERVICE" in str(assessment_data.get("impact_category")) else "BLST-IMP-003",
            rule_version="1.0",
            supporting=list(impact_rationale),
            limitations=list(limitations),
        )
    )

    # Step 4: Architectural criticality context
    reasons.append(
        BlastRadiusReason(
            step="ARCHITECTURAL_CRITICALITY_EVALUATION",
            claim=f"Downstream architectural criticality assessed as {assessment_data.get('criticality', 'UNKNOWN')}.",
            rule_id="BLST-CRT-001" if assessment_data.get("criticality") == "CRITICAL" else "BLST-CRT-006",
            rule_version="1.0",
            supporting=list(criticality_factors),
            limitations=[lim for lim in limitations if "criticality" in lim.lower() or "dependent count" in lim.lower()],
        )
    )

    return reasons


def build_blast_radius_explainability_report(assessment: BlastRadiusAssessment) -> Dict[str, Any]:
    """Generates an audit-ready explainability payload for GET /api/assets/{id}/blast-radius/why."""
    data = assessment.to_dict()
    return {
        "asset_id": assessment.asset_id,
        "scan_id": assessment.scan_id,
        "project_id": assessment.project_id,
        "state": data["state"],
        "impact_category": data["impact_category"],
        "criticality": data["criticality"],
        "confidence": data["confidence"],
        "direct_dependents_count": len(assessment.direct_dependents),
        "transitive_dependents_count": len(assessment.transitive_dependents),
        "total_paths_count": len(assessment.dependency_paths),
        "reason_chain": data["reason_chain"],
        "top_impacted_services": assessment.affected_services,
        "top_impacted_deployments": assessment.affected_deployments,
        "partial_result": assessment.partial_result,
        "limitations": assessment.limitations,
        "unknowns": assessment.unknowns,
        "provenance": {
            "graph_hash": assessment.graph_hash,
            "evidence_hash": assessment.evidence_hash,
            "configuration_hash": assessment.configuration_hash,
            "knowledge_base_version": assessment.knowledge_base_version,
            "engine_version": assessment.engine_version,
            "created_at": assessment.created_at,
        },
    }
