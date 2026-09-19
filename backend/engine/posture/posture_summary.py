"""
ECDAT V4 Posture Summary Engine.
"""
from __future__ import annotations

from typing import Any, Dict
from .models import PostureAssessment, PostureDimension


def summarize_posture(assessment: PostureAssessment) -> Dict[str, Any]:
    """Generates an executive-level posture briefing without single-score collapse."""
    dims = assessment.dimensions

    risk_d = dims.get(PostureDimension.QUANTUM_RISK.value)
    pqc_d = dims.get(PostureDimension.PQC_READINESS.value)
    agility_d = dims.get(PostureDimension.CRYPTO_AGILITY.value)
    blast_d = dims.get(PostureDimension.BLAST_RADIUS.value)
    mig_d = dims.get(PostureDimension.MIGRATION_STATUS.value)
    ev_d = dims.get(PostureDimension.EVIDENCE_QUALITY.value)

    status_matrix = {
        k: {
            "state": v.state,
            "numeric_metric": v.numeric_value,
            "summary": v.summary,
        }
        for k, v in dims.items()
    }

    highlights = []
    if risk_d and risk_d.state in ("CRITICAL", "HIGH"):
        highlights.append(f"URGENT: Quantum Risk is classified as {risk_d.state}.")
    if pqc_d and pqc_d.state == "COMPLIANT":
        highlights.append("EXEMPLARY: Complete PQC adoption verified across all inventory.")
    elif pqc_d and pqc_d.state == "NON_COMPLIANT":
        highlights.append("ATTENTION: Zero PQC primitives deployed.")
    if agility_d and agility_d.state in ("RIGID", "FRAGILE"):
        highlights.append("BOTTLENECK: Cryptographic agility is constrained by hardcoded primitives.")

    return {
        "assessment_id": assessment.assessment_id,
        "project_id": assessment.project_id,
        "scan_id": assessment.scan_id,
        "posture_hash": assessment.posture_hash,
        "status_matrix": status_matrix,
        "executive_highlights": highlights,
        "created_at": assessment.created_at,
    }
