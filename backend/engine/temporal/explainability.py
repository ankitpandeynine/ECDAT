"""
ECDAT V4 Temporal Explainability Generator.
"""
from __future__ import annotations

from typing import Any, Dict, List
from .models import ChangeCategory, RiskChange, PQCChange, AgilityChange, TemporalComparison


def build_temporal_explainability(comparison: TemporalComparison) -> Dict[str, Any]:
    """
    Generates deterministic human-readable and structured explainability reports
    for a temporal comparison.
    """
    risk_escalated = [c for c in comparison.asset_changes if c.risk_change == RiskChange.RISK_INCREASED]
    risk_reduced = [c for c in comparison.asset_changes if c.risk_change == RiskChange.RISK_DECREASED]
    pqc_introduced = [c for c in comparison.asset_changes if c.pqc_change == PQCChange.PQC_INTRODUCED]
    pqc_upgraded = [c for c in comparison.asset_changes if c.pqc_change == PQCChange.PQC_UPGRADED]
    pqc_removed = [c for c in comparison.asset_changes if c.pqc_change == PQCChange.PQC_REMOVED]
    agility_improved = [c for c in comparison.asset_changes if c.agility_change == AgilityChange.AGILITY_INCREASED]
    agility_degraded = [c for c in comparison.asset_changes if c.agility_change == AgilityChange.AGILITY_DECREASED]

    critical_findings: List[str] = []
    if risk_escalated:
        critical_findings.append(f"{len(risk_escalated)} asset(s) escalated in cryptographic risk.")
    if pqc_removed:
        critical_findings.append(f"⚠️ REGRESSION: {len(pqc_removed)} asset(s) had PQC implementations removed/reverted to classical.")
    if pqc_introduced:
        critical_findings.append(f"✅ PROGRESS: {len(pqc_introduced)} asset(s) adopted post-quantum / hybrid cryptography.")
    if pqc_upgraded:
        critical_findings.append(f"✅ PROGRESS: {len(pqc_upgraded)} asset(s) upgraded to FIPS standardized PQC parameters.")
    if agility_degraded:
        critical_findings.append(f"⚠️ Agility degraded for {len(agility_degraded)} asset(s).")

    recommendations: List[str] = []
    if risk_escalated:
        recommendations.append("Investigate root cause of risk escalation on newly introduced or modified primitives.")
    if pqc_removed:
        recommendations.append("Re-evaluate recent deployments to prevent accidental rollback of post-quantum algorithms.")
    if not pqc_introduced and not pqc_upgraded and comparison.added_count > 0:
        recommendations.append("Ensure new assets comply with CNSA 2.0 / NIST PQC migration mandates.")
    if not recommendations:
        recommendations.append("Cryptographic posture is stable. Continue periodic continuous monitoring.")

    narrative = (
        f"Temporal analysis between scan {comparison.base_scan_id} and {comparison.target_scan_id} "
        f"revealed {comparison.added_count} new assets, {comparison.removed_count} removed, "
        f"{comparison.changed_count} modified, and {comparison.unchanged_count} unchanged. "
        f"Risk escalated on {len(risk_escalated)} asset(s) and reduced on {len(risk_reduced)} asset(s)."
    )

    return {
        "comparison_id": comparison.comparison_id,
        "base_scan_id": comparison.base_scan_id,
        "target_scan_id": comparison.target_scan_id,
        "temporal_hash": comparison.temporal_hash,
        "narrative": narrative,
        "inventory_delta": {
            "added": comparison.added_count,
            "removed": comparison.removed_count,
            "changed": comparison.changed_count,
            "unchanged": comparison.unchanged_count,
        },
        "risk_delta": {
            "escalated_count": len(risk_escalated),
            "reduced_count": len(risk_reduced),
            "escalated_assets": [c.name for c in risk_escalated],
            "reduced_assets": [c.name for c in risk_reduced],
        },
        "pqc_delta": {
            "introduced_count": len(pqc_introduced),
            "upgraded_count": len(pqc_upgraded),
            "removed_count": len(pqc_removed),
        },
        "agility_delta": {
            "improved_count": len(agility_improved),
            "degraded_count": len(agility_degraded),
        },
        "critical_findings": critical_findings,
        "recommendations": recommendations,
    }
