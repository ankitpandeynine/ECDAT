"""
ECDAT V4 Continuous Cryptographic Posture Classifier.

Evaluates an inventory across 7 orthogonal cryptographic posture dimensions.
Never collapses posture into a single scalar number.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .models import (
    PostureDimension,
    InventoryState,
    QuantumRiskState,
    PQCReadinessState,
    CryptoAgilityState,
    BlastRadiusState,
    MigrationStatusState,
    EvidenceQualityState,
    DimensionAssessment,
    PostureAssessment,
)


def classify_inventory_posture(assets: List[Dict[str, Any]]) -> DimensionAssessment:
    count = len(assets)
    if count == 0:
        return DimensionAssessment(
            dimension=PostureDimension.CRYPTO_INVENTORY,
            state=InventoryState.EMPTY.value,
            numeric_value=0.0,
            summary="Zero cryptographic assets observed in scan.",
            evidence_count=0,
            details={"asset_count": 0},
        )
    return DimensionAssessment(
        dimension=PostureDimension.CRYPTO_INVENTORY,
        state=InventoryState.CATALOGED.value,
        numeric_value=float(count),
        summary=f"{count} cryptographic asset(s) cataloged in inventory.",
        evidence_count=count,
        details={"asset_count": count},
    )


def classify_quantum_risk_posture(risks: List[Dict[str, Any]]) -> DimensionAssessment:
    if not risks:
        return DimensionAssessment(
            dimension=PostureDimension.QUANTUM_RISK,
            state=QuantumRiskState.LOW.value,
            numeric_value=0.0,
            summary="No quantum risk findings recorded.",
            evidence_count=0,
            details={},
        )

    levels = [str(r.get("risk_level", "")).upper() for r in risks]
    scores = [float(r.get("risk_score") or r.get("mosca_score") or 0.0) for r in risks]
    max_score = max(scores) if scores else 0.0

    if "CRITICAL" in levels:
        state = QuantumRiskState.CRITICAL.value
        summary = f"CRITICAL quantum risk detected across {levels.count('CRITICAL')} asset(s)."
    elif "HIGH" in levels:
        state = QuantumRiskState.HIGH.value
        summary = f"HIGH quantum risk detected across {levels.count('HIGH')} asset(s)."
    elif "ELEVATED" in levels or "MEDIUM" in levels:
        state = QuantumRiskState.ELEVATED.value
        summary = f"Elevated quantum risk detected across {levels.count('ELEVATED') + levels.count('MEDIUM')} asset(s)."
    elif "MODERATE" in levels:
        state = QuantumRiskState.MODERATE.value
        summary = f"Moderate quantum risk detected across {levels.count('MODERATE')} asset(s)."
    else:
        state = QuantumRiskState.LOW.value
        summary = "Low quantum risk across observed assets."

    return DimensionAssessment(
        dimension=PostureDimension.QUANTUM_RISK,
        state=state,
        numeric_value=round(max_score, 2),
        summary=summary,
        evidence_count=len(risks),
        details={"max_score": max_score, "level_counts": {lvl: levels.count(lvl) for lvl in set(levels)}},
    )


def classify_pqc_readiness_posture(pqc_items: List[Dict[str, Any]], assets: List[Dict[str, Any]]) -> DimensionAssessment:
    if not assets:
        return DimensionAssessment(
            dimension=PostureDimension.PQC_READINESS,
            state=PQCReadinessState.NON_COMPLIANT.value,
            numeric_value=0.0,
            summary="No assets to evaluate for PQC readiness.",
            evidence_count=0,
        )

    algos = [str(a.get("algorithm", "")).upper() for a in assets]
    pqc_tokens = {"ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "LMS", "XMSS", "KYBER", "DILITHIUM"}
    
    pqc_count = sum(1 for a in algos if any(p in a for p in pqc_tokens))
    total = len(assets)
    ratio = pqc_count / total if total > 0 else 0.0

    if ratio == 1.0 and total > 0:
        state = PQCReadinessState.COMPLIANT.value
        summary = "100% of cryptographic inventory operates post-quantum primitives."
    elif ratio >= 0.5:
        state = PQCReadinessState.PQC_READY.value
        summary = f"Substantial PQC adoption ({pqc_count}/{total} assets, {int(ratio*100)}%)."
    elif ratio > 0.0:
        state = PQCReadinessState.HYBRID_TRANSITION.value
        summary = f"Initial hybrid / PQC transition underway ({pqc_count}/{total} assets)."
    elif pqc_items:
        state = PQCReadinessState.PLANNING.value
        summary = "PQC readiness assessment active but no production PQC primitives deployed."
    else:
        state = PQCReadinessState.NON_COMPLIANT.value
        summary = "No post-quantum algorithms detected in inventory."

    return DimensionAssessment(
        dimension=PostureDimension.PQC_READINESS,
        state=state,
        numeric_value=round(ratio, 2),
        summary=summary,
        evidence_count=total,
        details={"pqc_count": pqc_count, "total_assets": total, "adoption_ratio": round(ratio, 3)},
    )


def classify_crypto_agility_posture(agilities: List[Dict[str, Any]]) -> DimensionAssessment:
    if not agilities:
        return DimensionAssessment(
            dimension=PostureDimension.CRYPTO_AGILITY,
            state=CryptoAgilityState.RIGID.value,
            numeric_value=0.0,
            summary="No agility assessments recorded; assuming default rigid posture.",
            evidence_count=0,
        )

    scores = [float(ag.get("overall_score", 0.0)) for ag in agilities]
    avg_score = sum(scores) / len(scores) if scores else 0.0

    if avg_score >= 0.8:
        state = CryptoAgilityState.HIGHLY_AGILE.value
        summary = f"Highly agile cryptography (average score: {avg_score:.2f})."
    elif avg_score >= 0.6:
        state = CryptoAgilityState.AGILE.value
        summary = f"Agile cryptographic architecture (average score: {avg_score:.2f})."
    elif avg_score >= 0.4:
        state = CryptoAgilityState.PARTIALLY_AGILE.value
        summary = f"Partially agile configuration with manual points of intervention (average score: {avg_score:.2f})."
    elif avg_score >= 0.2:
        state = CryptoAgilityState.FRAGILE.value
        summary = f"Fragile agility with significant algorithm hardcoding (average score: {avg_score:.2f})."
    else:
        state = CryptoAgilityState.RIGID.value
        summary = f"Rigid cryptography tightly coupled to underlying source/binaries (average score: {avg_score:.2f})."

    return DimensionAssessment(
        dimension=PostureDimension.CRYPTO_AGILITY,
        state=state,
        numeric_value=round(avg_score, 2),
        summary=summary,
        evidence_count=len(agilities),
        details={"average_score": round(avg_score, 3), "evaluated_count": len(agilities)},
    )


def classify_blast_radius_posture(blast_radii: List[Dict[str, Any]]) -> DimensionAssessment:
    if not blast_radii:
        return DimensionAssessment(
            dimension=PostureDimension.BLAST_RADIUS,
            state=BlastRadiusState.MINIMAL.value,
            numeric_value=0.0,
            summary="Zero blast-radius dependencies identified.",
            evidence_count=0,
        )

    deps = [int(b.get("transitive_dependents_count", b.get("blast_radius_score", 0))) for b in blast_radii]
    max_deps = max(deps) if deps else 0

    if max_deps > 20:
        state = BlastRadiusState.UNBOUNDED.value
        summary = f"Unbounded dependency fan-out (max {max_deps} affected downstream components)."
    elif max_deps > 10:
        state = BlastRadiusState.BROAD.value
        summary = f"Broad blast radius across multiple microservices/modules (max {max_deps} dependents)."
    elif max_deps > 3:
        state = BlastRadiusState.CONTAINED.value
        summary = f"Contained blast radius within application boundary (max {max_deps} dependents)."
    elif max_deps > 0:
        state = BlastRadiusState.ISOLATED.value
        summary = f"Isolated blast radius with minimal direct dependents (max {max_deps})."
    else:
        state = BlastRadiusState.MINIMAL.value
        summary = "Minimal/isolated blast radius."

    return DimensionAssessment(
        dimension=PostureDimension.BLAST_RADIUS,
        state=state,
        numeric_value=float(max_deps),
        summary=summary,
        evidence_count=len(blast_radii),
        details={"max_dependents": max_deps},
    )


def classify_migration_status_posture(verifications: List[Dict[str, Any]], plans: List[Dict[str, Any]]) -> DimensionAssessment:
    states = [str(v.get("verification_state", "")).upper() for v in verifications]

    if "VERIFIED" in states or "MIGRATION_SUCCESSFUL" in states:
        state = MigrationStatusState.VERIFIED.value
        summary = f"Migration verified on {states.count('VERIFIED') + states.count('MIGRATION_SUCCESSFUL')} component(s)."
    elif "FAILED" in states:
        state = MigrationStatusState.BLOCKED.value
        summary = f"Migration blocked or failed verification on {states.count('FAILED')} component(s)."
    elif "IN_PROGRESS" in states or "PARTIAL" in states:
        state = MigrationStatusState.IN_PROGRESS.value
        summary = "PQC migration active and in-progress."
    elif plans:
        state = MigrationStatusState.PLANNED.value
        summary = f"{len(plans)} migration plan(s) formulated."
    else:
        state = MigrationStatusState.NOT_STARTED.value
        summary = "No formal PQC migration planning initiated."

    return DimensionAssessment(
        dimension=PostureDimension.MIGRATION_STATUS,
        state=state,
        numeric_value=1.0 if state == MigrationStatusState.VERIFIED.value else 0.0,
        summary=summary,
        evidence_count=len(verifications) + len(plans),
        details={"verification_states": states, "plan_count": len(plans)},
    )


def classify_evidence_quality_posture(assets: List[Dict[str, Any]], evidence_items: List[Any]) -> DimensionAssessment:
    if not evidence_items and not assets:
        return DimensionAssessment(
            dimension=PostureDimension.EVIDENCE_QUALITY,
            state=EvidenceQualityState.SPECULATIVE.value,
            numeric_value=0.0,
            summary="No evidence items available.",
            evidence_count=0,
        )

    fused_statuses = [str(a.get("fused_status", "")).upper() for a in assets]
    levels = [str(getattr(e, "level", "") or getattr(e, "evidence_level", "") or "").upper() for e in evidence_items]

    if "CORROBORATED" in fused_statuses:
        state = EvidenceQualityState.CORROBORATED.value
        summary = "Multi-modal evidence corroborated across independent observation modalities."
    elif any(l in ("E5", "E4", "EVIDENCELEVEL.E5", "EVIDENCELEVEL.E4") for l in levels):
        state = EvidenceQualityState.VERIFIED_RUNTIME.value
        summary = "High-fidelity runtime observation (E4/E5) verified."
    elif any(l in ("E3", "E2", "EVIDENCELEVEL.E3", "EVIDENCELEVEL.E2") for l in levels):
        state = EvidenceQualityState.VERIFIED_STATIC.value
        summary = "Static analysis & symbol evidence (E2/E3) verified."
    elif any(l in ("E1", "EVIDENCELEVEL.E1") for l in levels):
        state = EvidenceQualityState.HEURISTIC.value
        summary = "Heuristic rule matching (E1) detected."
    else:
        state = EvidenceQualityState.SPECULATIVE.value
        summary = "Speculative evidence baseline."

    return DimensionAssessment(
        dimension=PostureDimension.EVIDENCE_QUALITY,
        state=state,
        numeric_value=1.0 if state == EvidenceQualityState.CORROBORATED.value else 0.5,
        summary=summary,
        evidence_count=len(evidence_items),
        details={"fused_statuses": fused_statuses},
    )


def evaluate_posture(
    project: str,
    scan_id: str,
    assets: List[Dict[str, Any]],
    risks: Optional[List[Dict[str, Any]]] = None,
    pqc_readiness: Optional[List[Dict[str, Any]]] = None,
    agilities: Optional[List[Dict[str, Any]]] = None,
    blast_radii: Optional[List[Dict[str, Any]]] = None,
    verifications: Optional[List[Dict[str, Any]]] = None,
    plans: Optional[List[Dict[str, Any]]] = None,
    evidence_items: Optional[List[Any]] = None,
    asset_id: Optional[str] = None,
) -> PostureAssessment:
    """
    Synthesizes the complete 7-dimension posture profile without calculating
    any artificial aggregate scalar score.
    """
    dims: Dict[str, DimensionAssessment] = {
        PostureDimension.CRYPTO_INVENTORY.value: classify_inventory_posture(assets),
        PostureDimension.QUANTUM_RISK.value: classify_quantum_risk_posture(risks or []),
        PostureDimension.PQC_READINESS.value: classify_pqc_readiness_posture(pqc_readiness or [], assets),
        PostureDimension.CRYPTO_AGILITY.value: classify_crypto_agility_posture(agilities or []),
        PostureDimension.BLAST_RADIUS.value: classify_blast_radius_posture(blast_radii or []),
        PostureDimension.MIGRATION_STATUS.value: classify_migration_status_posture(verifications or [], plans or []),
        PostureDimension.EVIDENCE_QUALITY.value: classify_evidence_quality_posture(assets, evidence_items or []),
    }

    summary_text = (
        f"Posture for scan {scan_id} (project: {project}): "
        f"Inventory={dims[PostureDimension.CRYPTO_INVENTORY.value].state}, "
        f"Risk={dims[PostureDimension.QUANTUM_RISK.value].state}, "
        f"PQC={dims[PostureDimension.PQC_READINESS.value].state}, "
        f"Agility={dims[PostureDimension.CRYPTO_AGILITY.value].state}, "
        f"BlastRadius={dims[PostureDimension.BLAST_RADIUS.value].state}, "
        f"Migration={dims[PostureDimension.MIGRATION_STATUS.value].state}, "
        f"Evidence={dims[PostureDimension.EVIDENCE_QUALITY.value].state}."
    )

    assessment = PostureAssessment(
        assessment_id=f"posture-{uuid.uuid4().hex[:12]}",
        project_id=project,
        scan_id=scan_id,
        asset_id=asset_id,
        dimensions=dims,
        summary=summary_text,
    )
    assessment.posture_hash = assessment.compute_hash()
    return assessment
