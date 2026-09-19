"""
ECDAT V4 Agility Dimension 6: Deployment Agility (AGILITY_DEPLOYMENT).

Evaluates whether cryptographic changes can be rolled out via dynamic config reload,
container restart, or require full binary recompilation or firmware flashing.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from ..evidence import (
    AgilityEvidenceItem,
    extract_confidence,
    is_dimension_scanner_unavailable,
)
from ..models import (
    AgilityConfidence,
    AgilityDimension,
    AgilityReason,
    AgilityState,
    DimensionalAgility,
)


def assess_deployment_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_DEPLOYMENT

    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Deployment analyzer was unavailable."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_dynamic_reload = False
    has_container = False
    has_deployment_manifest = False
    has_recompile_required = False
    has_firmware_barrier = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        if item.has_text("dynamic_reload", "hot_reload", "zero_downtime_config"):
            has_dynamic_reload = True
            supporting.append(f"Zero-downtime dynamic reload verified: {item.description}")

        if item.has_text("container_image", "dockerfile", "k8s_manifest", "helm_chart"):
            has_container = True
            has_deployment_manifest = True
            supporting.append(f"Containerized / orchestrated deployment supported: {item.description}")

        if item.has_text("static_binary", "recompile_required", "no_external_config"):
            has_recompile_required = True
            contradicting.append(f"Recompilation required to update cryptographic primitives: {item.description}")

        if item.has_text("firmware_flash_barrier", "immutable_rom", "burned_in_silicon"):
            has_firmware_barrier = True
            contradicting.append(f"Immutable firmware/hardware barrier detected: {item.description}")

    # Explicit context flags
    if context.get("has_container"):
        has_container = True
        supporting.append("Context confirms containerized deployment.")
    if context.get("is_firmware"):
        # AXIOM: Firmware alone does NOT automatically prove BLOCKED unless reload barrier evidenced
        if not has_firmware_barrier:
            unknowns.append("Asset is firmware; flashing mechanism and anti-rollback policies unverified.")

    confidence = extract_confidence(evidence_items)

    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Deployment environment or CI/CD manifests were not available for inspection."],
            limitations=["Deployment agility unobserved."],
            derived_score=None,
        )

    # Determine State
    if has_firmware_barrier:
        state = AgilityState.BLOCKED
        score = 0.0
        claim = "Cryptographic logic is burned into hardware ROM or immutable firmware with no update path."
    elif has_dynamic_reload:
        state = AgilityState.OBSERVED
        score = 1.0
        claim = "Dynamic zero-downtime configuration reload actively observed in deployment environment."
    elif has_container or has_deployment_manifest:
        # AXIOM: Containerization alone != high agility; service restart is required
        state = AgilityState.SUPPORTED
        score = 0.80
        claim = "Containerized / orchestrated service enables rolling redeployment of updated configurations."
        limitations.append("Service restart or container roll required to apply cryptographic changes.")
    elif has_recompile_required:
        state = AgilityState.CONSTRAINED
        score = 0.25
        claim = "Changing cryptography requires full source build and binary deployment cycle."
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Deployment mechanisms could not be evaluated from available evidence."
        unknowns.append("No deployment manifests or runtime reload signals detected.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="DEPLOYMENT_AGILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-DPL-001" if state == AgilityState.OBSERVED else ("AGL-DPL-002" if state == AgilityState.SUPPORTED else ("AGL-DPL-003" if state == AgilityState.CONSTRAINED else ("AGL-DPL-004" if state == AgilityState.BLOCKED else None))),
            rule_version="1.0",
            evidence_refs=evidence_refs,
            supporting=supporting,
            contradicting=contradicting,
            unknowns=unknowns,
            limitations=limitations,
        )
    )

    return DimensionalAgility(
        dimension=dimension,
        state=state,
        confidence=confidence,
        evidence_refs=evidence_refs,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        unknowns=unknowns,
        limitations=limitations,
        reason_chain=reasons,
        derived_score=score,
    )
