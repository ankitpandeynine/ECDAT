"""
ECDAT V4 Agility Dimension 1: Algorithm Replaceability (AGILITY_ALGORITHM).

Evaluates whether cryptographic algorithms are invoked via provider abstractions,
factories, registries, or hardcoded directly into call sites.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
from ..evidence import (
    AgilityEvidenceItem,
    extract_confidence,
    is_dimension_scanner_unavailable,
    SIGNAL_ABSTRACTION,
    SIGNAL_FACTORY,
    SIGNAL_REGISTRY,
    SIGNAL_PROVIDER,
    SIGNAL_HARDCODED_ALGORITHM,
    SIGNAL_DIRECT_BINDING,
)
from ..models import (
    AgilityConfidence,
    AgilityDimension,
    AgilityReason,
    AgilityState,
    DimensionalAgility,
)


def assess_algorithm_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_ALGORITHM

    # Check for scanner unavailability
    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Static or dynamic algorithm analyzer could not complete evaluation."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    # Check for applicability
    asset_type = str(asset.get("asset_type", "")).upper()
    if asset_type in ("CONFIGURATION", "FILESYSTEM") and not evidence_items:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.NOT_APPLICABLE,
            confidence=AgilityConfidence.UNKNOWN,
            limitations=["Algorithm agility is not applicable to non-cryptographic passive containers."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_abstraction = False
    has_hardcoded = False
    has_blocked = False
    is_runtime_observed = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        # Abstraction indicators
        if item.has_text(
            "provider_abstraction", "crypto_abstraction", "algorithm_registry",
            "crypto_factory", "evp_", "cipher.getinstance", "subtlecrypto",
            "strategy", "jce_provider", "openssl_provider"
        ):
            has_abstraction = True
            supporting.append(f"Provider or factory abstraction detected: {item.description}")
            if item.state in ("MEASURED", "CORROBORATED") or item.level in ("E3", "E4", "E5"):
                is_runtime_observed = True

        # Hardcoded call sites
        if item.has_text(
            "hardcoded_algorithm", "direct_library_binding", "direct_primitive",
            "aes_encrypt", "des_encrypt", "md5_init", "sha1_init", "direct_call"
        ):
            has_hardcoded = True
            contradicting.append(f"Direct/hardcoded primitive call detected: {item.description}")

        # Blocked indicators (stripped binary / proprietary blob)
        if item.has_text("binary_no_symbols", "proprietary_binary_blob", "immutable_rom"):
            has_blocked = True
            contradicting.append(f"Immutable binary lock: {item.description}")

    # Explicit context flags
    if context.get("has_provider_abstraction"):
        has_abstraction = True
        supporting.append("Context declares verified provider abstraction architecture.")
    if context.get("hardcoded_primitives_count", 0) > 0:
        has_hardcoded = True
        contradicting.append(f"Context reports {context['hardcoded_primitives_count']} hardcoded primitives.")

    confidence = extract_confidence(evidence_items)

    # Invariant: If no evidence or context exists -> UNKNOWN
    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["No architectural or source code evidence observed for algorithm invocation."],
            limitations=["Algorithm invocation paths could not be evaluated."],
            derived_score=None,
        )

    # Determine State
    if has_blocked:
        state = AgilityState.BLOCKED
        score = 0.0
        claim = "Algorithm is locked inside an immutable binary or ROM without replacement interface."
    elif has_abstraction and has_hardcoded:
        state = AgilityState.PARTIALLY_OBSERVED
        score = 0.50
        claim = "Mixed algorithm invocation: some call sites use provider abstraction while others are directly hardcoded."
        limitations.append("Provider abstraction exists but hardcoded call sites impede uniform replacement.")
    elif has_abstraction:
        limitations.append("Provider abstraction does not guarantee that target replacement algorithm is installed or supported.")
        if is_runtime_observed:
            state = AgilityState.OBSERVED
            score = 1.0
            claim = "Dynamic algorithm selection via provider abstraction actively verified at runtime."
        else:
            state = AgilityState.SUPPORTED
            score = 0.80
            claim = "Provider or factory abstraction interface supported, permitting pluggable algorithm substitution."
            unknowns.append("Runtime parameterization of alternative algorithms was not directly observed.")

    elif has_hardcoded:
        # AXIOM: Direct API call is CONSTRAINED, NOT BLOCKED
        state = AgilityState.CONSTRAINED
        score = 0.25
        claim = "Algorithms are hardcoded into direct API calls; replacement requires source-level refactoring."
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Insufficient evidence to determine algorithm replaceability."
        unknowns.append("No concrete evidence of either abstraction or hardcoded calls found.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="ALGORITHM_REPLACEABILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-ALG-001" if state == AgilityState.OBSERVED else ("AGL-ALG-002" if state == AgilityState.SUPPORTED else ("AGL-ALG-003" if state == AgilityState.PARTIALLY_OBSERVED else ("AGL-ALG-004" if state == AgilityState.CONSTRAINED else ("AGL-ALG-005" if state == AgilityState.BLOCKED else None)))),
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
