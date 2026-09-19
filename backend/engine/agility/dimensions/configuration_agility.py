"""
ECDAT V4 Agility Dimension 2: Configuration Agility (AGILITY_CONFIGURATION).

Evaluates whether cryptographic algorithms, keys, and parameters can be changed
via external configuration (environment variables, config files, secret managers)
rather than source modifications.
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


def assess_configuration_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_CONFIGURATION

    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Configuration analyzer was unavailable."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_config_option = False
    has_runtime_reload = False
    has_hardcoded_fallback = False
    has_hardcoded_constants = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        if item.has_text("env_var", "environment_variable", "config_file", "configurable_algorithm", "config_driven"):
            has_config_option = True
            supporting.append(f"External configuration interface detected: {item.description}")
            if item.state in ("MEASURED", "CORROBORATED") or item.level in ("E3", "E4", "E5"):
                if item.has_text("runtime", "reload", "dynamic", "hot_reload"):
                    has_runtime_reload = True

        if item.has_text("hardcoded_fallback", "default_fallback"):
            has_hardcoded_fallback = True
            contradicting.append(f"Hardcoded configuration fallback detected: {item.description}")

        if item.has_text("hardcoded_key", "hardcoded_iv", "hardcoded_cipher_string", "static_config"):
            has_hardcoded_constants = True
            contradicting.append(f"Hardcoded cryptographic constant observed: {item.description}")

    if context.get("uses_config_driven_crypto"):
        has_config_option = True
        supporting.append("Context confirms configuration-driven cryptography.")
    if context.get("has_runtime_reload"):
        has_runtime_reload = True
        supporting.append("Context reports active runtime configuration reload mechanism.")

    confidence = extract_confidence(evidence_items)

    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Configuration source was not scanned or no configuration evidence available."],
            limitations=["Runtime configuration behavior unobserved."],
            derived_score=None,
        )

    # Determine State
    if has_config_option and has_runtime_reload:
        state = AgilityState.OBSERVED
        score = 1.0
        claim = "Runtime dynamic configuration and hot-reloading actively observed."
    elif (has_config_option and has_hardcoded_fallback) or (has_config_option and has_hardcoded_constants):
        state = AgilityState.PARTIALLY_OBSERVED
        score = 0.50
        claim = "Configuration options exist, but hardcoded fallbacks or constants impede complete externalization."
        limitations.append("Failure to configure external values will revert to hardcoded cryptographic parameters.")
    elif has_config_option:
        # AXIOM: Config option declared without runtime reload verified -> SUPPORTED (not OBSERVED)
        state = AgilityState.SUPPORTED
        score = 0.80
        claim = "External configuration supported; parameters can be altered via config files or environment variables."
        unknowns.append("Runtime configuration override was not directly exercised during the scan.")
    elif has_hardcoded_constants:
        state = AgilityState.CONSTRAINED
        score = 0.25
        claim = "Cryptographic parameters or keys are hardcoded; parameter changes require source or binary updates."
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Configuration mechanisms could not be determined from available evidence."
        unknowns.append("No configuration files or environment variable references observed.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="CONFIGURATION_AGILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-CFG-001" if state == AgilityState.OBSERVED else ("AGL-CFG-002" if state == AgilityState.SUPPORTED else ("AGL-CFG-003" if state == AgilityState.PARTIALLY_OBSERVED else ("AGL-CFG-004" if state == AgilityState.CONSTRAINED else None))),
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
