"""
ECDAT V4 Agility Dimension 4: Protocol Agility (AGILITY_PROTOCOL).

Evaluates whether network protocols (TLS, SSH, QUIC) dynamically negotiate
ciphers/KEX and allow runtime configuration of cipher suites and groups.
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


def assess_protocol_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_PROTOCOL

    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Network/protocol analyzer was unavailable."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    asset_type = str(asset.get("asset_type", "")).upper()
    protocol_types = ("PROTOCOL", "ENDPOINT", "SERVICE", "NETWORK_ENDPOINT")
    has_protocol_evidence = any(
        e.has_text("tls_", "ssh_", "quic_", "cipher_suite", "kex", "handshake", "protocol")
        for e in evidence_items
    )

    # If non-network asset and zero protocol evidence -> NOT_APPLICABLE
    if asset_type not in protocol_types and not has_protocol_evidence and not context.get("has_protocol"):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.NOT_APPLICABLE,
            confidence=AgilityConfidence.UNKNOWN,
            limitations=["Protocol agility is not applicable to non-network cryptographic assets."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_negotiation = False
    has_config = False
    has_hardcoded_protocol = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        if item.has_text("tls_negotiation", "ssh_negotiation", "quic_negotiation", "runtime_cipher_selection"):
            has_negotiation = True
            supporting.append(f"Live dynamic protocol negotiation observed: {item.description}")

        if item.has_text("protocol_configuration", "tls_configuration", "ciphersuite_config", "kex_config"):
            has_config = True
            supporting.append(f"Protocol configuration support detected: {item.description}")

        if item.has_text("hardcoded_protocol", "hardcoded_cipher_list", "fixed_cipher_suite", "hardcoded_ssl_version"):
            has_hardcoded_protocol = True
            contradicting.append(f"Hardcoded protocol or cipher list detected: {item.description}")

    confidence = extract_confidence(evidence_items)

    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Protocol endpoints were not probed or configuration was unobserved."],
            limitations=["Dynamic protocol negotiation could not be measured."],
            derived_score=None,
        )

    # Determine State
    if has_negotiation:
        state = AgilityState.OBSERVED
        score = 1.0
        claim = "Dynamic protocol negotiation actively verified over the network."
    elif has_config and has_hardcoded_protocol:
        state = AgilityState.PARTIALLY_OBSERVED
        score = 0.50
        claim = "Protocol has configuration options, but fixed cipher suites or protocol versions restrict runtime agility."
    elif has_config:
        state = AgilityState.SUPPORTED
        score = 0.80
        claim = "Protocol cipher suites and versions are externally configurable without code changes."
        unknowns.append("Live multi-cipher negotiation was not directly observed in the probe.")
    elif has_hardcoded_protocol:
        state = AgilityState.CONSTRAINED
        score = 0.25
        claim = "Protocol parameters or cipher suites are hardcoded in application code."
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Protocol agility could not be determined from available evidence."
        unknowns.append("No active protocol probe or configuration evidence recorded.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="PROTOCOL_AGILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-PRT-001" if state == AgilityState.OBSERVED else ("AGL-PRT-002" if state == AgilityState.SUPPORTED else ("AGL-PRT-003" if state == AgilityState.CONSTRAINED else None)),
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
