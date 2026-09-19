"""
ECDAT V4 Agility Dimension 5: Certificate / Key Agility (AGILITY_CERTIFICATE).

Evaluates whether certificates and private keys can be rotated automatically
or externalized via keystores vs static/embedded keys.
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


def assess_certificate_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_CERTIFICATE

    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Certificate/keystore analyzer was unavailable."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    asset_type = str(asset.get("asset_type", "")).upper()
    cert_types = ("CERTIFICATE", "KEY", "ENDPOINT", "SERVICE", "APPLICATION")
    has_cert_evidence = any(
        e.has_text("certificate", "x509", "keystore", "private_key", "acme", "rotation", "pkcs11")
        for e in evidence_items
    )

    if asset_type not in cert_types and not has_cert_evidence and not context.get("has_certificates"):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.NOT_APPLICABLE,
            confidence=AgilityConfidence.UNKNOWN,
            limitations=["Certificate agility is not applicable to assets without certificates or asymmetric keys."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_automated_rotation = False
    has_acme = False
    has_external_store = False
    has_static_cert = False
    has_embedded_key = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        if item.has_text("automated_rotation", "rotation_mechanism", "vault_agent", "cert_manager_renew", "certificate_rotation", "automated_certificate_rotation") or (item.has_text("rotation", "renew") and item.has_text("automated", "automatic")):
            has_automated_rotation = True
            supporting.append(f"Automated certificate rotation mechanism verified: {item.description}")


        if item.has_text("acme", "letsencrypt", "cert_manager"):
            has_acme = True
            supporting.append(f"ACME / cert-manager integration detected: {item.description}")

        if item.has_text("cert_externalization", "key_externalization", "keystore_path", "pkcs11", "cloud_kms"):
            has_external_store = True
            supporting.append(f"External keystore/certificate path supported: {item.description}")

        if item.has_text("static_cert", "x509_certificate") and not has_automated_rotation:
            has_static_cert = True

        if item.has_text("hardcoded_key", "embedded_certificate", "embedded_private_key", "hardcoded_pem"):
            has_embedded_key = True
            contradicting.append(f"Embedded private key or certificate material detected: {item.description}")

    if context.get("automated_cert_rotation"):
        has_automated_rotation = True
        supporting.append("Context declares automated certificate rotation enabled.")

    confidence = extract_confidence(evidence_items)

    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Certificate storage and rotation mechanisms were not observed."],
            limitations=["Certificate lifecycle agility unobserved."],
            derived_score=None,
        )

    # Determine State
    if has_automated_rotation:
        state = AgilityState.OBSERVED
        score = 1.0
        claim = "Automated certificate issuance and lifecycle rotation actively verified."
    elif has_embedded_key:
        state = AgilityState.CONSTRAINED
        score = 0.25
        claim = "Certificate or private key is embedded directly in source or binaries; rotation requires redeployment."
    elif has_acme or has_external_store:
        # AXIOM: ACME presence alone != successful automated rotation. Externalization != rotation.
        state = AgilityState.SUPPORTED
        score = 0.80
        claim = "External certificate management/ACME supported, permitting certificate replacement."
        unknowns.append("Automated lifecycle rotation was not directly verified in operational logs.")
    elif has_static_cert:
        state = AgilityState.PARTIALLY_OBSERVED
        score = 0.50
        claim = "Static certificate present without observed automated rotation mechanism."
        limitations.append("Manual certificate replacement required prior to expiration.")
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Certificate agility could not be determined from available evidence."
        unknowns.append("No certificate files or keystore configurations observed.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="CERTIFICATE_AGILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-CRT-001" if state == AgilityState.OBSERVED else ("AGL-CRT-002" if state == AgilityState.SUPPORTED else ("AGL-CRT-003" if state == AgilityState.PARTIALLY_OBSERVED else ("AGL-CRT-004" if state == AgilityState.CONSTRAINED else None))),
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
