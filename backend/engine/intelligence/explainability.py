"""
ECDAT V4 P2.1 Risk Explainability.

Produces structured reason chains from RiskAssessment.
Every WHY response is machine-readable first, human-readable second.

No sensitive raw material copied into explanations.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import AssessmentReason, EvidenceReference, RiskAssessment, RuleReference


def build_reason_chain(
    assessment: RiskAssessment,
    evidence_items: Optional[List[Dict[str, Any]]] = None,
) -> List[AssessmentReason]:
    """
    Build structured reason chain for an assessment.
    Returns one AssessmentReason per triggered risk factor.
    """
    reasons: List[AssessmentReason] = []
    evidence_items = evidence_items or []

    # Map evidence IDs to evidence items for fast lookup
    ev_by_id = {ev.get("id", ""): ev for ev in evidence_items if ev.get("id")}

    for factor, rule_ref in zip(assessment.risk_factors, assessment.rule_refs):
        # Find the best matching evidence reference for this factor
        ev_ref: Optional[EvidenceReference] = None
        if assessment.evidence_refs:
            ev_ref = assessment.evidence_refs[0]  # Use highest-quality evidence

        observation = _factor_to_observation(factor.value, assessment, evidence_items)
        interpretation = _factor_to_interpretation(factor.value)

        reason = AssessmentReason(
            observation=observation,
            evidence_ref=ev_ref,
            rule_ref=rule_ref,
            interpretation=interpretation,
            result=factor.value,
        )
        reasons.append(reason)

    # Unknowns also generate reason entries
    for unknown in assessment.unknowns:
        reason = AssessmentReason(
            observation=f"Unknown: {unknown.field}",
            evidence_ref=None,
            rule_ref=None,
            interpretation=unknown.reason,
            result="UNKNOWN",
        )
        reasons.append(reason)

    return reasons


def format_risk_explanation(assessment: RiskAssessment) -> Dict[str, Any]:
    """
    Produce a machine-readable WHY response for an assessment.
    """
    return {
        "asset_id": assessment.asset_id,
        "severity": assessment.severity.value,
        "confidence": assessment.confidence.value,
        "risk_factors": [f.value for f in assessment.risk_factors],
        "reason_chain": [
            {
                "observation": r.observation,
                "evidence_ref": vars(r.evidence_ref) if r.evidence_ref else None,
                "rule_ref": vars(r.rule_ref) if r.rule_ref else None,
                "interpretation": r.interpretation,
                "result": r.result,
            }
            for r in assessment.reason_chain
        ],
        "unknowns": [vars(u) for u in assessment.unknowns],
        "limitations": assessment.limitations,
        "knowledge_base_version": assessment.knowledge_base_version,
        "pqc_readiness": (
            {
                "key_establishment": assessment.pqc_readiness.key_establishment.value,
                "signature": assessment.pqc_readiness.signature.value,
                "certificate": assessment.pqc_readiness.certificate.value,
                "overall": assessment.pqc_readiness.overall,
            }
            if assessment.pqc_readiness else None
        ),
        "hndl": (
            {
                "state": assessment.hndl.state.value,
                "unknowns": assessment.hndl.unknowns,
                "reason": assessment.hndl.reason,
            }
            if assessment.hndl else None
        ),
    }


def _factor_to_observation(factor_value: str, assessment: RiskAssessment, evidence_items: List[Dict[str, Any]]) -> str:
    """Human-readable observation for a risk factor."""
    asset_id = assessment.asset_id
    ev_desc = ""
    if evidence_items:
        ev_desc = evidence_items[0].get("description", "")

    observations = {
        "QUANTUM_VULNERABLE_KEX":       f"Quantum-vulnerable key establishment observed on {asset_id}. {ev_desc}",
        "QUANTUM_VULNERABLE_SIGNATURE": f"Quantum-vulnerable digital signature observed on {asset_id}. {ev_desc}",
        "QUANTUM_VULNERABLE_ENCRYPTION":f"Quantum-vulnerable public-key encryption observed on {asset_id}. {ev_desc}",
        "QUANTUM_WEAKENED_SYMMETRIC":   f"Symmetric key weaker than 256 bits observed on {asset_id}.",
        "DEPRECATED_ALGORITHM":         f"Deprecated/prohibited algorithm observed on {asset_id}. {ev_desc}",
        "WEAK_ALGORITHM":               f"Cryptographically broken algorithm observed on {asset_id}. {ev_desc}",
        "LEGACY_PROTOCOL":              f"Legacy TLS/protocol version observed on {asset_id}.",
        "EXPIRED_CERTIFICATE":          f"Certificate has expired on {asset_id}.",
        "UNVERIFIED_CERTIFICATE_TRUST": f"Certificate trust validation failed on {asset_id}.",
        "HNDL_EXPOSURE":                f"HNDL exposure: quantum-vulnerable KEX on reachable endpoint {asset_id}.",
        "PQC_NOT_NEGOTIATED":           f"PQC not negotiated for key establishment on {asset_id}.",
        "PQC_PARTIAL_READINESS":        f"Partial PQC readiness: hybrid KEX but classical signatures on {asset_id}.",
        "UNKNOWN_PARAMETERS":           f"Algorithm parameters (key size) unknown for {asset_id}.",
        "SCANNER_UNAVAILABLE":          f"Scanner unavailable for {asset_id}. Cannot observe cryptographic behavior.",
    }
    return observations.get(factor_value, f"{factor_value} observed on {asset_id}.")


def _factor_to_interpretation(factor_value: str) -> str:
    """Research interpretation for a risk factor."""
    interps = {
        "QUANTUM_VULNERABLE_KEX": (
            "Classical key-establishment algorithms (RSA, DH, ECDH, X25519) are vulnerable to "
            "Shor's algorithm on a sufficiently capable quantum computer. Session keys established "
            "using these algorithms can be retrospectively decrypted."
        ),
        "QUANTUM_VULNERABLE_SIGNATURE": (
            "Classical digital signature algorithms (RSA, ECDSA, EdDSA) are vulnerable to "
            "Shor's algorithm. An adversary with a quantum computer can forge signatures."
        ),
        "QUANTUM_VULNERABLE_ENCRYPTION": (
            "Classical public-key encryption (RSA-OAEP etc.) is vulnerable to Shor's algorithm."
        ),
        "QUANTUM_WEAKENED_SYMMETRIC": (
            "Grover's algorithm provides a quadratic speedup against symmetric ciphers, "
            "effectively halving the key length. AES-128 provides ~64-bit post-quantum security. "
            "AES-256 is recommended."
        ),
        "DEPRECATED_ALGORITHM": (
            "This algorithm is deprecated or prohibited by NIST SP 800-131A Rev 2 or equivalent. "
            "Continued use increases compliance and security risk."
        ),
        "WEAK_ALGORITHM": (
            "This algorithm is cryptographically broken by known classical attacks "
            "(e.g., MD5 collision, DES brute-force, RC4 plaintext recovery)."
        ),
        "LEGACY_PROTOCOL": (
            "TLS 1.0 and TLS 1.1 are deprecated by RFC 8996. Supporting them enables "
            "downgrade attacks and exposes negotiated sessions to known protocol weaknesses."
        ),
        "EXPIRED_CERTIFICATE": (
            "An expired certificate cannot be used to establish authenticated identity. "
            "Clients may reject connections or bypass certificate validation."
        ),
        "UNVERIFIED_CERTIFICATE_TRUST": (
            "Certificate trust validation failed. The chain of trust to a trusted CA could not "
            "be verified. This does not automatically mean the cert is malicious, "
            "but authentication cannot be assured."
        ),
        "HNDL_EXPOSURE": (
            "Harvest-Now-Decrypt-Later: an adversary can record encrypted traffic today "
            "and decrypt it retroactively when a cryptanalytically relevant quantum computer "
            "becomes available. Confidential data with long retention periods is at risk."
        ),
        "PQC_NOT_NEGOTIATED": (
            "Post-quantum key establishment was not observed at the network level. "
            "If sensitive data is transmitted, HNDL risk exists."
        ),
        "PQC_PARTIAL_READINESS": (
            "Hybrid key exchange provides post-quantum protection for session key establishment, "
            "but certificate authentication still uses classical signatures (ECDSA, RSA). "
            "Full PQC readiness requires both KEX and signature migration."
        ),
        "UNKNOWN_PARAMETERS": (
            "Key size or algorithm parameters are unknown from available evidence. "
            "Security strength cannot be assessed without parameters. "
            "Do NOT assume a default key size."
        ),
        "SCANNER_UNAVAILABLE": (
            "The scanner was unavailable during assessment. "
            "This is NOT evidence that the algorithm is unsupported or absent. "
            "Risk assessment for this asset is incomplete."
        ),
    }
    return interps.get(factor_value, f"Risk factor {factor_value} was triggered.")
