"""
ECDAT V4 P2.1 HNDL Analyzer.

Harvest-Now-Decrypt-Later relevance assessment.

AXIOMS:
- HNDL applies to KEY_ESTABLISHMENT with quantum-vulnerable algorithms.
- Signatures are NOT subject to HNDL (cannot harvest-then-decrypt a signature).
- Hash functions are NOT subject to HNDL.
- Unknown data sensitivity stays UNKNOWN -- never invented.
- SCANNER_UNAVAILABLE -> HNDL_UNKNOWN, not HNDL_RELEVANT.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .algorithm_registry import normalize_algorithm
from .models import HNDLAssessment, HNDLState, QuantumImpact, CryptoRole


def assess_hndl(
    asset: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> HNDLAssessment:
    """
    Assess Harvest-Now-Decrypt-Later relevance.

    HNDL is relevant only when ALL of:
    1. Cryptographic role involves key establishment or encryption.
    2. Algorithm is quantum-vulnerable (SHOR_BREAKS).
    3. Endpoint or data is network-reachable / externally observable.

    Missing data_sensitivity or data_lifetime -> recorded as unknown, not assumed.
    """
    context = context or {}
    asset_id = asset.get("id", "")
    unknowns: List[str] = []
    limitations: List[str] = []

    scanner_unavailable = context.get("scanner_unavailable", False)
    if scanner_unavailable:
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_UNKNOWN,
            unknowns=["scanner_state"],
            reason="Scanner unavailable. HNDL relevance cannot be assessed.",
            limitations=["Scanner unavailability is not evidence of HNDL inapplicability."],
        )

    algo_name = asset.get("algorithm") or asset.get("name") or ""
    entry = normalize_algorithm(algo_name)
    if "roles" in asset and asset["roles"]:
        roles = [r.value if hasattr(r, "value") else str(r) for r in asset["roles"]]
    else:
        roles = [r.value for r in (entry.roles if entry else [])]
    q_impact = entry.quantum_impact if entry else QuantumImpact.UNKNOWN

    # Check if role is relevant to HNDL
    hndl_relevant_roles = {"KEY_ESTABLISHMENT", "PUBLIC_KEY_ENCRYPTION", "SYMMETRIC_ENCRYPTION"}
    hndl_irrelevant_roles = {"SIGNATURE", "CERTIFICATE_SIGNATURE", "HASH", "MAC"}

    if roles and all(r in hndl_irrelevant_roles for r in roles):
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_NOT_APPLICABLE,
            unknowns=[],
            reason=f"Algorithm roles ({roles}) are not subject to Harvest-Now-Decrypt-Later. "
                   "Signatures and hashes cannot be retrospectively decrypted.",
            limitations=[],
        )

    # Symmetric encryption: Grover impact, not HNDL in the same way as Shor
    if (q_impact == QuantumImpact.GROVER_HALVING and
            roles and all(r in {"SYMMETRIC_ENCRYPTION", "AEAD"} for r in roles)):
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_POSSIBLE,
            unknowns=["data_sensitivity", "data_lifetime"],
            reason="Symmetric encryption: Grover algorithm reduces effective key length. "
                   "Not the primary HNDL concern (Shor does not break symmetric). "
                   "HNDL_POSSIBLE indicates quadratic speedup risk if key size < 256 bits.",
            limitations=[
                "Data sensitivity is unknown.",
                "Data retention period is unknown.",
            ],
        )

    # PQC algorithms: not HNDL relevant
    if q_impact in (QuantumImpact.NONE_PQC_SECURE, QuantumImpact.HYBRID_PARTIAL):
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_NOT_APPLICABLE,
            unknowns=[],
            reason="Algorithm provides post-quantum key establishment security.",
            limitations=[],
        )

    # Unknown algorithm: cannot assess
    if q_impact == QuantumImpact.UNKNOWN:
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_UNKNOWN,
            unknowns=["algorithm_quantum_impact"],
            reason="Algorithm quantum impact unknown. HNDL relevance cannot be assessed.",
            limitations=["Algorithm not recognized in knowledge base."],
        )

    # At this point: SHOR_BREAKS on a KEX/encryption role
    network_reachable = context.get("network_reachable", False)
    endpoint_exposure = context.get("endpoint_exposure") or context.get("exposure") or "UNKNOWN"

    data_sensitivity = context.get("data_sensitivity") or context.get("sensitivity")
    data_lifetime = context.get("data_lifetime") or context.get("retention_years")

    if data_sensitivity is None:
        unknowns.append("data_sensitivity")
        limitations.append(
            "Data sensitivity is unknown. Do not infer sensitive data from names alone."
        )
    if data_lifetime is None:
        unknowns.append("data_lifetime")
        limitations.append("Data retention lifetime is unknown.")

    # If context is largely unknown and exposure is unestablished -> HNDL_UNKNOWN
    if (data_sensitivity is None or data_lifetime is None) and not network_reachable and endpoint_exposure == "UNKNOWN":
        unknowns.append("network_reachability")
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_UNKNOWN,
            unknowns=unknowns,
            reason="Quantum-vulnerable key establishment detected, but data sensitivity, retention lifetime, or network reachability is unknown.",
            limitations=limitations + [
                "HNDL relevance requires confirming network exposure and data sensitivity."
            ],
        )

    if network_reachable or endpoint_exposure in ("EXTERNAL", "INTERNET"):
        return HNDLAssessment(
            asset_id=asset_id,
            state=HNDLState.HNDL_RELEVANT,
            unknowns=unknowns,
            reason="Quantum-vulnerable key establishment on a network-reachable endpoint. "
                   "An adversary could record encrypted traffic today and decrypt it when "
                   "a cryptanalytically relevant quantum computer becomes available.",
            limitations=limitations,
        )

    return HNDLAssessment(
        asset_id=asset_id,
        state=HNDLState.HNDL_POSSIBLE,
        unknowns=unknowns,
        reason="Quantum-vulnerable key establishment detected. "
               "HNDL relevance requires confirming network exposure and data sensitivity.",
        limitations=limitations,
    )
