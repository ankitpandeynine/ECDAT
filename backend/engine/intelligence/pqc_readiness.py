"""
ECDAT V4 P2.1 PQC Readiness Assessor.

Role-aware post-quantum readiness evaluation.

AXIOMS enforced:
- HYBRID_KEX != PQ_SIGNATURE
- ML-KEM != ML-DSA
- CAPABLE != NEGOTIATED
- ADVERTISED != NEGOTIATED
- SUPPORTED != NEGOTIATED
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .algorithm_registry import (
    normalize_algorithm, is_pqc_kem, is_pqc_signature, is_hybrid_kem,
    get_quantum_impact,
)
from .models import PQCReadinessAssessment, PQCReadinessState, QuantumImpact


_NEGOTIATED_OBSERVATION_TYPES = {
    "TLS_NEGOTIATION", "PQC_NEGOTIATION", "SSH_NEGOTIATION",
}
_ADVERTISED_OBSERVATION_TYPES = {
    "SSH_CAPABILITY", "HTTP_HEADER", "PROTOCOL_OBSERVATION",
}
_CONFIGURED_OBSERVATION_TYPES = {
    "TLS_CONFIGURATION", "CONFIGURATION",
}
_DEPENDENCY_TYPES = {
    "DEPENDENCY_DECLARATION", "DEPENDENCY_LOCKFILE",
}
_SOURCE_TYPES = {
    "SOURCE_API_USE", "SOURCE_IMPORT", "SOURCE_PATTERN", "SOURCE_DATAFLOW",
}


def assess_pqc_readiness(
    asset: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    scanner_unavailable: bool = False,
) -> PQCReadinessAssessment:
    """
    Produce role-aware PQC readiness assessment.

    Separate roles:
    - key_establishment
    - signature
    - certificate
    - protocol
    - library
    - application

    Never promotes CAPABLE -> NEGOTIATED without appropriate evidence.
    Hybrid KEX -> HYBRID_NEGOTIATED for KEY_ESTABLISHMENT ONLY.
    """
    assessment = PQCReadinessAssessment(
        asset_id=asset.get("id", ""),
        scan_id=asset.get("scan_id"),
    )

    if scanner_unavailable:
        assessment.key_establishment = PQCReadinessState.SCANNER_UNAVAILABLE
        assessment.signature = PQCReadinessState.SCANNER_UNAVAILABLE
        assessment.certificate = PQCReadinessState.SCANNER_UNAVAILABLE
        assessment.protocol = PQCReadinessState.SCANNER_UNAVAILABLE
        assessment.overall = "SCANNER_UNAVAILABLE"
        assessment.limitations.append(
            "Scanner unavailable. PQC readiness cannot be assessed. "
            "This is NOT evidence that the endpoint lacks PQC support."
        )
        return assessment

    algo_name = asset.get("algorithm") or asset.get("name") or ""
    entry = normalize_algorithm(algo_name)

    # --- Key establishment readiness ---
    kex_state = _assess_kex_readiness(algo_name, entry, evidence_items)
    assessment.key_establishment = kex_state

    # --- Signature readiness ---
    # AXIOM: Hybrid KEX does NOT affect signature readiness.
    sig_state = _assess_signature_readiness(algo_name, entry, evidence_items)
    assessment.signature = sig_state

    # --- Certificate readiness ---
    cert_state = _assess_certificate_readiness(evidence_items)
    assessment.certificate = cert_state

    # --- Library readiness (dependency/source evidence) ---
    lib_state = _assess_library_readiness(asset, evidence_items)
    assessment.library = lib_state

    # --- Protocol readiness ---
    proto_state = _assess_protocol_readiness(evidence_items)
    assessment.protocol = proto_state

    # --- Aggregate overall ---
    assessment.overall = _aggregate_readiness(
        kex_state, sig_state, cert_state, proto_state, lib_state
    )

    assessment.limitations.append(
        "PQC readiness is assessed per role independently. "
        "Hybrid key exchange does NOT imply PQC signature readiness."
    )
    return assessment


def _assess_kex_readiness(
    algo_name: str,
    entry: Any,
    evidence_items: List[Dict[str, Any]],
) -> PQCReadinessState:
    """Assess key establishment PQC readiness from evidence."""
    # Check for advertised / offered states
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        state = str(ev.get("state", "")).upper()
        if obs_type in ("SSH_KEXINIT", "SSH_CAPABILITY") or state == "ADVERTISED":
            return PQCReadinessState.PQC_ADVERTISED
        if obs_type in ("TLS_CLIENT_HELLO",) or state == "OFFERED":
            return PQCReadinessState.PQC_OFFERED

    # Check for negotiated hybrid/PQC KEX in network evidence
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        state = str(ev.get("state", "")).upper()
        if (obs_type not in _NEGOTIATED_OBSERVATION_TYPES and
                state != "NEGOTIATED" and
                obs_type != "TLS_KEY_EXCHANGE"):
            continue
        raw = ev.get("raw_details") or ev.get("metadata") or {}
        kex = (raw.get("named_group") or raw.get("kex_algorithm") or raw.get("cipher") or
               ev.get("description") or ev.get("symbol") or "")
        kex_str = str(kex)
        if is_hybrid_kem(kex_str):
            return PQCReadinessState.HYBRID_NEGOTIATED
        if is_pqc_kem(kex_str):
            return PQCReadinessState.PQC_NEGOTIATED
        if kex_str and _is_quantum_vulnerable_kex(kex_str):
            return PQCReadinessState.CLASSICAL_ONLY

    # Check asset algorithm itself (for non-network assets)
    if algo_name:
        if is_hybrid_kem(algo_name):
            return PQCReadinessState.HYBRID_NEGOTIATED
        if is_pqc_kem(algo_name):
            return PQCReadinessState.PQC_NEGOTIATED

    # Check for PQC_NEGOTIATION observation type with algo in metadata
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        if obs_type == "PQC_NEGOTIATION":
            return PQCReadinessState.HYBRID_NEGOTIATED

    # Check dependency/source evidence for PQC_CAPABLE
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        if obs_type in _DEPENDENCY_TYPES or obs_type in _SOURCE_TYPES:
            desc = str(ev.get("description", "")).upper()
            sym = str(ev.get("symbol", "")).upper()
            combined = desc + " " + sym
            if any(k in combined for k in ("ML-KEM", "MLKEM", "KYBER", "LIBOQS", "OPENSSL 3.5")):
                return PQCReadinessState.PQC_CAPABLE

    # Check config
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        if obs_type in _CONFIGURED_OBSERVATION_TYPES:
            raw = ev.get("raw_details") or ev.get("metadata") or {}
            desc = str(ev.get("description", "")).upper()
            if any(k in desc for k in ("ML-KEM", "MLKEM", "X25519MLKEM")):
                return PQCReadinessState.PQC_CONFIGURED

    # Default: if network evidence present but no PQC found -> classical only
    has_network_evidence = any(
        str(ev.get("observation_type", "")).upper() in _NEGOTIATED_OBSERVATION_TYPES
        for ev in evidence_items
    )
    if has_network_evidence:
        return PQCReadinessState.CLASSICAL_ONLY

    if entry and entry.quantum_impact == QuantumImpact.SHOR_BREAKS:
        return PQCReadinessState.CLASSICAL_ONLY

    return PQCReadinessState.NOT_ASSESSED


def _assess_signature_readiness(
    algo_name: str,
    entry: Any,
    evidence_items: List[Dict[str, Any]],
) -> PQCReadinessState:
    """
    Assess signature PQC readiness.
    AXIOM: Hybrid KEX evidence does NOT affect signature readiness.
    """
    # Explicit PQC signature in algorithm
    if algo_name and is_pqc_signature(algo_name):
        return PQCReadinessState.PQC_NEGOTIATED

    # Check certificate evidence for PQC signature algorithm
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        if obs_type in ("X509_CERTIFICATE",):
            raw = ev.get("raw_details") or ev.get("metadata") or {}
            sig_algo = str(raw.get("signature_algorithm") or raw.get("public_key") or "").upper()
            if any(k in sig_algo for k in ("ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA")):
                return PQCReadinessState.PQC_NEGOTIATED
            if sig_algo and any(k in sig_algo for k in ("RSA", "ECDSA", "ED25519", "EC")):
                return PQCReadinessState.CLASSICAL_ONLY

    # Check entry roles
    if entry:
        if entry.category == "PQC_SIGNATURE":
            return PQCReadinessState.PQC_CAPABLE
        if entry.quantum_impact == QuantumImpact.SHOR_BREAKS and "SIGNATURE" in [r.value for r in entry.roles]:
            return PQCReadinessState.CLASSICAL_ONLY

    # Has network evidence? -> signature not explicitly upgraded
    has_tls_evidence = any(
        str(ev.get("observation_type", "")).upper() in {"TLS_NEGOTIATION", "X509_CERTIFICATE"}
        for ev in evidence_items
    )
    if has_tls_evidence:
        return PQCReadinessState.CLASSICAL_ONLY

    return PQCReadinessState.NOT_ASSESSED


def _assess_certificate_readiness(evidence_items: List[Dict[str, Any]]) -> PQCReadinessState:
    """Certificate PQC readiness from X509 evidence."""
    for ev in evidence_items:
        if str(ev.get("observation_type", "")).upper() == "X509_CERTIFICATE":
            raw = ev.get("raw_details") or ev.get("metadata") or {}
            pub_key = str(raw.get("public_key") or raw.get("public_key_algorithm") or "").upper()
            if any(k in pub_key for k in ("ML-DSA", "MLDSA", "SLH-DSA")):
                return PQCReadinessState.PQC_NEGOTIATED
            if pub_key:
                return PQCReadinessState.CLASSICAL_ONLY
    return PQCReadinessState.NOT_ASSESSED


def _assess_library_readiness(asset: Dict[str, Any], evidence_items: List[Dict[str, Any]]) -> PQCReadinessState:
    """Library PQC capability from dependency/source evidence."""
    lib_name = str(asset.get("library") or asset.get("name") or "").upper()
    if any(k in lib_name for k in ("LIBOQS", "OQS")):
        return PQCReadinessState.PQC_CAPABLE

    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        if (obs_type in _DEPENDENCY_TYPES or obs_type in _SOURCE_TYPES or
                "DEPENDENCY" in obs_type or "PACKAGE" in obs_type):
            raw = ev.get("raw_details") or ev.get("metadata") or {}
            combined = (
                str(ev.get("description", "")) + " " +
                str(ev.get("symbol", "")) + " " +
                str(raw.get("name", "")) + " " +
                str(raw.get("package", ""))
            ).upper()
            if any(k in combined for k in ("ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "LIBOQS", "OPENSSL 3.5", "OQS")):
                return PQCReadinessState.PQC_CAPABLE
    return PQCReadinessState.NOT_ASSESSED


def _assess_protocol_readiness(evidence_items: List[Dict[str, Any]]) -> PQCReadinessState:
    """SSH/QUIC protocol PQC advertisement."""
    for ev in evidence_items:
        obs_type = str(ev.get("observation_type", "")).upper()
        if obs_type == "SSH_CAPABILITY":
            raw = ev.get("raw_details") or ev.get("metadata") or {}
            kex_algos = raw.get("kex_algorithms") or []
            if any("mlkem" in str(k).lower() or "kyber" in str(k).lower() for k in kex_algos):
                return PQCReadinessState.PQC_ADVERTISED
        if obs_type == "SSH_NEGOTIATION":
            raw = ev.get("raw_details") or ev.get("metadata") or {}
            kex = str(raw.get("kex_algorithm") or "").lower()
            if "mlkem" in kex or "kyber" in kex:
                return PQCReadinessState.HYBRID_NEGOTIATED
    return PQCReadinessState.NOT_ASSESSED


def _is_quantum_vulnerable_kex(algo_str: str) -> bool:
    a = algo_str.upper()
    return any(k in a for k in ("RSA", "ECDH", "ECDHE", "DHE", "DH", "X25519", "X448"))


def _aggregate_readiness(
    kex: PQCReadinessState,
    sig: PQCReadinessState,
    cert: PQCReadinessState,
    proto: PQCReadinessState,
    lib: PQCReadinessState,
) -> str:
    states = {kex, sig, cert, proto, lib}
    not_assessed = {PQCReadinessState.NOT_ASSESSED, PQCReadinessState.UNKNOWN}

    has_pqc = any(s in (
        PQCReadinessState.PQC_CAPABLE, PQCReadinessState.PQC_CONFIGURED,
        PQCReadinessState.PQC_ADVERTISED, PQCReadinessState.PQC_OFFERED,
        PQCReadinessState.HYBRID_NEGOTIATED, PQCReadinessState.PQC_NEGOTIATED,
        PQCReadinessState.PQC_ONLY,
    ) for s in states)
    has_classical = any(s in (
        PQCReadinessState.CLASSICAL_ONLY,
    ) for s in states)
    all_not_assessed = all(s in not_assessed for s in states)
    has_scanner_unavail = PQCReadinessState.SCANNER_UNAVAILABLE in states

    if has_scanner_unavail:
        return "UNKNOWN"
    if all_not_assessed:
        return "UNKNOWN"
    if has_pqc and has_classical:
        return "PARTIAL"
    if has_pqc and not has_classical:
        # Check if all negotiated (full PQC)
        negotiated = {PQCReadinessState.PQC_NEGOTIATED, PQCReadinessState.PQC_ONLY}
        concrete = [s for s in states if s not in not_assessed]
        if all(s in negotiated for s in concrete):
            return "PQC_READY"
        if kex == PQCReadinessState.HYBRID_NEGOTIATED:
            return "HYBRID"
        return "PARTIAL"
    if has_classical and not has_pqc:
        return "CLASSICAL_ONLY"
    return "UNKNOWN"
