"""
ECDAT V4 P2.1 Protocol Risk Adapter.

Adapts P1.3 TLS/SSH network observations to risk context.

AXIOMS:
- SUPPORTED != NEGOTIATED
- ADVERTISED != NEGOTIATED
- CONFIGURED != RUNTIME
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .models import RiskFactor, RiskSeverity

_KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"
_PROTOCOL_PATH = _KNOWLEDGE_DIR / "protocol_security.yaml"
_LEGACY_TLS = {"TLSv1", "TLSv1.0", "TLSv1_1", "TLSv1.1"}


def _load_protocol_kb() -> Dict[str, Any]:
    with open(_PROTOCOL_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def extract_tls_risk_context(tls_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract a risk context dict from a P1.3 network prober TLS result.
    Preserves SUPPORTED != NEGOTIATED distinction.
    """
    ctx: Dict[str, Any] = {}

    # Negotiated version (stronger runtime evidence)
    neg_version = (
        tls_result.get("tls_version_negotiated") or
        tls_result.get("version") or
        tls_result.get("negotiated_version")
    )
    ctx["tls_version_negotiated"] = neg_version

    # Supported versions (from cipher_tests or supported_versions list)
    supported = tls_result.get("supported_versions") or []
    if isinstance(supported, str):
        supported = [supported]
    ctx["tls_version_supported"] = supported

    # Cipher suite negotiated
    cipher = (
        tls_result.get("cipher") or
        tls_result.get("negotiated_cipher") or
        tls_result.get("cipher_suite")
    )
    ctx["cipher_negotiated"] = cipher

    # KEX from cipher suite decomposition (best effort)
    ctx["kex_negotiated"] = _extract_kex_from_cipher(cipher)

    # PQC probe result
    pqc = tls_result.get("post_quantum") or {}
    ctx["pqc_status"] = pqc.get("pqc_status") or tls_result.get("pqc_status")
    ctx["pqc_groups"] = pqc.get("supported_groups") or []

    # Certificate info (do NOT imply trust validated)
    cert = tls_result.get("certificate") or {}
    ctx["certificate_present"] = bool(cert)
    ctx["trust_validated"] = cert.get("trust_validated", False)
    ctx["certificate_expired"] = cert.get("expired", False)
    ctx["certificate_public_key"] = cert.get("public_key") or cert.get("public_key_algorithm")
    ctx["trust_validation_performed"] = cert.get("trust_validation_performed", False)

    # Network reachable
    status = tls_result.get("status", "")
    ctx["network_reachable"] = status in ("success", "connected", "tls_success")

    return ctx


def check_tls_version_risk(version_str: Optional[str]) -> Optional[str]:
    """
    Return risk factor string if TLS version is legacy/prohibited.
    SUPPORTED != NEGOTIATED -- caller must specify which.
    Returns: "LEGACY_PROTOCOL" | None
    """
    if not version_str:
        return None
    if version_str in _LEGACY_TLS:
        return "LEGACY_PROTOCOL"
    return None


def extract_ssh_risk_context(ssh_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract SSH risk context from P1.3 SSH observation.
    ADVERTISED != NEGOTIATED. P1.3 does not authenticate SSH.
    """
    ctx: Dict[str, Any] = {}
    ctx["kex_algorithms"] = ssh_result.get("kex_algorithms") or []
    ctx["host_key_algorithms"] = ssh_result.get("server_host_key_algorithms") or []
    ctx["encryption_algorithms"] = (
        ssh_result.get("encryption_algorithms_server_to_client") or
        ssh_result.get("encryption_algorithms") or []
    )
    ctx["mac_algorithms"] = (
        ssh_result.get("mac_algorithms_server_to_client") or
        ssh_result.get("mac_algorithms") or []
    )

    kb = _load_protocol_kb()
    ssh_legacy = kb.get("ssh_legacy_algorithms", {})

    prohibited_kex = set(ssh_legacy.get("kex", {}).get("prohibited", []))
    deprecated_kex = set(ssh_legacy.get("kex", {}).get("deprecated", []))
    prohibited_hk = set(ssh_legacy.get("hostkey", {}).get("prohibited", []))
    deprecated_hk = set(ssh_legacy.get("hostkey", {}).get("deprecated", []))

    ctx["has_prohibited_kex"] = any(k in prohibited_kex for k in ctx["kex_algorithms"])
    ctx["has_deprecated_kex"] = any(k in deprecated_kex for k in ctx["kex_algorithms"])
    ctx["has_prohibited_hostkey"] = any(k in prohibited_hk for k in ctx["host_key_algorithms"])
    ctx["has_deprecated_hostkey"] = any(k in deprecated_hk for k in ctx["host_key_algorithms"])

    # PQC advertisement (ADVERTISED != NEGOTIATED)
    pqc_kex_markers = ("mlkem", "kyber", "sntrup", "bike", "frodo", "ntru")
    ctx["pqc_kex_advertised"] = any(
        any(m in k.lower() for m in pqc_kex_markers)
        for k in ctx["kex_algorithms"]
    )
    # P1.3 does not negotiate SSH -- all SSH info is ADVERTISED
    ctx["pqc_kex_negotiated"] = False  # P1.3 never claims negotiated

    return ctx


def _extract_kex_from_cipher(cipher: Optional[str]) -> Optional[str]:
    """Best-effort KEX extraction from TLS cipher suite name."""
    if not cipher:
        return None
    c = cipher.upper()
    if "ECDHE" in c:
        return "ECDHE"
    if "DHE" in c or "EDH" in c:
        return "DHE"
    if "RSA" in c and "ECDH" not in c:
        return "RSA"
    return None


def evaluate_tls_risk(
    version: Optional[str],
    cipher: Optional[str] = None,
    negotiated_kex: Optional[str] = None,
) -> Tuple[List[RiskFactor], RiskSeverity]:
    """Evaluates TLS configuration for protocol-level risk factors."""
    factors: List[RiskFactor] = []
    sev = RiskSeverity.NONE

    if check_tls_version_risk(version):
        factors.append(RiskFactor.LEGACY_PROTOCOL)
        sev = RiskSeverity.worst([sev, RiskSeverity.HIGH])

    if cipher:
        c_upper = cipher.upper()
        if any(w in c_upper for w in ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON", "CBC")):
            factors.append(RiskFactor.WEAK_TLS_CONFIGURATION)
            sev = RiskSeverity.worst([sev, RiskSeverity.CRITICAL])

    if negotiated_kex:
        nk = negotiated_kex.upper()
        if "MLKEM" in nk or "KYBER" in nk or "SNTRUP" in nk:
            pass
        else:
            factors.append(RiskFactor.PQC_NOT_NEGOTIATED)

    return factors, sev


def evaluate_ssh_risk(ssh_result: Dict[str, Any]) -> Tuple[List[RiskFactor], RiskSeverity]:
    """Evaluates SSH host keys and KEX for protocol-level risk factors."""
    ctx = extract_ssh_risk_context(ssh_result)
    factors: List[RiskFactor] = []
    sev = RiskSeverity.NONE

    if ctx.get("has_prohibited_kex") or ctx.get("has_prohibited_hostkey"):
        factors.append(RiskFactor.LEGACY_PROTOCOL)
        sev = RiskSeverity.CRITICAL
    elif ctx.get("has_deprecated_kex") or ctx.get("has_deprecated_hostkey"):
        factors.append(RiskFactor.LEGACY_PROTOCOL)
        sev = RiskSeverity.HIGH

    return factors, sev
