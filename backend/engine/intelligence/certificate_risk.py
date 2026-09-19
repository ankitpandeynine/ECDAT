"""
ECDAT V4 P2.1 Certificate Risk Adapter.

AXIOMS:
- CERT_PRESENT != TRUST_VALIDATED
- OCSP_EXTENSION_PRESENT != REVOCATION_CHECKED
- trust_validated=False does NOT mean UNTRUSTED unless trust check was performed
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import RiskFactor, RiskSeverity


def extract_cert_risk_context(cert_dict: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract certificate risk context from a P1.3 or P1.2 certificate observation.
    Never conflates presence with trust, or OCSP extension with revocation check.
    """
    if not cert_dict:
        return {
            "certificate_present": False,
            "trust_validated": False,
            "trust_measurement_performed": False,
            "trust_status": "TRUST_UNMEASURED",
            "certificate_expired": False,
            "expiry_known": False,
            "ocsp_present": False,
            "revocation_checked": False,
            "public_key_algorithm": None,
            "signature_algorithm": None,
            "key_size": None,
        }

    ctx: Dict[str, Any] = {
        "certificate_present": True,
    }

    # Trust: must explicitly differentiate
    trust_validated = cert_dict.get("trust_validated", False)
    trust_performed = cert_dict.get("trust_validation_performed", cert_dict.get("trust_check_performed", False))
    ctx["trust_validated"] = trust_validated
    ctx["trust_measurement_performed"] = trust_performed
    if not trust_performed:
        ctx["trust_status"] = "TRUST_UNMEASURED"
    elif trust_validated:
        ctx["trust_status"] = "TRUST_VALIDATED"
    else:
        ctx["trust_status"] = "TRUST_VALIDATION_FAILED"

    # Expiry
    not_before = cert_dict.get("not_before") or cert_dict.get("valid_from")
    not_after = cert_dict.get("not_after") or cert_dict.get("valid_until") or cert_dict.get("expires")
    eval_time = cert_dict.get("evaluation_time") or datetime.now(timezone.utc).isoformat()
    expired, days_remaining = assess_cert_expiry(not_before, not_after, eval_time)
    ctx["certificate_expired"] = expired
    ctx["expiry_known"] = not_after is not None
    ctx["days_remaining"] = days_remaining
    ctx["not_before"] = not_before
    ctx["not_after"] = not_after
    ctx["evaluation_time"] = eval_time

    # OCSP / revocation: presence != checked
    ctx["ocsp_present"] = bool(
        cert_dict.get("ocsp_url") or
        cert_dict.get("ocsp_staple") or
        cert_dict.get("ocsp_must_staple") or
        cert_dict.get("extensions", {}).get("ocsp")
    )
    # revocation_checked must be explicitly set by scanner
    ctx["revocation_checked"] = cert_dict.get("revocation_checked", False)

    # Public key
    ctx["public_key_algorithm"] = (
        cert_dict.get("public_key_algorithm") or
        cert_dict.get("public_key") or
        cert_dict.get("key_algorithm")
    )
    ctx["signature_algorithm"] = cert_dict.get("signature_algorithm")
    ctx["key_size"] = cert_dict.get("key_size") or cert_dict.get("bits")
    ctx["serial_number"] = cert_dict.get("serial") or cert_dict.get("serial_number")
    ctx["subject"] = cert_dict.get("subject")
    ctx["issuer"] = cert_dict.get("issuer")

    return ctx


def assess_cert_expiry(
    not_before: Optional[str],
    not_after: Optional[str],
    evaluation_time: Optional[str] = None,
) -> Tuple[bool, Optional[int]]:
    """
    Deterministically assess certificate expiry from timestamps.

    Returns:
        (expired: bool, days_remaining: Optional[int])
        days_remaining is None if not_after is unknown.
    """
    if not not_after:
        return False, None

    try:
        eval_dt = _parse_iso(evaluation_time) if evaluation_time else datetime.now(timezone.utc)
        expiry_dt = _parse_iso(not_after)
        if expiry_dt is None:
            return False, None
        delta = expiry_dt - eval_dt
        days = delta.days
        return days < 0, days
    except Exception:
        return False, None


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def evaluate_certificate_risk(cert_dict: Optional[Dict[str, Any]]) -> Tuple[List[RiskFactor], RiskSeverity]:
    """Evaluates a certificate dictionary for certificate-level risk factors."""
    ctx = extract_cert_risk_context(cert_dict)
    factors: List[RiskFactor] = []
    sev = RiskSeverity.NONE

    if not ctx.get("certificate_present"):
        return factors, sev

    if ctx.get("certificate_expired") or (cert_dict and cert_dict.get("is_expired")):
        factors.append(RiskFactor.EXPIRED_CERTIFICATE)
        sev = RiskSeverity.worst([sev, RiskSeverity.CRITICAL])

    # Trust validation
    if cert_dict and cert_dict.get("trust_validated") is False:
        factors.append(RiskFactor.UNVERIFIED_CERTIFICATE_TRUST)
        sev = RiskSeverity.worst([sev, RiskSeverity.MEDIUM])

    # Weak signature algorithm (e.g. MD5, SHA1)
    sig_algo = (ctx.get("signature_algorithm") or "").upper()
    if "MD5" in sig_algo:
        factors.append(RiskFactor.WEAK_CERTIFICATE_SIGNATURE)
        sev = RiskSeverity.worst([sev, RiskSeverity.CRITICAL])
    elif "SHA1" in sig_algo:
        factors.append(RiskFactor.WEAK_CERTIFICATE_SIGNATURE)
        sev = RiskSeverity.worst([sev, RiskSeverity.HIGH])

    return factors, sev
