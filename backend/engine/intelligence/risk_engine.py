"""
ECDAT V4 P2.1 Risk Engine.

Deterministic, evidence-traceable rule evaluation.

AXIOM: No risk conclusion without traceable evidence.
AXIOM: SCANNER_UNAVAILABLE != NOT_SUPPORTED
AXIOM: SEVERITY != CONFIDENCE
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .algorithm_registry import normalize_algorithm
from .evidence_context import derive_confidence_from_evidence
from .models import (
    EvidenceReference, RiskConfidence, RiskFactor, RiskSeverity,
    RuleReference, QuantumImpact, CryptoRole, UnknownFactor,
)

_KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"
_RULES_PATH = _KNOWLEDGE_DIR / "crypto_risk_rules.yaml"

_SEVERITY_MAP = {
    "NONE": RiskSeverity.NONE,
    "INFO": RiskSeverity.INFO,
    "LOW": RiskSeverity.LOW,
    "MEDIUM": RiskSeverity.MEDIUM,
    "HIGH": RiskSeverity.HIGH,
    "CRITICAL": RiskSeverity.CRITICAL,
    "UNKNOWN": RiskSeverity.UNKNOWN,
}

_FACTOR_MAP = {f.value: f for f in RiskFactor}

# Quantum-impacted status strings that indicate a break by Shor
_SHOR_STATUSES = {"QUANTUM_VULNERABLE", "BROKEN_BY_SHOR"}


_RULES_CACHE: Optional[Tuple[List[Dict[str, Any]], str]] = None


def _load_rules() -> Tuple[List[Dict[str, Any]], str]:
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE
    with open(_RULES_PATH, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    _RULES_CACHE = (data.get("rules", []), data.get("version", "UNKNOWN"))
    return _RULES_CACHE


def evaluate_risk_factors(
    asset: Dict[str, Any],
    evidence_items: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Tuple[RiskFactor, RuleReference]], str]:
    """
    Evaluate risk rules against an asset and its evidence.

    Returns:
        (list of (RiskFactor, RuleReference), knowledge_base_version)

    Each triggered rule produces exactly one RiskFactor + RuleReference pair.
    """
    rules, kb_version = _load_rules()
    context = context or {}
    results: List[Tuple[RiskFactor, RuleReference]] = []
    seen_factors: set = set()  # deduplicate same factor from multiple rules

    algo_name = asset.get("algorithm") or asset.get("name") or ""
    entry = normalize_algorithm(algo_name) if algo_name else None
    algo_status = entry.status if entry else "UNKNOWN"
    pqc_status = entry.pqc_status if entry else "UNKNOWN"
    q_impact = entry.quantum_impact if entry else QuantumImpact.UNKNOWN
    dep_status = entry.deprecation_status if entry else "UNKNOWN"
    roles = [r.value for r in (entry.roles if entry else [])]
    if "roles" in asset and asset["roles"]:
        roles = [r.value if hasattr(r, "value") else str(r) for r in asset["roles"]]

    # Contextual flags
    parameter = asset.get("key_size") or asset.get("parameter")
    scanner_unavailable = context.get("scanner_unavailable", False)
    network_reachable = context.get("network_reachable", False)
    tls_version_neg = context.get("tls_version_negotiated")
    tls_version_sup_list = list(context.get("tls_version_supported", []))
    cert_expired = context.get("certificate_expired", False)
    trust_validation_failed = context.get("trust_validation_failed", False)
    pqc_kex_state = context.get("pqc_kex_state", "NOT_ASSESSED")
    pqc_sig_state = context.get("pqc_sig_state", "NOT_ASSESSED")

    # Extract protocol & cert properties from evidence if not present in context
    for ev in evidence_items:
        raw = ev.get("raw_details") or ev.get("metadata") or {}
        obs = str(ev.get("observation_type", "")).upper()
        if "TLS" in obs or obs == "TLS_PROTOCOL":
            if not tls_version_neg and ev.get("state") in ("NEGOTIATED", "OBSERVED"):
                tls_version_neg = raw.get("version") or raw.get("tls_version")
            if raw.get("version") and raw.get("version") not in tls_version_sup_list:
                tls_version_sup_list.append(raw.get("version"))

    unknown_factors: List[UnknownFactor] = []

    def _add(rule: Dict[str, Any], triggered_by: str) -> None:
        factor_str = rule.get("result_factor", "")
        factor = _FACTOR_MAP.get(factor_str)
        if factor is None:
            return
        key = (factor.value, rule["id"])
        if key in seen_factors:
            return
        seen_factors.add(key)
        ref = RuleReference(
            rule_id=rule["id"],
            rule_version=rule.get("version", "1.0"),
            knowledge_base_version=kb_version,
            triggered_by=triggered_by,
            explanation=rule.get("explanation", ""),
        )
        results.append((factor, ref))

    # --- LEG-001: Deprecated algorithm ---
    if (algo_status in ("DEPRECATED", "PROHIBITED") or
            dep_status in ("DEPRECATED", "PROHIBITED") or
            ("SIGNATURE" in roles and entry and entry.canonical_name == "SHA-1")):
        _add({"id": "LEG-001", "version": "1.0", "result_factor": "DEPRECATED_ALGORITHM",
              "explanation": "Algorithm is deprecated or prohibited."},
             f"algorithm_status={algo_status}, deprecation_status={dep_status}")

    # --- LEG-002: Broken algorithm ---
    if algo_status == "INSUFFICIENT" or pqc_status in ("BROKEN", "BROKEN_CLASSICALLY"):
        _add({"id": "LEG-002", "version": "1.0", "result_factor": "WEAK_ALGORITHM",
              "explanation": "Algorithm is cryptographically broken by classical attacks."},
             f"algorithm_status={algo_status}, pqc_status={pqc_status}")

    # --- PQ-KEX-001: Quantum-vulnerable key establishment ---
    if (q_impact == QuantumImpact.SHOR_BREAKS and
            "KEY_ESTABLISHMENT" in roles and
            not scanner_unavailable):
        _add({"id": "PQ-KEX-001", "version": "1.0", "result_factor": "QUANTUM_VULNERABLE_KEX",
              "explanation": "Quantum-vulnerable key establishment observed."},
             f"roles={roles}, quantum_impact={q_impact.value}")

    # --- PQ-SIG-001: Quantum-vulnerable signature ---
    cert_sig = str(context.get("signature_algorithm") or context.get("certificate_signature_algorithm") or "").upper()
    cert_pk = str(context.get("certificate_public_key") or "").upper()
    has_classical_cert = any(k in cert_sig or k in cert_pk for k in ("RSA", "ECDSA", "DSA")) or pqc_sig_state == "CLASSICAL_ONLY"

    if not scanner_unavailable and (
        (q_impact == QuantumImpact.SHOR_BREAKS and ("SIGNATURE" in roles or "CERTIFICATE_SIGNATURE" in roles))
        or has_classical_cert
    ):
        _add({"id": "PQ-SIG-001", "version": "1.0", "result_factor": "QUANTUM_VULNERABLE_SIGNATURE",
              "explanation": "Quantum-vulnerable signature algorithm observed."},
             f"roles={roles}, cert_sig={cert_sig or pqc_sig_state}")

    # --- PQ-ENC-001: Quantum-vulnerable public-key encryption ---
    if (q_impact == QuantumImpact.SHOR_BREAKS and
            "PUBLIC_KEY_ENCRYPTION" in roles and
            not scanner_unavailable):
        _add({"id": "PQ-ENC-001", "version": "1.0", "result_factor": "QUANTUM_VULNERABLE_ENCRYPTION",
              "explanation": "Quantum-vulnerable public-key encryption observed."},
             f"roles={roles}")

    # --- PQ-SYM-001: Symmetric weakened by Grover ---
    if (q_impact == QuantumImpact.GROVER_HALVING and
            "SYMMETRIC_ENCRYPTION" in roles):
        qb = entry.quantum_security_bits if entry else None
        if qb is not None and qb < 128:
            _add({"id": "PQ-SYM-001", "version": "1.0", "result_factor": "QUANTUM_WEAKENED_SYMMETRIC",
                  "explanation": "Symmetric key weakened by Grover algorithm."},
                 f"quantum_security_bits={qb}")

    # --- TLS-001 / TLS-002: Legacy TLS versions ---
    _LEGACY_VERSIONS = {"TLSv1", "TLSv1.0", "TLSv1_1", "TLSv1.1"}
    if tls_version_neg and tls_version_neg in _LEGACY_VERSIONS:
        _add({"id": "TLS-001", "version": "1.0", "result_factor": "LEGACY_PROTOCOL",
              "explanation": "Legacy TLS version negotiated."},
             f"tls_version_negotiated={tls_version_neg}")
    elif any(v in _LEGACY_VERSIONS for v in tls_version_sup_list):
        _add({"id": "TLS-002", "version": "1.0", "result_factor": "LEGACY_PROTOCOL",
              "explanation": "Legacy TLS version supported (not necessarily negotiated)."},
             f"tls_version_supported={tls_version_sup_list}")

    # --- CERT-001: Expired certificate ---
    if cert_expired:
        _add({"id": "CERT-001", "version": "1.0", "result_factor": "EXPIRED_CERTIFICATE",
              "explanation": "Certificate has expired."},
             "certificate_expired=True")

    # --- CERT-002: Trust validation failed ---
    if trust_validation_failed:
        _add({"id": "CERT-002", "version": "1.0", "result_factor": "UNVERIFIED_CERTIFICATE_TRUST",
              "explanation": "Certificate trust validation failed."},
             "trust_validation_failed=True")

    # --- PQR-001: PQC not negotiated ---
    if pqc_kex_state == "CLASSICAL_ONLY":
        _add({"id": "PQR-001", "version": "1.0", "result_factor": "PQC_NOT_NEGOTIATED",
              "explanation": "PQC not negotiated for key establishment."},
             f"pqc_kex_state={pqc_kex_state}")

    # --- PQR-002: Partial PQC readiness ---
    if pqc_kex_state == "HYBRID_NEGOTIATED" and pqc_sig_state == "CLASSICAL_ONLY":
        _add({"id": "PQR-002", "version": "1.0", "result_factor": "PQC_PARTIAL_READINESS",
              "explanation": "Hybrid KEX but classical signatures."},
             f"kex={pqc_kex_state}, sig={pqc_sig_state}")

    # --- HNDL-001: HNDL exposure ---
    if (q_impact == QuantumImpact.SHOR_BREAKS and
            "KEY_ESTABLISHMENT" in roles and
            network_reachable and
            not scanner_unavailable):
        _add({"id": "HNDL-001", "version": "1.0", "result_factor": "HNDL_EXPOSURE",
              "explanation": "HNDL exposure on network-reachable endpoint."},
             f"roles={roles}, network_reachable=True")

    # --- UNK-001: Unknown parameters ---
    if parameter is None and entry and entry.default_parameter_status == "UNKNOWN":
        _add({"id": "UNK-001", "version": "1.0", "result_factor": "UNKNOWN_PARAMETERS",
              "explanation": "Algorithm parameters unknown."},
             "parameter=None, parameter_required=True")
        unknown_factors.append(UnknownFactor(field="key_size", reason="Algorithm parameter (key size) is unknown."))

    # --- UNK-002: Scanner unavailable ---
    if scanner_unavailable:
        _add({"id": "UNK-002", "version": "1.0", "result_factor": "SCANNER_UNAVAILABLE",
              "explanation": "Scanner unavailable. This is NOT evidence the algorithm is unsupported."},
             "scanner_unavailable=True")
        unknown_factors.append(UnknownFactor(field="scanner_state", reason="Scanner was unavailable."))

    return results, unknown_factors


def compute_severity(factor_rule_pairs: List[Tuple[RiskFactor, RuleReference]]) -> RiskSeverity:
    """Return worst severity from triggered rules, preserving UNKNOWN semantics."""
    if not factor_rule_pairs:
        return RiskSeverity.NONE
    _, kb = _load_rules()
    rules_by_id = {}
    rules_raw, _ = _load_rules()
    for r in rules_raw:
        rules_by_id[r["id"]] = r

    severities = []
    for _factor, ref in factor_rule_pairs:
        rule = rules_by_id.get(ref.rule_id, {})
        sev_str = rule.get("severity", "UNKNOWN")
        severities.append(_SEVERITY_MAP.get(sev_str, RiskSeverity.UNKNOWN))

    return RiskSeverity.worst(severities)


def compute_confidence(evidence_items: List[Dict[str, Any]]) -> RiskConfidence:
    return derive_confidence_from_evidence(evidence_items)
