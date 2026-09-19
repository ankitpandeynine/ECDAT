"""
ECDAT V4 P2.1 Security Strength Engine.

Parameter-aware classical and quantum security strength assessment.

AXIOM: If parameters are unknown, strength = UNKNOWN. Never invent a default.
"""
from __future__ import annotations

from typing import Optional

from .algorithm_registry import normalize_algorithm
from .models import (
    QuantumImpact, RiskConfidence, SecurityStrengthAssessment,
    StrengthCategory, ParameterStatus,
)


def assess_security_strength(
    algorithm: str,
    parameter: Optional[int] = None,
    evidence_level: str = "E0",
    parameter_source: str = "UNKNOWN",
) -> SecurityStrengthAssessment:
    """
    Produce a parameter-aware security strength assessment.

    Rules:
    - If parameter is None and algorithm requires parameters (RSA, DH), return UNKNOWN strength.
    - NEVER assume a default key size.
    - PQC algorithms are STRONG regardless of classical parameters.
    - Symmetric: strength depends on key size.
    """
    entry = normalize_algorithm(algorithm)
    canonical = entry.canonical_name if entry else algorithm

    # Determine quantum impact
    quantum_impact = entry.quantum_impact if entry else QuantumImpact.UNKNOWN

    # Determine classical strength bits
    classical_bits: Optional[int] = None
    param_status = ParameterStatus.UNKNOWN
    strength = StrengthCategory.UNKNOWN

    if entry is None:
        # Completely unknown algorithm
        return SecurityStrengthAssessment(
            algorithm=algorithm,
            canonical_name=None,
            parameter=parameter,
            parameter_status=ParameterStatus.UNKNOWN,
            parameter_source=parameter_source,
            classical_strength_bits=None,
            quantum_strength_bits=None,
            quantum_impact=QuantumImpact.UNKNOWN,
            strength_category=StrengthCategory.UNKNOWN,
            confidence=RiskConfidence.UNKNOWN,
            limitations=["Algorithm not recognized in knowledge base."],
        )

    # Hybrid KEM algorithms: classical component provides classical security bits, PQC provides quantum resistance
    if entry.category == "HYBRID_KEM":
        classical_bits = None
        if entry.components:
            classical_name = entry.components.get("classical")
            if classical_name:
                c_entry = normalize_algorithm(classical_name)
                if c_entry and isinstance(c_entry.classical_security_bits, int):
                    classical_bits = c_entry.classical_security_bits
                elif classical_name == "ECDH" and entry.components.get("classical_curve") == "P-256":
                    classical_bits = 128
                elif classical_name == "ECDH" and entry.components.get("classical_curve") == "P-384":
                    classical_bits = 192
        return SecurityStrengthAssessment(
            algorithm=algorithm,
            canonical_name=canonical,
            parameter=parameter,
            parameter_status=ParameterStatus.KNOWN if parameter is not None else ParameterStatus.UNKNOWN,
            parameter_source=parameter_source,
            classical_strength_bits=classical_bits,
            quantum_strength_bits=None,
            quantum_impact=quantum_impact,
            strength_category=StrengthCategory.STRONG,
            confidence=_level_to_confidence(evidence_level),
            limitations=[],
        )

    # Pure PQC algorithms: always STRONG, no classical parameter relevance
    if entry.category in ("PQC_KEM", "PQC_SIGNATURE"):
        return SecurityStrengthAssessment(
            algorithm=algorithm,
            canonical_name=canonical,
            parameter=parameter,
            parameter_status=ParameterStatus.KNOWN if parameter is not None else ParameterStatus.UNKNOWN,
            parameter_source=parameter_source,
            classical_strength_bits=None,
            quantum_strength_bits=None,
            quantum_impact=quantum_impact,
            strength_category=StrengthCategory.STRONG,
            confidence=_level_to_confidence(evidence_level),
            limitations=[],
        )

    # Symmetric / Hash / MAC: strength from key/output size where known
    if entry.category in ("SYMMETRIC", "HASH", "MAC", "AEAD"):
        cb = entry.classical_security_bits if isinstance(entry.classical_security_bits, int) else None
        qb = entry.quantum_security_bits
        strength = _symmetric_strength(entry.status)
        param_status = ParameterStatus.KNOWN  # symmetric params baked into name
        return SecurityStrengthAssessment(
            algorithm=algorithm,
            canonical_name=canonical,
            parameter=parameter,
            parameter_status=param_status,
            parameter_source=parameter_source,
            classical_strength_bits=cb,
            quantum_strength_bits=qb,
            quantum_impact=quantum_impact,
            strength_category=strength,
            confidence=_level_to_confidence(evidence_level),
            limitations=[],
        )

    # Public-key algorithms (RSA, DH, ECDH, ECDSA, etc.)
    param_required = entry.default_parameter_status == "UNKNOWN"
    classical_bits_by_param = entry.classical_security_bits if isinstance(entry.classical_security_bits, dict) else None

    if parameter is not None:
        param_status = ParameterStatus.KNOWN
        if classical_bits_by_param:
            # Look up strength by key size
            classical_bits = classical_bits_by_param.get(str(parameter)) or classical_bits_by_param.get(parameter)
            if classical_bits:
                strength = _classical_pk_strength(classical_bits)
            else:
                # Parameter value not in table — interpolate coarsely
                classical_bits = None
                strength = _pk_strength_from_size(algorithm, parameter)
        else:
            # Single value (e.g. ECDSA always ~128 bits for P-256)
            cb = entry.classical_security_bits if isinstance(entry.classical_security_bits, int) else None
            classical_bits = cb
            strength = _classical_pk_strength(cb) if cb else StrengthCategory.UNKNOWN
    else:
        # Parameter not known: strength is UNKNOWN regardless of algorithm
        param_status = ParameterStatus.UNKNOWN
        classical_bits = None
        strength = StrengthCategory.UNKNOWN

    limitations = []
    if param_status == ParameterStatus.UNKNOWN:
        limitations.append(
            f"Key size is unknown for {canonical}. "
            "Strength cannot be assessed without parameter information. "
            "Do NOT assume a default key size."
        )

    return SecurityStrengthAssessment(
        algorithm=algorithm,
        canonical_name=canonical,
        parameter=parameter,
        parameter_status=param_status,
        parameter_source=parameter_source,
        classical_strength_bits=classical_bits,
        quantum_strength_bits=None,  # public-key quantum strength: SHOR_BREAKS regardless
        quantum_impact=quantum_impact,
        strength_category=strength,
        confidence=_level_to_confidence(evidence_level),
        limitations=limitations,
    )


def _symmetric_strength(status: str) -> StrengthCategory:
    mapping = {
        "INSUFFICIENT": StrengthCategory.INSUFFICIENT,
        "LEGACY": StrengthCategory.LEGACY,
        "ACCEPTABLE": StrengthCategory.ACCEPTABLE,
        "STRONG": StrengthCategory.STRONG,
    }
    return mapping.get(status, StrengthCategory.UNKNOWN)


def _classical_pk_strength(bits: int) -> StrengthCategory:
    if bits <= 80:
        return StrengthCategory.INSUFFICIENT
    if bits < 112:
        return StrengthCategory.LEGACY
    if bits < 128:
        return StrengthCategory.ACCEPTABLE
    return StrengthCategory.STRONG


def _pk_strength_from_size(algorithm: str, bits: int) -> StrengthCategory:
    """Coarse RSA/DH/ECDH strength from key size."""
    algo_upper = algorithm.upper()
    if "RSA" in algo_upper or "DH" in algo_upper:
        if bits <= 1024:
            return StrengthCategory.INSUFFICIENT
        if bits < 2048:
            return StrengthCategory.LEGACY
        if bits < 3072:
            return StrengthCategory.ACCEPTABLE
        return StrengthCategory.STRONG
    if "EC" in algo_upper or "CURVE" in algo_upper or "ED" in algo_upper:
        if bits < 192:
            return StrengthCategory.LEGACY
        if bits < 256:
            return StrengthCategory.ACCEPTABLE
        return StrengthCategory.STRONG
    return StrengthCategory.UNKNOWN


def _level_to_confidence(level: str) -> RiskConfidence:
    mapping = {
        "E0": RiskConfidence.UNKNOWN,
        "E1": RiskConfidence.INFERRED,
        "E2": RiskConfidence.INFERRED,
        "E3": RiskConfidence.MEASURED,
        "E4": RiskConfidence.MEASURED,
        "E5": RiskConfidence.MEASURED,
    }
    return mapping.get(level, RiskConfidence.UNKNOWN)
