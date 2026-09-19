"""
ECDAT Quantum Risk Assessment & Mosca's Theorem Engine.

Implements Mosca's Theorem (X + Y > Z) and Harvest-Now, Decrypt-Later (HNDL) evaluation.

Theorem:
  X = Data Confidentiality / Shelf-Life Requirement (years)
  Y = Migration & Re-engineering Duration (years)
  Z = Estimated Cryptanalytically Relevant Quantum Computer (CRQC) Arrival Horizon (years)

Condition:
  If (X + Y) > Z:
      CRITICAL EXPOSURE (Harvest Now, Decrypt Later - Adversaries intercepting
      ciphertext today can retroactively decrypt before shelf-life expires).
  If (X + Y) <= Z:
      SECURE MARGIN (Safe window exists if migration begins immediately).

Literature Citations:
  - Craig Gidney & Martin Ekerå (2021), "How to factor 2048 bit RSA integers in 8 hours
    using 20 million noisy qubits", Quantum 5, 430.
  - NIST IR 8547 (2024), "Transitioning to Post-Quantum Cryptography Standards",
    National Institute of Standards and Technology.
  - Roetteler et al. (2017), "Quantum Resource Estimates for Computing Elliptic Curve
    Discrete Logarithms", ASIACRYPT 2017.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple
import re


# Published literature: Gidney & Ekerå 2021 + NIST IR 8547 (2024)
# Values represent estimated years until a Cryptanalytically Relevant Quantum Computer (CRQC)
# can feasibly execute cryptanalysis against the given primitive and key size.
QUANTUM_BREAK_YEARS: Dict[Tuple[str, Optional[int]], float] = {
    # Public-Key Cryptography (Shor's Algorithm - Polynomial Time Break)
    ("RSA", 1024): 4.0,   # Sub-2048 parameters breakable on early noisy QCs (<10M physical qubits)
    ("RSA", 2048): 9.0,   # Prime Gidney & Ekerå 2021 target (~20M physical qubits, ~8 hours)
    ("RSA", 3072): 13.0,  # Intermediate parameter; transition mandated by 2030 (NIST SP 800-52r2)
    ("RSA", 4096): 17.0,  # High parameter lattice surgery requirements
    ("ECDSA", 256): 7.0,  # Roetteler et al. (2017): ~2330 logical qubits (breaks faster than RSA-2048)
    ("ECDSA", 384): 10.0,
    ("ECDSA", 521): 14.0,
    ("ECDH", 256): 7.0,
    ("ECDH", 384): 10.0,
    ("ECDH", 521): 14.0,
    ("ED25519", 256): 7.0,
    ("X25519", 256): 7.0,
    ("DSA", 1024): 4.0,
    ("DSA", 2048): 8.0,
    ("DIFFIE-HELLMAN", 1024): 4.0,
    ("DIFFIE-HELLMAN", 2048): 8.0,

    # Legacy Broken Cryptography (Classically Deficient)
    ("DES", 56): 1.0,
    ("3DES", 168): 2.0,
    ("MD5", None): 1.0,
    ("SHA-1", None): 1.0,

    # Symmetric Cryptography (Grover's Algorithm - Quadratic Speedup)
    ("AES", 128): 15.0,  # 64-bit quantum security; upgrade to AES-256 mandated for classified data
    ("AES", 192): 25.0,
    ("AES", 256): 60.0,  # 128-bit quantum security; safe against CRQC
    ("CHACHA20", 256): 60.0,
    ("SHA-256", None): 60.0,
    ("SHA-384", None): 60.0,
    ("SHA-512", None): 60.0,
    ("SHA3-256", None): 60.0,
    ("SHA3-512", None): 60.0,

    # Post-Quantum Cryptography (NIST FIPS 203, 204, 205 Standards)
    ("ML-KEM", 512): 100.0,
    ("ML-KEM", 768): 100.0,
    ("ML-KEM", 1024): 100.0,
    ("ML-DSA", 44): 100.0,
    ("ML-DSA", 65): 100.0,
    ("ML-DSA", 87): 100.0,
    ("SLH-DSA", None): 100.0,
}


@dataclass
class MoscaResult:
    algorithm: str
    key_size: Optional[int]
    x_sensitivity_years: float
    y_migration_years: float
    z_threat_horizon_years: float
    quantum_deficit_years: float
    harvest_now_risk: bool
    risk_level: str  # "CRITICAL", "HIGH", "AT_RISK", "MEDIUM", "LOW", "SAFE"
    risk_score: float  # 0.0 to 100.0
    explanation: str
    recommendation: str
    literature_reference: str
    asset_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_algo_and_keysize(algorithm: str, key_size: Optional[int] = None) -> Tuple[str, Optional[int]]:
    """Normalizes raw algorithm strings into canonical algorithm families and key lengths."""
    raw = (algorithm or "UNKNOWN").upper().strip()
    clean = re.sub(r"[^A-Z0-9-]", " ", raw)
    detected_size = key_size

    # Extract embedded key lengths if key_size is not provided
    if detected_size is None:
        size_match = re.search(r"\b(512|768|1024|2048|3072|4096|256|384|521|128|192|56|168|44|65|87)\b", clean)
        if size_match:
            detected_size = int(size_match.group(1))

    if "ML-KEM" in clean or "MLKEM" in clean or "KYBER" in clean:
        return "ML-KEM", detected_size or 768
    if "ML-DSA" in clean or "MLDSA" in clean or "DILITHIUM" in clean:
        return "ML-DSA", detected_size or 65
    if "SLH-DSA" in clean or "SLHDSA" in clean or "SPHINCS" in clean:
        return "SLH-DSA", detected_size
    if "RSA" in clean:
        return "RSA", detected_size or 2048
    if "ECDSA" in clean or "SECP" in clean:
        return "ECDSA", detected_size or 256
    if "ECDH" in clean:
        return "ECDH", detected_size or 256
    if "ED25519" in clean:
        return "ED25519", 256
    if "X25519" in clean:
        return "X25519", 256
    if "AES" in clean:
        return "AES", detected_size or 256
    if "DES" in clean:
        return "DES" if "3DES" not in clean and "TRIPLE" not in clean else "3DES", detected_size or (168 if "3DES" in clean else 56)
    if "MD5" in clean:
        return "MD5", None
    if "SHA-1" in clean or "SHA1" in clean:
        return "SHA-1", None
    if "SHA-256" in clean or "SHA256" in clean:
        return "SHA-256", None
    if "SHA-384" in clean or "SHA384" in clean:
        return "SHA-384", None
    if "SHA-512" in clean or "SHA512" in clean:
        return "SHA-512", None
    if "CHACHA" in clean:
        return "CHACHA20", 256

    return clean.split()[0] if clean.split() else "UNKNOWN", detected_size


def lookup_quantum_break_years(algorithm: str, key_size: Optional[int] = None) -> float:
    """
    Returns estimated years until quantum break based on Gidney & Ekerå 2021 and NIST IR 8547.
    """
    family, size = normalize_algo_and_keysize(algorithm, key_size)

    # Direct match
    if (family, size) in QUANTUM_BREAK_YEARS:
        return QUANTUM_BREAK_YEARS[(family, size)]

    # Family match ignoring key size
    for (f, _), years in QUANTUM_BREAK_YEARS.items():
        if f == family:
            return years

    # Heuristic based on algorithm classification
    if any(k in family for k in ("RSA", "ECDSA", "ECDH", "DSA", "DIFFIE", "ED25519", "X25519")):
        return 8.0
    if any(k in family for k in ("DES", "MD5", "SHA1", "RC4")):
        return 1.0
    if any(k in family for k in ("ML-KEM", "ML-DSA", "SLH", "PQC", "HYBRID")):
        return 100.0

    return 20.0


def mosca_assess(
    algorithm: str,
    key_size: Optional[int] = None,
    data_sensitivity_years: float = 10.0,
    migration_time_years: float = 3.0,
    crqc_horizon_override: Optional[float] = None,
    asset_count: int = 1,
) -> MoscaResult:
    """
    Executes Mosca's Theorem assessment on a cryptographic algorithm/key configuration.
    """
    x = max(1.0, float(data_sensitivity_years if data_sensitivity_years is not None else 10.0))
    y = max(0.5, float(migration_time_years if migration_time_years is not None else 3.0))

    if crqc_horizon_override is not None and float(crqc_horizon_override) > 0:
        z = float(crqc_horizon_override)
    else:
        z = lookup_quantum_break_years(algorithm, key_size)

    family, size = normalize_algo_and_keysize(algorithm, key_size)
    canonical_name = f"{family}-{size}" if size else family

    is_quantum_safe = z >= 50.0
    total_needed = x + y
    deficit = round(total_needed - z, 1)

    # Harvest Now Decrypt Later risk:
    # Adversary records traffic today. If data sensitivity X + migration time Y exceeds CRQC arrival Z,
    # and primitive is used for confidentiality / key establishment, retroactive decryption occurs.
    is_confidentiality_primitive = family in ("RSA", "ECDH", "X25519", "DIFFIE-HELLMAN", "DES", "3DES", "AES")
    harvest_now_risk = bool(deficit > 0 and not is_quantum_safe and is_confidentiality_primitive)

    if is_quantum_safe:
        risk_level = "SAFE"
        risk_score = 0.0
        explanation = (
            f"{canonical_name} provides quantum-resistant cryptographic security (threat horizon: {z}+ years). "
            f"No Mosca deficit detected (margin: {abs(deficit)}y)."
        )
        recommendation = "Maintain current quantum-resistant deployment."
    elif deficit > 3.0:
        risk_level = "CRITICAL"
        risk_score = min(100.0, round(65.0 + (deficit * 3.5), 1))
        explanation = (
            f"CRITICAL MOSCA DEFICIT (+{deficit} years): Required protection period ({total_needed}y: "
            f"{x}y sensitivity + {y}y migration) exceeds estimated CRQC arrival ({z}y). "
            f"Harvested ciphertext will be cracked before confidentiality requirement expires."
        )
        recommendation = "Mandatory transition to FIPS 203 (ML-KEM-768) or FIPS 204 (ML-DSA-65) immediately."
    elif deficit > 0:
        risk_level = "AT_RISK"
        risk_score = min(85.0, round(50.0 + (deficit * 4.0), 1))
        explanation = (
            f"AT RISK (+{deficit} years deficit): Combined sensitivity and migration duration ({total_needed}y) "
            f"exceeds the quantum threat window ({z}y). High vulnerability to HNDL collection."
        )
        recommendation = "Accelerate migration planning to post-quantum standards within 12 months."
    elif z <= 10.0:
        risk_level = "MEDIUM"
        risk_score = round(35.0 + (10.0 - z) * 2.0, 1)
        explanation = (
            f"Near-term quantum threshold ({z}y). Secure margin of {abs(deficit)}y exists, but migration "
            f"must begin promptly to avoid entering a deficit state."
        )
        recommendation = "Begin PQC hybrid key encapsulation (X25519 + ML-KEM-768) pilot."
    else:
        risk_level = "LOW"
        risk_score = round(max(5.0, 20.0 - (z - 10.0)), 1)
        explanation = f"Comfortable quantum safety margin of {abs(deficit)} years remaining."
        recommendation = "Monitor post-quantum transition roadmaps annually."

    reference = "Gidney & Ekerå 2021 (Quantum 5, 430); NIST IR 8547 (2024)"

    return MoscaResult(
        algorithm=canonical_name,
        key_size=size,
        x_sensitivity_years=x,
        y_migration_years=y,
        z_threat_horizon_years=z,
        quantum_deficit_years=deficit,
        harvest_now_risk=harvest_now_risk,
        risk_level=risk_level,
        risk_score=risk_score,
        explanation=explanation,
        recommendation=recommendation,
        literature_reference=reference,
        asset_count=asset_count,
    )


def assess_project_assets(
    db: Any,
    project_id: str,
    data_sensitivity_years: Optional[float] = None,
    migration_time_years: Optional[float] = None,
    crqc_horizon_override: Optional[float] = None,
) -> List[MoscaResult]:
    """
    Queries all unique (algorithm, key_size) pairs from crypto_assets for the project,
    evaluates Mosca's Theorem for each, and returns results sorted by risk_score descending.
    """
    rows = db.execute(
        """SELECT algorithm, key_size, name, COUNT(*) as asset_count
           FROM crypto_assets
           WHERE project = ?
           GROUP BY algorithm, key_size""",
        (project_id,)
    ).fetchall()

    if not rows:
        return []

    results: List[MoscaResult] = []
    for r in rows:
        algo = r["algorithm"] or r["name"] or "UNKNOWN"
        key_size = r["key_size"]
        count = int(r["asset_count"] or 1)
        res = mosca_assess(
            algorithm=algo,
            key_size=key_size,
            data_sensitivity_years=data_sensitivity_years or 10.0,
            migration_time_years=migration_time_years or 3.0,
            crqc_horizon_override=crqc_horizon_override,
            asset_count=count,
        )
        results.append(res)

    results.sort(key=lambda item: item.risk_score, reverse=True)
    return results


def get_timeline_summary(db: Any, project_id: str) -> List[Dict[str, Any]]:
    """
    Returns per-algorithm quantum break timelines for dashboard visualization:
    [{algorithm: "RSA-2048", z_years: 9, risk_level: "AT_RISK", asset_count: 3}]
    """
    assessments = assess_project_assets(db, project_id)
    summary: List[Dict[str, Any]] = []
    for a in assessments:
        summary.append({
            "algorithm": a.algorithm,
            "z_years": a.z_threat_horizon_years,
            "risk_level": a.risk_level,
            "asset_count": a.asset_count,
        })
    return summary
