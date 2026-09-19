"""
ECDAT V4 Temporal PQC Readiness Evaluator.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from .models import PQCChange

PQC_STANDARDS = {"ML-KEM", "ML-DSA", "SLH-DSA", "FALCON", "XMSS", "LMS"}
PQC_ROUND3 = {"KYBER", "DILITHIUM", "SPHINCS+"}


def _is_pqc_or_hybrid(algo: str, readiness_status: Optional[str] = None) -> bool:
    upper = (algo or "").upper()
    if any(p in upper for p in PQC_STANDARDS | PQC_ROUND3 | {"HYBRID"}):
        return True
    if readiness_status and readiness_status.upper() in ("PQC_READY", "QUANTUM_RESISTANT", "HYBRID_READY"):
        return True
    return False


def _is_fips_standardized(algo: str) -> bool:
    upper = (algo or "").upper()
    return any(p in upper for p in PQC_STANDARDS)


def evaluate_temporal_pqc(
    base_pqc: Optional[Dict[str, Any]],
    target_pqc: Optional[Dict[str, Any]],
    base_asset: Optional[Dict[str, Any]] = None,
    target_asset: Optional[Dict[str, Any]] = None,
) -> Tuple[PQCChange, str]:
    """
    Evaluates PQC readiness evolution across time.
    Distinguishes:
    - PQC_INTRODUCED (classical -> hybrid or PQC)
    - PQC_REMOVED (PQC -> classical rollback)
    - PQC_UPGRADED (Round-3 candidate -> FIPS 203/204 standard, or security level increase)
    - PQC_UNCHANGED
    - PQC_UNKNOWN
    """
    base_algo = (base_asset.get("algorithm") if base_asset else "") or (base_pqc.get("algorithm") if base_pqc else "")
    target_algo = (target_asset.get("algorithm") if target_asset else "") or (target_pqc.get("algorithm") if target_pqc else "")

    base_status = base_pqc.get("status") if base_pqc else None
    target_status = target_pqc.get("status") if target_pqc else None

    base_is_pqc = _is_pqc_or_hybrid(base_algo, base_status)
    target_is_pqc = _is_pqc_or_hybrid(target_algo, target_status)

    if not base_is_pqc and target_is_pqc:
        return PQCChange.PQC_INTRODUCED, f"Upgraded to post-quantum algorithm ({target_algo or 'PQC/Hybrid'})."

    if base_is_pqc and not target_is_pqc:
        return PQCChange.PQC_REMOVED, f"Post-quantum implementation reverted to classical primitive ({target_algo or 'Classical'})."

    if base_is_pqc and target_is_pqc:
        # Check if upgraded to official FIPS standard or higher parameter
        if not _is_fips_standardized(base_algo) and _is_fips_standardized(target_algo):
            return PQCChange.PQC_UPGRADED, f"Upgraded from pre-standard draft ({base_algo}) to FIPS standardized primitive ({target_algo})."
        
        # Check key size/parameter upgrade (e.g. 512 to 768 or 1024)
        b_size = base_asset.get("key_size") if base_asset else None
        t_size = target_asset.get("key_size") if target_asset else None
        if b_size and t_size and t_size > b_size:
            return PQCChange.PQC_UPGRADED, f"Upgraded security parameter from {b_size}-bit to {t_size}-bit."

        if base_algo != target_algo and target_algo:
            return PQCChange.PQC_UPGRADED, f"Transitioned PQC primitive from {base_algo} to {target_algo}."

        return PQCChange.PQC_UNCHANGED, f"PQC readiness remains stable ({target_algo or 'Quantum Resistant'})."

    if base_pqc is None and target_pqc is None and not base_algo and not target_algo:
        return PQCChange.PQC_UNKNOWN, "No PQC readiness data available."

    return PQCChange.PQC_UNCHANGED, "Classical cryptography remains unchanged (non-PQC)."
