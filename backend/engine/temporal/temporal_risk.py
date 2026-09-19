"""
ECDAT V4 Temporal Risk Change Evaluator.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from .models import RiskChange

LEVEL_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def evaluate_temporal_risk(
    base_risk: Optional[Dict[str, Any]],
    target_risk: Optional[Dict[str, Any]],
) -> Tuple[RiskChange, str]:
    """
    Evaluates how risk evolved between base and target observations.
    Returns (RiskChange, explanation).
    """
    if base_risk is None and target_risk is None:
        return RiskChange.RISK_UNKNOWN, "No risk assessment available in either scan."

    if base_risk is None and target_risk is not None:
        level = target_risk.get("risk_level", "UNKNOWN")
        score = target_risk.get("risk_score", target_risk.get("mosca_score", "N/A"))
        return RiskChange.RISK_NEW, f"Newly observed asset introduced into inventory with {level} risk (score: {score})."

    if base_risk is not None and target_risk is None:
        b_level = base_risk.get("risk_level", "UNKNOWN")
        return RiskChange.RISK_DECREASED, f"Asset was previously observed with {b_level} risk, but is not present in target scan."

    # Both base and target risk present
    base_score = base_risk.get("risk_score", base_risk.get("mosca_score"))
    target_score = target_risk.get("risk_score", target_risk.get("mosca_score"))

    base_level = str(base_risk.get("risk_level", "")).upper()
    target_level = str(target_risk.get("risk_level", "")).upper()

    # Compare numeric scores if both valid numbers
    if base_score is not None and target_score is not None:
        try:
            bs = float(base_score)
            ts = float(target_score)
            if round(ts, 2) > round(bs, 2):
                return RiskChange.RISK_INCREASED, f"Risk score increased from {bs:.2f} ({base_level}) to {ts:.2f} ({target_level})."
            elif round(ts, 2) < round(bs, 2):
                return RiskChange.RISK_DECREASED, f"Risk score decreased from {bs:.2f} ({base_level}) to {ts:.2f} ({target_level})."
            else:
                return RiskChange.RISK_UNCHANGED, f"Risk score unchanged at {ts:.2f} ({target_level})."
        except (ValueError, TypeError):
            pass

    # Compare levels
    b_rank = LEVEL_ORDER.get(base_level, 0)
    t_rank = LEVEL_ORDER.get(target_level, 0)

    if t_rank > b_rank and t_rank > 0 and b_rank > 0:
        return RiskChange.RISK_INCREASED, f"Risk level escalated from {base_level} to {target_level}."
    elif t_rank < b_rank and t_rank > 0 and b_rank > 0:
        return RiskChange.RISK_DECREASED, f"Risk level reduced from {base_level} to {target_level}."
    elif b_rank == t_rank and b_rank > 0:
        return RiskChange.RISK_UNCHANGED, f"Risk level remained stable at {target_level}."

    return RiskChange.RISK_UNKNOWN, f"Indeterminate risk delta (base: {base_level}, target: {target_level})."
