"""
ECDAT V4 Temporal Crypto Agility Evaluator.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from .models import AgilityChange


def evaluate_temporal_agility(
    base_agility: Optional[Dict[str, Any]],
    target_agility: Optional[Dict[str, Any]],
) -> Tuple[AgilityChange, str]:
    """
    Evaluates cryptographic agility changes across time.
    Returns (AgilityChange, explanation).
    """
    if base_agility is None and target_agility is None:
        return AgilityChange.AGILITY_UNKNOWN, "No agility assessment available in either scan."

    if base_agility is None and target_agility is not None:
        score = target_agility.get("overall_score", 0.0)
        return AgilityChange.AGILITY_INCREASED, f"Agility baseline established at score {score}."

    if base_agility is not None and target_agility is None:
        return AgilityChange.AGILITY_UNKNOWN, "Target agility evaluation missing."

    base_score = float(base_agility.get("overall_score", 0.0))
    target_score = float(target_agility.get("overall_score", 0.0))

    score_delta = round(target_score - base_score, 3)

    if score_delta > 0.02:
        return AgilityChange.AGILITY_INCREASED, f"Cryptographic agility improved from {base_score:.2f} to {target_score:.2f} (+{score_delta:.2f})."
    elif score_delta < -0.02:
        return AgilityChange.AGILITY_DECREASED, f"Cryptographic agility degraded from {base_score:.2f} to {target_score:.2f} ({score_delta:.2f})."
    else:
        return AgilityChange.AGILITY_UNCHANGED, f"Cryptographic agility remained stable at {target_score:.2f}."
