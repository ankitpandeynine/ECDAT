"""
ECDAT V4 Crypto-Agility Intelligence Engine (P2.2).

Measures cryptographic changeability across 7 independent dimensions:
1. Algorithm Replaceability
2. Configuration Agility
3. Dependency Agility
4. Protocol Agility
5. Certificate / Key Agility
6. Deployment Agility
7. Validation Agility
"""
from .models import (
    AgilityDimension,
    AgilityState,
    AgilityConfidence,
    ChangeComplexity,
    DimensionalAgility,
    CryptoChangeSurface,
    AgilityAssessment,
    AgilityReason,
)
from .agility_pipeline import evaluate_agility, evaluate_agility_for_scan

__all__ = [
    "AgilityDimension",
    "AgilityState",
    "AgilityConfidence",
    "ChangeComplexity",
    "DimensionalAgility",
    "CryptoChangeSurface",
    "AgilityAssessment",
    "AgilityReason",
    "evaluate_agility",
    "evaluate_agility_for_scan",
]
