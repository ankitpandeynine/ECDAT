"""
ECDAT V4 P2.3 Architectural Criticality Assessment.

Evaluates the architectural importance of an asset or its impacted consumers
based strictly on concrete metadata and relationship evidence, avoiding speculative
business criticality assumptions.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .models import CriticalityLevel


def assess_architectural_criticality(
    target_asset: Dict[str, Any],
    impacted_assets: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
) -> Tuple[CriticalityLevel, List[str], List[str]]:
    """
    Evaluates architectural criticality.
    Returns: (CriticalityLevel, factors, limitations)
    """
    context = context or {}
    factors: List[str] = []
    limitations: List[str] = []

    # Check for explicit production indicators
    is_prod = (
        target_asset.get("is_production")
        or str(target_asset.get("environment", "")).lower() == "production"
        or context.get("is_production")
        or any(a.get("is_production") for a in impacted_assets)
    )

    # Check for data protection relationship
    protects_data = (
        context.get("protects_data_asset")
        or any(a.get("asset_type") == "DATA_ASSET" for a in impacted_assets)
        or any("data" in str(a.get("asset_type", "")).lower() for a in impacted_assets)
    )

    # Check for external exposure
    externally_exposed = (
        target_asset.get("is_externally_exposed")
        or context.get("is_externally_exposed")
        or any(a.get("is_externally_exposed") for a in impacted_assets)
    )

    # Check for dev / test environment
    env = str(target_asset.get("environment", "")).lower()
    is_dev = env in ("dev", "development", "test", "testing", "staging") or context.get("is_dev")

    # AXIOM: Do not infer business criticality from number of dependents or centrality alone
    if len(impacted_assets) > 10:
        limitations.append("High dependent count reflects architectural footprint, not business importance.")

    if externally_exposed and not is_prod:
        limitations.append("External exposure indicates network accessibility, but does not guarantee production status.")

    if is_prod:
        factors.append("Asset or downstream consumer is deployed in a verified production environment (Rule BLST-CRT-001).")
        return CriticalityLevel.CRITICAL, factors, limitations

    if protects_data:
        factors.append("Asset directly protects persistent or sensitive data assets (Rule BLST-CRT-002).")
        return CriticalityLevel.HIGH, factors, limitations

    if externally_exposed:
        factors.append("Asset or consumer is an externally exposed ingress endpoint (Rule BLST-CRT-003).")
        return CriticalityLevel.HIGH, factors, limitations

    if any(a.get("asset_type") in ("SERVICE", "APPLICATION") for a in impacted_assets):
        factors.append("Asset serves internal microservices or application modules (Rule BLST-CRT-004).")
        return CriticalityLevel.MEDIUM, factors, limitations

    if is_dev:
        factors.append("Asset resides in a development or ephemeral test environment (Rule BLST-CRT-005).")
        return CriticalityLevel.LOW, factors, limitations

    # Default to UNKNOWN if no concrete indicators exist
    limitations.append("Insufficient architectural metadata to classify criticality without speculation (Rule BLST-CRT-006).")
    return CriticalityLevel.UNKNOWN, factors, limitations
