"""
ECDAT V4 P2.3 Blast Radius State & Impact Classifier.

Classifies the topological state and architectural impact category of blast radius
purely from observed graph relationships, avoiding conflation with risk or agility.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from .dependency_paths import has_independent_multi_paths
from .models import BlastRadiusState, DependencyPath, ImpactCategory


def classify_blast_radius_state(
    paths: List[DependencyPath],
    impacted_assets: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
    has_contradiction: bool = False,
) -> Tuple[BlastRadiusState, List[str]]:
    """
    Determines categorical BlastRadiusState from graph topology.
    Returns: (BlastRadiusState, rationale_bullets)
    """
    context = context or {}
    rationale: List[str] = []

    if context.get("scanner_unavailable") or context.get("graph_unavailable"):
        rationale.append("Graph analysis or dependency scanner was unavailable.")
        return BlastRadiusState.SCANNER_UNAVAILABLE, rationale

    if has_contradiction:
        rationale.append("Conflicting graph relationships or removal evidence prevents definitive state.")
        return BlastRadiusState.INCONCLUSIVE, rationale

    if context.get("insufficient_evidence") or context.get("missing_graph_data"):
        rationale.append("Insufficient graph connectivity evidence observed.")
        return BlastRadiusState.UNKNOWN, rationale

    if not paths and not impacted_assets:
        rationale.append("Graph was successfully queried and zero dependents were observed within analyzed scope.")
        return BlastRadiusState.NO_DEPENDENTS_OBSERVED, rationale

    # Check for independent multi-paths
    if has_independent_multi_paths(paths):
        rationale.append("Multiple independent dependency paths link target asset to downstream consumers.")
        return BlastRadiusState.MULTI_PATH, rationale

    services_count = len({
        a["id"] for a in impacted_assets
        if str(a.get("asset_type", "")).upper() in ("SERVICE", "MICROSERVICE")
    })
    deployments_count = len({
        a["id"] for a in impacted_assets
        if str(a.get("asset_type", "")).upper() in ("DEPLOYMENT", "K8S_DEPLOYMENT", "CONTAINER")
    })

    if services_count >= 3 or len(impacted_assets) >= 15 or deployments_count >= 2:
        rationale.append("Impact spans widespread architectural scope across multiple services or deployment units.")
        return BlastRadiusState.WIDESPREAD, rationale

    # Check direct vs transitive
    has_transitive = any(p.path_length > 1 for p in paths)
    has_direct = any(p.path_length == 1 for p in paths)

    if has_direct and not has_transitive:
        rationale.append("All observed dependency paths are direct single-hop connections.")
        return BlastRadiusState.DIRECT_ONLY, rationale

    if has_transitive and len(impacted_assets) <= 3 and services_count <= 1:
        rationale.append("Transitive dependencies observed but impact remains contained within local service boundary.")
        return BlastRadiusState.CONTAINED, rationale

    if has_transitive:
        rationale.append("Transitive multi-hop dependency paths observed.")
        return BlastRadiusState.TRANSITIVE, rationale

    return BlastRadiusState.UNKNOWN, rationale


def classify_impact_category(
    paths: List[DependencyPath],
    impacted_assets: List[Dict[str, Any]],
    context: Optional[Dict[str, Any]] = None,
    has_contradiction: bool = False,
) -> Tuple[ImpactCategory, List[str]]:
    """
    Determines architectural ImpactCategory from graph footprint.
    Returns: (ImpactCategory, rationale_bullets)
    """
    context = context or {}
    rationale: List[str] = []

    if context.get("scanner_unavailable") or context.get("graph_unavailable"):
        return ImpactCategory.SCANNER_UNAVAILABLE, ["Graph scanner unavailable."]

    if has_contradiction:
        return ImpactCategory.INCONCLUSIVE, ["Inconclusive due to conflicting graph relationships."]

    if not paths and not impacted_assets:
        return ImpactCategory.NONE_OBSERVED, ["Zero dependent assets observed in current graph scope."]

    services = {
        a["id"] for a in impacted_assets
        if str(a.get("asset_type", "")).upper() in ("SERVICE", "MICROSERVICE")
    }
    deployments = {
        a["id"] for a in impacted_assets
        if str(a.get("asset_type", "")).upper() in ("DEPLOYMENT", "K8S_DEPLOYMENT", "CONTAINER")
    }

    if len(services) >= 5 or len(impacted_assets) >= 20:
        rationale.append(f"Widespread impact across {len(services)} services and {len(impacted_assets)} total assets.")
        return ImpactCategory.WIDESPREAD, rationale

    if len(deployments) >= 2:
        rationale.append(f"Cross-deployment impact across {len(deployments)} independent deployment units.")
        return ImpactCategory.CROSS_DEPLOYMENT, rationale

    if len(services) >= 2:
        rationale.append(f"Multi-service impact across {len(services)} distinct services.")
        return ImpactCategory.MULTI_SERVICE, rationale

    # Check if transitive or direct
    has_transitive = any(p.path_length > 1 for p in paths)
    if has_transitive:
        rationale.append("Transitive propagation within a single application/service boundary.")
        return ImpactCategory.TRANSITIVE, rationale

    # Check if local (same module/file)
    modules = {a.get("module") for a in impacted_assets if a.get("module")}
    if len(modules) == 1 and len(impacted_assets) <= 2:
        rationale.append("Impact strictly localized to single module.")
        return ImpactCategory.LOCAL, rationale

    rationale.append("Direct single-hop consumers impacted.")
    return ImpactCategory.DIRECT, rationale
