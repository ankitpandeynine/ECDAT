"""
ECDAT V4 P3 Dependency-Aware Migration Ordering.

Uses P2.3 Blast Radius dependency paths to establish correct prerequisite sequences.
Ensures lower-level shared primitives and cryptographic libraries are upgraded
before downstream services, applications, and deployments are migrated.
"""
from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

from .models import MigrationContext


def plan_migration_dependency_order(
    context: MigrationContext,
) -> List[str]:
    """
    Extracts topological dependency order from P2.3 Blast Radius paths.
    Returns: ordered_components (List[str])
    """
    paths = context.dependency_paths

    if not paths and not context.blast_radius.get("direct_dependents") and not context.blast_radius.get("affected_assets"):
        return [context.asset_id]


    # Group components by dependency tier
    # Target Asset -> Direct Callers (Libraries/APIs) -> Applications -> Services -> Deployments
    libraries: Set[str] = set()
    applications: Set[str] = set()
    services: Set[str] = set()
    deployments: Set[str] = set()
    others: Set[str] = set()

    raw_affected = context.blast_radius.get("affected_assets", [])
    for a in raw_affected:
        atype = str(a.get("asset_type") or a.get("type", "")).upper()
        aname = a.get("name") or a.get("id")
        if atype in ("CRYPTO_LIBRARY", "DEPENDENCY", "LIBRARY"):


            libraries.add(aname)
        elif atype in ("APPLICATION", "MODULE", "BINARY"):
            applications.add(aname)
        elif atype in ("SERVICE", "MICROSERVICE"):
            services.add(aname)
        elif atype in ("DEPLOYMENT", "CONTAINER", "K8S_DEPLOYMENT"):
            deployments.add(aname)
        else:
            others.add(aname)

    # If affected_assets was sparse, pull IDs from direct/transitive dependents
    if not libraries and not applications and not services:
        for d in context.blast_radius.get("direct_dependents", []):
            libraries.add(d)
        for t in context.blast_radius.get("transitive_dependents", []):
            services.add(t)

    # Topological execution order: Target -> Libraries -> Applications -> Services -> Deployments
    ordered_sequence: List[str] = [context.asset_id]
    ordered_sequence.extend(sorted(list(libraries)))
    ordered_sequence.extend(sorted(list(applications)))
    ordered_sequence.extend(sorted(list(services)))
    ordered_sequence.extend(sorted(list(deployments)))
    ordered_sequence.extend(sorted(list(others)))

    # Deduplicate while preserving order
    deduped: List[str] = []
    seen: Set[str] = set()
    for item in ordered_sequence:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)

    return deduped
