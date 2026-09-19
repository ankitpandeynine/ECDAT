"""
ECDAT V4 Agility Dimension 3: Dependency Agility (AGILITY_DEPENDENCY).

Evaluates whether cryptographic libraries and providers can be upgraded or replaced
via standard dependency management vs pinned/vendored/statically-linked barriers.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from ..evidence import (
    AgilityEvidenceItem,
    extract_confidence,
    is_dimension_scanner_unavailable,
)
from ..models import (
    AgilityConfidence,
    AgilityDimension,
    AgilityReason,
    AgilityState,
    DimensionalAgility,
)


def assess_dependency_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_DEPENDENCY

    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Dependency analyzer was unavailable."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_pluggable_module = False
    has_package_dependency = False
    has_pinned_dependency = False
    has_vendored = False
    has_static_proprietary = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        if item.has_text("dynamic_library", "provider_interface", "dynamic_provider", "shared_library"):
            has_pluggable_module = True
            supporting.append(f"Pluggable/dynamic library provider observed: {item.description}")

        if item.has_text("dependency_declaration", "package_manager", "pip", "npm", "cargo", "maven"):
            has_package_dependency = True
            supporting.append(f"Standard package manager dependency declaration: {item.description}")

        if item.has_text("dependency_lock", "pinned_version", "hash_pinning"):
            has_pinned_dependency = True
            contradicting.append(f"Strictly pinned dependency lockfile: {item.description}")

        if item.has_text("vendored_source", "in_tree_crypto"):
            has_vendored = True
            contradicting.append(f"Vendored in-tree cryptographic dependency: {item.description}")

        if item.has_text("static_binary_binding", "proprietary_binary_blob", "no_source_available"):
            has_static_proprietary = True
            contradicting.append(f"Statically bound proprietary binary without source: {item.description}")

    # Note on graph centrality:
    centrality = context.get("graph_centrality", 0.0)
    blast_count = context.get("blast_radius_count", 0)
    if blast_count > 5 or centrality > 0.5:
        # AXIOM: Graph centrality indicates coupling/change surface, NOT low agility!
        unknowns.append(f"High graph coupling ({blast_count} downstream nodes); coupling affects change surface, not individual dependency agility.")

    confidence = extract_confidence(evidence_items)

    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["No dependency manifests or package manager lockfiles observed for this asset."],
            limitations=["External dependency management could not be verified."],
            derived_score=None,
        )

    # Determine State
    if has_static_proprietary:
        state = AgilityState.BLOCKED
        score = 0.0
        claim = "Statically bound proprietary crypto library with no replacement provider interface."
    elif has_pluggable_module:
        state = AgilityState.OBSERVED
        score = 1.0
        claim = "Pluggable modular cryptographic provider allows drop-in replacement on disk."
    elif has_vendored:
        state = AgilityState.CONSTRAINED
        score = 0.25
        claim = "Cryptographic library is vendored in-tree; upstream updates require manual patching."
    elif has_package_dependency and has_pinned_dependency:
        # AXIOM: Pinned lockfile is PARTIALLY_OBSERVED (upgrades supported via package manager, but constrained by lock)
        state = AgilityState.PARTIALLY_OBSERVED
        score = 0.60
        claim = "Standard package dependency with lockfile pinning; updates require lockfile regeneration and testing."
        limitations.append("Dependency lockfile prevents spontaneous upgrades without explicit developer intervention.")
    elif has_package_dependency:
        state = AgilityState.SUPPORTED
        score = 0.80
        claim = "Declared via standard package manager, enabling straightforward version upgrades."
    elif has_pinned_dependency:
        state = AgilityState.CONSTRAINED
        score = 0.35
        claim = "Strictly pinned dependency with update friction."
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Dependency agility could not be determined from available evidence."
        unknowns.append("No package manifests or link analysis observed.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="DEPENDENCY_AGILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-DEP-001" if state == AgilityState.OBSERVED else ("AGL-DEP-002" if state == AgilityState.SUPPORTED else ("AGL-DEP-003" if state in (AgilityState.CONSTRAINED, AgilityState.PARTIALLY_OBSERVED) else ("AGL-DEP-004" if state == AgilityState.BLOCKED else None))),
            rule_version="1.0",
            evidence_refs=evidence_refs,
            supporting=supporting,
            contradicting=contradicting,
            unknowns=unknowns,
            limitations=limitations,
        )
    )

    return DimensionalAgility(
        dimension=dimension,
        state=state,
        confidence=confidence,
        evidence_refs=evidence_refs,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        unknowns=unknowns,
        limitations=limitations,
        reason_chain=reasons,
        derived_score=score,
    )
