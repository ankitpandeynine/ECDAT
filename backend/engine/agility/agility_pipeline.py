"""
ECDAT V4 Master Agility Pipeline (P2.2).

Orchestrates the evaluation of all 7 cryptographic agility dimensions,
computes change surfaces, determines overall agility state, and generates
transparent explainability records.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid

from .change_surface import calculate_change_surface
from .dimensions import (
    assess_algorithm_agility,
    assess_certificate_agility,
    assess_configuration_agility,
    assess_dependency_agility,
    assess_deployment_agility,
    assess_protocol_agility,
    assess_validation_agility,
)
from .evidence import AgilityEvidenceItem
from .models import (
    AgilityAssessment,
    AgilityDimension,
    AgilityReason,
    AgilityState,
    DimensionalAgility,
)


def evaluate_agility(
    asset: Dict[str, Any],
    evidence_items: Optional[List[Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    graph_service: Optional[Any] = None,
    blast_radius: Optional[Dict[str, Any]] = None,
) -> AgilityAssessment:
    """Evaluates an asset across all 7 cryptographic agility dimensions."""
    asset_id = asset.get("id", str(uuid.uuid4()))
    scan_id = asset.get("scan_id")
    context = context or {}

    # Normalize raw evidence
    normalized_evidence: List[AgilityEvidenceItem] = []
    if evidence_items:
        for e in evidence_items:
            normalized_evidence.append(AgilityEvidenceItem(e))

    # Evaluate 7 dimensions independently
    dims: Dict[str, DimensionalAgility] = {}

    d1 = assess_algorithm_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_ALGORITHM.value] = d1

    d2 = assess_configuration_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_CONFIGURATION.value] = d2

    d3 = assess_dependency_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_DEPENDENCY.value] = d3

    d4 = assess_protocol_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_PROTOCOL.value] = d4

    d5 = assess_certificate_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_CERTIFICATE.value] = d5

    d6 = assess_deployment_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_DEPLOYMENT.value] = d6

    d7 = assess_validation_agility(asset, normalized_evidence, context)
    dims[AgilityDimension.AGILITY_VALIDATION.value] = d7

    # Calculate change surface
    change_surf = calculate_change_surface(
        asset=asset,
        evidence_items=normalized_evidence,
        dimensions=dims,
        graph_service=graph_service,
        blast_radius=blast_radius,
        context=context,
    )


    # Determine Overall State & Derived Composite Score
    # Filter active (applicable) dimensions
    active_dims = [
        d for d in dims.values()
        if d.state not in (AgilityState.NOT_APPLICABLE, AgilityState.SCANNER_UNAVAILABLE)
    ]

    all_reasons: List[AgilityReason] = []
    all_unknowns: List[str] = []
    all_limitations: List[str] = []

    for d in dims.values():
        all_reasons.extend(d.reason_chain)
        all_unknowns.extend(d.unknowns)
        all_limitations.extend(d.limitations)

    states = {d.state for d in active_dims}

    if not active_dims:
        if any(d.state == AgilityState.SCANNER_UNAVAILABLE for d in dims.values()):
            overall_state = AgilityState.SCANNER_UNAVAILABLE
        else:
            overall_state = AgilityState.NOT_APPLICABLE
    elif states == {AgilityState.UNKNOWN}:
        overall_state = AgilityState.UNKNOWN
    elif AgilityState.BLOCKED in states:
        overall_state = AgilityState.BLOCKED
    elif (AgilityState.CONSTRAINED in states) and (AgilityState.OBSERVED in states or AgilityState.SUPPORTED in states):
        overall_state = AgilityState.PARTIALLY_OBSERVED
    elif AgilityState.PARTIALLY_OBSERVED in states:
        overall_state = AgilityState.PARTIALLY_OBSERVED
    elif states.issubset({AgilityState.OBSERVED, AgilityState.SUPPORTED, AgilityState.UNKNOWN}):
        if AgilityState.OBSERVED in states:
            overall_state = AgilityState.OBSERVED
        elif AgilityState.SUPPORTED in states:
            overall_state = AgilityState.SUPPORTED
        else:
            overall_state = AgilityState.UNKNOWN
    elif states.issubset({AgilityState.CONSTRAINED, AgilityState.UNKNOWN}):
        overall_state = AgilityState.CONSTRAINED
    else:
        overall_state = AgilityState.PARTIALLY_OBSERVED

    # Composite derived score calculation:
    # AXIOM: Score is DERIVED. Dimensions are authoritative.
    # Missing/unknown dimensions do NOT silently become 0.
    scored_dims = [d for d in active_dims if d.derived_score is not None]
    if scored_dims:
        composite_score = round(sum(d.derived_score for d in scored_dims) / len(scored_dims), 2)
        derived_meta = {
            "is_derived": True,
            "formula": "unweighted_mean_of_applicable_dimensions",
            "scored_dimensions_count": len(scored_dims),
            "excluded_unknown_count": len(active_dims) - len(scored_dims),
            "scale": "0.00 (Rigid) to 1.00 (Fully Agile)",
        }
    else:
        composite_score = None
        derived_meta = {
            "is_derived": True,
            "formula": "unweighted_mean_of_applicable_dimensions",
            "scored_dimensions_count": 0,
            "excluded_unknown_count": len(active_dims),
            "note": "No dimensions had sufficient concrete evidence for numeric derivation.",
        }

    # Deterministic Hashes
    evidence_ids = sorted([item.id for item in normalized_evidence])
    ev_hash = hashlib.sha256(json.dumps(evidence_ids, sort_keys=True).encode("utf-8")).hexdigest()
    cfg_hash = hashlib.sha256(json.dumps(context, sort_keys=True).encode("utf-8")).hexdigest()

    return AgilityAssessment(
        assessment_id=str(uuid.uuid4()),
        asset_id=asset_id,
        scan_id=scan_id,
        overall_state=overall_state,
        composite_score=composite_score,
        derived_score_metadata=derived_meta,
        dimensions=dims,
        change_surface=change_surf,
        reasons=all_reasons,
        unknowns=sorted(list(set(all_unknowns))),
        limitations=sorted(list(set(all_limitations))),
        evidence_hash=ev_hash,
        configuration_hash=cfg_hash,
        knowledge_base_version="2024.1",
        engine_version="4.0.0",
    )


def evaluate_agility_for_scan(
    scan_id: str,
    project: str,
    store: Any,
) -> List[AgilityAssessment]:
    """Evaluates agility for all assets associated with a scan."""
    assets = store.get_assets(project, scan_id=scan_id)
    assessments: List[AgilityAssessment] = []

    for asset_dict in assets:
        asset_id = asset_dict["id"]
        evidence = store.get_asset_evidence(asset_id)
        blast = store.get_blast_radius(asset_id)
        assessment = evaluate_agility(
            asset=asset_dict,
            evidence_items=evidence,
            graph_service=store,
            blast_radius=blast,
        )
        if hasattr(store, "save_agility_assessment"):
            store.save_agility_assessment(assessment)
        assessments.append(assessment)

    return assessments
