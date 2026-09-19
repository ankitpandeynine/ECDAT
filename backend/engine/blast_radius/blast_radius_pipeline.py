"""
ECDAT V4 Master Blast Radius Pipeline (P2.3).

Orchestrates the evaluation of cryptographic blast radius:
- Bounded traversal of the authoritative Crypto Asset Graph
- Direct vs Transitive dependent classification with concrete DependencyPaths
- Categorical BlastRadiusState and architectural ImpactCategory
- Evidence-backed Architectural Criticality evaluation
- Full explainability reason chains and deterministic provenance hashes
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid

from .criticality import assess_architectural_criticality
from .evidence import compute_evidence_hash, correlate_path_evidence
from .explainability import generate_blast_radius_reason_chain
from .graph_analyzer import (
    DEFAULT_MAX_DEPTH,
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    DEFAULT_MAX_PATHS,
    BoundedGraphAnalyzer,
)
from .impact_classifier import classify_blast_radius_state, classify_impact_category
from .models import (
    BlastRadiusAssessment,
    BlastRadiusState,
    CriticalityLevel,
    GraphConfidence,
    ImpactCategory,
)
from .normalizer import compute_canonical_graph_hash, normalize_node


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def evaluate_blast_radius(
    target_asset: Dict[str, Any],
    graph_service: Optional[Any] = None,
    evidence_items: Optional[List[Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    raw_edges: Optional[List[Dict[str, Any]]] = None,
    raw_nodes: Optional[List[Dict[str, Any]]] = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> BlastRadiusAssessment:
    """
    Evaluates evidence-driven blast radius and impact for target_asset.
    Answers: 'If this cryptographic asset changes, what other assets may be affected?'
    """
    target_norm = normalize_node(target_asset)
    target_id = target_norm["id"] or target_asset.get("id", str(uuid.uuid4()))
    scan_id = target_asset.get("scan_id")
    project_id = target_asset.get("project") or target_asset.get("project_id")
    context = dict(context or {})
    evidence_items = list(evidence_items or [])

    # 1. Bounded graph traversal
    analyzer = BoundedGraphAnalyzer(
        max_depth=max_depth,
        max_paths=max_paths,
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
    traversal_result = analyzer.analyze_blast_radius(
        target_asset_id=target_id,
        graph_service=graph_service,
        raw_edges=raw_edges,
        raw_nodes=raw_nodes,
    )

    discovered_paths = traversal_result["dependency_paths"]
    impacted_assets = traversal_result["impacted_assets"]
    direct_dependents = traversal_result["direct_dependents"]
    transitive_dependents = traversal_result["transitive_dependents"]
    partial_result = traversal_result["partial_result"]
    limitations = list(traversal_result["limitations"])
    graph_scope = traversal_result["graph_scope"]

    # 2. Correlate path evidence and check for contradictions
    ev_refs, supporting_ev, contradicting_ev, has_contradiction = correlate_path_evidence(
        paths=discovered_paths,
        evidence_items=evidence_items,
    )

    # 3. Classify Categorical State
    state, state_rationale = classify_blast_radius_state(
        paths=discovered_paths,
        impacted_assets=impacted_assets,
        context=context,
        has_contradiction=has_contradiction,
    )

    # 4. Classify Architectural Impact Category
    impact_category, impact_rationale = classify_impact_category(
        paths=discovered_paths,
        impacted_assets=impacted_assets,
        context=context,
        has_contradiction=has_contradiction,
    )

    # 5. Assess Architectural Criticality
    criticality, crit_factors, crit_limitations = assess_architectural_criticality(
        target_asset=target_norm,
        impacted_assets=impacted_assets,
        context=context,
    )
    limitations.extend(crit_limitations)

    # 6. Categorize Affected Assets by Type
    affected_files: List[str] = []
    affected_modules: List[str] = []
    affected_functions: List[str] = []
    affected_call_sites: int = 0
    affected_dependencies: List[str] = []
    affected_protocols: List[str] = []
    affected_certificates: List[str] = []
    affected_services: List[str] = []
    affected_deployments: List[str] = []
    affected_data_assets: List[str] = []

    for a in impacted_assets:
        atype = str(a.get("asset_type", "")).upper()
        aname = a.get("name") or a.get("id")
        if a.get("file_path"):
            affected_files.append(str(a["file_path"]))
        if a.get("module"):
            affected_modules.append(str(a["module"]))
        if atype in ("FUNCTION", "BINARY_CRYPTO_FUNCTION", "CRYPTO_API"):
            affected_functions.append(aname)
        if atype in ("DEPENDENCY", "CRYPTO_LIBRARY"):
            affected_dependencies.append(aname)
        if atype == "PROTOCOL":
            affected_protocols.append(aname)
        if atype == "CERTIFICATE":
            affected_certificates.append(aname)
        if atype in ("SERVICE", "MICROSERVICE"):
            affected_services.append(aname)
        if atype in ("DEPLOYMENT", "K8S_DEPLOYMENT", "CONTAINER"):
            affected_deployments.append(aname)
        if atype == "DATA_ASSET" or "DATA" in atype:
            affected_data_assets.append(aname)
        if a.get("call_sites"):
            try:
                affected_call_sites += int(a["call_sites"])
            except (ValueError, TypeError):
                pass

    # Tally call sites from direct caller edges if call_sites metadata missing
    if affected_call_sites == 0:
        affected_call_sites = len([p for p in discovered_paths if p.path_length == 1])

    # 7. Overall Graph Confidence
    if has_contradiction:
        confidence = GraphConfidence.CONTRADICTED
    elif context.get("scanner_unavailable") or context.get("graph_unavailable"):
        confidence = GraphConfidence.UNKNOWN
    elif not discovered_paths and not impacted_assets:
        confidence = GraphConfidence.MEASURED
    elif all(p.confidence == GraphConfidence.MEASURED.value for p in discovered_paths):
        confidence = GraphConfidence.MEASURED
    else:
        confidence = GraphConfidence.INFERRED

    # 8. Deterministic Provenance Hashes
    traversed_edges = traversal_result.get("traversal_edges", [])
    graph_hash = compute_canonical_graph_hash(
        nodes=[target_norm] + impacted_assets,
        edges=traversed_edges,
    )
    evidence_hash = compute_evidence_hash(ev_refs)
    cfg_payload = {
        "max_depth": max_depth,
        "max_paths": max_paths,
        "max_nodes": max_nodes,
        "max_edges": max_edges,
        "context": context,
    }
    configuration_hash = hashlib.sha256(
        json.dumps(cfg_payload, sort_keys=True).encode("utf-8")
    ).hexdigest()

    # 9. Explainability Reason Chain
    assessment_dict = {
        "asset_id": target_id,
        "state": state.value,
        "impact_category": impact_category.value,
        "criticality": criticality.value,
    }
    reason_chain = generate_blast_radius_reason_chain(
        assessment_data=assessment_dict,
        direct_dependents=direct_dependents,
        transitive_dependents=transitive_dependents,
        dependency_paths=discovered_paths,
        impact_rationale=state_rationale + impact_rationale,
        criticality_factors=crit_factors,
        limitations=limitations,
    )

    # 10. Assemble and return final assessment
    return BlastRadiusAssessment(
        assessment_id=str(uuid.uuid4()),
        asset_id=target_id,
        scan_id=scan_id,
        project_id=project_id,
        state=state,
        impact_category=impact_category,
        criticality=criticality,
        confidence=confidence,
        direct_dependents=sorted(list(set(direct_dependents))),
        transitive_dependents=sorted(list(set(transitive_dependents))),
        affected_assets=impacted_assets,
        affected_files=sorted(list(set(affected_files))),
        affected_modules=sorted(list(set(affected_modules))),
        affected_functions=sorted(list(set(affected_functions))),
        affected_call_sites=affected_call_sites,
        affected_dependencies=sorted(list(set(affected_dependencies))),
        affected_protocols=sorted(list(set(affected_protocols))),
        affected_certificates=sorted(list(set(affected_certificates))),
        affected_services=sorted(list(set(affected_services))),
        affected_deployments=sorted(list(set(affected_deployments))),
        affected_data_assets=sorted(list(set(affected_data_assets))),
        dependency_paths=discovered_paths,
        evidence_refs=ev_refs,
        supporting_evidence=supporting_ev,
        contradicting_evidence=contradicting_ev,
        unknowns=[lim for lim in limitations if "unknown" in lim.lower()],
        limitations=sorted(list(set(limitations))),
        reason_chain=reason_chain,
        graph_hash=graph_hash,
        evidence_hash=evidence_hash,
        configuration_hash=configuration_hash,
        knowledge_base_version="2024.1",
        engine_version="4.0.0",
        created_at=now_iso(),
        graph_scope=graph_scope,
        max_depth=max_depth,
        max_paths=max_paths,
        max_nodes=max_nodes,
        max_edges=max_edges,
        partial_result=partial_result,
    )
