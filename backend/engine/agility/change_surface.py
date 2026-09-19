"""
ECDAT V4 Crypto Change Surface & Blast Radius Calculator.

Computes the observed architectural footprint of a cryptographic change.
Reuses get_blast_radius() from AssetGraphService -- does not invent a parallel graph.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set
import uuid

from .evidence import AgilityEvidenceItem
from .models import (
    AgilityDimension,
    AgilityState,
    ChangeComplexity,
    CryptoChangeSurface,
    DimensionalAgility,
)


def calculate_change_surface(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    dimensions: Optional[Dict[str, DimensionalAgility]] = None,
    graph_service: Optional[Any] = None,
    blast_radius: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> CryptoChangeSurface:
    context = context or {}
    asset_id = asset.get("id", "")
    scan_id = asset.get("scan_id")


    files: Set[str] = set()
    modules: Set[str] = set()
    functions: Set[str] = set()
    call_sites = 0
    deps: Set[str] = set()
    protocols: Set[str] = set()
    certs: Set[str] = set()
    services: Set[str] = set()
    deployments: Set[str] = set()

    for item in evidence_items:
        if item.file_path:
            files.add(item.file_path)
            # Infer module name from file path
            parts = item.file_path.replace("\\", "/").split("/")
            if len(parts) > 1:
                modules.add(parts[-2])

        func = item.data.get("function_name") or item.metadata.get("function_name")
        if func:
            functions.add(func)

        sym = item.symbol or item.data.get("symbol")
        if sym:
            functions.add(sym)

        if item.has_text("call", "invoke", "direct_call", "api_use", "source_api_use"):
            call_sites += 1

        lib = item.data.get("library") or item.metadata.get("library")
        if lib:
            deps.add(lib)

        if item.has_text("tls", "ssh", "quic", "http"):
            proto = item.metadata.get("protocol") or item.data.get("protocol")
            if proto:
                protocols.add(proto)

        if item.has_text("certificate", "x509"):
            cert_id = item.metadata.get("certificate_id") or item.data.get("certificate_id")
            if cert_id:
                certs.add(cert_id)

    # Contextual assets
    if asset.get("library"):
        deps.add(asset["library"])
    if asset.get("asset_type") == "PROTOCOL":
        protocols.add(asset.get("name", ""))
    if asset.get("asset_type") == "CERTIFICATE":
        certs.add(asset.get("name", ""))

    # Reuse existing blast radius
    direct_dependents: List[str] = []
    transitive_dependents: List[str] = []
    blast: Dict[str, Any] = blast_radius or {}

    if not blast and graph_service and hasattr(graph_service, "get_blast_radius"):
        try:
            blast = graph_service.get_blast_radius(asset_id)
        except Exception:
            blast = {}

    if blast and "impacted_assets" in blast:
        for node in blast.get("impacted_assets", []):
            nid = node.get("id", "")
            ntype = node.get("asset_type", "")
            if ntype in ("SERVICE", "APPLICATION"):
                services.add(node.get("name", nid))
            direct_dependents.append(nid)

    if not direct_dependents and context.get("blast_radius_count"):
        count = int(context["blast_radius_count"])
        direct_dependents.extend([f"dep-node-{i}" for i in range(count)])

    # Complexity Assessment

    complexity_factors: List[str] = []
    dimensions = dimensions or {}

    alg_dim = dimensions.get(AgilityDimension.AGILITY_ALGORITHM.value)
    cfg_dim = dimensions.get(AgilityDimension.AGILITY_CONFIGURATION.value)
    dpl_dim = dimensions.get(AgilityDimension.AGILITY_DEPLOYMENT.value)

    if not evidence_items and not blast:
        complexity = ChangeComplexity.UNKNOWN
        complexity_factors.append("No evidence or graph connections available to assess complexity.")
    elif dpl_dim and dpl_dim.state == AgilityState.BLOCKED:
        complexity = ChangeComplexity.CRITICAL
        complexity_factors.append("Deployment agility is BLOCKED (immutable firmware / silicon lock).")
    elif alg_dim and alg_dim.state == AgilityState.CONSTRAINED and len(files) > 3:
        complexity = ChangeComplexity.HIGH
        complexity_factors.append(f"Hardcoded algorithm invocation spread across {len(files)} files.")
        if len(direct_dependents) > 5:
            complexity_factors.append(f"High graph coupling: {len(direct_dependents)} downstream dependent nodes.")
    elif alg_dim and alg_dim.state == AgilityState.BLOCKED:
        complexity = ChangeComplexity.CRITICAL
        complexity_factors.append("Algorithm replaceability is BLOCKED in stripped binary.")
    elif (cfg_dim and cfg_dim.state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)) and (alg_dim and alg_dim.state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)):
        if len(direct_dependents) > 10:
            complexity = ChangeComplexity.MEDIUM
            complexity_factors.append("Provider abstraction present, but high downstream dependent count.")
        else:
            complexity = ChangeComplexity.LOW
            complexity_factors.append("Provider abstraction and external configuration verified; low blast radius.")
    elif len(direct_dependents) > 10 or len(files) > 5 or call_sites > 15:
        complexity = ChangeComplexity.HIGH
        complexity_factors.append(f"Broad blast radius ({len(direct_dependents)} dependents, {len(files)} files, {call_sites} call sites).")
    elif len(files) > 1 or len(direct_dependents) > 2:
        complexity = ChangeComplexity.MEDIUM
        complexity_factors.append("Moderate coupling across multiple files or callers.")
    else:
        complexity = ChangeComplexity.LOW
        complexity_factors.append("Localized cryptographic call sites with manageable footprint.")

    return CryptoChangeSurface(
        asset_id=asset_id,
        surface_id=str(uuid.uuid4()),
        scan_id=scan_id,
        affected_files=sorted(list(files)),
        affected_modules=sorted(list(modules)),
        affected_functions=sorted(list(functions)),
        call_sites_count=call_sites,
        affected_dependencies=sorted(list(deps)),
        affected_protocols=sorted(list(protocols)),
        affected_certificates=sorted(list(certs)),
        affected_services=sorted(list(services)),
        affected_deployments=sorted(list(deployments)),
        direct_dependents=sorted(direct_dependents),
        transitive_dependents=sorted(transitive_dependents),
        graph_blast_radius=blast,
        complexity=complexity,
        complexity_factors=complexity_factors,
    )
