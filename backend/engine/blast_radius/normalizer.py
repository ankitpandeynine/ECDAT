"""
ECDAT V4 P2.3 Blast Radius Graph & Edge Normalizer.

Ensures consistent representation of graph nodes, edges, relationship types,
and computes deterministic SHA-256 graph hashes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple


RELEVANT_RELATIONSHIPS = {
    "USES",
    "DEPENDS_ON",
    "IMPLEMENTS",
    "PROTECTS",
    "SERVES",
    "PRESENT_ON",
    "PROVIDES",
    "CALLS",
    "CONTAINS",
    "CONFIGURED_BY",
    "BINDS_TO",
}

EXCLUDED_RELATIONSHIPS = {
    "EVIDENCED_BY",
    "OBSERVED_BY",
    "MIGRATES_TO",
    "SCAN_TARGET",
}


def normalize_relationship(rel: Any) -> str:
    """Canonicalizes relationship string or enum."""
    if hasattr(rel, "value"):
        rel = rel.value
    s = str(rel or "").strip().upper().replace("-", "_")
    return s


def is_relevant_relationship(rel: str) -> bool:
    """Returns True if edge represents an architectural or runtime dependency."""
    norm = normalize_relationship(rel)
    if norm in EXCLUDED_RELATIONSHIPS:
        return False
    return norm in RELEVANT_RELATIONSHIPS or "DEPEND" in norm or "USE" in norm or "CALL" in norm


def normalize_node(node: Any) -> Dict[str, Any]:
    """Normalizes an asset node into a standard dictionary."""
    if hasattr(node, "to_dict"):
        data = node.to_dict()
    elif isinstance(node, dict):
        data = dict(node)
    else:
        data = {"id": str(node), "name": str(node)}

    return {
        "id": str(data.get("id") or ""),
        "name": str(data.get("name") or data.get("id") or "Unknown"),
        "asset_type": str(data.get("asset_type") or data.get("type") or "UNKNOWN").upper(),
        "algorithm": str(data.get("algorithm") or ""),
        "file_path": data.get("file_path") or data.get("path"),
        "module": data.get("module"),
        "environment": str(data.get("environment") or data.get("env") or "").lower(),
        "is_production": bool(data.get("is_production", False) or str(data.get("environment", "")).lower() == "production"),
        "is_externally_exposed": bool(data.get("is_externally_exposed", False) or data.get("public_ingress", False)),
        "metadata": data.get("metadata", {}),
    }


def normalize_edge(edge: Any) -> Dict[str, Any]:
    """Normalizes a graph edge into a standard dictionary."""
    if hasattr(edge, "to_dict"):
        data = edge.to_dict()
    elif isinstance(edge, dict):
        data = dict(edge)
    else:
        data = {}

    rel = normalize_relationship(data.get("relationship") or data.get("rel") or "USES")
    return {
        "id": str(data.get("id") or ""),
        "source_id": str(data.get("source_id") or data.get("source") or ""),
        "source_type": str(data.get("source_type") or "").upper(),
        "target_id": str(data.get("target_id") or data.get("target") or ""),
        "target_type": str(data.get("target_type") or "").upper(),
        "relationship": rel,
        "evidence_id": data.get("evidence_id"),
        "confidence": float(data.get("confidence", 1.0)),
        "project": data.get("project"),
        "scan_id": data.get("scan_id"),
    }


def compute_canonical_graph_hash(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> str:
    """
    Computes a deterministic SHA-256 hash over relevant graph topology.
    Omits timestamps, database primary keys, and random UUIDs.
    """
    canonical_nodes = []
    for n in nodes:
        canonical_nodes.append({
            "id": n.get("id", ""),
            "name": n.get("name", ""),
            "type": n.get("asset_type", ""),
        })
    canonical_nodes.sort(key=lambda x: (x["id"], x["name"]))

    canonical_edges = []
    for e in edges:
        canonical_edges.append({
            "source": e.get("source_id", ""),
            "target": e.get("target_id", ""),
            "rel": normalize_relationship(e.get("relationship", "")),
        })
    canonical_edges.sort(key=lambda x: (x["source"], x["target"], x["rel"]))

    payload = {
        "nodes": canonical_nodes,
        "edges": canonical_edges,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
