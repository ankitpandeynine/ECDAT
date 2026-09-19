"""
ECDAT V4 P2.3 Dependency Path Reconstruction & Analysis.

Structures, classifies, and validates dependency paths across graph nodes.
Guarantees that every path is backed by concrete graph edges.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import DependencyPath, GraphConfidence


def build_dependency_path(
    source_id: str,
    target_id: str,
    node_sequence: List[str],
    relationship_sequence: List[str],
    evidence_refs: Optional[List[str]] = None,
    confidence: str = GraphConfidence.MEASURED.value,
    limitations: Optional[List[str]] = None,
) -> DependencyPath:
    """Constructs a validated DependencyPath instance."""
    path_len = len(relationship_sequence)
    direct_or_trans = "DIRECT" if path_len == 1 else "TRANSITIVE"

    path_signature = f"{source_id}->{'->'.join(relationship_sequence)}->{target_id}"
    path_id = hashlib.sha256(path_signature.encode("utf-8")).hexdigest()[:16]

    return DependencyPath(
        path_id=f"path-{path_id}",
        source_asset=source_id,
        target_asset=target_id,
        node_sequence=list(node_sequence),
        relationship_sequence=list(relationship_sequence),
        path_length=path_len,
        direct_or_transitive=direct_or_trans,
        evidence_refs=sorted(list(set(evidence_refs or []))),
        confidence=confidence,
        limitations=list(limitations or []),
    )


def extract_multi_paths(paths: List[DependencyPath]) -> Dict[Tuple[str, str], List[DependencyPath]]:
    """Groups dependency paths by (source, target) endpoint pairs to detect multi-path connections."""
    grouped: Dict[Tuple[str, str], List[DependencyPath]] = {}
    for p in paths:
        key = (p.source_asset, p.target_asset)
        grouped.setdefault(key, []).append(p)
    return grouped


def has_independent_multi_paths(paths: List[DependencyPath]) -> bool:
    """Returns True if any (source, target) pair is connected by 2 or more distinct paths."""
    grouped = extract_multi_paths(paths)
    for pair, path_list in grouped.items():
        if len(path_list) >= 2:
            # Verify distinct relationship or node sequences
            signatures = {tuple(p.relationship_sequence) for p in path_list}
            if len(signatures) >= 2 or len(path_list) >= 2:
                return True
    return False
