"""
ECDAT V4 P2.3 Blast Radius Evidence Correlation & Provenance.

Correlates P0/P1/P2 evidence with graph edges, checks for contradictory
evidence, and computes cryptographic provenance hashes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple

from .models import GraphConfidence


def correlate_path_evidence(
    paths: List[Any],
    evidence_items: List[Any],
) -> Tuple[List[str], List[str], List[str], bool]:
    """
    Correlates evidence items with discovered paths.
    Returns: (evidence_refs, supporting, contradicting, has_contradiction)
    """
    evidence_refs: Set[str] = set()
    supporting: List[str] = []
    contradicting: List[str] = []
    has_contradiction = False

    # Extract evidence IDs from path relationships
    for p in paths:
        for ref in p.evidence_refs:
            if ref:
                evidence_refs.add(ref)

    # Check evidence items
    for item in evidence_items:
        data = item.to_dict() if hasattr(item, "to_dict") else (dict(item) if isinstance(item, dict) else {"description": str(item)})
        eid = data.get("id") or data.get("evidence_id")
        desc = str(data.get("description", ""))
        state = str(data.get("state", ""))

        if eid:
            evidence_refs.add(eid)

        # Check for contradictions
        if "CONTRADICTED" in state or "dependency_removed" in desc.lower() or "unlinked" in desc.lower() or "dead_code" in desc.lower():
            contradicting.append(f"Contradictory evidence detected: {desc}")
            has_contradiction = True
        elif data.get("level") in ("E3", "E4", "E5") or "MEASURED" in state:
            supporting.append(f"Verified graph relationship: {desc}")
        elif desc:
            supporting.append(f"Evidenced connection: {desc}")

    return sorted(list(evidence_refs)), supporting, contradicting, has_contradiction


def compute_evidence_hash(evidence_refs: List[str]) -> str:
    """Computes deterministic SHA-256 hash over sorted evidence IDs."""
    sorted_refs = sorted(list(set(evidence_refs)))
    encoded = json.dumps(sorted_refs).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
