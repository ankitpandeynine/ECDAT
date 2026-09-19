"""
ECDAT V4 P3 Migration Evidence Correlation & Tracking.

Provides functions to normalize, correlate, and verify cryptographic evidence items,
detect discrepancies between before/after scans, and maintain strict provenance.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .models import MigrationContext
from .normalizer import compute_migration_evidence_hash


def correlate_migration_evidence(
    context: MigrationContext,
    raw_evidence: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Correlates evidence items from P0/P1 scan data, AST detections, configuration files,
    network handshakes, and certificates into a unified migration evidence payload.
    """
    raw_evidence = raw_evidence or []
    correlated: Dict[str, Any] = {
        "asset_id": context.asset_id,
        "algorithm": context.algorithm,
        "role": context.cryptographic_role,
        "evidence_count": len(raw_evidence),
        "source_files": set(),
        "call_sites": [],
        "ciphersuites": [],
        "certificates": [],
        "libraries": set(),
        "evidence_refs": list(context.evidence_refs),
    }

    for item in raw_evidence:
        if not isinstance(item, dict):
            continue
        ev_id = item.get("id") or item.get("evidence_id")
        if ev_id and ev_id not in correlated["evidence_refs"]:
            correlated["evidence_refs"].append(str(ev_id))

        if item.get("file_path"):
            correlated["source_files"].add(str(item["file_path"]))
        if item.get("call_site"):
            correlated["call_sites"].append(item["call_site"])
        if item.get("ciphersuite"):
            correlated["ciphersuites"].append(str(item["ciphersuite"]))
        if item.get("certificate"):
            correlated["certificates"].append(item["certificate"])
        if item.get("library") or item.get("dependency"):
            correlated["libraries"].add(str(item.get("library") or item.get("dependency")))

    correlated["source_files"] = sorted(list(correlated["source_files"]))
    correlated["libraries"] = sorted(list(correlated["libraries"]))
    correlated["evidence_hash"] = compute_migration_evidence_hash(raw_evidence)
    return correlated


def detect_evidence_discrepancies(
    before_evidence: Optional[List[Dict[str, Any]]] = None,
    after_evidence: Optional[Dict[str, Any] | List[Dict[str, Any]]] = None,
) -> List[str]:
    """
    Detects concrete discrepancies and regressions between pre- and post-migration evidence.
    """
    discrepancies: List[str] = []
    before_list = before_evidence if isinstance(before_evidence, list) else []
    after_list = after_evidence if isinstance(after_evidence, list) else []

    # Extract algorithms and configurations
    before_algos = {str(item.get("algorithm", "")).upper() for item in before_list if item.get("algorithm")}
    after_algos = {str(item.get("algorithm", "")).upper() for item in after_list if item.get("algorithm")}

    # Check for unexpected algorithm reversions or regressions
    for b_algo in before_algos:
        if b_algo in ("MD5", "DES", "RC4", "SHA1"):
            if b_algo in after_algos:
                discrepancies.append(f"Deprecated primitive '{b_algo}' was retained in post-migration evidence.")

    # Check for empty post-evidence when pre-evidence existed
    if before_list and not after_list:
        discrepancies.append("Post-migration scan yielded no observable cryptographic evidence.")

    return discrepancies
