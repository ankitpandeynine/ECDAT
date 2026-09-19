"""
ECDAT V4 Temporal Scan Comparator.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from .models import (
    AssetChange,
    ChangeCategory,
    TemporalComparison,
)
from .normalizer import compute_asset_key, normalize_asset
from .change_detector import detect_property_changes
from .temporal_risk import evaluate_temporal_risk
from .temporal_pqc import evaluate_temporal_pqc
from .temporal_agility import evaluate_temporal_agility
from .temporal_migration import evaluate_temporal_migration


def compare_scans(
    project: str,
    base_scan_id: str,
    target_scan_id: str,
    base_assets: List[Dict[str, Any]],
    target_assets: List[Dict[str, Any]],
    base_timestamp: Optional[str] = None,
    target_timestamp: Optional[str] = None,
    base_risks: Optional[Dict[str, Dict[str, Any]]] = None,
    target_risks: Optional[Dict[str, Dict[str, Any]]] = None,
    base_pqcs: Optional[Dict[str, Dict[str, Any]]] = None,
    target_pqcs: Optional[Dict[str, Dict[str, Any]]] = None,
    base_agilities: Optional[Dict[str, Dict[str, Any]]] = None,
    target_agilities: Optional[Dict[str, Dict[str, Any]]] = None,
    base_migrations: Optional[Dict[str, Dict[str, Any]]] = None,
    target_migrations: Optional[Dict[str, Dict[str, Any]]] = None,
) -> TemporalComparison:
    """
    Compares cryptographic assets across two discrete scans.
    Computes fine-grained inventory, risk, PQC, agility, and migration deltas.
    """
    b_risks = base_risks or {}
    t_risks = target_risks or {}
    b_pqcs = base_pqcs or {}
    t_pqcs = target_pqcs or {}
    b_agilities = base_agilities or {}
    t_agilities = target_agilities or {}
    b_migs = base_migrations or {}
    t_migs = target_migrations or {}

    # Map assets by deterministic key
    # Pass 1: If assets share explicit same non-empty id, bind their asset_keys
    id_map = {}
    for a in target_assets:
        aid = a.get("id")
        if aid:
            id_map[str(aid)] = a

    for a in base_assets:
        aid = str(a.get("id", ""))
        if aid and aid in id_map:
            t_item = id_map[aid]
            k = a.get("asset_key") or t_item.get("asset_key") or compute_asset_key(a)
            a["asset_key"] = k
            t_item["asset_key"] = k

    base_map: Dict[str, Dict[str, Any]] = {}
    for a in base_assets:
        norm = normalize_asset(a)
        k = norm.get("asset_key") or compute_asset_key(norm)
        base_map[k] = norm

    target_map: Dict[str, Dict[str, Any]] = {}
    for a in target_assets:
        norm = normalize_asset(a)
        k = norm.get("asset_key") or compute_asset_key(norm)
        target_map[k] = norm

    all_keys = sorted(set(base_map.keys()) | set(target_map.keys()))

    changes: List[AssetChange] = []
    added_count = 0
    removed_count = 0
    changed_count = 0
    unchanged_count = 0

    for k in all_keys:
        in_base = k in base_map
        in_target = k in target_map

        b_item = base_map.get(k)
        t_item = target_map.get(k)
        asset_id = (t_item.get("id") if t_item else None) or (b_item.get("id") if b_item else None) or k
        name = (t_item.get("name") if t_item else None) or (b_item.get("name") if b_item else None) or k

        # Lookup auxiliary evaluations by asset_id or key
        b_risk = b_risks.get(asset_id) or b_risks.get(k)
        t_risk = t_risks.get(asset_id) or t_risks.get(k)

        b_pqc = b_pqcs.get(asset_id) or b_pqcs.get(k)
        t_pqc = t_pqcs.get(asset_id) or t_pqcs.get(k)

        b_agility = b_agilities.get(asset_id) or b_agilities.get(k)
        t_agility = t_agilities.get(asset_id) or t_agilities.get(k)

        b_mig = b_migs.get(asset_id) or b_migs.get(k)
        t_mig = t_migs.get(asset_id) or t_migs.get(k)

        risk_change, r_expl = evaluate_temporal_risk(b_risk, t_risk)
        pqc_change, p_expl = evaluate_temporal_pqc(b_pqc, t_pqc, b_item, t_item)
        agility_change, a_expl = evaluate_temporal_agility(b_agility, t_agility)
        mig_change, m_expl = evaluate_temporal_migration(b_mig, t_mig)

        if not in_base and in_target:
            category = ChangeCategory.NEW
            added_count += 1
            diff = {"event": "new_asset_introduced", "properties": t_item}
            explanation = f"New asset {name} observed in scan {target_scan_id}. {r_expl} {p_expl}"
        elif in_base and not in_target:
            category = ChangeCategory.REMOVED
            removed_count += 1
            diff = {"event": "asset_removed", "properties": b_item}
            explanation = f"Asset {name} was present in scan {base_scan_id} but not observed in scan {target_scan_id}. {r_expl}"
        else:
            diff = detect_property_changes(b_item, t_item)
            if diff["has_changes"]:
                category = ChangeCategory.CHANGED
                changed_count += 1
                prop_list = ", ".join(diff["changed_properties"])
                explanation = f"Asset {name} modified ({prop_list}). {r_expl} {p_expl} {a_expl}"
            else:
                category = ChangeCategory.UNCHANGED
                unchanged_count += 1
                explanation = f"Asset {name} remained identical between scans."

        change = AssetChange(
            asset_key=k,
            asset_id=asset_id,
            name=name,
            category=category,
            base_asset=b_item,
            target_asset=t_item,
            diff_summary=diff,
            risk_change=risk_change,
            pqc_change=pqc_change,
            agility_change=agility_change,
            migration_change=mig_change,
            confidence=1.0,
            explanation=explanation.strip(),
        )
        changes.append(change)

    summary_expl = (
        f"Compared base scan {base_scan_id} and target scan {target_scan_id}: "
        f"{added_count} added, {removed_count} removed, {changed_count} changed, {unchanged_count} unchanged."
    )

    comparison = TemporalComparison(
        comparison_id=f"cmp-{uuid.uuid4().hex[:12]}",
        project_id=project,
        base_scan_id=base_scan_id,
        target_scan_id=target_scan_id,
        base_timestamp=base_timestamp,
        target_timestamp=target_timestamp,
        added_count=added_count,
        removed_count=removed_count,
        changed_count=changed_count,
        unchanged_count=unchanged_count,
        asset_changes=changes,
        explanation=summary_expl,
    )
    comparison.temporal_hash = comparison.compute_hash()
    return comparison
