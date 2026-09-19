"""
ECDAT V4 Temporal Orchestration Pipeline.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import TemporalComparison, AssetTimeline
from .comparator import compare_scans
from .evidence_timeline import build_asset_timeline
from .normalizer import compute_asset_key
from .explainability import build_temporal_explainability


class TemporalPipeline:
    def __init__(self, store: Any):
        self.store = store

    def run_comparison(
        self,
        project: str,
        base_scan_id: str,
        target_scan_id: str,
        force_recompute: bool = False,
    ) -> Dict[str, Any]:
        """Runs or retrieves a temporal comparison between two scans."""
        if not force_recompute:
            cached = self.store.get_temporal_comparison(project, base_scan_id, target_scan_id)
            if cached:
                return cached

        # Load scans
        base_scan = self.store.get_scan(base_scan_id) if hasattr(self.store, "get_scan") else None
        target_scan = self.store.get_scan(target_scan_id) if hasattr(self.store, "get_scan") else None

        base_ts = base_scan.get("created_at") if base_scan else None
        target_ts = target_scan.get("created_at") if target_scan else None

        # Load assets
        base_assets = self.store.graph.get_scan_assets(base_scan_id) if hasattr(self.store, "graph") else []
        target_assets = self.store.graph.get_scan_assets(target_scan_id) if hasattr(self.store, "graph") else []

        # Convert to dicts if needed
        b_dicts = [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in base_assets]
        t_dicts = [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in target_assets]

        # Load auxiliary intelligence for base scan
        b_risks = {}
        b_pqcs = {}
        b_agilities = {}
        for a in b_dicts:
            aid = a.get("id")
            if aid and hasattr(self.store, "graph"):
                r = self.store.graph.get_risk_assessment(aid)
                if r:
                    b_risks[aid] = r
                p = self.store.graph.get_pqc_readiness(aid)
                if p:
                    b_pqcs[aid] = p
                ag = self.store.graph.get_agility_assessment(aid, base_scan_id)
                if ag:
                    b_agilities[aid] = ag

        # Load auxiliary intelligence for target scan
        t_risks = {}
        t_pqcs = {}
        t_agilities = {}
        for a in t_dicts:
            aid = a.get("id")
            if aid and hasattr(self.store, "graph"):
                r = self.store.graph.get_risk_assessment(aid)
                if r:
                    t_risks[aid] = r
                p = self.store.graph.get_pqc_readiness(aid)
                if p:
                    t_pqcs[aid] = p
                ag = self.store.graph.get_agility_assessment(aid, target_scan_id)
                if ag:
                    t_agilities[aid] = ag

        comparison = compare_scans(
            project=project,
            base_scan_id=base_scan_id,
            target_scan_id=target_scan_id,
            base_assets=b_dicts,
            target_assets=t_dicts,
            base_timestamp=base_ts,
            target_timestamp=target_ts,
            base_risks=b_risks,
            target_risks=t_risks,
            base_pqcs=b_pqcs,
            target_pqcs=t_pqcs,
            base_agilities=b_agilities,
            target_agilities=t_agilities,
        )

        res_dict = comparison.to_dict()
        res_dict["explainability"] = build_temporal_explainability(comparison)
        self.store.save_temporal_comparison(res_dict)
        return res_dict

    def get_asset_timeline(
        self,
        project: str,
        asset_id: str,
        force_recompute: bool = False,
    ) -> Dict[str, Any]:
        """Constructs or retrieves the timeline for an asset."""
        if not force_recompute:
            cached = self.store.get_evidence_timeline(asset_id, project)
            if cached:
                return cached

        # Fetch asset
        asset = self.store.graph.get_asset(asset_id, project) if hasattr(self.store, "graph") else None
        asset_dict = asset.to_dict() if hasattr(asset, "to_dict") else (dict(asset) if asset else {"id": asset_id, "name": asset_id})
        asset_key = compute_asset_key(asset_dict)

        # Get evidence items for this asset
        ev_items = self.store.graph.get_asset_evidence(asset_id) if hasattr(self.store, "graph") else []

        # Group evidence by scan
        scans_map: Dict[str, List[Any]] = {}
        for ev in ev_items:
            sid = getattr(ev, "scan_id", None) or "unknown"
            if sid not in scans_map:
                scans_map[sid] = []
            scans_map[sid].append(ev)

        # Build list of scan payloads
        scans_with_evidence: List[Dict[str, Any]] = []
        for sid, items in scans_map.items():
            scan_obj = self.store.get_scan(sid) if hasattr(self.store, "get_scan") else None
            ts = scan_obj.get("created_at") if scan_obj else None
            scans_with_evidence.append({
                "scan_id": sid,
                "timestamp": ts,
                "evidence_items": items,
            })

        if not scans_with_evidence:
            # Create a single baseline entry
            scans_with_evidence.append({
                "scan_id": asset_dict.get("scan_id") or "scan-1",
                "timestamp": asset_dict.get("created_at"),
                "evidence_items": ev_items,
            })

        timeline = build_asset_timeline(
            project=project,
            asset_key=asset_key,
            scans_with_evidence=scans_with_evidence,
            asset_id=asset_id,
        )

        res_dict = timeline.to_dict()
        self.store.save_evidence_timeline(res_dict)
        return res_dict
