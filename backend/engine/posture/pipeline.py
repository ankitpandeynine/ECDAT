"""
ECDAT V4 Posture Orchestration Pipeline.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .models import PostureAssessment, PostureChangeAssessment
from .posture_classifier import evaluate_posture
from .posture_changes import evaluate_posture_change
from .posture_summary import summarize_posture
from .explainability import build_posture_explainability, build_posture_change_explainability


class PosturePipeline:
    def __init__(self, store: Any):
        self.store = store

    def evaluate_scan_posture(
        self,
        project: str,
        scan_id: str,
        asset_id: Optional[str] = None,
        force_recompute: bool = False,
    ) -> Dict[str, Any]:
        """Evaluates or retrieves the 7-dimension posture assessment for a scan."""
        if not force_recompute:
            cached = self.store.get_posture_assessment(scan_id, project=project, asset_id=asset_id)
            if cached:
                return cached

        # Fetch assets
        if asset_id:
            asset = self.store.graph.get_asset(asset_id, project) if hasattr(self.store, "graph") else None
            assets = [asset.to_dict() if hasattr(asset, "to_dict") else dict(asset)] if asset else []
        else:
            raw_assets = self.store.graph.get_scan_assets(scan_id) if hasattr(self.store, "graph") else []
            assets = [a.to_dict() if hasattr(a, "to_dict") else dict(a) for a in raw_assets]

        # Gather auxiliary assessments
        risks: List[Dict[str, Any]] = []
        pqc_items: List[Dict[str, Any]] = []
        agilities: List[Dict[str, Any]] = []
        blast_radii: List[Dict[str, Any]] = []
        verifications: List[Dict[str, Any]] = []
        plans: List[Dict[str, Any]] = []
        evidence_items: List[Any] = []

        for a in assets:
            aid = a.get("id")
            if aid and hasattr(self.store, "graph"):
                r = self.store.graph.get_risk_assessment(aid)
                if r:
                    risks.append(r)
                p = self.store.graph.get_pqc_readiness(aid)
                if p:
                    pqc_items.append(p)
                ag = self.store.graph.get_agility_assessment(aid, scan_id)
                if ag:
                    agilities.append(ag)
                br = self.store.graph.get_blast_radius_assessment(aid, scan_id)
                if br:
                    blast_radii.append(br)
                v = self.store.graph.get_migration_verification(aid)
                if v:
                    verifications.append(v)
                pl = self.store.graph.get_pqc_migration_plan(aid, scan_id)
                if pl:
                    plans.append(pl)
                ev = self.store.graph.get_asset_evidence(aid)
                if ev:
                    evidence_items.extend(ev)

        assessment = evaluate_posture(
            project=project,
            scan_id=scan_id,
            assets=assets,
            risks=risks,
            pqc_readiness=pqc_items,
            agilities=agilities,
            blast_radii=blast_radii,
            verifications=verifications,
            plans=plans,
            evidence_items=evidence_items,
            asset_id=asset_id,
        )

        res_dict = assessment.to_dict()
        res_dict["summary_report"] = summarize_posture(assessment)
        res_dict["explainability"] = build_posture_explainability(assessment)
        self.store.save_posture_assessment(res_dict)
        return res_dict

    def evaluate_posture_change_between_scans(
        self,
        project: str,
        base_scan_id: str,
        target_scan_id: str,
        asset_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluates continuous posture change between two scans."""
        base_posture = self.evaluate_scan_posture(project, base_scan_id, asset_id=asset_id)
        target_posture = self.evaluate_scan_posture(project, target_scan_id, asset_id=asset_id)

        change = evaluate_posture_change(
            base=base_posture,
            target=target_posture,
            project=project,
            asset_id=asset_id,
        )

        res_dict = change.to_dict()
        res_dict["explainability"] = build_posture_change_explainability(change)
        self.store.save_posture_change(res_dict)
        return res_dict

    def get_asset_posture_history(self, project: str, asset_id: str) -> List[Dict[str, Any]]:
        """Retrieves historical posture assessments for an asset."""
        return self.store.get_posture_history(asset_id=asset_id, project=project)
