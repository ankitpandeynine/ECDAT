"""
ECDAT Quantum Risk & Mosca Timeline Routes.

Exposes:
- POST /api/quantum/mosca-project-scan
- GET /api/quantum/timeline-summary?project={id}
"""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from engine.mosca import (
    assess_project_assets,
    get_quantum_risk_summary,
    get_timeline_summary,
    mosca_assess,
)

router = APIRouter(prefix="/quantum", tags=["quantum"])


class MoscaProjectScanRequest(BaseModel):
    project_id: str = Field(min_length=1, max_length=64)
    data_sensitivity_years: Optional[float] = Field(default=10.0, ge=0.0, le=100.0)
    migration_time_years: Optional[float] = Field(default=3.0, ge=0.0, le=50.0)
    crqc_horizon_override: Optional[float] = Field(default=None, ge=1.0, le=100.0)


@router.post("/mosca-project-scan")
def mosca_project_scan(req: MoscaProjectScanRequest, request: Request):
    """
    Evaluates Mosca's Theorem (X + Y > Z) for all cryptographic assets in the specified project.
    Returns MoscaResult objects sorted by risk_score descending.
    If project has no assets: returns {results: [], message: 'No assets discovered yet. Run a scan.'}.
    """
    store = request.app.state.store
    with store.connect() as db:
        results = assess_project_assets(
            db=db,
            project_id=req.project_id,
            data_sensitivity_years=req.data_sensitivity_years,
            migration_time_years=req.migration_time_years,
            crqc_horizon_override=req.crqc_horizon_override,
        )

        if not results:
            return {
                "results": [],
                "message": "No assets discovered yet. Run a scan.",
                "project_id": req.project_id,
            }

        return {
            "results": [r.to_dict() for r in results],
            "project_id": req.project_id,
            "total_assessed": len(results),
            "hndl_exposed_count": sum(1 for r in results if r.harvest_now_risk),
        }


@router.get("/timeline-summary")
def timeline_summary(request: Request, project: str = Query("default", min_length=1, max_length=64)):
    """
    Returns per-algorithm quantum break timelines for dashboard visualization:
    [{algorithm: "RSA-2048", z_years: 9, mosca_verdict: "AT_RISK", risk_level: "AT_RISK", asset_count: 3}]
    """
    store = request.app.state.store
    with store.connect() as db:
        return get_timeline_summary(db=db, project_id=project)


@router.get("/risk-summary")
def risk_summary(
    request: Request,
    project: str = Query("default", min_length=1, max_length=64),
    project_id: Optional[str] = Query(None, min_length=1, max_length=64),
    data_sensitivity_years: Optional[float] = Query(10.0, ge=0.0, le=100.0),
    migration_time_years: Optional[float] = Query(3.0, ge=0.0, le=50.0),
):
    """
    Returns high-level quantum risk metric card counts:
    - Broken NOW (CLASSICALLY_BROKEN, no quantum needed)
    - Quantum Critical (SHOR_VULNERABLE)
    - Mosca At Risk (X + Y > Z)
    - Quantum Safe (NIST PQC minimum / Grover resistant)
    """
    proj = project_id or project
    store = request.app.state.store
    with store.connect() as db:
        return get_quantum_risk_summary(
            db=db,
            project_id=proj,
            data_sensitivity_years=data_sensitivity_years or 10.0,
            migration_time_years=migration_time_years or 3.0,
        )
