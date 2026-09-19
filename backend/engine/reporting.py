"""
ECDAT Reporting Center — Multi-Format Security, Risk, and Compliance Reports.
Generates:
- Executive Summary
- Technical Cryptographic Inventory
- Quantum Risk & HNDL Report
- Crypto Agility Report
- Blast Radius Report
- Migration Plan & Roadmap
- Verification Report
- Archive Security Report
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional


class ReportGenerator:
    def __init__(self, store):
        self.store = store

    def generate_report(self, project_id: str, report_type: str = "EXECUTIVE_SUMMARY") -> Dict[str, Any]:
        with self.store.connect() as db:
            project_row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
            project = dict(project_row) if project_row else {"id": project_id, "name": project_id}

            assets = [dict(r) for r in db.execute("SELECT * FROM crypto_assets WHERE project=?", (project_id,)).fetchall()]
            scans = [dict(r) for r in db.execute("SELECT * FROM scans WHERE project=? ORDER BY created_at DESC LIMIT 20", (project_id,)).fetchall()]
            risks = [dict(r) for r in db.execute("""
                SELECT r.*, a.name as asset_name, a.algorithm
                FROM risk_assessments r
                JOIN crypto_assets a ON r.asset_id = a.id
                WHERE a.project = ?
            """, (project_id,)).fetchall()]

        now_ts = datetime.now(timezone.utc).isoformat()
        report_id = f"rep-{datetime.now().strftime('%Y%m%d%H%M%S')}-{project_id[:6]}"

        if report_type == "EXECUTIVE_SUMMARY":
            critical_count = sum(1 for r in risks if r.get("severity") == "CRITICAL")
            high_count = sum(1 for r in risks if r.get("severity") == "HIGH")
            return {
                "report_id": report_id,
                "title": f"Executive Cryptographic Posture & PQC Readiness Summary",
                "project": project,
                "generated_at": now_ts,
                "report_type": report_type,
                "executive_summary": {
                    "total_assets_discovered": len(assets),
                    "total_scans_conducted": len(scans),
                    "critical_quantum_risks": critical_count,
                    "high_quantum_risks": high_count,
                    "overall_posture": "ACTION_REQUIRED" if (critical_count + high_count) > 0 else "STABLE",
                    "pqc_migration_readiness": "PLANNING_STAGE"
                },
                "key_findings": [
                    f"{critical_count} critical cryptographic weaknesses requiring immediate deprecation or hybrid substitution.",
                    f"{len(assets)} total cryptographic assets cataloged in relational asset graph.",
                    f"Assessed data protection horizon: {project.get('data_lifetime_years', 10)} years against CRQC threat window."
                ],
                "recommended_actions": [
                    "Initiate PQC hybrid key exchange migration for public network gateways.",
                    "Review Shor-vulnerable asymmetric keys protecting persistent sensitive data.",
                    "Execute closed-loop verification scans to confirm algorithm replacement."
                ]
            }

        elif report_type == "TECHNICAL_INVENTORY":
            return {
                "report_id": report_id,
                "title": f"Technical Cryptographic Asset Inventory",
                "project": project,
                "generated_at": now_ts,
                "report_type": report_type,
                "total_assets": len(assets),
                "assets": assets,
                "scans": scans
            }

        elif report_type == "QUANTUM_RISK":
            return {
                "report_id": report_id,
                "title": "Quantum Vulnerability, Mosca Horizon & HNDL Risk Assessment",
                "project": project,
                "generated_at": now_ts,
                "report_type": report_type,
                "risk_count": len(risks),
                "risks": risks,
                "mosca_evaluation": {
                    "data_lifetime_years": project.get("data_lifetime_years", 10.0),
                    "assumed_threat_horizon_years": 8.0,
                    "migration_time_years": 3.0,
                    "hndl_exposure": "CRITICAL" if (float(project.get("data_lifetime_years", 10)) + 3.0) > 8.0 else "MANAGED"
                }
            }

        else:
            return {
                "report_id": report_id,
                "title": f"Comprehensive ECDAT Security & Cryptographic Report ({report_type})",
                "project": project,
                "generated_at": now_ts,
                "report_type": report_type,
                "assets": assets,
                "risks": risks,
                "scans": scans
            }
