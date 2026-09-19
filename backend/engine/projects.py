"""
ECDAT Project Management Service.
Handles rich enterprise project metadata, business context, environment, data lifetime,
and project-level cryptographic summaries.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import json
import secrets
from typing import Any, Dict, List, Optional


class EnvironmentType(str, Enum):
    PRODUCTION = "Production"
    STAGING = "Staging"
    DEVELOPMENT = "Development"
    RESEARCH = "Research"
    OTHER = "Other"


class BusinessCriticality(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


class DataSensitivity(str, Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    SENSITIVE = "Sensitive"
    CLASSIFIED = "Classified"
    UNKNOWN = "Unknown"


class ProjectService:
    def __init__(self, db_connector):
        self.connect = db_connector
        self._init_tables()
        self._seed_default_project()

    def _init_tables(self):
        with self.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                organization TEXT,
                environment TEXT NOT NULL DEFAULT 'Production',
                business_criticality TEXT NOT NULL DEFAULT 'Critical',
                data_sensitivity TEXT NOT NULL DEFAULT 'Sensitive',
                data_lifetime_years REAL NOT NULL DEFAULT 10.0,
                migration_target_date TEXT,
                owner TEXT,
                tags TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )''')
            db.execute('''CREATE TABLE IF NOT EXISTS project_members (
                project_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'SECURITY_ANALYST',
                created_at TEXT NOT NULL,
                PRIMARY KEY(project_id, user_id),
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            )''')

    def _seed_default_project(self):
        with self.connect() as db:
            row = db.execute("SELECT id FROM projects WHERE id='default'").fetchone()
            if not row:
                now_ts = datetime.now(timezone.utc).isoformat()
                db.execute(
                    "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "default",
                        "Default Enterprise System",
                        "High-assurance cryptographic asset boundary and post-quantum migration tracking.",
                        "Cyber Defense Command",
                        EnvironmentType.PRODUCTION.value,
                        BusinessCriticality.CRITICAL.value,
                        DataSensitivity.SENSITIVE.value,
                        20.0,
                        "2030-01-01",
                        "admin@ecdat.local",
                        json.dumps(["core", "production", "hndl-critical"]),
                        now_ts,
                        now_ts
                    )
                )

    def create_project(self, data: Dict[str, Any], owner: str = "admin@ecdat.local") -> Dict[str, Any]:
        p_id = data.get("id") or f"proj-{secrets.token_hex(6)}"
        name = data.get("name", "").strip() or "Untitled Project"
        description = data.get("description", "")
        organization = data.get("organization", "Default Org")
        environment = data.get("environment", EnvironmentType.PRODUCTION.value)
        criticality = data.get("business_criticality", BusinessCriticality.HIGH.value)
        sensitivity = data.get("data_sensitivity", DataSensitivity.SENSITIVE.value)
        lifetime = float(data.get("data_lifetime_years", 10.0))
        target_date = data.get("migration_target_date", None)
        tags = json.dumps(data.get("tags", [])) if isinstance(data.get("tags"), list) else json.dumps([])

        now_ts = datetime.now(timezone.utc).isoformat()

        with self.connect() as db:
            existing = db.execute("SELECT id FROM projects WHERE id=?", (p_id,)).fetchone()
            if existing:
                raise ValueError(f"Project ID '{p_id}' already exists")

            db.execute(
                "INSERT INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (p_id, name, description, organization, environment, criticality, sensitivity, lifetime, target_date, owner, tags, now_ts, now_ts)
            )

        return self.get_project(p_id)

    def update_project(self, project_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        fields = []
        params = []
        now_ts = datetime.now(timezone.utc).isoformat()

        for key in ["name", "description", "organization", "environment", "business_criticality", "data_sensitivity", "migration_target_date", "owner"]:
            if key in updates:
                fields.append(f"{key} = ?")
                params.append(updates[key])

        if "data_lifetime_years" in updates:
            fields.append("data_lifetime_years = ?")
            params.append(float(updates["data_lifetime_years"]))

        if "tags" in updates:
            fields.append("tags = ?")
            params.append(json.dumps(updates["tags"]) if isinstance(updates["tags"], list) else str(updates["tags"]))

        if not fields:
            return self.get_project(project_id)

        fields.append("updated_at = ?")
        params.append(now_ts)
        params.append(project_id)

        with self.connect() as db:
            db.execute(f"UPDATE projects SET {', '.join(fields)} WHERE id=?", params)

        return self.get_project(project_id)

    def delete_project(self, project_id: str) -> bool:
        if project_id == "default":
            raise ValueError("Cannot delete default project")
        with self.connect() as db:
            res = db.execute("DELETE FROM projects WHERE id=?", (project_id,)).rowcount
            return res > 0

    def get_project(self, project_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone()
            if not row and '-' in project_id:
                row = db.execute("SELECT * FROM projects WHERE id=?", (project_id.replace('-', ' '),)).fetchone()
            if not row and ' ' in project_id:
                row = db.execute("SELECT * FROM projects WHERE id=?", (project_id.replace(' ', '-'),)).fetchone()
            if not row:
                return None
            res = dict(row)
            actual_id = res["id"]
            try:
                res["tags"] = json.loads(res.get("tags") or "[]")
            except Exception:
                res["tags"] = []

            # Compute live telemetry summary for project
            asset_count = db.execute("SELECT count(*) FROM crypto_assets WHERE project=?", (actual_id,)).fetchone()[0]
            scan_count = db.execute("SELECT count(*) FROM scans WHERE project=?", (actual_id,)).fetchone()[0]
            last_scan = db.execute("SELECT finished_at, status FROM scans WHERE project=? AND status='completed' ORDER BY created_at DESC LIMIT 1", (actual_id,)).fetchone()

            # Quantum risk count
            quantum_count = db.execute("""
                SELECT count(*) FROM risk_assessments r
                JOIN crypto_assets a ON r.asset_id = a.id
                WHERE a.project = ? AND r.severity IN ('CRITICAL', 'HIGH')
            """, (project_id,)).fetchone()[0]

            res["is_demo"] = False
            res["metrics"] = {
                "asset_count": asset_count,
                "scan_count": scan_count,
                "quantum_risk_count": quantum_count,
                "last_scan_at": last_scan[0] if last_scan else None,
            }
            return res

    def list_projects(self, search: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.connect() as db:
            query = "SELECT id FROM projects ORDER BY created_at DESC"
            rows = db.execute(query).fetchall()

        projects = []
        for r in rows:
            p = self.get_project(r["id"])
            if p:
                if search:
                    s = search.lower()
                    if s not in p["name"].lower() and s not in p.get("description", "").lower() and s not in p["id"].lower():
                        continue
                projects.append(p)
        return projects
