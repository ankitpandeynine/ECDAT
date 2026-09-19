"""Persistent scan jobs and relational ECDAT V4 database store. Run one API process; worker threads are bounded."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional
import uuid

from .asset_graph import AssetGraphService, CryptoAsset
from .evidence_fusion import EvidenceFusionEngine
from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
from .scan_manifest import ScanManifest
from .auth import AuthService
from .projects import ProjectService
from .archive_lab import SecureArchiveLab
from .reporting import ReportGenerator


def now():
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    def __init__(self, path=None):
        self.path = path or os.getenv('ECDAT_DB', 'data/scans.sqlite3')
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='scan')
        self.lock = threading.Lock()
        with self.connect() as db:
            # 1. Existing baseline tables
            db.execute('''CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, kind TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT,
                input_hash TEXT NOT NULL, payload TEXT, result TEXT, error TEXT)''')
            db.execute('''CREATE TABLE IF NOT EXISTS migration_plans (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, created_at TEXT NOT NULL,
                result TEXT NOT NULL)''')

            # 2. ECDAT V4 Reproducibility Manifests
            db.execute('''CREATE TABLE IF NOT EXISTS scan_manifests (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                scanner_version TEXT NOT NULL,
                configuration_hash TEXT NOT NULL,
                result_hash TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            # 3. ECDAT V4 Relational Crypto Asset Graph
            db.execute('''CREATE TABLE IF NOT EXISTS crypto_assets (
                id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                scan_id TEXT,
                asset_type TEXT NOT NULL,
                name TEXT NOT NULL,
                algorithm TEXT,
                variant TEXT,
                key_size INTEGER,
                library TEXT,
                version TEXT,
                artifact_id TEXT,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                fused_status TEXT NOT NULL DEFAULT 'SINGLE_SOURCE',
                highest_evidence_level TEXT NOT NULL DEFAULT 'E0',
                confidence REAL NOT NULL DEFAULT 0.0,
                explanation TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL)''')

            # 4. ECDAT V4 Unified Evidence Store
            db.execute('''CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                asset_id TEXT,
                scan_id TEXT NOT NULL,
                project TEXT NOT NULL,
                state TEXT NOT NULL,
                level TEXT NOT NULL,
                confidence REAL NOT NULL,
                source_engine TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                rule_id TEXT,
                rule_version TEXT,
                observation_type TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                byte_offset TEXT,
                symbol TEXT,
                description TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            # 5. ECDAT V4 Graph Edges
            db.execute('''CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                scan_id TEXT,
                source_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                relationship TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                evidence_id TEXT,
                confidence REAL NOT NULL DEFAULT 1.0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL)''')

            # 5a. ECDAT V4 Graph Nodes
            db.execute('''CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                label TEXT NOT NULL,
                type TEXT NOT NULL,
                risk_level TEXT NOT NULL DEFAULT 'low',
                evidence_count INTEGER NOT NULL DEFAULT 0,
                blast_radius_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL)''')

            # 6. ECDAT V4 Crypto Risk & PQC Readiness Intelligence
            db.execute('''CREATE TABLE IF NOT EXISTS risk_assessments (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            db.execute('''CREATE TABLE IF NOT EXISTS pqc_readiness (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                overall TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            db.execute('''CREATE TABLE IF NOT EXISTS hndl_assessments (
                asset_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE)''')

            # 8. Upload Sessions for Chunked Uploads (up to 500MB)
            db.execute('''CREATE TABLE IF NOT EXISTS upload_sessions (
                upload_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                surface TEXT NOT NULL,
                total_chunks INTEGER NOT NULL,
                received_chunks INTEGER NOT NULL DEFAULT 0,
                temp_path TEXT NOT NULL,
                status TEXT NOT NULL,
                scan_job_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL)''')

            # 7. Performance Indexes
            db.execute('CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_scans_proj_created ON scans(project, created_at DESC)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_upload_sessions_scan ON upload_sessions(scan_job_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_manifests_scan ON scan_manifests(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_assets_project ON crypto_assets(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_assets_scan ON crypto_assets(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_assets_algo ON crypto_assets(algorithm)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence(asset_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_level_state ON evidence(level, state)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_project ON graph_edges(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_nodes_project ON graph_nodes(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_rel ON graph_edges(relationship)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_risk_asset ON risk_assessments(asset_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_risk_scan ON risk_assessments(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_pqc_asset ON pqc_readiness(asset_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_pqc_scan ON pqc_readiness(scan_id)')

            # Mark interrupted jobs as failed on restart
            db.execute("UPDATE scans SET status='failed', error='Worker interrupted; submit again', finished_at=? WHERE status IN ('queued','running')", (now(),))

        self.graph = AssetGraphService(self.connect)
        self.fusion = EvidenceFusionEngine(self.graph)
        self.auth = AuthService(self.connect)
        self.projects = ProjectService(self.connect)
        self.archive_lab = SecureArchiveLab(self)
        self.reports = ReportGenerator(self)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON;')
        db.execute('PRAGMA journal_mode = WAL;')
        return db

    def submit(self, project, kind, payload, worker):
        encoded = json.dumps(payload, sort_keys=True)
        scan_id = str(uuid.uuid4())
        input_hash = hashlib.sha256(encoded.encode()).hexdigest()
        with self.lock, self.connect() as db:
            count = db.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]
            if count >= 20:
                raise ValueError('Scan queue is full; retry later')
            db.execute('INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (scan_id, project, kind, 'queued', now(), None,
                        input_hash, encoded, None, None))
        self.pool.submit(self._run, scan_id, project, payload, input_hash, worker)
        return self.get(scan_id, project)

    def _run(self, scan_id, project, payload, input_hash, worker):
        with self.connect() as db:
            changed = db.execute("UPDATE scans SET status='running' WHERE id=? AND status='queued'", (scan_id,)).rowcount
        if not changed:
            return
        manifest = ScanManifest(
            scan_id=scan_id,
            input_hash=input_hash,
            configuration=payload if isinstance(payload, dict) else {},
        )
        try:
            result = worker(payload)
            status = 'failed' if result.get('status') == 'error' else 'completed'
            error = result.get('error')

            if status == 'completed' and isinstance(result, dict):
                # Normalize and fuse evidence records into CryptoAsset Graph
                raw_ev_list = result.get('evidence', [])
                parsed_ev = []
                for item in raw_ev_list:
                    if isinstance(item, dict):
                        # Ensure scan_id is attributed
                        if 'provenance' in item and isinstance(item['provenance'], dict):
                            item['provenance']['scan_id'] = scan_id
                        parsed_ev.append(Evidence.from_dict(item))
                    elif isinstance(item, Evidence):
                        item.provenance.scan_id = scan_id
                        parsed_ev.append(item)

                if parsed_ev:
                    fused_assets = self.fusion.fuse_scan_evidence(project, scan_id, parsed_ev)
                    result['fused_assets'] = [a.to_dict() for a in fused_assets]
                    try:
                        from .intelligence.intelligence_pipeline import evaluate_asset
                        for a in fused_assets:
                            ev_list = self.graph.get_asset_evidence(a.id)
                            eval_report = evaluate_asset(a.to_dict(), ev_list)
                            self.graph.save_risk_assessment(eval_report)
                    except Exception:
                        pass

                # Connect call graph edges to asset graph
                try:
                    if result and isinstance(result, dict) and 'call_graph' in result:
                        for call in result.get('call_graph', []):
                            caller = call.get('caller')
                            callee = call.get('callee')
                            file_path = call.get('file', '')
                            if caller and callee and caller != "<global>":
                                caller_id = f"svc-{project}-{caller.lower()}"
                                if not self.graph.get_asset(caller_id, project):
                                    self.graph.create_asset(
                                        project,
                                        AssetType.SERVICE,
                                        caller,
                                        scan_id=scan_id,
                                        asset_id=caller_id,
                                    )
                                callee_norm = callee.lower().replace(" ", "_").replace("-", "_")
                                target_id = f"asset-{project}-{callee_norm}"
                                if not self.graph.get_asset(target_id, project):
                                    self.graph.create_asset(
                                        project,
                                        AssetType.ALGORITHM,
                                        callee,
                                        scan_id=scan_id,
                                        algorithm=callee,
                                        asset_id=target_id,
                                    )
                                self.graph.add_relationship(
                                    project=project,
                                    source_id=caller_id,
                                    source_type="SERVICE",
                                    relationship=RelationshipType.CALLS,
                                    target_id=target_id,
                                    target_type="ALGORITHM",
                                    scan_id=scan_id,
                                )

                except Exception:
                    pass


                # Compute reproducible result hash and save ScanManifest
                manifest.finalize_result(result)
                self.save_manifest(manifest)

                # Synchronize real graph_nodes and graph_edges in database
                try:
                    from .knowledge_graph import sync_knowledge_graph_tables
                    sync_knowledge_graph_tables(self, project)
                except Exception:
                    pass

        except Exception as exc:
            result, status, error = None, 'failed', str(exc)
        with self.connect() as db:
            db.execute("UPDATE scans SET status=?, result=?, error=?, finished_at=? WHERE id=? AND status='running'",
                       (status, json.dumps(result) if result is not None else None, error, now(), scan_id))

        # Update associated chunked upload session if triggered from upload_chunk
        if isinstance(payload, dict) and payload.get('upload_id'):
            try:
                self.update_upload_session(payload['upload_id'], status=status)
            except Exception:
                pass

    def save_manifest(self, manifest: ScanManifest) -> None:
        m_dict = manifest.to_dict()
        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO scan_manifests (
                    id, scan_id, input_hash, scanner_version, configuration_hash,
                    result_hash, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    manifest.manifest_id, manifest.scan_id, manifest.input_hash,
                    manifest.scanner_version, manifest.configuration_hash,
                    manifest.result_hash, json.dumps(m_dict), manifest.timestamp
                ),
            )

    def get_manifest(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute("SELECT data FROM scan_manifests WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def get(self, scan_id, project):
        alt = project.replace('-', ' ') if '-' in project else project.replace(' ', '-')
        with self.connect() as db:
            row = db.execute('SELECT * FROM scans WHERE id=? AND (project=? OR project=?)', (scan_id, project, alt)).fetchone()
        if not row:
            return None
        value = dict(row)
        value.pop('payload', None)
        value['result'] = json.loads(value['result']) if value['result'] else None
        value['engine_version'] = '4.0.0'
        return value

    def list(self, project):
        alt = project.replace('-', ' ') if '-' in project else project.replace(' ', '-')
        with self.connect() as db:
            rows = db.execute(
                'SELECT id, project, kind, status, created_at, finished_at, input_hash, result, error '
                'FROM scans WHERE (project=? OR project=?) ORDER BY created_at DESC LIMIT 200',
                (project, alt)
            ).fetchall()
        items = []
        for row in rows:
            val = dict(row)
            try:
                val['result'] = json.loads(val['result']) if val['result'] else None
            except Exception:
                val['result'] = None
            val['engine_version'] = '4.0.0'
            items.append(val)
        return items

    def cancel(self, scan_id, project):
        alt = project.replace('-', ' ') if '-' in project else project.replace(' ', '-')
        with self.connect() as db:
            db.execute("UPDATE scans SET status='cancelled', finished_at=? WHERE id=? AND (project=? OR project=?) AND status IN ('queued','running')", (now(), scan_id, project, alt))
        return self.get(scan_id, project)

    def save_plan(self, project, result):
        value = dict(result, id=str(uuid.uuid4()), project=project)
        with self.connect() as db:
            db.execute('INSERT INTO migration_plans VALUES (?,?,?,?)',
                       (value['id'], project, value['created_at'], json.dumps(value)))
        return value

    def get_plan(self, plan_id, project):
        with self.connect() as db:
            row = db.execute('SELECT result FROM migration_plans WHERE id=? AND project=?', (plan_id, project)).fetchone()
        return json.loads(row['result']) if row else None

    def list_plans(self, project):
        with self.connect() as db:
            rows = db.execute('SELECT id, created_at, result FROM migration_plans WHERE project=? ORDER BY created_at DESC LIMIT 100', (project,)).fetchall()
        return [{'id': r['id'], 'created_at': r['created_at'], 'target': json.loads(r['result'])['target']} for r in rows]

    # Graph & Evidence Query Helpers
    def get_assets(self, project: str, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        alt = project.replace('-', ' ') if '-' in project else project.replace(' ', '-')
        query = "SELECT * FROM crypto_assets WHERE (project = ? OR project = ?)"
        params: List[Any] = [project, alt]
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        query += " ORDER BY created_at DESC"
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        return [CryptoAsset.from_row(r).to_dict() for r in rows]

    def get_asset(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        asset = self.graph.get_asset(asset_id, project)
        return asset.to_dict() if asset else None

    def get_asset_evidence(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_asset_evidence(asset_id)

    def get_scan_evidence(self, scan_id: str, project: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.graph.get_scan_evidence(scan_id, project)

    def get_asset_relationships(self, asset_id: str, project: Optional[str] = None) -> Dict[str, Any]:
        return self.graph.get_neighbors(asset_id, direction="both")

    def get_blast_radius(self, node_id: str) -> Dict[str, Any]:
        return self.graph.get_blast_radius(node_id)

    def get_graph(self, project: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        return self.graph.export_graph_for_ui(project, scan_id)

    # P2.1 Intelligence Query Helpers
    def get_risk_assessment(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_risk_assessment(asset_id)

    def save_risk_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        return self.graph.save_risk_assessment(assessment, engine_version=engine_version)

    def get_pqc_readiness(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_pqc_readiness(asset_id)

    def save_pqc_readiness(self, assessment: Any) -> str:
        return self.graph.save_pqc_readiness(assessment)

    def get_hndl_assessment(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_hndl_assessment(asset_id)

    def save_hndl_assessment(self, assessment: Any) -> None:
        self.graph.save_hndl_assessment(assessment)

    def get_asset_intelligence(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_asset_intelligence(asset_id, project)

    def get_why_risk(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_risk(asset_id, project)

    # P2.2 Agility Intelligence Query Helpers
    def get_agility_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_agility_assessment(asset_id, scan_id)

    def get_all_agility_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_agility_assessments(asset_id)

    def save_agility_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        return self.graph.save_agility_assessment(assessment, engine_version=engine_version)

    def get_change_surface(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_change_surface(asset_id, scan_id)

    def save_change_surface(self, surface: Any) -> str:
        return self.graph.save_change_surface(surface)

    def get_why_agility(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_agility(asset_id, project)

    # P2.3 Blast Radius Intelligence Query Helpers
    def get_blast_radius_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_blast_radius_assessment(asset_id, scan_id)

    def get_all_blast_radius_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_blast_radius_assessments(asset_id)

    def save_blast_radius_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        return self.graph.save_blast_radius_assessment(assessment, engine_version=engine_version)

    def get_why_blast_radius(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_blast_radius(asset_id, project)

    # P3 Migration Intelligence & Verification Query Helpers
    def get_pqc_migration_plan(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_pqc_migration_plan(asset_id, scan_id)

    def get_pqc_migration_plan_by_id(self, plan_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_pqc_migration_plan_by_id(plan_id)

    def get_all_pqc_migration_plans(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_pqc_migration_plans(asset_id)

    def save_pqc_migration_plan(self, plan: Any) -> str:
        return self.graph.save_pqc_migration_plan(plan)

    def get_migration_verification(self, asset_id: str, plan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_migration_verification(asset_id, plan_id)

    def get_migration_verification_by_id(self, verification_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_migration_verification_by_id(verification_id)

    def get_all_migration_verifications(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_migration_verifications(asset_id)

    def save_migration_verification(self, verification: Any) -> str:
        return self.graph.save_migration_verification(verification)

    def get_why_migration(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_migration(asset_id, project)

    # P5 Temporal Intelligence & Continuous Posture Query Helpers
    def save_temporal_comparison(self, comparison: Any) -> str:
        return self.graph.save_temporal_comparison(comparison)

    def get_temporal_comparison(self, project: str, base_scan_id: str, target_scan_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_temporal_comparison(project, base_scan_id, target_scan_id)

    def get_temporal_comparison_by_id(self, comparison_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_temporal_comparison_by_id(comparison_id)

    def save_evidence_timeline(self, timeline: Any) -> str:
        return self.graph.save_evidence_timeline(timeline)

    def get_evidence_timeline(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_evidence_timeline(asset_id, project)

    def get_evidence_timeline_by_key(self, asset_key: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_evidence_timeline_by_key(asset_key, project)

    def save_posture_assessment(self, assessment: Any) -> str:
        return self.graph.save_posture_assessment(assessment)

    def get_posture_assessment(self, scan_id: str, project: Optional[str] = None, asset_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_posture_assessment(scan_id, project, asset_id)

    def get_posture_assessment_by_id(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_posture_assessment_by_id(assessment_id)

    def get_posture_history(self, asset_id: Optional[str] = None, project: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.graph.get_posture_history(asset_id, project)

    def save_posture_change(self, change: Any) -> str:
        return self.graph.save_posture_change(change)

    def get_posture_change(self, base_assessment_id: str, target_assessment_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_posture_change(base_assessment_id, target_assessment_id)

    def create_upload_session(
        self,
        upload_id: str,
        project_id: str,
        filename: str,
        surface: str,
        total_chunks: int,
        temp_path: str,
    ) -> Dict[str, Any]:
        now_ts = now()
        with self.lock, self.connect() as db:
            db.execute(
                """INSERT INTO upload_sessions 
                   (upload_id, project_id, filename, surface, total_chunks, received_chunks, temp_path, status, scan_job_id, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, 1, ?, 'uploading', NULL, ?, ?)""",
                (upload_id, project_id, filename, surface, total_chunks, temp_path, now_ts, now_ts)
            )
        return self.get_upload_session(upload_id)

    def update_upload_session(
        self,
        upload_id: str,
        received_chunks: Optional[int] = None,
        status: Optional[str] = None,
        scan_job_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        now_ts = now()
        fields = ["updated_at = ?"]
        params = [now_ts]
        if received_chunks is not None:
            fields.append("received_chunks = ?")
            params.append(received_chunks)
        if status is not None:
            fields.append("status = ?")
            params.append(status)
        if scan_job_id is not None:
            fields.append("scan_job_id = ?")
            params.append(scan_job_id)
        params.append(upload_id)

        with self.lock, self.connect() as db:
            db.execute(f"UPDATE upload_sessions SET {', '.join(fields)} WHERE upload_id = ?", params)
        return self.get_upload_session(upload_id)

    def get_upload_session(self, upload_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM upload_sessions WHERE upload_id = ?", (upload_id,)).fetchone()
            if not row:
                return None
            return dict(row)

    def close(self):
        self.pool.shutdown(wait=True)



