"""
ECDAT V4 Persistent Relational Crypto Asset Graph Service.

Stores and queries:
- Crypto Assets (Algorithms, Libraries, Keys, Certificates, Protocols, Endpoints)
- Granular Evidence items bound to assets
- Typed Graph Relationships (USES, PROVIDES, IMPLEMENTS, PROTECTS, SERVES, etc.)
- Multi-hop traversal and blast-radius computation (upstream affected systems)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from .evidence_model import Evidence, EvidenceLevel, EvidenceState


class AssetType(str, Enum):
    ALGORITHM = "ALGORITHM"
    CRYPTO_LIBRARY = "CRYPTO_LIBRARY"
    CRYPTO_API = "CRYPTO_API"
    KEY = "KEY"
    CERTIFICATE = "CERTIFICATE"
    PROTOCOL = "PROTOCOL"
    ENDPOINT = "ENDPOINT"
    DEPENDENCY = "DEPENDENCY"
    BINARY_CRYPTO_FUNCTION = "BINARY_CRYPTO_FUNCTION"
    CONFIGURATION = "CONFIGURATION"
    APPLICATION = "APPLICATION"
    SERVICE = "SERVICE"
    BINARY = "BINARY"
    FIRMWARE = "FIRMWARE"
    FILESYSTEM = "FILESYSTEM"


class RelationshipType(str, Enum):
    USES = "USES"
    CALLS = "CALLS"
    PROVIDES = "PROVIDES"
    IMPLEMENTS = "IMPLEMENTS"
    DEPENDS_ON = "DEPENDS_ON"
    PRESENT_ON = "PRESENT_ON"
    SERVES = "SERVES"
    PROTECTS = "PROTECTS"
    CONFIGURED_BY = "CONFIGURED_BY"
    OBSERVED_BY = "OBSERVED_BY"
    EVIDENCED_BY = "EVIDENCED_BY"
    REACHABLE_FROM = "REACHABLE_FROM"
    MIGRATES_TO = "MIGRATES_TO"
    AFFECTS = "AFFECTS"
    CONTAINS = "CONTAINS"



def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CryptoAsset:
    id: str
    project: str
    asset_type: str
    name: str
    scan_id: Optional[str] = None
    algorithm: Optional[str] = None
    variant: Optional[str] = None
    key_size: Optional[int] = None
    library: Optional[str] = None
    version: Optional[str] = None
    artifact_id: Optional[str] = None
    status: str = "ACTIVE"
    fused_status: str = "SINGLE_SOURCE"  # SINGLE_SOURCE, CORROBORATED, CONTRADICTED, INCONCLUSIVE
    highest_evidence_level: str = "E0"
    confidence: float = 0.0
    explanation: str = ""
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "project": self.project,
            "asset_type": self.asset_type,
            "name": self.name,
            "scan_id": self.scan_id,
            "algorithm": self.algorithm,
            "variant": self.variant,
            "key_size": self.key_size,
            "library": self.library,
            "version": self.version,
            "artifact_id": self.artifact_id,
            "status": self.status,
            "fused_status": self.fused_status,
            "highest_evidence_level": self.highest_evidence_level,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> CryptoAsset:
        return cls(
            id=row["id"],
            project=row["project"],
            asset_type=row["asset_type"],
            name=row["name"],
            scan_id=row["scan_id"],
            algorithm=row["algorithm"],
            variant=row["variant"],
            key_size=row["key_size"],
            library=row["library"],
            version=row["version"],
            artifact_id=row["artifact_id"],
            status=row["status"],
            fused_status=row["fused_status"],
            highest_evidence_level=row["highest_evidence_level"],
            confidence=row["confidence"],
            explanation=row["explanation"] or "",
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class AssetGraphService:
    def __init__(self, db_conn_factory):
        self.connect = db_conn_factory

    def create_asset(
        self,
        project: str,
        asset_type: str | AssetType,
        name: str,
        scan_id: Optional[str] = None,
        algorithm: Optional[str] = None,
        variant: Optional[str] = None,
        key_size: Optional[int] = None,
        library: Optional[str] = None,
        version: Optional[str] = None,
        artifact_id: Optional[str] = None,
        status: str = "ACTIVE",
        fused_status: str = "SINGLE_SOURCE",
        highest_evidence_level: str = "E0",
        confidence: float = 0.0,
        explanation: str = "",
        asset_id: Optional[str] = None,
    ) -> CryptoAsset:
        uid = asset_id or str(uuid.uuid4())
        created = now_iso()
        a_type = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
        with self.connect() as db:
            db.execute(
                """INSERT INTO crypto_assets (
                    id, project, scan_id, asset_type, name, algorithm, variant,
                    key_size, library, version, artifact_id, status, fused_status,
                    highest_evidence_level, confidence, explanation, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    uid, project, scan_id, a_type, name, algorithm, variant,
                    key_size, library, version, artifact_id, status, fused_status,
                    highest_evidence_level, confidence, explanation, created, created
                ),
            )
        return self.get_asset(uid, project)  # type: ignore

    def get_asset(self, asset_id: Any, project: Optional[str] = None) -> Optional[CryptoAsset]:
        aid = asset_id.id if hasattr(asset_id, "id") else str(asset_id)
        query = "SELECT * FROM crypto_assets WHERE id = ?"
        params: List[Any] = [aid]
        if project:
            query += " AND project = ?"
            params.append(project)
        with self.connect() as db:
            row = db.execute(query, params).fetchone()
        return CryptoAsset.from_row(row) if row else None

    def get_scan_assets(self, scan_id: str, project: Optional[str] = None) -> List[CryptoAsset]:
        query = "SELECT * FROM crypto_assets WHERE scan_id = ?"
        params: List[Any] = [scan_id]
        if project:
            query += " AND project = ?"
            params.append(project)
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        return [CryptoAsset.from_row(r) for r in rows]

    def upsert_asset(
        self,
        project: str,
        asset_type: str | AssetType,
        name: str,
        **kwargs: Any,
    ) -> CryptoAsset:
        a_type = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
        with self.connect() as db:
            row = db.execute(
                "SELECT id FROM crypto_assets WHERE project = ? AND asset_type = ? AND name = ?",
                (project, a_type, name),
            ).fetchone()
        if row:
            asset_id = row["id"]
            self.update_asset(asset_id, **kwargs)
            return self.get_asset(asset_id, project)  # type: ignore
        return self.create_asset(project, a_type, name, **kwargs)

    def update_asset(self, asset_id: str, **kwargs: Any) -> None:
        # Enforce evidence level monotonicity and max confidence
        existing = self.get_asset(asset_id)
        if existing:
            if "highest_evidence_level" in kwargs and kwargs["highest_evidence_level"]:
                curr_level_str = existing.highest_evidence_level or "E0"
                new_level_str = kwargs["highest_evidence_level"]
                curr_rank = int(curr_level_str[1]) if len(curr_level_str) >= 2 and curr_level_str[1].isdigit() else 0
                new_rank = int(new_level_str[1]) if len(new_level_str) >= 2 and new_level_str[1].isdigit() else 0
                if curr_rank > new_rank:
                    kwargs["highest_evidence_level"] = curr_level_str
            if "confidence" in kwargs and kwargs["confidence"] is not None:
                if existing.confidence > kwargs["confidence"]:
                    kwargs["confidence"] = existing.confidence

        fields_to_update = []
        params = []
        for k, v in kwargs.items():
            if k in (
                "algorithm", "variant", "key_size", "library", "version",
                "artifact_id", "status", "fused_status", "highest_evidence_level",
                "confidence", "explanation", "scan_id"
            ):
                fields_to_update.append(f"{k} = ?")
                params.append(v)
        if not fields_to_update:
            return
        fields_to_update.append("updated_at = ?")
        params.append(now_iso())
        params.append(asset_id)
        with self.connect() as db:
            db.execute(f"UPDATE crypto_assets SET {', '.join(fields_to_update)} WHERE id = ?", params)

    def add_evidence(self, asset_id: Any, evidence: Evidence, project: str) -> None:
        aid = asset_id.id if hasattr(asset_id, "id") else str(asset_id)
        e_dict = evidence.to_dict()
        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO evidence (
                    id, asset_id, scan_id, project, state, level, confidence,
                    source_engine, engine_version, rule_id, rule_version,
                    observation_type, artifact_type, file_path, line_start,
                    line_end, byte_offset, symbol, description, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence.id, aid, evidence.provenance.scan_id, project,
                    evidence.state.value, evidence.level.value, evidence.confidence,
                    evidence.source_engine, evidence.engine_version, evidence.rule_id,
                    evidence.rule_version, evidence.observation_type.value,
                    evidence.artifact_type, evidence.file_path, evidence.line_start,
                    evidence.line_end, evidence.byte_offset, evidence.symbol,
                    evidence.description, json.dumps(e_dict), evidence.timestamp
                ),
            )

    def get_asset_evidence(self, asset_id: Any) -> List[Dict[str, Any]]:
        aid = asset_id.id if hasattr(asset_id, "id") else str(asset_id)
        with self.connect() as db:
            rows = db.execute("SELECT data FROM evidence WHERE asset_id = ? ORDER BY created_at ASC", (aid,)).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def get_scan_evidence(self, scan_id: str, project: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT data FROM evidence WHERE scan_id = ?"
        params: List[Any] = [scan_id]
        if project:
            query += " AND project = ?"
            params.append(project)
        query += " ORDER BY created_at ASC"
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def add_relationship(
        self,
        project: str,
        source_id: Any,
        source_type: str,
        relationship: str | RelationshipType,
        target_id: Any,
        target_type: str,
        scan_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        confidence: float = 1.0,
    ) -> str:
        edge_id = str(uuid.uuid4())
        s_id = source_id.id if hasattr(source_id, "id") else str(source_id)
        t_id = target_id.id if hasattr(target_id, "id") else str(target_id)
        rel = relationship.value if isinstance(relationship, RelationshipType) else str(relationship)
        created = now_iso()
        with self.connect() as db:
            # Check if identical relationship already exists
            existing = db.execute(
                """SELECT id FROM graph_edges
                   WHERE project = ? AND source_id = ? AND relationship = ? AND target_id = ?""",
                (project, s_id, rel, t_id),
            ).fetchone()
            if existing:
                return existing["id"]
            db.execute(
                """INSERT INTO graph_edges (
                    id, project, scan_id, source_id, source_type, relationship,
                    target_id, target_type, evidence_id, confidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    edge_id, project, scan_id, s_id, source_type, rel,
                    t_id, target_type, evidence_id, confidence, created
                ),
            )
        return edge_id

    def get_relationships(
        self,
        project: Optional[str] = None,
        scan_id: Optional[str] = None,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        clauses = []
        params = []
        if project:
            clauses.append("project = ?")
            params.append(project)
        if scan_id:
            clauses.append("scan_id = ?")
            params.append(scan_id)
        if source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        if target_id:
            clauses.append("target_id = ?")
            params.append(target_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as db:
            rows = db.execute(f"SELECT * FROM graph_edges {where} ORDER BY created_at ASC", params).fetchall()
        return [dict(r) for r in rows]

    def get_neighbors(self, node_id: str, direction: str = "both") -> Dict[str, List[Dict[str, Any]]]:
        outbound: List[Dict[str, Any]] = []
        inbound: List[Dict[str, Any]] = []
        with self.connect() as db:
            if direction in ("outbound", "outgoing", "both"):
                out_rows = db.execute("SELECT * FROM graph_edges WHERE source_id = ?", (node_id,)).fetchall()
                outbound = [dict(r) for r in out_rows]
            if direction in ("inbound", "incoming", "both"):
                in_rows = db.execute("SELECT * FROM graph_edges WHERE target_id = ?", (node_id,)).fetchall()
                inbound = [dict(r) for r in in_rows]
        return {
            "outbound": outbound,
            "inbound": inbound,
            "outgoing": outbound,
            "incoming": inbound,
        }


    def get_blast_radius(self, target_node_id: Any) -> Dict[str, Any]:
        """
        Calculates blast radius: if target_node (e.g. RSA-1024 or OpenSSL 1.0) is compromised,
        which upstream callers, endpoints, services, and applications are exposed?
        Traverses reverse graph edges (who depends on / uses / is protected by this asset).
        """
        target_id_str = target_node_id.id if hasattr(target_node_id, "id") else str(target_node_id)
        visited: Set[str] = set()
        queue: List[str] = [target_id_str]
        impacted_nodes: List[Dict[str, Any]] = []
        impacted_edges: List[Dict[str, Any]] = []

        with self.connect() as db:
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)

                # Incoming edges where target is current node (e.g. Service -> USES -> Primitive)
                edges = db.execute(
                    """SELECT * FROM graph_edges
                       WHERE target_id = ? AND relationship IN ('USES', 'DEPENDS_ON', 'IMPLEMENTS', 'PROTECTS', 'SERVES', 'PRESENT_ON', 'PROVIDES', 'CALLS', 'CONTAINS')""",
                    (current,),
                ).fetchall()

                for edge in edges:
                    source_id = edge["source_id"]
                    impacted_edges.append(dict(edge))
                    if source_id not in visited:
                        queue.append(source_id)
                        # Fetch source asset details
                        asset_row = db.execute("SELECT * FROM crypto_assets WHERE id = ?", (source_id,)).fetchone()
                        if asset_row:
                            impacted_nodes.append(dict(asset_row))
                        else:
                            impacted_nodes.append({"id": source_id, "name": source_id, "asset_type": edge["source_type"]})

        return {
            "target_node_id": target_id_str,
            "total_impacted_count": len(impacted_nodes),
            "impacted_assets": impacted_nodes,
            "traversal_edges": impacted_edges,
        }

    def find_assets_by_algorithm(self, algorithm: str, project: Optional[str] = None) -> List[CryptoAsset]:
        query = "SELECT * FROM crypto_assets WHERE (algorithm = ? OR name LIKE ?)"
        params: List[Any] = [algorithm, f"%{algorithm}%"]
        if project:
            query += " AND project = ?"
            params.append(project)
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        return [CryptoAsset.from_row(r) for r in rows]

    def find_assets_by_project(self, project: str) -> List[CryptoAsset]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM crypto_assets WHERE project = ? ORDER BY created_at DESC", (project,)).fetchall()
        return [CryptoAsset.from_row(r) for r in rows]

    get_assets_by_project = find_assets_by_project

    def export_graph_for_ui(self, project: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Exports graph in React Force Graph format (nodes and links)."""
        if scan_id:
            with self.connect() as db:
                rows = db.execute("SELECT * FROM crypto_assets WHERE project = ? AND scan_id = ? ORDER BY created_at DESC", (project, scan_id)).fetchall()
            assets = [CryptoAsset.from_row(r) for r in rows]
        else:
            assets = self.find_assets_by_project(project)
        relationships = self.get_relationships(project=project, scan_id=scan_id)

        nodes = []
        for a in assets:
            blast = self.get_blast_radius(a.id)
            nodes.append({
                "id": a.id,
                "label": a.name,
                "group": a.asset_type.lower(),
                "severity": "critical" if a.highest_evidence_level in ("E4", "E5") and a.fused_status == "CORROBORATED" else "low",
                "evidence_level": a.highest_evidence_level,
                "fused_status": a.fused_status,
                "confidence": a.confidence,
                "blast_radius": [n["id"] for n in blast["impacted_assets"]],
                "explanation": a.explanation,
            })

        links = []
        for r in relationships:
            links.append({
                "id": r["id"],
                "source": r["source_id"],
                "target": r["target_id"],
                "label": r["relationship"],
                "confidence": r["confidence"],
            })

        return {"nodes": nodes, "links": links, "total_nodes": len(nodes), "total_links": len(links)}

    # P2.1 Crypto Risk & PQC Intelligence Persistence
    def _ensure_intelligence_tables(self) -> None:
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS risk_assessments (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS pqc_readiness (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                overall TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS hndl_assessments (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                state TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            # Safe schema migration for existing sqlite db files
            try:
                cursor = db.execute("PRAGMA table_info(hndl_assessments)")
                cols = {row[1] for row in cursor.fetchall()}
                if "scan_id" not in cols:
                    db.execute("ALTER TABLE hndl_assessments ADD COLUMN scan_id TEXT")
                if "assessment_id" not in cols:
                    db.execute("ALTER TABLE hndl_assessments ADD COLUMN assessment_id TEXT")
            except Exception:
                pass

            db.execute("CREATE INDEX IF NOT EXISTS idx_risk_asset ON risk_assessments(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_risk_scan ON risk_assessments(scan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_pqc_asset ON pqc_readiness(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_pqc_scan ON pqc_readiness(scan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_hndl_asset ON hndl_assessments(asset_id)")
            try:
                db.execute("CREATE INDEX IF NOT EXISTS idx_hndl_scan ON hndl_assessments(scan_id)")
            except Exception:
                pass

    def save_risk_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        self._ensure_intelligence_tables()
        if hasattr(assessment, "to_dict"):
            data = assessment.to_dict()
        elif isinstance(assessment, dict):
            data = dict(assessment)
        else:
            raise ValueError(f"Unsupported assessment type: {type(assessment)}")

        aid = data.get("assessment_id") or str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        scan_id = data.get("scan_id")
        risk_block = data.get("risk", {})
        severity = risk_block.get("severity") or getattr(getattr(assessment, "severity", None), "value", "UNKNOWN")
        confidence = risk_block.get("confidence") or getattr(getattr(assessment, "confidence", None), "value", "UNKNOWN")
        kb_ver = data.get("knowledge_base_version") or getattr(assessment, "knowledge_base_version", "2024.1")
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO risk_assessments (
                    assessment_id, asset_id, scan_id, severity, confidence,
                    knowledge_base_version, engine_version, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (aid, asset_id, scan_id, severity, confidence, kb_ver, engine_version, json.dumps(data), created)
            )

        if data.get("pqc_readiness"):
            self.save_pqc_readiness(data["pqc_readiness"])
        if data.get("hndl"):
            self.save_hndl_assessment(data["hndl"])

        return aid

    def get_risk_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_intelligence_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM risk_assessments WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM risk_assessments WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        return json.loads(row["data"]) if row else None

    def get_all_risk_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        self._ensure_intelligence_tables()
        with self.connect() as db:
            rows = db.execute(
                "SELECT data FROM risk_assessments WHERE asset_id = ? ORDER BY created_at DESC",
                (asset_id,)
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def save_pqc_readiness(self, assessment: Any) -> str:
        self._ensure_intelligence_tables()
        if hasattr(assessment, "to_dict"):
            data = assessment.to_dict()
        elif isinstance(assessment, dict):
            data = dict(assessment)
        else:
            raise ValueError(f"Unsupported assessment type: {type(assessment)}")

        aid = data.get("assessment_id") or str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        scan_id = data.get("scan_id")
        overall = data.get("overall", "UNKNOWN")
        kb_ver = data.get("knowledge_base_version", "2024.1")
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO pqc_readiness (
                    assessment_id, asset_id, scan_id, overall,
                    knowledge_base_version, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (aid, asset_id, scan_id, overall, kb_ver, json.dumps(data), created)
            )
        return aid

    def get_pqc_readiness(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_intelligence_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM pqc_readiness WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM pqc_readiness WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        return json.loads(row["data"]) if row else None

    def save_hndl_assessment(self, assessment: Any) -> str:
        self._ensure_intelligence_tables()
        if hasattr(assessment, "to_dict"):
            data = assessment.to_dict()
        elif isinstance(assessment, dict):
            data = dict(assessment)
        else:
            raise ValueError(f"Unsupported assessment type: {type(assessment)}")

        aid = data.get("assessment_id") or str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        scan_id = data.get("scan_id")
        state = data.get("state") or getattr(getattr(assessment, "state", None), "value", "HNDL_UNKNOWN")
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO hndl_assessments (
                    assessment_id, asset_id, scan_id, state, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (aid, asset_id, scan_id, state, json.dumps(data), created)
            )
        return aid

    def get_hndl_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_intelligence_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM hndl_assessments WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM hndl_assessments WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        return json.loads(row["data"]) if row else None

    def get_asset_intelligence(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        saved = self.get_risk_assessment(asset_id)
        asset = self.get_asset(asset_id, project)
        if not saved:
            if not asset:
                return None
            from .intelligence.intelligence_pipeline import evaluate_asset
            evidence = self.get_asset_evidence(asset_id)
            eval_result = evaluate_asset(asset.to_dict(), evidence)
            self.save_risk_assessment(eval_result)
            saved = eval_result.to_dict()

        blast = self.get_blast_radius(asset_id)
        saved["blast_radius"] = blast
        if asset:
            saved["asset"] = asset.to_dict()
        return saved

    def get_why_risk(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        intelligence = self.get_asset_intelligence(asset_id, project)
        if not intelligence:
            return None

        reasons = intelligence.get("reason_chain", [])
        unknowns = intelligence.get("unknowns", [])
        limitations = intelligence.get("limitations", [])
        evidence_refs = intelligence.get("evidence_refs", [])
        rule_refs = intelligence.get("rule_refs", [])
        risk = intelligence.get("risk", {})

        return {
            "asset_id": asset_id,
            "severity": risk.get("severity", "UNKNOWN"),
            "confidence": risk.get("confidence", "UNKNOWN"),
            "factors": risk.get("factors", []),
            "reason_chain": reasons,
            "unknowns": unknowns,
            "limitations": limitations,
            "evidence_refs": evidence_refs,
            "rule_refs": rule_refs,
            "explanation": f"Assessment for {asset_id}: severity {risk.get('severity', 'UNKNOWN')} ({len(reasons)} reason steps, {len(evidence_refs)} evidence links).",
        }

    def _ensure_agility_tables(self) -> None:
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS agility_assessments (
                assessment_id TEXT PRIMARY KEY,
                scan_id TEXT,
                asset_id TEXT NOT NULL,
                overall_state TEXT NOT NULL,
                composite_score REAL,
                dimensions_json TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                evidence_hash TEXT,
                configuration_hash TEXT,
                knowledge_base_version TEXT,
                engine_version TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS change_surfaces (
                surface_id TEXT PRIMARY KEY,
                scan_id TEXT,
                asset_id TEXT NOT NULL,
                change_surface_json TEXT NOT NULL,
                blast_radius_json TEXT,
                complexity TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_agility_asset ON agility_assessments(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_agility_scan ON agility_assessments(scan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_surface_asset ON change_surfaces(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_surface_scan ON change_surfaces(scan_id)")

    def save_agility_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        self._ensure_agility_tables()
        if hasattr(assessment, "to_dict"):
            data = assessment.to_dict()
        elif isinstance(assessment, dict):
            data = dict(assessment)
        else:
            raise ValueError(f"Unsupported assessment type: {type(assessment)}")

        aid = data.get("assessment_id") or str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        scan_id = data.get("scan_id")
        overall_state = data.get("overall_state", "UNKNOWN")
        composite_score = data.get("composite_score")
        dimensions_json = json.dumps(data.get("dimensions", {}))
        reasons_json = json.dumps(data.get("reasons", []))
        ev_hash = data.get("evidence_hash", "")
        cfg_hash = data.get("configuration_hash", "")
        kb_ver = data.get("knowledge_base_version", "2024.1")
        eng_ver = data.get("engine_version", engine_version)
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO agility_assessments (
                    assessment_id, scan_id, asset_id, overall_state,
                    composite_score, dimensions_json, reasons_json,
                    evidence_hash, configuration_hash, knowledge_base_version,
                    engine_version, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    aid, scan_id, asset_id, overall_state, composite_score,
                    dimensions_json, reasons_json, ev_hash, cfg_hash,
                    kb_ver, eng_ver, json.dumps(data), created
                )
            )

        if data.get("change_surface"):
            self.save_change_surface(data["change_surface"])

        return aid

    def get_agility_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_agility_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM agility_assessments WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM agility_assessments WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        return json.loads(row["data"]) if row else None

    def get_all_agility_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        self._ensure_agility_tables()
        with self.connect() as db:
            rows = db.execute(
                "SELECT data FROM agility_assessments WHERE asset_id = ? ORDER BY created_at DESC",
                (asset_id,)
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def save_change_surface(self, surface: Any) -> str:
        self._ensure_agility_tables()
        if hasattr(surface, "to_dict"):
            data = surface.to_dict()
        elif isinstance(surface, dict):
            data = dict(surface)
        else:
            raise ValueError(f"Unsupported change surface type: {type(surface)}")

        sid = data.get("surface_id") or str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        scan_id = data.get("scan_id")
        complexity = data.get("complexity") or getattr(getattr(surface, "complexity", None), "value", "UNKNOWN")
        blast_json = json.dumps(data.get("graph_blast_radius", {}))
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO change_surfaces (
                    surface_id, scan_id, asset_id, change_surface_json,
                    blast_radius_json, complexity, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (sid, scan_id, asset_id, json.dumps(data), blast_json, complexity, json.dumps(data), created)
            )
        return sid

    def get_change_surface(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_agility_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM change_surfaces WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM change_surfaces WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        return json.loads(row["data"]) if row else None

    def get_why_agility(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        assessment = self.get_agility_assessment(asset_id)
        if not assessment:
            asset = self.get_asset(asset_id, project)
            if not asset:
                return None
            from .agility.agility_pipeline import evaluate_agility
            evidence = self.get_asset_evidence(asset_id)
            blast = self.get_blast_radius(asset_id)
            eval_res = evaluate_agility(asset.to_dict(), evidence, graph_service=self, blast_radius=blast)
            self.save_agility_assessment(eval_res)
            assessment = eval_res.to_dict()

        from .agility.explainability import build_agility_explainability_report
        from .agility.models import AgilityAssessment
        obj = AgilityAssessment.from_dict(assessment)
        return build_agility_explainability_report(obj)

    # P2.3 Blast Radius Intelligence Persistence
    def _ensure_blast_radius_tables(self) -> None:
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS blast_radius_assessments (
                assessment_id TEXT PRIMARY KEY,
                scan_id TEXT,
                asset_id TEXT NOT NULL,
                state TEXT NOT NULL,
                impact_category TEXT NOT NULL,
                criticality TEXT NOT NULL,
                confidence TEXT NOT NULL,
                direct_dependents_json TEXT NOT NULL,
                transitive_dependents_json TEXT NOT NULL,
                dependency_paths_json TEXT NOT NULL,
                graph_hash TEXT,
                evidence_hash TEXT,
                configuration_hash TEXT,
                knowledge_base_version TEXT,
                engine_version TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_blast_asset ON blast_radius_assessments(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_blast_scan ON blast_radius_assessments(scan_id)")

    def save_blast_radius_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        self._ensure_blast_radius_tables()
        if hasattr(assessment, "to_dict"):
            data = assessment.to_dict()
        elif isinstance(assessment, dict):
            data = dict(assessment)
        else:
            raise ValueError(f"Unsupported assessment type: {type(assessment)}")

        aid = data.get("assessment_id") or str(uuid.uuid4())
        asset_id = data.get("asset_id", "")
        scan_id = data.get("scan_id")
        state = data.get("state", "UNKNOWN")
        impact_category = data.get("impact_category", "UNKNOWN")
        criticality = data.get("criticality", "UNKNOWN")
        confidence = data.get("confidence", "UNKNOWN")
        direct_json = json.dumps(data.get("direct_dependents", []))
        transitive_json = json.dumps(data.get("transitive_dependents", []))
        paths_json = json.dumps(data.get("dependency_paths", []))
        ghash = data.get("graph_hash", "")
        ev_hash = data.get("evidence_hash", "")
        cfg_hash = data.get("configuration_hash", "")
        kb_ver = data.get("knowledge_base_version", "2024.1")
        eng_ver = data.get("engine_version", engine_version)
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO blast_radius_assessments (
                    assessment_id, scan_id, asset_id, state, impact_category,
                    criticality, confidence, direct_dependents_json,
                    transitive_dependents_json, dependency_paths_json,
                    graph_hash, evidence_hash, configuration_hash,
                    knowledge_base_version, engine_version, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    aid, scan_id, asset_id, state, impact_category,
                    criticality, confidence, direct_json,
                    transitive_json, paths_json,
                    ghash, ev_hash, cfg_hash,
                    kb_ver, eng_ver, json.dumps(data), created
                )
            )
        return aid

    def get_blast_radius_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_blast_radius_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM blast_radius_assessments WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM blast_radius_assessments WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        return json.loads(row["data"]) if row else None

    def get_all_blast_radius_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        self._ensure_blast_radius_tables()
        with self.connect() as db:
            rows = db.execute(
                "SELECT data FROM blast_radius_assessments WHERE asset_id = ? ORDER BY created_at DESC",
                (asset_id,)
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def get_why_blast_radius(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        assessment = self.get_blast_radius_assessment(asset_id)
        if not assessment:
            asset = self.get_asset(asset_id, project)
            if not asset:
                return None
            from .blast_radius.blast_radius_pipeline import evaluate_blast_radius
            evidence = self.get_asset_evidence(asset_id)
            eval_res = evaluate_blast_radius(asset.to_dict(), graph_service=self, evidence_items=evidence)
            self.save_blast_radius_assessment(eval_res)
            assessment = eval_res.to_dict()

        from .blast_radius.explainability import build_blast_radius_explainability_report
        from .blast_radius.models import BlastRadiusAssessment
        obj = BlastRadiusAssessment.from_dict(assessment)
        return build_blast_radius_explainability_report(obj)

    # ---------------------------------------------------------
    # P3: Migration Intelligence & Verification Persistence
    # ---------------------------------------------------------
    def _ensure_migration_tables(self) -> None:
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS pqc_migration_plans (
                plan_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                project_id TEXT,
                priority TEXT NOT NULL,
                target_algorithm TEXT NOT NULL,
                transition_mode TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                configuration_hash TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS migration_verifications (
                verification_id TEXT PRIMARY KEY,
                migration_plan_id TEXT,
                asset_id TEXT NOT NULL,
                before_scan_id TEXT,
                after_scan_id TEXT,
                verification_state TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                evidence_hash TEXT NOT NULL,
                configuration_hash TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_pqc_plan_asset ON pqc_migration_plans(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_pqc_plan_scan ON pqc_migration_plans(scan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_mver_plan ON migration_verifications(migration_plan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_mver_asset ON migration_verifications(asset_id)")


    def save_pqc_migration_plan(self, plan: Any) -> str:
        self._ensure_migration_tables()
        if hasattr(plan, "to_dict"):
            data = plan.to_dict()
        else:
            data = dict(plan)

        pid = data.get("plan_id") or f"plan-{uuid.uuid4().hex[:12]}"
        aid = data.get("asset_id", "")
        sid = data.get("scan_id")
        project_id = data.get("project_id")
        priority = data.get("priority", "UNKNOWN")
        target_algo = data.get("migration_target", {}).get("target_algorithm", "UNKNOWN") if isinstance(data.get("migration_target"), dict) else "UNKNOWN"
        trans_mode = data.get("migration_target", {}).get("transition_mode", "UNKNOWN") if isinstance(data.get("migration_target"), dict) else "UNKNOWN"
        kb_ver = data.get("knowledge_base_version", "2024.1")
        eng_ver = data.get("engine_version", "4.0.0")
        ev_hash = data.get("evidence_hash", "")
        cfg_hash = data.get("configuration_hash", "")
        created = data.get("created_at") or datetime.now(timezone.utc).isoformat()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO pqc_migration_plans (
                    plan_id, asset_id, scan_id, project_id, priority,
                    target_algorithm, transition_mode, knowledge_base_version,
                    engine_version, evidence_hash, configuration_hash, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    pid, aid, sid, project_id, priority,
                    target_algo, trans_mode, kb_ver,
                    eng_ver, ev_hash, cfg_hash, json.dumps(data), created
                )
            )
        return pid

    def get_pqc_migration_plan(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_migration_tables()
        with self.connect() as db:
            if scan_id:
                row = db.execute(
                    "SELECT data FROM pqc_migration_plans WHERE asset_id = ? AND scan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, scan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM pqc_migration_plans WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        if not row:
            return None
        val = row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0]
        return json.loads(val)

    def get_pqc_migration_plan_by_id(self, plan_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_migration_tables()
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM pqc_migration_plans WHERE plan_id = ? LIMIT 1",
                (plan_id,)
            ).fetchone()
        if not row:
            return None
        val = row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0]
        return json.loads(val)

    def get_all_pqc_migration_plans(self, asset_id: str) -> List[Dict[str, Any]]:
        self._ensure_migration_tables()
        with self.connect() as db:
            rows = db.execute(
                "SELECT data FROM pqc_migration_plans WHERE asset_id = ? ORDER BY created_at DESC",
                (asset_id,)
            ).fetchall()
        return [json.loads(r["data"] if hasattr(r, "keys") and "data" in r.keys() else r[0]) for r in rows]

    def save_migration_verification(self, verification: Any) -> str:
        self._ensure_migration_tables()
        if hasattr(verification, "to_dict"):
            data = verification.to_dict()
        else:
            data = dict(verification)

        vid = data.get("verification_id") or f"mver-{uuid.uuid4().hex[:12]}"
        mpid = data.get("migration_plan_id")
        aid = data.get("asset_id", "")
        bsid = data.get("before_scan_id")
        asid = data.get("after_scan_id")
        state = data.get("verification_state", "UNKNOWN")
        kb_ver = data.get("knowledge_base_version", "2024.1")
        eng_ver = data.get("engine_version", "4.0.0")
        ev_hash = data.get("evidence_hash", "")
        cfg_hash = data.get("configuration_hash", "")
        created = data.get("created_at") or datetime.now(timezone.utc).isoformat()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO migration_verifications (
                    verification_id, migration_plan_id, asset_id,
                    before_scan_id, after_scan_id, verification_state,
                    knowledge_base_version, engine_version, evidence_hash,
                    configuration_hash, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    vid, mpid, aid, bsid, asid, state,
                    kb_ver, eng_ver, ev_hash, cfg_hash, json.dumps(data), created
                )
            )
        return vid

    def get_migration_verification(self, asset_id: str, plan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_migration_tables()
        with self.connect() as db:
            if plan_id:
                row = db.execute(
                    "SELECT data FROM migration_verifications WHERE asset_id = ? AND migration_plan_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id, plan_id)
                ).fetchone()
            else:
                row = db.execute(
                    "SELECT data FROM migration_verifications WHERE asset_id = ? ORDER BY created_at DESC LIMIT 1",
                    (asset_id,)
                ).fetchone()
        if not row:
            return None
        val = row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0]
        return json.loads(val)

    def get_migration_verification_by_id(self, verification_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_migration_tables()
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM migration_verifications WHERE verification_id = ? LIMIT 1",
                (verification_id,)
            ).fetchone()
        if not row:
            return None
        val = row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0]
        return json.loads(val)

    def get_all_migration_verifications(self, asset_id: str) -> List[Dict[str, Any]]:
        self._ensure_migration_tables()
        with self.connect() as db:
            rows = db.execute(
                "SELECT data FROM migration_verifications WHERE asset_id = ? ORDER BY created_at DESC",
                (asset_id,)
            ).fetchall()
        return [json.loads(r["data"] if hasattr(r, "keys") and "data" in r.keys() else r[0]) for r in rows]


    def get_why_migration(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        plan_dict = self.get_pqc_migration_plan(asset_id)
        if not plan_dict:
            asset = self.get_asset(asset_id, project)
            if not asset:
                return None
            from .migration.migration_pipeline import generate_migration_plan
            risk = self.get_risk_assessment(asset_id)
            agility = self.get_agility_assessment(asset_id)
            pqc = self.get_pqc_readiness(asset_id)
            blast = self.get_blast_radius_assessment(asset_id)
            evidence = self.get_asset_evidence(asset_id)
            plan_res = generate_migration_plan(
                asset=asset.to_dict(),
                risk_assessment=risk,
                agility_assessment=agility,
                pqc_readiness=pqc,
                blast_radius=blast,
                evidence_items=evidence,
            )
            self.save_pqc_migration_plan(plan_res)
            plan_dict = plan_res.to_dict()

        from .migration.explainability import build_migration_explainability_report
        from .migration.models import MigrationPlan
        plan_obj = MigrationPlan.from_dict(plan_dict)
        return build_migration_explainability_report(plan_obj)

    # ---------------------------------------------------------
    # P5: Temporal Crypto Intelligence & Posture Persistence
    # ---------------------------------------------------------
    def _ensure_temporal_and_posture_tables(self) -> None:
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS temporal_comparisons (
                comparison_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                base_scan_id TEXT NOT NULL,
                target_scan_id TEXT NOT NULL,
                base_timestamp TEXT,
                target_timestamp TEXT,
                added_count INTEGER NOT NULL DEFAULT 0,
                removed_count INTEGER NOT NULL DEFAULT 0,
                changed_count INTEGER NOT NULL DEFAULT 0,
                unchanged_count INTEGER NOT NULL DEFAULT 0,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS evidence_timelines (
                timeline_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                asset_key TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS posture_assessments (
                assessment_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                asset_id TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("""CREATE TABLE IF NOT EXISTS posture_changes (
                change_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                base_assessment_id TEXT NOT NULL,
                target_assessment_id TEXT NOT NULL,
                asset_id TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_temp_comp ON temporal_comparisons(project_id, base_scan_id, target_scan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_ev_time_asset ON evidence_timelines(project_id, asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_ev_time_key ON evidence_timelines(project_id, asset_key)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_posture_proj_scan ON posture_assessments(project_id, scan_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_posture_asset ON posture_assessments(asset_id)")
            db.execute("CREATE INDEX IF NOT EXISTS idx_posture_changes ON posture_changes(project_id, base_assessment_id, target_assessment_id)")

    def save_temporal_comparison(self, comparison: Any) -> str:
        self._ensure_temporal_and_posture_tables()
        if hasattr(comparison, "to_dict"):
            data = comparison.to_dict()
        else:
            data = dict(comparison)
        cid = data.get("comparison_id") or f"cmp-{uuid.uuid4().hex[:12]}"
        project_id = data.get("project_id", "default")
        base_scan_id = data.get("base_scan_id", "")
        target_scan_id = data.get("target_scan_id", "")
        base_ts = data.get("base_timestamp")
        target_ts = data.get("target_timestamp")
        added_cnt = data.get("added_count", 0)
        removed_cnt = data.get("removed_count", 0)
        changed_cnt = data.get("changed_count", 0)
        unchanged_cnt = data.get("unchanged_count", 0)
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO temporal_comparisons (
                    comparison_id, project_id, base_scan_id, target_scan_id,
                    base_timestamp, target_timestamp, added_count, removed_count,
                    changed_count, unchanged_count, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cid, project_id, base_scan_id, target_scan_id,
                    base_ts, target_ts, added_cnt, removed_cnt,
                    changed_cnt, unchanged_cnt, json.dumps(data), created,
                ),
            )
        return cid

    def get_temporal_comparison(self, project: str, base_scan_id: str, target_scan_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            row = db.execute(
                """SELECT data FROM temporal_comparisons
                   WHERE project_id = ? AND base_scan_id = ? AND target_scan_id = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (project, base_scan_id, target_scan_id),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])

    def get_temporal_comparison_by_id(self, comparison_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM temporal_comparisons WHERE comparison_id = ?",
                (comparison_id,),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])

    def save_evidence_timeline(self, timeline: Any) -> str:
        self._ensure_temporal_and_posture_tables()
        if hasattr(timeline, "to_dict"):
            data = timeline.to_dict()
        else:
            data = dict(timeline)
        tid = data.get("timeline_id") or f"tl-{uuid.uuid4().hex[:12]}"
        project_id = data.get("project_id", "default")
        asset_id = data.get("asset_id", "")
        asset_key = data.get("asset_key", "")
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO evidence_timelines (
                    timeline_id, project_id, asset_id, asset_key, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (tid, project_id, asset_id, asset_key, json.dumps(data), created),
            )
        return tid

    def get_evidence_timeline(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            if project:
                row = db.execute(
                    """SELECT data FROM evidence_timelines
                       WHERE asset_id = ? AND project_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (asset_id, project),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT data FROM evidence_timelines
                       WHERE asset_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (asset_id,),
                ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])

    def get_evidence_timeline_by_key(self, asset_key: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            if project:
                row = db.execute(
                    """SELECT data FROM evidence_timelines
                       WHERE asset_key = ? AND project_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (asset_key, project),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT data FROM evidence_timelines
                       WHERE asset_key = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (asset_key,),
                ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])

    def save_posture_assessment(self, assessment: Any) -> str:
        self._ensure_temporal_and_posture_tables()
        if hasattr(assessment, "to_dict"):
            data = assessment.to_dict()
        else:
            data = dict(assessment)
        aid = data.get("assessment_id") or f"posture-{uuid.uuid4().hex[:12]}"
        project_id = data.get("project_id", "default")
        scan_id = data.get("scan_id", "")
        asset_id = data.get("asset_id")
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO posture_assessments (
                    assessment_id, project_id, scan_id, asset_id, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (aid, project_id, scan_id, asset_id, json.dumps(data), created),
            )
        return aid

    def get_posture_assessment(self, scan_id: str, project: Optional[str] = None, asset_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            if asset_id and project:
                row = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE scan_id = ? AND project_id = ? AND asset_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (scan_id, project, asset_id),
                ).fetchone()
            elif asset_id:
                row = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE scan_id = ? AND asset_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (scan_id, asset_id),
                ).fetchone()
            elif project:
                row = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE scan_id = ? AND project_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (scan_id, project),
                ).fetchone()
            else:
                row = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE scan_id = ?
                       ORDER BY created_at DESC LIMIT 1""",
                    (scan_id,),
                ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])

    def get_posture_assessment_by_id(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            row = db.execute(
                "SELECT data FROM posture_assessments WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])

    def get_posture_history(self, asset_id: Optional[str] = None, project: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            if asset_id and project:
                rows = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE asset_id = ? AND project_id = ?
                       ORDER BY created_at ASC""",
                    (asset_id, project),
                ).fetchall()
            elif asset_id:
                rows = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE asset_id = ?
                       ORDER BY created_at ASC""",
                    (asset_id,),
                ).fetchall()
            elif project:
                rows = db.execute(
                    """SELECT data FROM posture_assessments
                       WHERE project_id = ?
                       ORDER BY created_at ASC""",
                    (project,),
                ).fetchall()
            else:
                rows = db.execute(
                    "SELECT data FROM posture_assessments ORDER BY created_at ASC"
                ).fetchall()
        return [json.loads(r["data"] if hasattr(r, "keys") and "data" in r.keys() else r[0]) for r in rows]

    def save_posture_change(self, change: Any) -> str:
        self._ensure_temporal_and_posture_tables()
        if hasattr(change, "to_dict"):
            data = change.to_dict()
        else:
            data = dict(change)
        cid = data.get("change_id") or f"pchange-{uuid.uuid4().hex[:12]}"
        project_id = data.get("project_id", "default")
        base_id = data.get("base_assessment_id", "")
        target_id = data.get("target_assessment_id", "")
        asset_id = data.get("asset_id")
        created = data.get("created_at") or now_iso()

        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO posture_changes (
                    change_id, project_id, base_assessment_id, target_assessment_id,
                    asset_id, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (cid, project_id, base_id, target_id, asset_id, json.dumps(data), created),
            )
        return cid

    def get_posture_change(self, base_assessment_id: str, target_assessment_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_temporal_and_posture_tables()
        with self.connect() as db:
            row = db.execute(
                """SELECT data FROM posture_changes
                   WHERE base_assessment_id = ? AND target_assessment_id = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (base_assessment_id, target_assessment_id),
            ).fetchone()
        if not row:
            return None
        return json.loads(row["data"] if hasattr(row, "keys") and "data" in row.keys() else row[0])




