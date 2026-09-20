import networkx as nx
from typing import Dict, Any, List, Optional
from .evidence_model import EvidenceRecord
from .correlator import CrossSurfaceCorrelator, CorrelatedTopology


class CryptoKnowledgeGraph:
    """Crypto Asset Graph implementing Section 6 & 19 of the specification.

    Nodes represent assets: applications, services, libraries, algorithms, certificates, endpoints, binaries.
    Edges represent relationships: uses, implements, depends_on, protects, serves, authenticated_by.
    """

    def __init__(self, seed_demo: bool = False):
        self.G = nx.DiGraph()
        if seed_demo:
            self._initialize_base_graph()

    def _initialize_base_graph(self):
        """Seeds the graph with a realistic enterprise topology mimicking discovering
        code, live TLS services, and certificates (used only for demo workspaces).
        """
        # Apps
        self.G.add_node("App: AuthGateway", type="application", severity="medium")
        self.G.add_node("App: CoreBanking", type="application", severity="high")
        
        # Services
        self.G.add_node("Service: login-api", type="service", severity="critical")
        self.G.add_node("Service: transaction-api", type="service", severity="medium")
        self.G.add_node("Service: legacy-payment", type="service", severity="high")
        
        # Crypto Primitives & Certificates
        self.G.add_node("Algo: DES (56-bit)", type="algorithm", severity="critical")
        self.G.add_node("Algo: AES-256-GCM", type="algorithm", severity="low")
        self.G.add_node("Algo: RSA-1024", type="algorithm", severity="high")
        self.G.add_node("Cert: Auth-Prod-2024", type="certificate", severity="medium")
        self.G.add_node("Protocol: TLSv1.0", type="protocol", severity="critical")
        self.G.add_node("Protocol: TLSv1.3", type="protocol", severity="low")

        # Relationships (Dependencies)
        self.G.add_edge("App: AuthGateway", "Service: login-api", relationship="uses", context="Architecture dependency")
        self.G.add_edge("App: CoreBanking", "Service: transaction-api", relationship="uses", context="Architecture dependency")
        self.G.add_edge("App: CoreBanking", "Service: legacy-payment", relationship="uses", context="Architecture dependency")

        # Crypto bindings
        self.G.add_edge("Service: login-api", "Algo: DES (56-bit)", relationship="implements", context="Source Code (Hardcoded)")
        self.G.add_edge("Service: login-api", "Cert: Auth-Prod-2024", relationship="authenticated_by", context="Network Prober (Live TLS)")
        self.G.add_edge("Cert: Auth-Prod-2024", "Algo: RSA-1024", relationship="implements", context="Certificate PKI")
        self.G.add_edge("Service: legacy-payment", "Protocol: TLSv1.0", relationship="uses", context="Network Prober")
        self.G.add_edge("Service: transaction-api", "Algo: AES-256-GCM", relationship="implements", context="Source Code")
        self.G.add_edge("Service: transaction-api", "Protocol: TLSv1.3", relationship="uses", context="Network Prober")

    def add_finding(self, service: str, primitive: str, context: str, severity: str, relationship: str = "uses"):
        """Dynamically add findings from AST or Network Scanners."""
        if not self.G.has_node(service):
            self.G.add_node(service, type="service", severity=severity)
        if not self.G.has_node(primitive):
            self.G.add_node(primitive, type="algorithm", severity=severity)
        
        self.G.add_edge(service, primitive, context=context, relationship=relationship)

    def load_from_topology(self, topology: CorrelatedTopology):
        """Rebuilds the internal graph from a correlated topology."""
        self.G.clear()
        for node in topology.nodes:
            self.G.add_node(
                node.id,
                label=node.label,
                type=node.type,
                severity=node.severity,
                surface=node.surface,
                quantum_vulnerable=node.quantum_vulnerable,
                metadata=node.metadata
            )
        for link in topology.links:
            self.G.add_edge(
                link.source,
                link.target,
                relationship=link.relationship,
                confidence=link.confidence,
                context=link.context,
                evidence_ids=link.evidence_ids
            )

    @classmethod
    def from_evidence_records(cls, records: List[EvidenceRecord], app_name: str = "Enterprise System") -> "CryptoKnowledgeGraph":
        correlator = CrossSurfaceCorrelator()
        correlator.ingest_records(records)
        topo = correlator.correlate(default_app_name=app_name)
        graph = cls()
        graph.load_from_topology(topo)
        return graph

    @classmethod
    def from_scans(cls, scan_records: List[Dict[str, Any]], app_name: str = "Enterprise System") -> "CryptoKnowledgeGraph":
        correlator = CrossSurfaceCorrelator()
        correlator.ingest_scan_results(scan_records)
        topo = correlator.correlate(default_app_name=app_name)
        graph = cls()
        graph.load_from_topology(topo)
        return graph

    def compute_blast_radius(self, target_node: str) -> List[str]:
        """Calculates blast radius (Module 4): if a primitive (e.g., RSA-1024) is

        cracked, which upstream services and apps are compromised?
        Uses reverse graph traversal on directed edges.
        """
        if not self.G.has_node(target_node):
            return []
        impacted_nodes = list(nx.ancestors(self.G, target_node))
        return sorted(impacted_nodes)

    def export_for_ui(self) -> Dict[str, Any]:
        """Exports the NetworkX graph to the React Force Graph format."""
        nodes = []
        links = []
        
        for node, data in self.G.nodes(data=True):
            label = data.get("label") or (node.split(": ")[-1] if ": " in node else node)
            nodes.append({
                "id": node,
                "label": label,
                "group": data.get("type", "unknown"),
                "severity": data.get("severity", "low"),
                "surface": data.get("surface", "unknown"),
                "quantum_vulnerable": data.get("quantum_vulnerable"),
                "blast_radius": self.compute_blast_radius(node),
                "metadata": data.get("metadata", {})
            })
            
        for source, target, data in self.G.edges(data=True):
            links.append({
                "source": source,
                "target": target,
                "relationship": data.get("relationship", "uses"),
                "confidence": data.get("confidence", "observed"),
                "label": data.get("context") or data.get("relationship", "")
            })
            
        return {
            "nodes": nodes,
            "links": links
        }

    def get_kpis(self) -> Dict[str, Any]:
        """Calculates dynamic KPIs based on graph state."""
        critical_count = sum(1 for _, d in self.G.nodes(data=True) if d.get("severity") in ("critical", "CRITICAL"))
        total_findings = sum(1 for _, d in self.G.nodes(data=True) if d.get("type") in ["algorithm", "protocol", "certificate"])
        
        qv_certs = sum(
            1 for n, d in self.G.nodes(data=True)
            if d.get("quantum_vulnerable") is True or (d.get("type") == "certificate" and ("RSA" in str(n) or "DES" in str(n)))
        )
        
        return {
            "total_findings": total_findings,
            "critical": critical_count,
            "quantum_vulnerable_certs": qv_certs,
            "est_migration_effort": f"{critical_count * 2} weeks" if critical_count > 0 else "0 weeks"
        }


# Global singleton for demo
kg = CryptoKnowledgeGraph()


def sync_knowledge_graph_tables(store: Any, project: str) -> Dict[str, Any]:
    """
    Synchronizes real crypto_assets and relationships into graph_nodes and graph_edges tables.
    Rule 1: If assets = 0, graph_nodes = 0.
    Rule 4: Graph edges cannot exist without both source and target nodes in the database.
    """
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()

    with store.connect() as db:
        # Ensure graph_nodes table exists
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

        assets = db.execute("SELECT * FROM crypto_assets WHERE project = ?", (project,)).fetchall()
        if not assets:
            db.execute("DELETE FROM graph_nodes WHERE project = ?", (project,))
            return {"nodes": [], "edges": []}

        # 1. Batch fetch evidence counts
        ev_rows = db.execute("SELECT asset_id, COUNT(*) as c FROM evidence WHERE project = ? GROUP BY asset_id", (project,)).fetchall()
        ev_counts = {r["asset_id"]: r["c"] for r in ev_rows}

        # 2. Batch fetch risk severities
        risk_rows = db.execute(
            "SELECT asset_id, severity FROM risk_assessments WHERE asset_id IN (SELECT id FROM crypto_assets WHERE project = ?)",
            (project,)
        ).fetchall()
        risk_severities = {r["asset_id"]: r["severity"] for r in risk_rows if r["severity"]}

        # 3. Preload project edges to compute blast radius in-memory via BFS (replaces N separate DB roundtrips)
        edges = db.execute(
            """SELECT source_id, target_id FROM graph_edges
               WHERE project = ? AND relationship IN ('USES', 'DEPENDS_ON', 'IMPLEMENTS', 'PROTECTS', 'SERVES', 'PRESENT_ON', 'PROVIDES', 'CALLS', 'CONTAINS')""",
            (project,)
        ).fetchall()
        from collections import defaultdict, deque
        reverse_adj = defaultdict(list)
        for e in edges:
            reverse_adj[e["target_id"]].append(e["source_id"])

        def _calc_blast(target_id: str) -> int:
            visited = set()
            q = deque([target_id])
            while q:
                curr = q.popleft()
                if curr not in visited:
                    visited.add(curr)
                    for parent in reverse_adj.get(curr, ()):
                        if parent not in visited:
                            q.append(parent)
            return len(visited) - 1 if len(visited) > 1 else 0

        active_node_ids = set()
        node_records = []

        for a in assets:
            asset_id = a["id"]
            active_node_ids.add(asset_id)
            label = a["name"] or a["algorithm"] or asset_id
            asset_type = (a["asset_type"] or "algorithm").lower()

            if asset_id in risk_severities:
                risk_level = risk_severities[asset_id].lower()
            else:
                algo_str = f"{a['algorithm'] or ''} {a['name'] or ''}".upper()
                if any(x in algo_str for x in ("RSA-1024", "RSA-512", "DES", "3DES", "MD5", "RC4")):
                    risk_level = "critical"
                elif any(x in algo_str for x in ("RSA", "ECDSA", "ECDH", "DSA", "SHA-1", "SHA1")):
                    risk_level = "high"
                elif any(x in algo_str for x in ("AES-128", "ECC")):
                    risk_level = "medium"
                else:
                    risk_level = "low"

            ev_count = ev_counts.get(asset_id, 0)
            blast_count = _calc_blast(asset_id)
            node_records.append((asset_id, project, label, asset_type, risk_level, int(ev_count), int(blast_count), now_iso, now_iso))

        if node_records:
            db.executemany('''
                INSERT INTO graph_nodes (id, project, label, type, risk_level, evidence_count, blast_radius_count, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    label = excluded.label,
                    type = excluded.type,
                    risk_level = excluded.risk_level,
                    evidence_count = excluded.evidence_count,
                    blast_radius_count = excluded.blast_radius_count,
                    updated_at = excluded.updated_at
            ''', node_records)

        # Check for service / application / endpoint nodes in graph_edges that connect to these assets
        edge_nodes = db.execute(
            "SELECT DISTINCT source_id, source_type FROM graph_edges WHERE project = ?",
            (project,)
        ).fetchall()

        edge_records = []
        for en in edge_nodes:
            s_id = en["source_id"]
            s_type = (en["source_type"] or "service").lower()
            if s_id not in active_node_ids:
                active_node_ids.add(s_id)
                edge_records.append((s_id, project, s_id, s_type, "low", 0, 0, now_iso, now_iso))

        if edge_records:
            db.executemany('''
                INSERT INTO graph_nodes (id, project, label, type, risk_level, evidence_count, blast_radius_count, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    type = excluded.type,
                    updated_at = excluded.updated_at
            ''', edge_records)

        # Delete any obsolete graph_nodes for this project that are no longer active
        if active_node_ids:
            placeholders = ','.join(['?'] * len(active_node_ids))
            db.execute(f"DELETE FROM graph_nodes WHERE project = ? AND id NOT IN ({placeholders})", (project, *active_node_ids))

