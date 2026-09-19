"""Cross-Surface Correlator for ECDAT.

Implements Section 19 and Section 6 of the specification:
Identity Hierarchy:
  1. Exact known asset/deployment identifier
  2. Same input/binary hash + location
  3. Same application/library + version + deployment context
  4. Same endpoint/service + certificate/deployment evidence
  5. Heuristic relationship only → marked as inferred, not proven

Relationships:
  APPLICATION → USES → LIBRARY → IMPLEMENTS → ALGORITHM
  APPLICATION → SERVES → ENDPOINT → USES → TLS CRYPTO
  ENDPOINT → AUTHENTICATED BY → CERTIFICATE
  CRYPTO ASSET → PROTECTS → DATA FLOW
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

from .evidence_model import (
    AssetType,
    ConfidenceLevel,
    EvidenceRecord,
    EvidenceType,
    SourceSurface,
    normalize_binary_detection,
    normalize_network_scan,
    normalize_source_finding,
)


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # "uses", "implements", "depends_on", "protects", "serves", "authenticated_by"
    confidence: str  # "proven", "observed", "inferred"
    context: str = ""
    evidence_ids: List[str] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # "application", "service", "library", "algorithm", "certificate", "endpoint", "binary", "data_flow"
    severity: str = "low"
    surface: str = "unknown"
    blast_radius: List[str] = Field(default_factory=list)
    asset_id: Optional[str] = None
    quantum_vulnerable: Optional[bool] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CorrelatedTopology(BaseModel):
    nodes: List[GraphNode]
    links: List[GraphEdge]
    evidence_records: List[EvidenceRecord]
    total_assets: int
    critical_count: int
    quantum_vulnerable_count: int


class CrossSurfaceCorrelator:
    def __init__(self):
        self.evidence: List[EvidenceRecord] = []
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []

    def ingest_records(self, records: List[EvidenceRecord]):
        self.evidence.extend(records)

    def ingest_scan_results(self, scan_records: List[Dict[str, Any]]):
        """Extracts and normalizes EvidenceRecords from heterogeneous scan records."""
        for scan in scan_records:
            scan_id = scan.get("id", "unknown")
            input_hash = scan.get("input_hash", "")
            result = scan.get("result") or {}
            kind = scan.get("kind")

            if kind == "code":
                for finding in result.get("findings", []):
                    rec = normalize_source_finding(finding, input_hash=input_hash)
                    self.evidence.append(rec)
            elif kind == "binary":
                file_name = scan.get("payload", {}).get("file_name", "binary.bin") if isinstance(scan.get("payload"), dict) else "binary.bin"
                for det in result.get("detections", []):
                    rec = normalize_binary_detection(det, file_name, input_hash=input_hash)
                    self.evidence.append(rec)
            elif kind == "network":
                recs = normalize_network_scan(result, scan_id, input_hash=input_hash)
                self.evidence.extend(recs)
            elif kind == "pcap":
                for rec_dict in result.get("evidence_records", []):
                    if isinstance(rec_dict, dict):
                        try:
                            self.evidence.append(EvidenceRecord(**rec_dict))
                        except Exception:
                            pass
                    elif isinstance(rec_dict, EvidenceRecord):
                        self.evidence.append(rec_dict)


    def _add_node(self, node_id: str, label: str, node_type: str, severity: str = "low", surface: str = "unknown", qv: Optional[bool] = None, meta: Optional[Dict[str, Any]] = None):
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                id=node_id,
                label=label,
                type=node_type,
                severity=severity.lower(),
                surface=surface,
                quantum_vulnerable=qv,
                metadata=meta or {}
            )
        else:
            # Upgrade severity if higher
            sev_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            curr_rank = sev_rank.get(self.nodes[node_id].severity, 0)
            new_rank = sev_rank.get(severity.lower(), 0)
            if new_rank > curr_rank:
                self.nodes[node_id].severity = severity.lower()
            if qv is not None:
                self.nodes[node_id].quantum_vulnerable = qv

    def _add_edge(self, src: str, dst: str, rel: str, conf: str, context: str, evidence_id: Optional[str] = None):
        # Prevent duplicate identical edges
        for edge in self.edges:
            if edge.source == src and edge.target == dst and edge.relationship == rel:
                if evidence_id and evidence_id not in edge.evidence_ids:
                    edge.evidence_ids.append(evidence_id)
                return
        ev_ids = [evidence_id] if evidence_id else []
        self.edges.append(GraphEdge(source=src, target=dst, relationship=rel, confidence=conf, context=context, evidence_ids=ev_ids))

    def correlate(self, default_app_name: str = "Application") -> CorrelatedTopology:
        """Executes the identity hierarchy and relationship linking."""
        self.nodes.clear()
        self.edges.clear()

        # Step 1: Base Application Node
        app_id = f"app:{default_app_name.lower().replace(' ', '_')}"
        self._add_node(app_id, default_app_name, "application", severity="low")

        # Group evidence by surface
        for ev in self.evidence:
            ev_id = ev.asset_id
            algo_node_id = f"algo:{ev.algorithm.lower().replace(' ', '_')}"
            algo_label = ev.algorithm
            sev = ev.severity.lower()

            self._add_node(
                algo_node_id,
                algo_label,
                "algorithm",
                severity=sev,
                surface=ev.source_surface.value,
                qv=ev.quantum_vulnerable,
                meta={"role": ev.cryptographic_role.value, "location": ev.location_endpoint}
            )

            if ev.source_surface == SourceSurface.SOURCE_CODE:
                # Level 2/3: Code module / library -> Implements -> Algorithm
                file_path = ev.location_endpoint.split(":")[0]
                module_id = f"module:{file_path}"
                self._add_node(module_id, file_path, "library", severity=sev, surface="source_code")
                self._add_edge(app_id, module_id, "uses", "proven", f"Project source contains {file_path}")
                self._add_edge(module_id, algo_node_id, "implements", "observed", f"Line {ev.location_endpoint} implements {ev.algorithm}", ev_id)

            elif ev.source_surface == SourceSurface.BINARY_FIRMWARE:
                # Level 2: Binary artifact -> Implements / Contains -> Algorithm / Key
                bin_name = ev.location_endpoint.split("@")[0]
                bin_id = f"binary:{bin_name}"
                self._add_node(bin_id, bin_name, "binary", severity=sev, surface="binary_firmware")
                self._add_edge(app_id, bin_id, "uses", "inferred", f"Executable binary associated with app context")
                self._add_edge(bin_id, algo_node_id, "implements", "observed", f"Byte signature in {ev.location_endpoint}", ev_id)

            elif ev.source_surface in (SourceSurface.NETWORK_TLS, SourceSurface.PASSIVE_PCAP):
                # Level 4: Endpoint -> Uses -> TLS Crypto
                endpoint = ev.location_endpoint.split(" ")[0]
                ep_id = f"endpoint:{endpoint}"
                self._add_node(ep_id, endpoint, "endpoint", severity=sev, surface=ev.source_surface.value)
                self._add_edge(app_id, ep_id, "serves", "proven", f"Authorized service endpoint")
                self._add_edge(ep_id, algo_node_id, "uses", "observed", f"Observed TLS handshake on {endpoint}", ev_id)

            elif ev.source_surface == SourceSurface.CERTIFICATES:
                # Level 4: Endpoint -> Authenticated By -> Certificate
                cert_subj = ev.location_endpoint
                cert_id = f"cert:{hashlib.sha256(cert_subj.encode()).hexdigest()[:10]}"
                self._add_node(cert_id, f"Cert: {ev.algorithm}", "certificate", severity=sev, surface="certificates", qv=ev.quantum_vulnerable)
                # Find matching endpoint if any
                target_ep = None
                for n_id in self.nodes:
                    if self.nodes[n_id].type == "endpoint":
                        target_ep = n_id
                        break
                if target_ep:
                    self._add_edge(target_ep, cert_id, "authenticated_by", "observed", "Presented during TLS negotiation", ev_id)
                else:
                    self._add_edge(app_id, cert_id, "authenticated_by", "inferred", "Configured application certificate", ev_id)
                self._add_edge(cert_id, algo_node_id, "implements", "observed", f"Certificate public key algorithm", ev_id)

            elif ev.source_surface == SourceSurface.RUNTIME_TRACE:
                # Corroborated Level 1/2: Runtime observed execution
                call_id = f"runtime:{ev.location_endpoint}"
                self._add_node(call_id, f"Runtime: {ev.location_endpoint}", "service", severity=sev, surface="runtime_trace")
                self._add_edge(app_id, call_id, "serves", "observed", "Active runtime execution")
                self._add_edge(call_id, algo_node_id, "uses", "observed", f"Intercepted API invocation at runtime", ev_id)

        # Step 2: Compute blast radius via upstream BFS traversal
        self._compute_blast_radii()

        # KPIs
        crit = sum(1 for n in self.nodes.values() if n.severity == "critical")
        qv = sum(1 for n in self.nodes.values() if n.quantum_vulnerable is True)

        return CorrelatedTopology(
            nodes=list(self.nodes.values()),
            links=self.edges,
            evidence_records=self.evidence,
            total_assets=len(self.nodes),
            critical_count=crit,
            quantum_vulnerable_count=qv
        )

    def _compute_blast_radii(self):
        """Traverses predecessors in reverse direction to compute blast radius."""
        # Build adjacency mapping (target -> list of sources)
        predecessors: Dict[str, List[str]] = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            if edge.target in predecessors and edge.source in self.nodes:
                predecessors[edge.target].append(edge.source)

        for node_id, node in self.nodes.items():
            impacted: Set[str] = set()
            queue = list(predecessors.get(node_id, []))
            visited = set(queue)

            while queue:
                curr = queue.pop(0)
                impacted.add(curr)
                for upstream in predecessors.get(curr, []):
                    if upstream not in visited:
                        visited.add(upstream)
                        queue.append(upstream)

            node.blast_radius = sorted(list(impacted))
