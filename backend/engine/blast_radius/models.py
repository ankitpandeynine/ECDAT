"""
ECDAT V4 P2.3 Blast Radius Models & Types.

Defines categorical states, impact classifications, architectural criticality levels,
structured dependency paths, and assessment dataclasses.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class BlastRadiusState(str, Enum):
    """Categorical state of blast radius reachability."""
    DIRECT_ONLY = "DIRECT_ONLY"
    TRANSITIVE = "TRANSITIVE"
    MULTI_PATH = "MULTI_PATH"
    CONTAINED = "CONTAINED"
    WIDESPREAD = "WIDESPREAD"
    UNKNOWN = "UNKNOWN"
    INCONCLUSIVE = "INCONCLUSIVE"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"
    NO_DEPENDENTS_OBSERVED = "NO_DEPENDENTS_OBSERVED"


class ImpactCategory(str, Enum):
    """Architectural scope of downstream impact."""
    NONE_OBSERVED = "NONE_OBSERVED"
    LOCAL = "LOCAL"
    DIRECT = "DIRECT"
    TRANSITIVE = "TRANSITIVE"
    MULTI_SERVICE = "MULTI_SERVICE"
    CROSS_DEPLOYMENT = "CROSS_DEPLOYMENT"
    WIDESPREAD = "WIDESPREAD"
    UNKNOWN = "UNKNOWN"
    INCONCLUSIVE = "INCONCLUSIVE"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"


class CriticalityLevel(str, Enum):
    """Evidence-backed architectural importance of impacted node."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class GraphConfidence(str, Enum):
    """Confidence in graph relationship traversal and evidence backing."""
    MEASURED = "MEASURED"
    INFERRED = "INFERRED"
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class DependencyPath:
    """Structured representation of an evidenced dependency path."""
    path_id: str
    source_asset: str
    target_asset: str
    node_sequence: List[str]
    relationship_sequence: List[str]
    path_length: int
    direct_or_transitive: str  # "DIRECT" or "TRANSITIVE"
    evidence_refs: List[str] = field(default_factory=list)
    confidence: str = GraphConfidence.MEASURED.value
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DependencyPath:
        return cls(**data)


@dataclass
class BlastRadiusReason:
    """Explainable step within an impact analysis reason chain."""
    step: str
    claim: str
    rule_id: Optional[str] = None
    rule_version: Optional[str] = None
    evidence_refs: List[str] = field(default_factory=list)
    supporting: List[str] = field(default_factory=list)
    contradicting: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BlastRadiusReason:
        return cls(**data)


@dataclass
class BlastRadiusAssessment:
    """Comprehensive evidence-backed blast radius and impact assessment."""
    assessment_id: str
    asset_id: str
    scan_id: Optional[str] = None
    project_id: Optional[str] = None
    state: BlastRadiusState = BlastRadiusState.UNKNOWN
    impact_category: ImpactCategory = ImpactCategory.UNKNOWN
    criticality: CriticalityLevel = CriticalityLevel.UNKNOWN
    confidence: GraphConfidence = GraphConfidence.UNKNOWN

    # Direct vs Transitive
    direct_dependents: List[str] = field(default_factory=list)
    transitive_dependents: List[str] = field(default_factory=list)

    # Affected Asset Categories
    affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    affected_files: List[str] = field(default_factory=list)
    affected_modules: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    affected_call_sites: int = 0
    affected_dependencies: List[str] = field(default_factory=list)
    affected_protocols: List[str] = field(default_factory=list)
    affected_certificates: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    affected_deployments: List[str] = field(default_factory=list)
    affected_data_assets: List[str] = field(default_factory=list)

    # Concrete Paths
    dependency_paths: List[DependencyPath] = field(default_factory=list)

    # Evidence & Explainability
    evidence_refs: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    reason_chain: List[BlastRadiusReason] = field(default_factory=list)

    # Provenance
    graph_hash: str = ""
    evidence_hash: str = ""
    configuration_hash: str = ""
    knowledge_base_version: str = "2024.1"
    engine_version: str = "4.0.0"
    created_at: str = ""

    # Bounded Traversal Scope
    graph_scope: Dict[str, Any] = field(default_factory=dict)
    max_depth: int = 10
    max_paths: int = 100
    max_nodes: int = 500
    max_edges: int = 1000
    partial_result: bool = False

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["state"] = self.state.value if isinstance(self.state, BlastRadiusState) else str(self.state)
        res["impact_category"] = self.impact_category.value if isinstance(self.impact_category, ImpactCategory) else str(self.impact_category)
        res["criticality"] = self.criticality.value if isinstance(self.criticality, CriticalityLevel) else str(self.criticality)
        res["confidence"] = self.confidence.value if isinstance(self.confidence, GraphConfidence) else str(self.confidence)
        res["dependency_paths"] = [p.to_dict() if hasattr(p, "to_dict") else p for p in self.dependency_paths]
        res["reason_chain"] = [r.to_dict() if hasattr(r, "to_dict") else r for r in self.reason_chain]
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BlastRadiusAssessment:
        d = dict(data)
        d["state"] = BlastRadiusState(d["state"]) if isinstance(d.get("state"), str) else d.get("state", BlastRadiusState.UNKNOWN)
        d["impact_category"] = ImpactCategory(d["impact_category"]) if isinstance(d.get("impact_category"), str) else d.get("impact_category", ImpactCategory.UNKNOWN)
        d["criticality"] = CriticalityLevel(d["criticality"]) if isinstance(d.get("criticality"), str) else d.get("criticality", CriticalityLevel.UNKNOWN)
        d["confidence"] = GraphConfidence(d["confidence"]) if isinstance(d.get("confidence"), str) else d.get("confidence", GraphConfidence.UNKNOWN)
        if "dependency_paths" in d and isinstance(d["dependency_paths"], list):
            d["dependency_paths"] = [DependencyPath.from_dict(p) if isinstance(p, dict) else p for p in d["dependency_paths"]]
        if "reason_chain" in d and isinstance(d["reason_chain"], list):
            d["reason_chain"] = [BlastRadiusReason.from_dict(r) if isinstance(r, dict) else r for r in d["reason_chain"]]
        return cls(**d)
