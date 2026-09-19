"""
ECDAT V4 P2.2 Crypto-Agility Intelligence Data Models.

Core Principles:
1. Agility measures CHANGEABILITY, not simply security.
2. The 7 dimensions are the authoritative source of truth.
3. No single black-box score is the primary output; any scalar score is explicitly DERIVED.
4. UNKNOWN is preserved and never coerced to BLOCKED or SUPPORTED.
5. Contradictory evidence is preserved and results in PARTIALLY_OBSERVED with dual evidence chains.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgilityDimension(str, Enum):
    """The 7 independent dimensions of cryptographic agility."""
    AGILITY_ALGORITHM = "AGILITY_ALGORITHM"
    AGILITY_CONFIGURATION = "AGILITY_CONFIGURATION"
    AGILITY_DEPENDENCY = "AGILITY_DEPENDENCY"
    AGILITY_PROTOCOL = "AGILITY_PROTOCOL"
    AGILITY_CERTIFICATE = "AGILITY_CERTIFICATE"
    AGILITY_DEPLOYMENT = "AGILITY_DEPLOYMENT"
    AGILITY_VALIDATION = "AGILITY_VALIDATION"


class AgilityState(str, Enum):
    """Observable agility state for a dimension or overall assessment."""
    SUPPORTED = "SUPPORTED"
    OBSERVED = "OBSERVED"
    PARTIALLY_OBSERVED = "PARTIALLY_OBSERVED"
    CONSTRAINED = "CONSTRAINED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"

    @property
    def rank(self) -> int:
        """Ordinal rank for conservative aggregation (higher rank = more agile)."""
        _ranks = {
            "BLOCKED": 0,
            "CONSTRAINED": 1,
            "PARTIALLY_OBSERVED": 2,
            "SUPPORTED": 3,
            "OBSERVED": 4,
            "NOT_APPLICABLE": -1,
            "SCANNER_UNAVAILABLE": -2,
            "UNKNOWN": -3,
        }
        return _ranks[self.value]


class AgilityConfidence(str, Enum):
    """Confidence in the evidence supporting an agility conclusion."""
    MEASURED = "MEASURED"           # Directly observed runtime or network behavior (E3+)
    INFERRED = "INFERRED"           # Inferred from code structure, patterns, or config (E1-E2)
    CORROBORATED = "CORROBORATED"   # Corroborated by static + dynamic observations
    UNVERIFIED = "UNVERIFIED"       # Declared in metadata without runtime proof
    CONTRADICTED = "CONTRADICTED"   # Conflicting signals present
    UNKNOWN = "UNKNOWN"             # Missing evidence


class ChangeComplexity(str, Enum):
    """Evidence-backed estimated complexity of executing a cryptographic change."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class AgilityReason:
    """Structured, traceable reason step explaining an agility conclusion."""
    dimension: str
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
    def from_dict(cls, data: Dict[str, Any]) -> AgilityReason:
        return cls(**data)


@dataclass
class DimensionalAgility:
    """Assessment result for one of the 7 agility dimensions."""
    dimension: AgilityDimension
    state: AgilityState
    confidence: AgilityConfidence
    evidence_refs: List[str] = field(default_factory=list)
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    reason_chain: List[AgilityReason] = field(default_factory=list)
    derived_score: Optional[float] = None  # Explicitly labeled derived score

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["dimension"] = self.dimension.value
        res["state"] = self.state.value
        res["confidence"] = self.confidence.value
        res["reason_chain"] = [r.to_dict() if hasattr(r, "to_dict") else r for r in self.reason_chain]
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DimensionalAgility:
        d = dict(data)
        d["dimension"] = AgilityDimension(d["dimension"])
        d["state"] = AgilityState(d["state"])
        d["confidence"] = AgilityConfidence(d["confidence"])
        d["reason_chain"] = [
            AgilityReason.from_dict(r) if isinstance(r, dict) else r
            for r in d.get("reason_chain", [])
        ]
        return cls(**d)


@dataclass
class CryptoChangeSurface:
    """Structured footprint of what must change during a cryptographic upgrade."""
    asset_id: str
    surface_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    affected_files: List[str] = field(default_factory=list)
    affected_modules: List[str] = field(default_factory=list)
    affected_functions: List[str] = field(default_factory=list)
    call_sites_count: int = 0
    affected_dependencies: List[str] = field(default_factory=list)
    affected_protocols: List[str] = field(default_factory=list)
    affected_certificates: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    affected_deployments: List[str] = field(default_factory=list)
    direct_dependents: List[str] = field(default_factory=list)
    transitive_dependents: List[str] = field(default_factory=list)
    graph_blast_radius: Dict[str, Any] = field(default_factory=dict)
    complexity: ChangeComplexity = ChangeComplexity.UNKNOWN
    complexity_factors: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["complexity"] = self.complexity.value
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CryptoChangeSurface:
        d = dict(data)
        d["complexity"] = ChangeComplexity(d["complexity"])
        return cls(**d)


@dataclass
class AgilityAssessment:
    """Master evidence-driven agility assessment for an asset."""
    asset_id: str
    overall_state: AgilityState
    dimensions: Dict[str, DimensionalAgility]
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: Optional[str] = None
    composite_score: Optional[float] = None
    derived_score_metadata: Dict[str, Any] = field(default_factory=dict)
    change_surface: Optional[CryptoChangeSurface] = None
    reasons: List[AgilityReason] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    evidence_hash: str = ""
    configuration_hash: str = ""
    knowledge_base_version: str = "2024.1"
    engine_version: str = "4.0.0"
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "overall_state": self.overall_state.value,
            "composite_score": self.composite_score,
            "derived_score_metadata": self.derived_score_metadata,
            "dimensions": {k: v.to_dict() if hasattr(v, "to_dict") else v for k, v in self.dimensions.items()},
            "change_surface": self.change_surface.to_dict() if self.change_surface else None,
            "reasons": [r.to_dict() if hasattr(r, "to_dict") else r for r in self.reasons],
            "unknowns": self.unknowns,
            "limitations": self.limitations,
            "evidence_hash": self.evidence_hash,
            "configuration_hash": self.configuration_hash,
            "knowledge_base_version": self.knowledge_base_version,
            "engine_version": self.engine_version,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgilityAssessment:
        d = dict(data)
        d["overall_state"] = AgilityState(d["overall_state"])
        dims = {}
        for k, v in d.get("dimensions", {}).items():
            dims[k] = DimensionalAgility.from_dict(v) if isinstance(v, dict) else v
        d["dimensions"] = dims
        if d.get("change_surface"):
            d["change_surface"] = CryptoChangeSurface.from_dict(d["change_surface"])
        d["reasons"] = [
            AgilityReason.from_dict(r) if isinstance(r, dict) else r
            for r in d.get("reasons", [])
        ]
        return cls(**d)

    def compute_evidence_hash(self, evidence_list: List[Any]) -> str:
        """Deterministic sha256 hash of all input evidence items."""
        ids = sorted([
            getattr(e, "id", None) or (e.get("id") if isinstance(e, dict) else str(e))
            for e in evidence_list
        ])
        serialized = json.dumps(ids, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
