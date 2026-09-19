"""
ECDAT V4 Continuous Posture Models and Structured Data Contracts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PostureDimension(str, Enum):
    CRYPTO_INVENTORY = "CRYPTO_INVENTORY"
    QUANTUM_RISK = "QUANTUM_RISK"
    PQC_READINESS = "PQC_READINESS"
    CRYPTO_AGILITY = "CRYPTO_AGILITY"
    BLAST_RADIUS = "BLAST_RADIUS"
    MIGRATION_STATUS = "MIGRATION_STATUS"
    EVIDENCE_QUALITY = "EVIDENCE_QUALITY"


class InventoryState(str, Enum):
    EMPTY = "EMPTY"
    CATALOGED = "CATALOGED"
    EXPANDING = "EXPANDING"
    SHRINKING = "SHRINKING"
    STABLE = "STABLE"


class QuantumRiskState(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    ELEVATED = "ELEVATED"
    MODERATE = "MODERATE"
    LOW = "LOW"


class PQCReadinessState(str, Enum):
    NON_COMPLIANT = "NON_COMPLIANT"
    PLANNING = "PLANNING"
    HYBRID_TRANSITION = "HYBRID_TRANSITION"
    PQC_READY = "PQC_READY"
    COMPLIANT = "COMPLIANT"


class CryptoAgilityState(str, Enum):
    RIGID = "RIGID"
    FRAGILE = "FRAGILE"
    PARTIALLY_AGILE = "PARTIALLY_AGILE"
    AGILE = "AGILE"
    HIGHLY_AGILE = "HIGHLY_AGILE"


class BlastRadiusState(str, Enum):
    UNBOUNDED = "UNBOUNDED"
    BROAD = "BROAD"
    CONTAINED = "CONTAINED"
    ISOLATED = "ISOLATED"
    MINIMAL = "MINIMAL"


class MigrationStatusState(str, Enum):
    NOT_STARTED = "NOT_STARTED"
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


class EvidenceQualityState(str, Enum):
    SPECULATIVE = "SPECULATIVE"
    HEURISTIC = "HEURISTIC"
    VERIFIED_STATIC = "VERIFIED_STATIC"
    VERIFIED_RUNTIME = "VERIFIED_RUNTIME"
    CORROBORATED = "CORROBORATED"


class PostureTrend(str, Enum):
    IMPROVED = "IMPROVED"
    DEGRADED = "DEGRADED"
    UNCHANGED = "UNCHANGED"
    NOT_ENOUGH_HISTORY = "NOT_ENOUGH_HISTORY"
    UNKNOWN = "UNKNOWN"


@dataclass
class DimensionAssessment:
    dimension: PostureDimension
    state: str
    numeric_value: Optional[float] = None
    summary: str = ""
    evidence_count: int = 0
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension.value if hasattr(self.dimension, "value") else str(self.dimension),
            "state": self.state,
            "numeric_value": self.numeric_value,
            "summary": self.summary,
            "evidence_count": self.evidence_count,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DimensionAssessment:
        dim_str = data.get("dimension", PostureDimension.CRYPTO_INVENTORY.value)
        try:
            dim = PostureDimension(dim_str)
        except Exception:
            dim = PostureDimension.CRYPTO_INVENTORY
        return cls(
            dimension=dim,
            state=data.get("state", "UNKNOWN"),
            numeric_value=data.get("numeric_value"),
            summary=data.get("summary", ""),
            evidence_count=data.get("evidence_count", 0),
            details=data.get("details", {}),
        )


@dataclass
class PostureAssessment:
    assessment_id: str
    project_id: str
    scan_id: str
    asset_id: Optional[str] = None
    dimensions: Dict[str, DimensionAssessment] = field(default_factory=dict)
    posture_hash: str = ""
    summary: str = ""
    created_at: str = field(default_factory=now_iso)

    def compute_hash(self) -> str:
        serialized = json.dumps(
            {
                "project_id": self.project_id,
                "scan_id": self.scan_id,
                "asset_id": self.asset_id,
                "dimensions": {k: v.to_dict() for k, v in sorted(self.dimensions.items())},
            },
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "project_id": self.project_id,
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
            "posture_hash": self.posture_hash or self.compute_hash(),
            "summary": self.summary,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PostureAssessment:
        raw_dims = data.get("dimensions", {})
        dimensions = {k: DimensionAssessment.from_dict(v) for k, v in raw_dims.items()}
        return cls(
            assessment_id=data.get("assessment_id", ""),
            project_id=data.get("project_id", "default"),
            scan_id=data.get("scan_id", ""),
            asset_id=data.get("asset_id"),
            dimensions=dimensions,
            posture_hash=data.get("posture_hash", ""),
            summary=data.get("summary", ""),
            created_at=data.get("created_at", now_iso()),
        )


@dataclass
class PostureDimensionTransition:
    dimension: PostureDimension
    base_state: str
    target_state: str
    trend: PostureTrend
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dimension": self.dimension.value if hasattr(self.dimension, "value") else str(self.dimension),
            "base_state": self.base_state,
            "target_state": self.target_state,
            "trend": self.trend.value if hasattr(self.trend, "value") else str(self.trend),
            "explanation": self.explanation,
        }


@dataclass
class PostureChangeAssessment:
    change_id: str
    project_id: str
    base_assessment_id: str
    target_assessment_id: str
    asset_id: Optional[str] = None
    overall_trend: PostureTrend = PostureTrend.NOT_ENOUGH_HISTORY
    dimension_transitions: Dict[str, PostureDimensionTransition] = field(default_factory=dict)
    summary: str = ""
    created_at: str = field(default_factory=now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_id": self.change_id,
            "project_id": self.project_id,
            "base_assessment_id": self.base_assessment_id,
            "target_assessment_id": self.target_assessment_id,
            "asset_id": self.asset_id,
            "overall_trend": self.overall_trend.value if hasattr(self.overall_trend, "value") else str(self.overall_trend),
            "dimension_transitions": {k: v.to_dict() for k, v in self.dimension_transitions.items()},
            "summary": self.summary,
            "created_at": self.created_at,
        }
