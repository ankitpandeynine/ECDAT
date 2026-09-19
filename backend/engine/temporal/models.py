"""
ECDAT V4 Temporal Models and Data Structures.
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


class ChangeCategory(str, Enum):
    NEW = "NEW"
    REMOVED = "REMOVED"
    CHANGED = "CHANGED"
    UNCHANGED = "UNCHANGED"
    UNKNOWN = "UNKNOWN"


class RiskChange(str, Enum):
    RISK_NEW = "RISK_NEW"
    RISK_INCREASED = "RISK_INCREASED"
    RISK_DECREASED = "RISK_DECREASED"
    RISK_UNCHANGED = "RISK_UNCHANGED"
    RISK_UNKNOWN = "RISK_UNKNOWN"


class PQCChange(str, Enum):
    PQC_INTRODUCED = "PQC_INTRODUCED"
    PQC_REMOVED = "PQC_REMOVED"
    PQC_UPGRADED = "PQC_UPGRADED"
    PQC_UNCHANGED = "PQC_UNCHANGED"
    PQC_UNKNOWN = "PQC_UNKNOWN"


class AgilityChange(str, Enum):
    AGILITY_INCREASED = "AGILITY_INCREASED"
    AGILITY_DECREASED = "AGILITY_DECREASED"
    AGILITY_UNCHANGED = "AGILITY_UNCHANGED"
    AGILITY_UNKNOWN = "AGILITY_UNKNOWN"


class MigrationChange(str, Enum):
    MIGRATION_STARTED = "MIGRATION_STARTED"
    MIGRATION_PROGRESSING = "MIGRATION_PROGRESSING"
    MIGRATION_VERIFIED = "MIGRATION_VERIFIED"
    MIGRATION_FAILED = "MIGRATION_FAILED"
    MIGRATION_UNCHANGED = "MIGRATION_UNCHANGED"
    MIGRATION_UNKNOWN = "MIGRATION_UNKNOWN"


class TimelineEventType(str, Enum):
    FIRST_OBSERVED = "FIRST_OBSERVED"
    OBSERVED = "OBSERVED"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"
    UNOBSERVED = "UNOBSERVED"
    ALGORITHM_CHANGED = "ALGORITHM_CHANGED"
    RISK_CHANGED = "RISK_CHANGED"
    REMOVED = "REMOVED"


@dataclass
class TimelineEvent:
    scan_id: str
    timestamp: str
    event_type: TimelineEventType
    description: str
    evidence_level: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value if hasattr(self.event_type, "value") else str(self.event_type),
            "description": self.description,
            "evidence_level": self.evidence_level,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TimelineEvent:
        et = data.get("event_type", TimelineEventType.OBSERVED.value)
        try:
            event_type = TimelineEventType(et)
        except Exception:
            event_type = TimelineEventType.OBSERVED
        return cls(
            scan_id=data.get("scan_id", "unknown"),
            timestamp=data.get("timestamp", now_iso()),
            event_type=event_type,
            description=data.get("description", ""),
            evidence_level=data.get("evidence_level"),
            confidence=data.get("confidence"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AssetTimeline:
    timeline_id: str
    asset_id: str
    asset_key: str
    project_id: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    observation_count: int = 0
    events: List[TimelineEvent] = field(default_factory=list)
    current_status: str = "ACTIVE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline_id": self.timeline_id,
            "asset_id": self.asset_id,
            "asset_key": self.asset_key,
            "project_id": self.project_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "events": [e.to_dict() for e in self.events],
            "current_status": self.current_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetTimeline:
        events = [TimelineEvent.from_dict(e) for e in data.get("events", [])]
        return cls(
            timeline_id=data.get("timeline_id", ""),
            asset_id=data.get("asset_id", ""),
            asset_key=data.get("asset_key", ""),
            project_id=data.get("project_id", "default"),
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            observation_count=data.get("observation_count", len(events)),
            events=events,
            current_status=data.get("current_status", "ACTIVE"),
        )


@dataclass
class AssetChange:
    asset_key: str
    asset_id: Optional[str] = None
    name: str = ""
    category: ChangeCategory = ChangeCategory.UNKNOWN
    base_asset: Optional[Dict[str, Any]] = None
    target_asset: Optional[Dict[str, Any]] = None
    diff_summary: Dict[str, Any] = field(default_factory=dict)
    risk_change: RiskChange = RiskChange.RISK_UNKNOWN
    pqc_change: PQCChange = PQCChange.PQC_UNKNOWN
    agility_change: AgilityChange = AgilityChange.AGILITY_UNKNOWN
    migration_change: MigrationChange = MigrationChange.MIGRATION_UNKNOWN
    confidence: float = 1.0
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_key": self.asset_key,
            "asset_id": self.asset_id,
            "name": self.name,
            "category": self.category.value if hasattr(self.category, "value") else str(self.category),
            "base_asset": self.base_asset,
            "target_asset": self.target_asset,
            "diff_summary": self.diff_summary,
            "risk_change": self.risk_change.value if hasattr(self.risk_change, "value") else str(self.risk_change),
            "pqc_change": self.pqc_change.value if hasattr(self.pqc_change, "value") else str(self.pqc_change),
            "agility_change": self.agility_change.value if hasattr(self.agility_change, "value") else str(self.agility_change),
            "migration_change": self.migration_change.value if hasattr(self.migration_change, "value") else str(self.migration_change),
            "confidence": self.confidence,
            "explanation": self.explanation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AssetChange:
        cat_val = data.get("category", ChangeCategory.UNKNOWN.value)
        try:
            category = ChangeCategory(cat_val)
        except Exception:
            category = ChangeCategory.UNKNOWN

        rc_val = data.get("risk_change", RiskChange.RISK_UNKNOWN.value)
        try:
            risk_change = RiskChange(rc_val)
        except Exception:
            risk_change = RiskChange.RISK_UNKNOWN

        pqc_val = data.get("pqc_change", PQCChange.PQC_UNKNOWN.value)
        try:
            pqc_change = PQCChange(pqc_val)
        except Exception:
            pqc_change = PQCChange.PQC_UNKNOWN

        ag_val = data.get("agility_change", AgilityChange.AGILITY_UNKNOWN.value)
        try:
            agility_change = AgilityChange(ag_val)
        except Exception:
            agility_change = AgilityChange.AGILITY_UNKNOWN

        mg_val = data.get("migration_change", MigrationChange.MIGRATION_UNKNOWN.value)
        try:
            migration_change = MigrationChange(mg_val)
        except Exception:
            migration_change = MigrationChange.MIGRATION_UNKNOWN

        return cls(
            asset_key=data.get("asset_key", ""),
            asset_id=data.get("asset_id"),
            name=data.get("name", ""),
            category=category,
            base_asset=data.get("base_asset"),
            target_asset=data.get("target_asset"),
            diff_summary=data.get("diff_summary", {}),
            risk_change=risk_change,
            pqc_change=pqc_change,
            agility_change=agility_change,
            migration_change=migration_change,
            confidence=data.get("confidence", 1.0),
            explanation=data.get("explanation", ""),
        )


@dataclass
class TemporalComparison:
    comparison_id: str
    project_id: str
    base_scan_id: str
    target_scan_id: str
    base_timestamp: Optional[str] = None
    target_timestamp: Optional[str] = None
    added_count: int = 0
    removed_count: int = 0
    changed_count: int = 0
    unchanged_count: int = 0
    asset_changes: List[AssetChange] = field(default_factory=list)
    temporal_hash: str = ""
    explanation: str = ""
    created_at: str = field(default_factory=now_iso)

    def compute_hash(self) -> str:
        serialized = json.dumps(
            {
                "project_id": self.project_id,
                "base_scan_id": self.base_scan_id,
                "target_scan_id": self.target_scan_id,
                "added_count": self.added_count,
                "removed_count": self.removed_count,
                "changed_count": self.changed_count,
                "unchanged_count": self.unchanged_count,
                "changes": [
                    {
                        "asset_key": c.asset_key,
                        "category": c.category.value if hasattr(c.category, "value") else str(c.category),
                        "risk_change": c.risk_change.value if hasattr(c.risk_change, "value") else str(c.risk_change),
                    }
                    for c in self.asset_changes
                ],
            },
            sort_keys=True,
        )
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "comparison_id": self.comparison_id,
            "project_id": self.project_id,
            "base_scan_id": self.base_scan_id,
            "target_scan_id": self.target_scan_id,
            "base_timestamp": self.base_timestamp,
            "target_timestamp": self.target_timestamp,
            "added_count": self.added_count,
            "removed_count": self.removed_count,
            "changed_count": self.changed_count,
            "unchanged_count": self.unchanged_count,
            "asset_changes": [c.to_dict() for c in self.asset_changes],
            "temporal_hash": self.temporal_hash or self.compute_hash(),
            "explanation": self.explanation,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TemporalComparison:
        changes = [AssetChange.from_dict(c) for c in data.get("asset_changes", [])]
        return cls(
            comparison_id=data.get("comparison_id", ""),
            project_id=data.get("project_id", "default"),
            base_scan_id=data.get("base_scan_id", ""),
            target_scan_id=data.get("target_scan_id", ""),
            base_timestamp=data.get("base_timestamp"),
            target_timestamp=data.get("target_timestamp"),
            added_count=data.get("added_count", 0),
            removed_count=data.get("removed_count", 0),
            changed_count=data.get("changed_count", 0),
            unchanged_count=data.get("unchanged_count", 0),
            asset_changes=changes,
            temporal_hash=data.get("temporal_hash", ""),
            explanation=data.get("explanation", ""),
            created_at=data.get("created_at", now_iso()),
        )
