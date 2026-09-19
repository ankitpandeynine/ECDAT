"""
ECDAT V4 P3.1 + P3.2 Migration Intelligence & Verification Models.

Defines transition modes, priorities, step actions, verification states,
and dataclasses for MigrationContext, MigrationTarget, MigrationStep,
MigrationPlan, and MigrationVerification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TransitionMode(str, Enum):
    """Supported migration and transition strategies."""
    DIRECT_REPLACEMENT = "DIRECT_REPLACEMENT"
    HYBRID_TRANSITION = "HYBRID_TRANSITION"
    DUAL_SUPPORT = "DUAL_SUPPORT"
    CONFIGURATION_MIGRATION = "CONFIGURATION_MIGRATION"
    DEPENDENCY_UPGRADE = "DEPENDENCY_UPGRADE"
    CERTIFICATE_MIGRATION = "CERTIFICATE_MIGRATION"
    PROTOCOL_MIGRATION = "PROTOCOL_MIGRATION"
    APPLICATION_REFACTOR = "APPLICATION_REFACTOR"
    UNKNOWN = "UNKNOWN"


class MigrationPriority(str, Enum):
    """Derived migration planning priority (orthogonal to raw risk severity)."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class VerificationState(str, Enum):
    """Status of before/after migration completion verification."""
    VERIFIED = "VERIFIED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNKNOWN = "UNKNOWN"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"


class MigrationStepAction(str, Enum):
    """Standardized action types for migration plan steps."""
    UPGRADE_DEPENDENCY = "UPGRADE_DEPENDENCY"
    REPLACE_PRIMITIVE = "REPLACE_PRIMITIVE"
    ENABLE_HYBRID_KEX = "ENABLE_HYBRID_KEX"
    MIGRATE_CERTIFICATE = "MIGRATE_CERTIFICATE"
    UPDATE_PROTOCOL_CONFIG = "UPDATE_PROTOCOL_CONFIG"
    REFACTOR_CALL_SITES = "REFACTOR_CALL_SITES"
    DEPLOY_TO_STAGING = "DEPLOY_TO_STAGING"
    PERFORM_VERIFICATION_SCAN = "PERFORM_VERIFICATION_SCAN"


@dataclass
class MigrationTarget:
    """Designated post-quantum replacement or transition candidate."""
    current_algorithm: str
    current_role: str
    target_algorithm: str
    target_role: str
    target_parameters: Dict[str, Any] = field(default_factory=dict)
    transition_mode: TransitionMode = TransitionMode.UNKNOWN
    rationale: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["transition_mode"] = self.transition_mode.value if isinstance(self.transition_mode, TransitionMode) else str(self.transition_mode)
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MigrationTarget:
        d = dict(data)
        d["transition_mode"] = TransitionMode(d["transition_mode"]) if isinstance(d.get("transition_mode"), str) else d.get("transition_mode", TransitionMode.UNKNOWN)
        return cls(**d)


@dataclass
class MigrationStep:
    """Actionable, sequenced step within an overall migration plan."""
    step_id: str
    order: int
    action: str
    target_component: str
    prerequisite_steps: List[str] = field(default_factory=list)
    expected_change: str = ""
    verification_method: str = ""
    evidence_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MigrationStep:
        return cls(**data)


@dataclass
class MigrationReason:
    """Structured step within an explainable migration reasoning chain."""
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
    def from_dict(cls, data: Dict[str, Any]) -> MigrationReason:
        return cls(**data)


@dataclass
class MigrationContext:
    """Synthesized input context uniting P0, P1, P2.1, P2.2, and P2.3 intelligence."""
    asset_id: str
    scan_id: Optional[str] = None
    project_id: Optional[str] = None
    algorithm: str = ""
    cryptographic_role: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    pqc_readiness: Dict[str, Any] = field(default_factory=dict)
    agility_assessment: Dict[str, Any] = field(default_factory=dict)
    blast_radius: Dict[str, Any] = field(default_factory=dict)
    dependency_paths: List[Dict[str, Any]] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    knowledge_base_version: str = "2024.1"
    engine_version: str = "4.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MigrationContext:
        return cls(**data)


@dataclass
class MigrationPlan:
    """Comprehensive, evidence-grounded PQC Migration Plan."""
    plan_id: str
    asset_id: str
    scan_id: Optional[str] = None
    project_id: Optional[str] = None
    current_state: str = "CLASSICAL"
    target_state: str = "PQC_PROTECTED"
    priority: MigrationPriority = MigrationPriority.UNKNOWN
    migration_target: Optional[MigrationTarget] = None
    steps: List[MigrationStep] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    affected_assets: List[Dict[str, Any]] = field(default_factory=list)
    blast_radius_summary: Dict[str, Any] = field(default_factory=dict)
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    agility_summary: Dict[str, Any] = field(default_factory=dict)
    pqc_summary: Dict[str, Any] = field(default_factory=dict)
    verification_criteria: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    reason_chain: List[MigrationReason] = field(default_factory=list)
    evidence_hash: str = ""
    configuration_hash: str = ""
    knowledge_base_version: str = "2024.1"
    engine_version: str = "4.0.0"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["priority"] = self.priority.value if isinstance(self.priority, MigrationPriority) else str(self.priority)
        if self.migration_target:
            res["migration_target"] = self.migration_target.to_dict()
        res["steps"] = [s.to_dict() if hasattr(s, "to_dict") else s for s in self.steps]
        res["reason_chain"] = [r.to_dict() if hasattr(r, "to_dict") else r for r in self.reason_chain]
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MigrationPlan:
        d = dict(data)
        d["priority"] = MigrationPriority(d["priority"]) if isinstance(d.get("priority"), str) else d.get("priority", MigrationPriority.UNKNOWN)
        if d.get("migration_target") and isinstance(d["migration_target"], dict):
            d["migration_target"] = MigrationTarget.from_dict(d["migration_target"])
        if d.get("steps") and isinstance(d["steps"], list):
            d["steps"] = [MigrationStep.from_dict(s) if isinstance(s, dict) else s for s in d["steps"]]
        if d.get("reason_chain") and isinstance(d["reason_chain"], list):
            d["reason_chain"] = [MigrationReason.from_dict(r) if isinstance(r, dict) else r for r in d["reason_chain"]]
        return cls(**d)


@dataclass
class MigrationVerification:
    """Audit verification comparing pre-migration state against post-migration scans."""
    verification_id: str
    migration_plan_id: Optional[str] = None
    asset_id: str = ""
    before_scan_id: Optional[str] = None
    after_scan_id: Optional[str] = None
    expected_changes: List[str] = field(default_factory=list)
    observed_changes: List[str] = field(default_factory=list)
    verification_state: VerificationState = VerificationState.UNKNOWN
    evidence_refs: List[str] = field(default_factory=list)
    discrepancies: List[str] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    reason_chain: List[MigrationReason] = field(default_factory=list)
    evidence_hash: str = ""
    configuration_hash: str = ""
    knowledge_base_version: str = "2024.1"
    engine_version: str = "4.0.0"
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["verification_state"] = self.verification_state.value if isinstance(self.verification_state, VerificationState) else str(self.verification_state)
        res["reason_chain"] = [r.to_dict() if hasattr(r, "to_dict") else r for r in self.reason_chain]
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MigrationVerification:
        d = dict(data)
        d["verification_state"] = VerificationState(d["verification_state"]) if isinstance(d.get("verification_state"), str) else d.get("verification_state", VerificationState.UNKNOWN)
        if d.get("reason_chain") and isinstance(d["reason_chain"], list):
            d["reason_chain"] = [MigrationReason.from_dict(r) if isinstance(r, dict) else r for r in d["reason_chain"]]
        return cls(**d)
