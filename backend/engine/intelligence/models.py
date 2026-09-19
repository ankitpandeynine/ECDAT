"""
ECDAT V4 P2.1 Intelligence Data Models.

Core principle: severity != confidence. Every field is distinct.
UNKNOWN is a valid and meaningful result -- it must never be coerced to LOW/SAFE/FALSE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid


class RiskSeverity(str, Enum):
    """Categorical severity of a risk conclusion.

    Ordered: NONE < INFO < LOW < MEDIUM < HIGH < CRITICAL < UNKNOWN
    UNKNOWN is not 'safe' -- it means the severity cannot be determined.
    """
    NONE = "NONE"
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        _ranks = {
            "NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3,
            "HIGH": 4, "CRITICAL": 5, "UNKNOWN": -1,
        }
        return _ranks[self.value]

    @classmethod
    def worst(cls, severities: List["RiskSeverity"]) -> "RiskSeverity":
        """Return worst deterministic severity (UNKNOWN stays UNKNOWN if no concrete worst)."""
        concrete = [s for s in severities if s != cls.UNKNOWN]
        if not concrete:
            return cls.UNKNOWN if severities else cls.NONE
        return max(concrete, key=lambda s: s.rank)


class RiskConfidence(str, Enum):
    """Confidence in the evidence supporting a risk conclusion.

    Distinct from RiskSeverity. A HIGH-severity finding may have LOW confidence.
    """
    CORROBORATED = "CORROBORATED"   # Multiple independent strong observations agree
    MEASURED = "MEASURED"           # Single strong direct observation (E3+)
    INFERRED = "INFERRED"           # Derived from indirect evidence (E1-E2)
    UNVERIFIED = "UNVERIFIED"       # Declared/estimated, not directly measured
    CONTRADICTED = "CONTRADICTED"   # Conflicting observations present
    UNKNOWN = "UNKNOWN"             # E0 only or no usable evidence


class CryptoRole(str, Enum):
    """The cryptographic function an algorithm serves in context."""
    KEY_ESTABLISHMENT = "KEY_ESTABLISHMENT"
    SIGNATURE = "SIGNATURE"
    PUBLIC_KEY_ENCRYPTION = "PUBLIC_KEY_ENCRYPTION"
    SYMMETRIC_ENCRYPTION = "SYMMETRIC_ENCRYPTION"
    HASH = "HASH"
    MAC = "MAC"
    KDF = "KDF"
    AUTHENTICATION = "AUTHENTICATION"
    CERTIFICATE_SIGNATURE = "CERTIFICATE_SIGNATURE"
    AEAD = "AEAD"
    UNKNOWN = "UNKNOWN"


class QuantumImpact(str, Enum):
    """How quantum computation affects this algorithm."""
    SHOR_BREAKS = "SHOR_BREAKS"                   # Broken by Shor's (public-key)
    GROVER_HALVING = "GROVER_HALVING"              # Effective key size halved
    GROVER_HALVING_COLLISION = "GROVER_HALVING_COLLISION"  # Hash collision speedup
    HYBRID_PARTIAL = "HYBRID_PARTIAL"              # Hybrid: PQC component + classical
    NONE_PQC_SECURE = "NONE_PQC_SECURE"            # Post-quantum secure algorithm
    BROKEN_CLASSICALLY = "BROKEN_CLASSICALLY"      # Already broken classically
    UNKNOWN = "UNKNOWN"


class PQCReadinessState(str, Enum):
    """PQC readiness state for a specific cryptographic role or aggregate.

    These states are strictly ordered by evidence strength:
    UNKNOWN < NOT_ASSESSED < CLASSICAL_ONLY < PQC_CAPABLE < PQC_CONFIGURED
    < PQC_ADVERTISED < PQC_OFFERED < HYBRID_NEGOTIATED < PQC_NEGOTIATED < PQC_ONLY

    Never promote: CAPABLE -> NEGOTIATED without appropriate evidence.
    """
    UNKNOWN = "UNKNOWN"
    NOT_ASSESSED = "NOT_ASSESSED"
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    PQC_CAPABLE = "PQC_CAPABLE"        # Library supports PQC
    PQC_CONFIGURED = "PQC_CONFIGURED"  # Config references PQC
    PQC_ADVERTISED = "PQC_ADVERTISED"  # Protocol advertisement (SSH KEXINIT)
    PQC_OFFERED = "PQC_OFFERED"        # Client offered PQC in handshake
    HYBRID_NEGOTIATED = "HYBRID_NEGOTIATED"    # Hybrid KEX successfully negotiated
    PQC_NEGOTIATED = "PQC_NEGOTIATED"          # Pure PQC negotiated
    PQC_ONLY = "PQC_ONLY"                      # Only PQC, no classical
    INCONCLUSIVE = "INCONCLUSIVE"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"


class HNDLState(str, Enum):
    """Harvest-Now-Decrypt-Later relevance assessment."""
    HNDL_RELEVANT = "HNDL_RELEVANT"       # Confidentiality at risk of HNDL
    HNDL_POSSIBLE = "HNDL_POSSIBLE"       # Conditions partially met
    HNDL_NOT_APPLICABLE = "HNDL_NOT_APPLICABLE"  # Role/algorithm not subject to HNDL
    HNDL_UNKNOWN = "HNDL_UNKNOWN"         # Insufficient information to assess


class StrengthCategory(str, Enum):
    """Categorical security strength. NOT a numeric score."""
    INSUFFICIENT = "INSUFFICIENT"
    LEGACY = "LEGACY"
    ACCEPTABLE = "ACCEPTABLE"
    STRONG = "STRONG"
    UNKNOWN = "UNKNOWN"


class ParameterStatus(str, Enum):
    """Whether algorithm parameters (key size, curve) are known."""
    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    INFERRED = "INFERRED"


class RiskFactor(str, Enum):
    """Individual risk factors that can be triggered by the rule engine."""
    WEAK_ALGORITHM = "WEAK_ALGORITHM"
    DEPRECATED_ALGORITHM = "DEPRECATED_ALGORITHM"
    INSUFFICIENT_KEY_SIZE = "INSUFFICIENT_KEY_SIZE"
    QUANTUM_VULNERABLE_KEX = "QUANTUM_VULNERABLE_KEX"
    QUANTUM_VULNERABLE_SIGNATURE = "QUANTUM_VULNERABLE_SIGNATURE"
    QUANTUM_VULNERABLE_ENCRYPTION = "QUANTUM_VULNERABLE_ENCRYPTION"
    QUANTUM_WEAKENED_SYMMETRIC = "QUANTUM_WEAKENED_SYMMETRIC"
    LEGACY_PROTOCOL = "LEGACY_PROTOCOL"
    WEAK_TLS_CONFIGURATION = "WEAK_TLS_CONFIGURATION"
    WEAK_CERTIFICATE_SIGNATURE = "WEAK_CERTIFICATE_SIGNATURE"
    EXPIRED_CERTIFICATE = "EXPIRED_CERTIFICATE"
    UNVERIFIED_CERTIFICATE_TRUST = "UNVERIFIED_CERTIFICATE_TRUST"
    INTERNET_EXPOSURE = "INTERNET_EXPOSURE"
    PQC_NOT_NEGOTIATED = "PQC_NOT_NEGOTIATED"
    PQC_PARTIAL_READINESS = "PQC_PARTIAL_READINESS"
    HNDL_EXPOSURE = "HNDL_EXPOSURE"
    UNKNOWN_PARAMETERS = "UNKNOWN_PARAMETERS"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"


@dataclass
class RuleReference:
    """Provenance record for a triggered rule."""
    rule_id: str
    rule_version: str
    knowledge_base_version: str
    triggered_by: str          # human-readable description of the triggering condition
    explanation: str


@dataclass
class EvidenceReference:
    """Lightweight reference to a P0 Evidence item."""
    evidence_id: str
    level: str                 # EvidenceLevel value (E0-E5)
    state: str                 # EvidenceState value
    observation_type: str
    source_engine: str
    location: Optional[str] = None


@dataclass
class UnknownFactor:
    """Records a field that is unknown and affects assessment completeness."""
    field: str
    reason: str


@dataclass
class AssessmentReason:
    """A single structured step in the explanation chain."""
    observation: str
    evidence_ref: Optional[EvidenceReference]
    rule_ref: Optional[RuleReference]
    interpretation: str
    result: str


@dataclass
class SecurityStrengthAssessment:
    """Parameter-aware security strength for a single algorithm."""
    algorithm: str
    canonical_name: Optional[str]
    parameter: Optional[int]              # key size in bits, None if unknown
    parameter_status: ParameterStatus
    parameter_source: str                 # e.g. X509_CERTIFICATE, DEPENDENCY, UNKNOWN
    classical_strength_bits: Optional[int]
    quantum_strength_bits: Optional[int]
    quantum_impact: QuantumImpact
    strength_category: StrengthCategory
    confidence: RiskConfidence
    limitations: List[str] = field(default_factory=list)
    knowledge_base_version: str = "2024.1"


@dataclass
class PQCRoleReadiness:
    """PQC readiness for a single cryptographic role."""
    role: str                     # CryptoRole value
    state: PQCReadinessState
    evidence_refs: List[EvidenceReference] = field(default_factory=list)
    notes: str = ""


@dataclass
class PQCReadinessAssessment:
    """Role-aware PQC readiness assessment for a crypto asset."""
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    scan_id: Optional[str] = None
    key_establishment: PQCReadinessState = PQCReadinessState.NOT_ASSESSED
    signature: PQCReadinessState = PQCReadinessState.NOT_ASSESSED
    certificate: PQCReadinessState = PQCReadinessState.NOT_ASSESSED
    protocol: PQCReadinessState = PQCReadinessState.NOT_ASSESSED
    library: PQCReadinessState = PQCReadinessState.NOT_ASSESSED
    application: PQCReadinessState = PQCReadinessState.NOT_ASSESSED
    overall: str = "UNKNOWN"              # CLASSICAL_ONLY | PARTIAL | HYBRID | PQC_READY | UNKNOWN
    evidence_refs: List[EvidenceReference] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    knowledge_base_version: str = "2024.1"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "key_establishment": self.key_establishment.value,
            "signature": self.signature.value,
            "certificate": self.certificate.value,
            "protocol": self.protocol.value,
            "library": self.library.value,
            "application": self.application.value,
            "overall": self.overall,
            "evidence_refs": [vars(e) for e in self.evidence_refs],
            "limitations": self.limitations,
            "knowledge_base_version": self.knowledge_base_version,
            "created_at": self.created_at,
        }


@dataclass
class HNDLAssessment:
    """Harvest-Now-Decrypt-Later relevance assessment."""
    asset_id: str = ""
    state: HNDLState = HNDLState.HNDL_UNKNOWN
    unknowns: List[str] = field(default_factory=list)
    reason: str = ""
    evidence_refs: List[EvidenceReference] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "state": self.state.value,
            "unknowns": self.unknowns,
            "reason": self.reason,
            "evidence_refs": [vars(e) for e in self.evidence_refs],
            "limitations": self.limitations,
            "created_at": self.created_at,
        }


@dataclass
class RiskAssessment:
    """
    Evidence-driven risk assessment for a crypto asset.

    severity and confidence are ALWAYS separate fields.
    severity=HIGH confidence=UNKNOWN is valid: the risk consequence is high but evidence is weak.
    """
    assessment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    scan_id: Optional[str] = None
    risk_factors: List[RiskFactor] = field(default_factory=list)
    severity: RiskSeverity = RiskSeverity.UNKNOWN
    confidence: RiskConfidence = RiskConfidence.UNKNOWN
    evidence_refs: List[EvidenceReference] = field(default_factory=list)
    rule_refs: List[RuleReference] = field(default_factory=list)
    reason_chain: List[AssessmentReason] = field(default_factory=list)
    unknowns: List[UnknownFactor] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    knowledge_base_version: str = "2024.1"
    pqc_readiness: Optional[PQCReadinessAssessment] = None
    hndl: Optional[HNDLAssessment] = None
    security_strength: Optional[SecurityStrengthAssessment] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "asset_id": self.asset_id,
            "scan_id": self.scan_id,
            "risk": {
                "severity": self.severity.value,
                "confidence": self.confidence.value,
                "factors": [f.value for f in self.risk_factors],
            },
            "evidence_refs": [vars(e) for e in self.evidence_refs],
            "rule_refs": [vars(r) for r in self.rule_refs],
            "reason_chain": [
                {
                    "observation": r.observation,
                    "evidence_ref": vars(r.evidence_ref) if r.evidence_ref else None,
                    "rule_ref": vars(r.rule_ref) if r.rule_ref else None,
                    "interpretation": r.interpretation,
                    "result": r.result,
                }
                for r in self.reason_chain
            ],
            "unknowns": [vars(u) for u in self.unknowns],
            "limitations": self.limitations,
            "created_at": self.created_at,
            "knowledge_base_version": self.knowledge_base_version,
            "pqc_readiness": self.pqc_readiness.to_dict() if self.pqc_readiness else None,
            "hndl": self.hndl.to_dict() if self.hndl else None,
            "security_strength": vars(self.security_strength) if self.security_strength else None,
        }
