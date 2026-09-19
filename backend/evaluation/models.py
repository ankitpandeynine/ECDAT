"""
ECDAT V4 Evaluation & Benchmark Models.

Defines the core data contracts for ground-truth benchmark datasets,
individual test cases, evaluation metrics, confusion analysis, and reproducibility.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional


class ModalityType(str, Enum):
    SOURCE = "SOURCE"
    DEPENDENCY = "DEPENDENCY"
    BINARY = "BINARY"
    FIRMWARE = "FIRMWARE"
    NETWORK = "NETWORK"
    X509 = "X509"
    PQC = "PQC"


class GroundTruthLabel(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    UNKNOWN = "UNKNOWN"


class UseState(str, Enum):
    ACTUAL_USE = "ACTUAL_USE"
    IMPORT_ONLY = "IMPORT_ONLY"
    STRING_ONLY = "STRING_ONLY"
    SYMBOL_ONLY = "SYMBOL_ONLY"
    DEPENDENCY_DECLARED = "DEPENDENCY_DECLARED"
    NEGOTIATED = "NEGOTIATED"
    ADVERTISED_ONLY = "ADVERTISED_ONLY"
    UNUSED = "UNUSED"
    CAPABILITY_ONLY = "CAPABILITY_ONLY"
    CONFIGURATION_ONLY = "CONFIGURATION_ONLY"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class BenchmarkCase:
    case_id: str
    modality: str
    language_platform: str
    input_artifact: Dict[str, Any]
    ground_truth_label: str
    cryptographic_algorithm: Optional[str] = None
    cryptographic_role: Optional[str] = None
    expected_evidence_state: Optional[str] = None
    expected_use_state: Optional[str] = None
    expected_confidence_class: Optional[str] = None
    expected_pqc_state: Optional[str] = None
    expected_risk_category: Optional[str] = None
    expected_agility_category: Optional[str] = None
    expected_blast_radius_relation: Optional[str] = None
    dataset_version: str = "1.0.0"
    dataset_type: str = "SYNTHETIC"
    description: Optional[str] = None
    hard_negative_category: Optional[str] = None
    multi_modal_components: Optional[List[Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BenchmarkCase:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class BenchmarkDataset:
    dataset_id: str
    dataset_version: str
    dataset_type: str
    dataset_hash: str
    cases: List[BenchmarkCase]
    total_cases: int
    modality_counts: Dict[str, int]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["cases"] = [c.to_dict() for c in self.cases]
        return res


@dataclass
class ModalityMetrics:
    modality: str
    total: int
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    support: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfusionEntry:
    expected: str
    predicted: str
    count: int
    modality: str
    case_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReproducibilityMetadata:
    benchmark_version: str
    dataset_version: str
    knowledge_base_version: str
    engine_version: str
    configuration_hash: str
    dataset_hash: str
    knowledge_hash: str
    result_hash: str
    timestamp: str
    environment: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    benchmark_version: str
    dataset_version: str
    dataset_hash: str
    knowledge_base_version: str
    knowledge_hash: str
    engine_version: str
    configuration_hash: str
    timestamp: str
    environment: Dict[str, Any]
    result_hash: str
    overall_metrics: Dict[str, Any]
    modality_metrics: Dict[str, Dict[str, Any]]
    label_metrics: Dict[str, Dict[str, Any]]
    evidence_category_metrics: Dict[str, Dict[str, Any]]
    confusion_matrix: Dict[str, Any]
    false_positive_cases: List[Dict[str, Any]]
    false_negative_cases: List[Dict[str, Any]]
    case_results: List[Dict[str, Any]]
    dataset_metadata: Dict[str, Any]
    knowledge_metadata: Dict[str, Any]
    reproducibility_metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
