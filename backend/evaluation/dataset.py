"""
ECDAT V4 Ground-Truth Benchmark Dataset Loader & Validator.

Validates schema, detects duplicate case IDs, validates label taxonomy,
and computes deterministic SHA-256 dataset hashes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

from .models import BenchmarkCase, BenchmarkDataset, GroundTruthLabel, ModalityType


_DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "datasets" / "ground_truth_v1.yaml"

VALID_MODALITIES = {m.value for m in ModalityType}
VALID_LABELS = {
    GroundTruthLabel.POSITIVE.value,
    GroundTruthLabel.NEGATIVE.value,
    GroundTruthLabel.INCONCLUSIVE.value,
    GroundTruthLabel.CORROBORATED.value,
    GroundTruthLabel.CONTRADICTED.value,
    GroundTruthLabel.UNKNOWN.value,
}


def compute_dataset_hash(cases: List[BenchmarkCase | Dict[str, Any]]) -> str:
    """
    Computes a deterministic SHA-256 digest of the dataset cases.
    Canonicalizes ordering by case_id, excludes machine-specific paths,
    timestamps, and non-deterministic UUIDs.
    """
    canonical_cases = []
    for c in sorted(cases, key=lambda x: x.case_id if isinstance(x, BenchmarkCase) else x["case_id"]):
        if isinstance(c, BenchmarkCase):
            d = c.to_dict()
        else:
            d = dict(c)

        canonical_cases.append({
            "case_id": d["case_id"],
            "modality": d["modality"],
            "language_platform": d["language_platform"],
            "ground_truth_label": d["ground_truth_label"],
            "cryptographic_algorithm": d.get("cryptographic_algorithm"),
            "cryptographic_role": d.get("cryptographic_role"),
            "expected_use_state": d.get("expected_use_state"),
            "expected_evidence_state": d.get("expected_evidence_state"),
            "expected_confidence_class": d.get("expected_confidence_class"),
            "expected_pqc_state": d.get("expected_pqc_state"),
            "dataset_version": d.get("dataset_version", "1.0.0"),
            "dataset_type": d.get("dataset_type", "SYNTHETIC"),
            "hard_negative_category": d.get("hard_negative_category"),
            "input_artifact": d["input_artifact"],
        })

    serialized = json.dumps(canonical_cases, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def validate_case(raw_case: Dict[str, Any], seen_ids: Set[str]) -> BenchmarkCase:
    """Validates a single benchmark case against strict schema rules."""
    case_id = raw_case.get("case_id")
    if not case_id or not isinstance(case_id, str):
        raise ValueError("Benchmark case must have a non-empty string case_id")

    if case_id in seen_ids:
        raise ValueError(f"Duplicate benchmark case_id detected: {case_id}")
    seen_ids.add(case_id)

    modality = raw_case.get("modality")
    if modality not in VALID_MODALITIES:
        raise ValueError(f"Invalid modality '{modality}' in case {case_id}. Allowed: {sorted(VALID_MODALITIES)}")

    label = raw_case.get("ground_truth_label")
    if label not in VALID_LABELS:
        raise ValueError(f"Invalid ground_truth_label '{label}' in case {case_id}. Allowed: {sorted(VALID_LABELS)}")

    artifact = raw_case.get("input_artifact")
    if not isinstance(artifact, dict) or not artifact:
        raise ValueError(f"Case {case_id} input_artifact must be a non-empty dictionary")

    dtype = raw_case.get("dataset_type", "SYNTHETIC")
    if dtype != "SYNTHETIC":
        raise ValueError(f"Case {case_id} must have dataset_type='SYNTHETIC', got: {dtype}")

    return BenchmarkCase(
        case_id=case_id,
        modality=modality,
        language_platform=raw_case.get("language_platform", "generic"),
        input_artifact=artifact,
        ground_truth_label=label,
        cryptographic_algorithm=raw_case.get("cryptographic_algorithm"),
        cryptographic_role=raw_case.get("cryptographic_role"),
        expected_evidence_state=raw_case.get("expected_evidence_state"),
        expected_use_state=raw_case.get("expected_use_state"),
        expected_confidence_class=raw_case.get("expected_confidence_class"),
        expected_pqc_state=raw_case.get("expected_pqc_state"),
        expected_risk_category=raw_case.get("expected_risk_category"),
        expected_agility_category=raw_case.get("expected_agility_category"),
        expected_blast_radius_relation=raw_case.get("expected_blast_radius_relation"),
        dataset_version=str(raw_case.get("dataset_version", "1.0.0")),
        dataset_type=dtype,
        description=raw_case.get("description"),
        hard_negative_category=raw_case.get("hard_negative_category"),
        multi_modal_components=raw_case.get("multi_modal_components"),
    )


def load_dataset(file_path: Optional[Path | str] = None) -> BenchmarkDataset:
    """
    Loads and validates a ground truth benchmark dataset from YAML or JSON.
    Computes dataset_hash and aggregates modality counts.
    """
    target_path = Path(file_path).resolve() if file_path else _DEFAULT_DATASET_PATH

    if not target_path.exists():
        raise FileNotFoundError(f"Benchmark dataset not found at: {target_path}")

    with open(target_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    raw_cases = data.get("cases", [])
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(f"Dataset at {target_path} contains no cases")

    seen_ids: Set[str] = set()
    validated_cases: List[BenchmarkCase] = []
    modality_counts: Dict[str, int] = {m: 0 for m in VALID_MODALITIES}

    for idx, c in enumerate(raw_cases):
        if not isinstance(c, dict):
            raise ValueError(f"Case at index {idx} is not a dictionary")
        case = validate_case(c, seen_ids)
        validated_cases.append(case)
        modality_counts[case.modality] = modality_counts.get(case.modality, 0) + 1

    d_hash = compute_dataset_hash(validated_cases)
    d_version = str(data.get("dataset_version", "1.0.0"))
    d_id = str(data.get("dataset_id", "ecdat-v4-ground-truth-benchmark"))

    return BenchmarkDataset(
        dataset_id=d_id,
        dataset_version=d_version,
        dataset_type="SYNTHETIC",
        dataset_hash=d_hash,
        cases=validated_cases,
        total_cases=len(validated_cases),
        modality_counts=modality_counts,
        metadata={
            "description": data.get("description", "ECDAT V4 Ground-Truth Benchmark Dataset"),
            "disclaimer": "These benchmark results are based on deterministic synthetic controlled fixtures and are not a substitute for validation on real-world production scan data.",
            "generator": data.get("generator", "deterministic_fixture_generator"),
        },
    )


def save_dataset(dataset: BenchmarkDataset, file_path: Path | str) -> None:
    """Saves a BenchmarkDataset to YAML safely."""
    p = Path(file_path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = dataset.to_dict()
    with open(p, "w", encoding="utf-8") as f:
        yaml.dump(payload, f, sort_keys=False, default_flow_style=False, allow_unicode=True)
