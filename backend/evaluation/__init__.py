"""
ECDAT V4 Evaluation & Benchmark Subsystem.

Exports evaluation models, dataset loaders, pipeline evaluators,
metric calculators, and benchmark report generators.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from engine.knowledge_version import KnowledgeBaseVersion, load_knowledge_version
from .models import (
    BenchmarkCase,
    BenchmarkDataset,
    ConfusionEntry,
    EvaluationResult,
    GroundTruthLabel,
    ModalityMetrics,
    ModalityType,
    ReproducibilityMetadata,
    UseState,
)
from .dataset import compute_dataset_hash, load_dataset, save_dataset
from .generator import generate_and_save_dataset, generate_benchmark_cases
from .evaluator import BenchmarkEvaluator
from .metrics import calculate_binary_metrics, compute_evaluation_metrics
from .confusion import analyze_confusion_and_errors
from .report import generate_markdown_report, save_evaluation_reports


def compute_deterministic_result_hash(
    dataset_hash: str,
    knowledge_hash: str,
    config_hash: str,
    case_results: list[dict[str, Any]],
) -> str:
    """Computes deterministic SHA-256 digest over sorted case predictions."""
    canonical_preds = []
    for cr in sorted(case_results, key=lambda x: x["case_id"]):
        canonical_preds.append({
            "case_id": cr["case_id"],
            "modality": cr["modality"],
            "predicted_label": cr["predicted_label"],
            "predicted_use_state": cr.get("predicted_use_state"),
            "is_correct": cr["is_correct"],
        })
    payload = {
        "dataset_hash": dataset_hash,
        "knowledge_hash": knowledge_hash,
        "config_hash": config_hash,
        "predictions": canonical_preds,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def run_benchmark(
    dataset_path: Optional[Path | str] = None,
    output_dir: Optional[Path | str] = None,
    kb_version: Optional[KnowledgeBaseVersion] = None,
) -> EvaluationResult:
    """
    Runs the full ECDAT V4 benchmark suite:
    1. Loads or generates ground-truth dataset.
    2. Executes actual ECDAT pipelines on all cases.
    3. Computes precision, recall, F1, accuracy, and support.
    4. Analyzes confusion matrix and false positive/negative patterns.
    5. Computes deterministic reproducibility hashes.
    6. Saves JSON and Markdown reports to output_dir if specified.
    """
    kb = kb_version or load_knowledge_version()

    # Load or generate dataset
    if dataset_path and Path(dataset_path).exists():
        dataset = load_dataset(dataset_path)
    else:
        default_ds_path = Path(__file__).resolve().parent / "datasets" / "ground_truth_v1.yaml"
        if not default_ds_path.exists():
            dataset = generate_and_save_dataset(str(default_ds_path))
        else:
            dataset = load_dataset(default_ds_path)

    # Evaluate cases using real pipelines
    evaluator = BenchmarkEvaluator(kb_version=kb)
    case_results = []
    for c in dataset.cases:
        res = evaluator.evaluate_case(c)
        case_results.append(res)

    # Compute metrics
    metrics = compute_evaluation_metrics(case_results)

    # Compute confusion analysis
    confusion = analyze_confusion_and_errors(case_results)

    # Configuration hash
    config_payload = {
        "benchmark_version": "1.0.0",
        "engine_version": "4.0.0",
        "knowledge_base_version": kb.version,
    }
    config_hash = hashlib.sha256(json.dumps(config_payload, sort_keys=True).encode("utf-8")).hexdigest()

    # Result hash
    result_hash = compute_deterministic_result_hash(
        dataset_hash=dataset.dataset_hash,
        knowledge_hash=kb.knowledge_hash,
        config_hash=config_hash,
        case_results=case_results,
    )

    now_iso = datetime.now(timezone.utc).isoformat()
    repro = ReproducibilityMetadata(
        benchmark_version="1.0.0",
        dataset_version=dataset.dataset_version,
        knowledge_base_version=kb.version,
        engine_version="4.0.0",
        configuration_hash=config_hash,
        dataset_hash=dataset.dataset_hash,
        knowledge_hash=kb.knowledge_hash,
        result_hash=result_hash,
        timestamp=now_iso,
        environment={
            "python_version": os.sys.version.split()[0],
            "platform": os.sys.platform,
        },
    )

    eval_result = EvaluationResult(
        benchmark_version="1.0.0",
        dataset_version=dataset.dataset_version,
        dataset_hash=dataset.dataset_hash,
        knowledge_base_version=kb.version,
        knowledge_hash=kb.knowledge_hash,
        engine_version="4.0.0",
        configuration_hash=config_hash,
        timestamp=now_iso,
        environment=repro.environment,
        result_hash=result_hash,
        overall_metrics=metrics["overall"],
        modality_metrics=metrics["modalities"],
        label_metrics=metrics["labels"],
        evidence_category_metrics=metrics["evidence_categories"],
        confusion_matrix=confusion,
        false_positive_cases=confusion["false_positives"],
        false_negative_cases=confusion["false_negatives"],
        case_results=case_results,
        dataset_metadata=dataset.metadata,
        knowledge_metadata=kb.to_dict(),
        reproducibility_metadata=repro.to_dict(),
    )

    # Save reports if output dir requested or default
    target_out_dir = Path(output_dir) if output_dir else Path(__file__).resolve().parent / "results"
    save_evaluation_reports(eval_result, target_out_dir)

    return eval_result


__all__ = [
    "BenchmarkCase",
    "BenchmarkDataset",
    "EvaluationResult",
    "ModalityMetrics",
    "ConfusionEntry",
    "ReproducibilityMetadata",
    "GroundTruthLabel",
    "ModalityType",
    "UseState",
    "BenchmarkEvaluator",
    "load_dataset",
    "save_dataset",
    "generate_benchmark_cases",
    "generate_and_save_dataset",
    "compute_evaluation_metrics",
    "analyze_confusion_and_errors",
    "generate_markdown_report",
    "save_evaluation_reports",
    "run_benchmark",
]
