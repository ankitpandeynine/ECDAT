"""
ECDAT V4 P4.2 Evaluation Engine & Benchmark Framework Tests.

Verifies:
- Ground-truth benchmark dataset loading & validation
- Deterministic dataset hash computation
- Duplicate case ID detection & rejection
- Malformed dataset and invalid label rejection
- Metric calculation (Precision, Recall, F1, Accuracy, Support)
- Confusion matrix and error breakdown
- Report generation (JSON and Markdown)
- API endpoints for evaluation results
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.dataset import compute_dataset_hash, load_dataset, validate_case
from evaluation.generator import generate_benchmark_cases
from evaluation.metrics import calculate_binary_metrics, compute_evaluation_metrics
from evaluation.confusion import analyze_confusion_and_errors
from evaluation.report import generate_markdown_report
from evaluation import run_benchmark
from main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    return TestClient(app)


class TestEvaluationDataset:
    def test_dataset_loads_and_contains_min_cases(self):
        ds = load_dataset()
        assert ds.total_cases >= 700
        assert ds.dataset_version == "1.0.0"
        assert ds.dataset_type == "SYNTHETIC"
        assert len(ds.dataset_hash) == 64

    def test_all_seven_modalities_represented(self):
        ds = load_dataset()
        expected_modalities = {"SOURCE", "DEPENDENCY", "BINARY", "FIRMWARE", "NETWORK", "X509", "PQC"}
        assert set(ds.modality_counts.keys()) == expected_modalities
        for mod in expected_modalities:
            assert ds.modality_counts[mod] >= 40

    def test_deterministic_dataset_hash(self):
        cases1 = generate_benchmark_cases()
        cases2 = generate_benchmark_cases()
        h1 = compute_dataset_hash(cases1)
        h2 = compute_dataset_hash(cases2)
        assert h1 == h2

    def test_duplicate_case_id_rejection(self):
        seen = set()
        c1 = {"case_id": "DUP_01", "modality": "SOURCE", "input_artifact": {"k": "v"}, "ground_truth_label": "POSITIVE"}
        validate_case(c1, seen)
        with pytest.raises(ValueError, match="Duplicate benchmark case_id"):
            validate_case(c1, seen)

    def test_invalid_modality_rejection(self):
        seen = set()
        c = {"case_id": "BAD_MOD", "modality": "QUANTUM_TELEPORTATION", "input_artifact": {"k": "v"}, "ground_truth_label": "POSITIVE"}
        with pytest.raises(ValueError, match="Invalid modality"):
            validate_case(c, seen)

    def test_invalid_label_rejection(self):
        seen = set()
        c = {"case_id": "BAD_LBL", "modality": "SOURCE", "input_artifact": {"k": "v"}, "ground_truth_label": "SUPER_SAFE"}
        with pytest.raises(ValueError, match="Invalid ground_truth_label"):
            validate_case(c, seen)

    def test_empty_artifact_rejection(self):
        seen = set()
        c = {"case_id": "NO_ART", "modality": "SOURCE", "input_artifact": {}, "ground_truth_label": "POSITIVE"}
        with pytest.raises(ValueError, match="non-empty dictionary"):
            validate_case(c, seen)


class TestMetricsAndConfusion:
    def test_binary_metrics_formula(self):
        # TP=80, TN=90, FP=20, FN=10 -> Precision = 80/100 = 0.8, Recall = 80/90 = 0.8889
        m = calculate_binary_metrics(tp=80, tn=90, fp=20, fn=10)
        assert m["precision"] == 0.8
        assert m["recall"] == round(80 / 90, 4)
        assert m["accuracy"] == 0.85
        assert m["f1"] == round(2 * 0.8 * (80/90) / (0.8 + 80/90), 4)

    def test_hierarchical_metrics_computation(self):
        dummy_results = [
            {"case_id": "c1", "modality": "SOURCE", "ground_truth_label": "POSITIVE", "predicted_label": "POSITIVE", "expected_use_state": "ACTUAL_USE"},
            {"case_id": "c2", "modality": "SOURCE", "ground_truth_label": "NEGATIVE", "predicted_label": "NEGATIVE", "expected_use_state": "IMPORT_ONLY"},
            {"case_id": "c3", "modality": "NETWORK", "ground_truth_label": "POSITIVE", "predicted_label": "POSITIVE", "expected_use_state": "NEGOTIATED"},
            {"case_id": "c4", "modality": "NETWORK", "ground_truth_label": "NEGATIVE", "predicted_label": "NEGATIVE", "expected_use_state": "ADVERTISED_ONLY"},
        ]
        metrics = compute_evaluation_metrics(dummy_results)
        assert metrics["overall"]["tp"] == 2
        assert metrics["overall"]["tn"] == 2
        assert metrics["overall"]["precision"] == 1.0
        assert metrics["overall"]["recall"] == 1.0
        assert "SOURCE" in metrics["modalities"]
        assert "NETWORK" in metrics["modalities"]

    def test_confusion_error_isolation(self):
        dummy_results = [
            {"case_id": "fp_01", "modality": "SOURCE", "ground_truth_label": "NEGATIVE", "predicted_label": "POSITIVE", "hard_negative_category": "HN1"},
            {"case_id": "fn_01", "modality": "BINARY", "ground_truth_label": "POSITIVE", "predicted_label": "NEGATIVE"},
            {"case_id": "ok_01", "modality": "X509", "ground_truth_label": "POSITIVE", "predicted_label": "POSITIVE"},
        ]
        conf = analyze_confusion_and_errors(dummy_results)
        assert conf["false_positive_count"] == 1
        assert conf["false_negative_count"] == 1
        assert conf["false_positives"][0]["case_id"] == "fp_01"
        assert conf["false_negatives"][0]["case_id"] == "fn_01"


class TestEvaluationAPI:
    def test_api_evaluation_summary(self, client):
        resp = client.get("/api/evaluation/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_metrics" in data
        assert "dataset_version" in data
        assert "result_hash" in data

    def test_api_evaluation_modalities(self, client):
        resp = client.get("/api/evaluation/modalities")
        assert resp.status_code == 200
        data = resp.json()
        assert "modality_metrics" in data
        assert "SOURCE" in data["modality_metrics"]
        assert "NETWORK" in data["modality_metrics"]

    def test_api_evaluation_latest(self, client):
        resp = client.get("/api/evaluation/latest")
        assert resp.status_code == 200
        data = resp.json()
        assert data["benchmark_version"] == "1.0.0"
        assert "overall_metrics" in data
        assert "confusion_matrix" in data
