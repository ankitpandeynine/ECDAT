# ECDAT V4 — Research & Validation Benchmark Report

> **Notice & Disclaimer**: These benchmark results are based on deterministic synthetic controlled fixtures and are not a substitute for validation on real-world production scan data.

## 1. Executive Summary & Headline Metrics

- **Total Benchmark Cases**: 736
- **Dataset Version**: `1.0.0` (Hash: `c9de8400c10d28ec...`)
- **Knowledge Base Version**: `2024.1` (Hash: `7b668faaae011b81...`)
- **Engine Version**: `4.0.0`
- **Result Content Hash**: `8aeed2c32044d47ae302fdfc5275c2b9b8d898ea5830ba73da57e8b7ca5c8e01`

| Metric | Value | Interpretation |
|:---|:---:|:---|
| **Precision** | **1.0000** | Ratio of true positive crypto detections to all positive alarms |
| **Recall** | **0.8694** | Proportion of actual cryptographic instances detected |
| **F1 Score** | **0.9301** | Harmonic mean of precision and recall |
| **Accuracy** | **0.9130** | Overall correctness (non-headline context metric) |
| **True Positives (TP)** | 426 | Correctly detected active cryptographic implementations |
| **True Negatives (TN)** | 246 | Correctly identified non-crypto or unexecuted assets |
| **False Positives (FP)** | 0 | Non-crypto falsely flagged as active crypto |
| **False Negatives (FN)** | 64 | Active crypto instances missed by scanners |

---

## 2. Per-Modality Performance Breakdown

| Modality | Cases | TP | TN | FP | FN | Precision | Recall | F1 |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **BINARY** | 135 | 60 | 35 | 0 | 40 | 1.0000 | 0.6000 | **0.7500** |
| **DEPENDENCY** | 130 | 36 | 70 | 0 | 24 | 1.0000 | 0.6000 | **0.7500** |
| **FIRMWARE** | 50 | 35 | 15 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **NETWORK** | 142 | 90 | 52 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **PQC** | 74 | 56 | 18 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **SOURCE** | 130 | 99 | 31 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **X509** | 75 | 50 | 25 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |

---

## 3. Confusion Matrix & Error Analysis

- **Total False Positives**: 0
- **Total False Negatives**: 64

### Categorical Confusion Matrix:
```json
{
  "POSITIVE": {
    "POSITIVE": 411,
    "NEGATIVE": 64
  },
  "NEGATIVE": {
    "NEGATIVE": 221
  },
  "CORROBORATED": {
    "CORROBORATED": 15
  },
  "CONTRADICTED": {
    "CONTRADICTED": 15
  },
  "INCONCLUSIVE": {
    "INCONCLUSIVE": 5
  },
  "UNKNOWN": {
    "UNKNOWN": 5
  }
}
```

### Top False Positive Patterns:
- Zero false positives observed across the benchmark suite.

### Top False Negative Patterns:
- Case `DEP_JAVASCRIPT_003` (DEPENDENCY): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (DEPENDENCY_DECLARED)
- Case `DEP_GOLANG_007` (DEPENDENCY): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (DEPENDENCY_DECLARED)
- Case `DEP_JAVASCRIPT_013` (DEPENDENCY): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (DEPENDENCY_DECLARED)
- Case `DEP_GOLANG_017` (DEPENDENCY): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (DEPENDENCY_DECLARED)
- Case `DEP_JAVASCRIPT_023` (DEPENDENCY): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (DEPENDENCY_DECLARED)

---

## 4. Reproducibility & Provenance

- **Benchmark Version**: `1.0.0`
- **Dataset SHA-256**: `c9de8400c10d28ecb2cc0b6631770fe20ae691daea7a3fcef4da3129265b9371`
- **Knowledge Base SHA-256**: `7b668faaae011b8122fa127f09979bbc68d761c344f65bceff5247824c3b4c2f`
- **Configuration SHA-256**: `b101eb2732e9c92f1c70f67f1689beafa5ab573eb5ea13fb63261fed8dabc0f5`
- **Evaluation Result SHA-256**: `8aeed2c32044d47ae302fdfc5275c2b9b8d898ea5830ba73da57e8b7ca5c8e01`
- **Execution Timestamp (UTC)**: `2026-09-20T07:33:50.819970+00:00`
