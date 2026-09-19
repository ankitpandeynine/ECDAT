# ECDAT V4 — Research & Validation Benchmark Report

> **Notice & Disclaimer**: These benchmark results are based on deterministic synthetic controlled fixtures and are not a substitute for validation on real-world production scan data.

## 1. Executive Summary & Headline Metrics

- **Total Benchmark Cases**: 736
- **Dataset Version**: `1.0.0` (Hash: `c9de8400c10d28ec...`)
- **Knowledge Base Version**: `2024.1` (Hash: `0b6ca8945302ae00...`)
- **Engine Version**: `4.0.0`
- **Result Content Hash**: `8633dd992cf1d54b584b197549459e1c4bb389c504cc89818a1b51ee27a4dc83`

| Metric | Value | Interpretation |
|:---|:---:|:---|
| **Precision** | **1.0000** | Ratio of true positive crypto detections to all positive alarms |
| **Recall** | **0.8408** | Proportion of actual cryptographic instances detected |
| **F1 Score** | **0.9135** | Harmonic mean of precision and recall |
| **Accuracy** | **0.8940** | Overall correctness (non-headline context metric) |
| **True Positives (TP)** | 412 | Correctly detected active cryptographic implementations |
| **True Negatives (TN)** | 246 | Correctly identified non-crypto or unexecuted assets |
| **False Positives (FP)** | 0 | Non-crypto falsely flagged as active crypto |
| **False Negatives (FN)** | 78 | Active crypto instances missed by scanners |

---

## 2. Per-Modality Performance Breakdown

| Modality | Cases | TP | TN | FP | FN | Precision | Recall | F1 |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **BINARY** | 135 | 60 | 35 | 0 | 40 | 1.0000 | 0.6000 | **0.7500** |
| **DEPENDENCY** | 130 | 36 | 70 | 0 | 24 | 1.0000 | 0.6000 | **0.7500** |
| **FIRMWARE** | 50 | 35 | 15 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **NETWORK** | 142 | 90 | 52 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **PQC** | 74 | 56 | 18 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |
| **SOURCE** | 130 | 85 | 31 | 0 | 14 | 1.0000 | 0.8586 | **0.9239** |
| **X509** | 75 | 50 | 25 | 0 | 0 | 1.0000 | 1.0000 | **1.0000** |

---

## 3. Confusion Matrix & Error Analysis

- **Total False Positives**: 0
- **Total False Negatives**: 78

### Categorical Confusion Matrix:
```json
{
  "POSITIVE": {
    "POSITIVE": 397,
    "NEGATIVE": 78
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
- Case `SRC_POS_RUST_057` (SOURCE): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (ACTUAL_USE)
- Case `SRC_POS_RUST_058` (SOURCE): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (ACTUAL_USE)
- Case `SRC_POS_RUST_059` (SOURCE): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (ACTUAL_USE)
- Case `SRC_POS_RUST_060` (SOURCE): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (ACTUAL_USE)
- Case `SRC_POS_RUST_061` (SOURCE): Predicted 'NEGATIVE' (UNUSED) vs Expected 'POSITIVE' (ACTUAL_USE)

---

## 4. Reproducibility & Provenance

- **Benchmark Version**: `1.0.0`
- **Dataset SHA-256**: `c9de8400c10d28ecb2cc0b6631770fe20ae691daea7a3fcef4da3129265b9371`
- **Knowledge Base SHA-256**: `0b6ca8945302ae0073e127a7e53d92cc092a2cf086928e15323c313da8285dfb`
- **Configuration SHA-256**: `b101eb2732e9c92f1c70f67f1689beafa5ab573eb5ea13fb63261fed8dabc0f5`
- **Evaluation Result SHA-256**: `8633dd992cf1d54b584b197549459e1c4bb389c504cc89818a1b51ee27a4dc83`
- **Execution Timestamp (UTC)**: `2026-09-19T14:58:59.395345+00:00`
