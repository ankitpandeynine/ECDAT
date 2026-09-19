"""
ECDAT V4 Research Metrics Computation.

Computes precision, recall, F1, accuracy, and support across:
- Overall dataset
- Modalities (SOURCE, DEPENDENCY, BINARY, FIRMWARE, NETWORK, X509, PQC)
- Ground-truth labels (POSITIVE, NEGATIVE, INCONCLUSIVE, CORROBORATED, CONTRADICTED, UNKNOWN)
- Evidence categories (IMPORT, STRING, SYMBOL, DEPENDENCY, ACTUAL_USE, NEGOTIATION, CERTIFICATE, PQC)
"""
from __future__ import annotations

from typing import Any, Dict, List
from .models import ModalityMetrics


def calculate_binary_metrics(tp: int, tn: int, fp: int, fn: int) -> Dict[str, float]:
    """Calculates precision, recall, F1, and accuracy from confusion counts."""
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def compute_evaluation_metrics(case_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes comprehensive hierarchical metrics over evaluation case results.
    """
    overall_tp = 0
    overall_tn = 0
    overall_fp = 0
    overall_fn = 0

    modality_counts: Dict[str, Dict[str, int]] = {}
    label_counts: Dict[str, Dict[str, int]] = {}
    evidence_cat_counts: Dict[str, Dict[str, int]] = {
        "IMPORT": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "STRING": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "SYMBOL": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "DEPENDENCY": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "ACTUAL_USE": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "NEGOTIATION": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "CERTIFICATE": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
        "PQC": {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0},
    }

    for cr in case_results:
        exp_label = cr["ground_truth_label"]
        pred_label = cr["predicted_label"]
        modality = cr["modality"]
        use_state = cr.get("expected_use_state", "ACTUAL_USE")

        # Map to binary class: POSITIVE vs NON-POSITIVE (NEGATIVE / INCONCLUSIVE / etc.)
        is_pos_truth = (exp_label in ("POSITIVE", "CORROBORATED"))
        is_pos_pred = (pred_label in ("POSITIVE", "CORROBORATED"))

        is_tp = is_pos_truth and is_pos_pred
        is_tn = (not is_pos_truth) and (not is_pos_pred)
        is_fp = (not is_pos_truth) and is_pos_pred
        is_fn = is_pos_truth and (not is_pos_pred)

        if is_tp:
            overall_tp += 1
        elif is_tn:
            overall_tn += 1
        elif is_fp:
            overall_fp += 1
        elif is_fn:
            overall_fn += 1

        # Per modality tracking
        if modality not in modality_counts:
            modality_counts[modality] = {"tp": 0, "tn": 0, "fp": 0, "fn": 0, "total": 0}
        m_dict = modality_counts[modality]
        m_dict["total"] += 1
        if is_tp:
            m_dict["tp"] += 1
        elif is_tn:
            m_dict["tn"] += 1
        elif is_fp:
            m_dict["fp"] += 1
        elif is_fn:
            m_dict["fn"] += 1

        # Per label tracking
        if exp_label not in label_counts:
            label_counts[exp_label] = {"correct": 0, "total": 0}
        label_counts[exp_label]["total"] += 1
        if pred_label == exp_label:
            label_counts[exp_label]["correct"] += 1

        # Per evidence category tracking
        ev_cat = "ACTUAL_USE"
        if "IMPORT" in use_state:
            ev_cat = "IMPORT"
        elif "STRING" in use_state:
            ev_cat = "STRING"
        elif "SYMBOL" in use_state:
            ev_cat = "SYMBOL"
        elif "DEPENDENCY" in use_state or modality == "DEPENDENCY":
            ev_cat = "DEPENDENCY"
        elif "NEGOTIATED" in use_state or "ADVERTISED" in use_state or modality == "NETWORK":
            ev_cat = "NEGOTIATION"
        elif modality == "X509" or "CERT" in use_state:
            ev_cat = "CERTIFICATE"
        elif modality == "PQC":
            ev_cat = "PQC"

        if ev_cat in evidence_cat_counts:
            cat_d = evidence_cat_counts[ev_cat]
            cat_d["total"] += 1
            if is_tp:
                cat_d["tp"] += 1
            elif is_tn:
                cat_d["tn"] += 1
            elif is_fp:
                cat_d["fp"] += 1
            elif is_fn:
                cat_d["fn"] += 1

    # Calculate overall
    overall = calculate_binary_metrics(overall_tp, overall_tn, overall_fp, overall_fn)
    overall.update({
        "tp": overall_tp,
        "tn": overall_tn,
        "fp": overall_fp,
        "fn": overall_fn,
        "total_cases": len(case_results),
        "support": overall_tp + overall_fn,
    })

    # Calculate per modality
    modality_metrics: Dict[str, Dict[str, Any]] = {}
    for mod, counts in modality_counts.items():
        m_calc = calculate_binary_metrics(counts["tp"], counts["tn"], counts["fp"], counts["fn"])
        m_calc.update({
            "modality": mod,
            "tp": counts["tp"],
            "tn": counts["tn"],
            "fp": counts["fp"],
            "fn": counts["fn"],
            "total": counts["total"],
            "support": counts["tp"] + counts["fn"],
        })
        modality_metrics[mod] = m_calc

    # Calculate per label accuracy
    label_metrics: Dict[str, Dict[str, Any]] = {}
    for lbl, counts in label_counts.items():
        tot = counts["total"]
        corr = counts["correct"]
        label_metrics[lbl] = {
            "total": tot,
            "correct": corr,
            "accuracy": round(corr / tot, 4) if tot > 0 else 0.0,
        }

    # Calculate per evidence category
    evidence_metrics: Dict[str, Dict[str, Any]] = {}
    for cat, counts in evidence_cat_counts.items():
        if counts["total"] > 0:
            c_calc = calculate_binary_metrics(counts["tp"], counts["tn"], counts["fp"], counts["fn"])
            c_calc.update({
                "category": cat,
                "tp": counts["tp"],
                "tn": counts["tn"],
                "fp": counts["fp"],
                "fn": counts["fn"],
                "total": counts["total"],
                "support": counts["tp"] + counts["fn"],
            })
            evidence_metrics[cat] = c_calc

    return {
        "overall": overall,
        "modalities": modality_metrics,
        "labels": label_metrics,
        "evidence_categories": evidence_metrics,
    }
