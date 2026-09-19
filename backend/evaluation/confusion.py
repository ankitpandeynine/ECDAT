"""
ECDAT V4 Confusion Matrix & Error Pattern Analyzer.

Analyzes false positive and false negative patterns, builds categorical
confusion matrices, and breaks down errors by modality, evidence category,
algorithm, and hard-negative types.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List


def analyze_confusion_and_errors(case_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Builds confusion matrix and isolates failure patterns with case references.
    """
    confusion_matrix: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    false_positives: List[Dict[str, Any]] = []
    false_negatives: List[Dict[str, Any]] = []
    modality_errors: Dict[str, List[str]] = defaultdict(list)
    hn_errors: Dict[str, List[str]] = defaultdict(list)
    algo_errors: Dict[str, int] = defaultdict(int)

    for cr in case_results:
        exp = cr["ground_truth_label"]
        pred = cr["predicted_label"]
        cid = cr["case_id"]
        mod = cr["modality"]
        algo = cr.get("expected_algorithm") or "UNKNOWN"
        hn_cat = cr.get("hard_negative_category")

        confusion_matrix[exp][pred] += 1

        is_pos_truth = (exp in ("POSITIVE", "CORROBORATED"))
        is_pos_pred = (pred in ("POSITIVE", "CORROBORATED"))

        if not is_pos_truth and is_pos_pred:
            # False Positive
            fp_info = {
                "case_id": cid,
                "modality": mod,
                "expected": exp,
                "predicted": pred,
                "expected_use_state": cr.get("expected_use_state"),
                "predicted_use_state": cr.get("predicted_use_state"),
                "hard_negative_category": hn_cat,
                "reason": cr.get("mismatch_reason", "Negative case falsely classified as positive"),
            }
            false_positives.append(fp_info)
            modality_errors[mod].append(cid)
            if hn_cat:
                hn_errors[hn_cat].append(cid)
            algo_errors[algo] += 1

        elif is_pos_truth and not is_pos_pred:
            # False Negative
            fn_info = {
                "case_id": cid,
                "modality": mod,
                "expected": exp,
                "predicted": pred,
                "expected_use_state": cr.get("expected_use_state"),
                "predicted_use_state": cr.get("predicted_use_state"),
                "hard_negative_category": hn_cat,
                "reason": cr.get("mismatch_reason", "Positive case missed by scanner/evaluator"),
            }
            false_negatives.append(fn_info)
            modality_errors[mod].append(cid)
            if hn_cat:
                hn_errors[hn_cat].append(cid)
            algo_errors[algo] += 1

    # Convert defaultdict to regular dict
    matrix_dict = {k: dict(v) for k, v in confusion_matrix.items()}

    top_fp_patterns = sorted(
        [{"pattern": f"Expected {fp['expected']} -> Predicted {fp['predicted']} ({fp['hard_negative_category'] or fp['modality']})", "case_id": fp["case_id"]} for fp in false_positives],
        key=lambda x: x["pattern"],
    )
    top_fn_patterns = sorted(
        [{"pattern": f"Expected {fn['expected']} -> Predicted {fn['predicted']} ({fn['modality']})", "case_id": fn["case_id"]} for fn in false_negatives],
        key=lambda x: x["pattern"],
    )

    return {
        "matrix": matrix_dict,
        "false_positive_count": len(false_positives),
        "false_negative_count": len(false_negatives),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "top_fp_patterns": top_fp_patterns[:10],
        "top_fn_patterns": top_fn_patterns[:10],
        "modality_error_distribution": {k: len(v) for k, v in modality_errors.items()},
        "hard_negative_failures": {k: len(v) for k, v in hn_errors.items()},
        "algorithm_error_distribution": dict(algo_errors),
    }
