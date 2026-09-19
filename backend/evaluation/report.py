"""
ECDAT V4 Evaluation Report Generator.

Generates both machine-readable JSON (evaluation_result.json)
and audit-grade Markdown (evaluation_report.md) summaries.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from .models import EvaluationResult


def generate_markdown_report(result: EvaluationResult) -> str:
    """Renders an audit-ready research report in Markdown."""
    ov = result.overall_metrics
    mods = result.modality_metrics
    conf = result.confusion_matrix
    repro = result.reproducibility_metadata

    lines = [
        "# ECDAT V4 — Research & Validation Benchmark Report",
        "",
        "> **Notice & Disclaimer**: These benchmark results are based on deterministic synthetic controlled fixtures and are not a substitute for validation on real-world production scan data.",
        "",
        "## 1. Executive Summary & Headline Metrics",
        "",
        f"- **Total Benchmark Cases**: {ov.get('total_cases', 0)}",
        f"- **Dataset Version**: `{result.dataset_version}` (Hash: `{result.dataset_hash[:16]}...`)",
        f"- **Knowledge Base Version**: `{result.knowledge_base_version}` (Hash: `{result.knowledge_hash[:16]}...`)",
        f"- **Engine Version**: `{result.engine_version}`",
        f"- **Result Content Hash**: `{result.result_hash}`",
        "",
        "| Metric | Value | Interpretation |",
        "|:---|:---:|:---|",
        f"| **Precision** | **{ov.get('precision', 0.0):.4f}** | Ratio of true positive crypto detections to all positive alarms |",
        f"| **Recall** | **{ov.get('recall', 0.0):.4f}** | Proportion of actual cryptographic instances detected |",
        f"| **F1 Score** | **{ov.get('f1', 0.0):.4f}** | Harmonic mean of precision and recall |",
        f"| **Accuracy** | **{ov.get('accuracy', 0.0):.4f}** | Overall correctness (non-headline context metric) |",
        f"| **True Positives (TP)** | {ov.get('tp', 0)} | Correctly detected active cryptographic implementations |",
        f"| **True Negatives (TN)** | {ov.get('tn', 0)} | Correctly identified non-crypto or unexecuted assets |",
        f"| **False Positives (FP)** | {ov.get('fp', 0)} | Non-crypto falsely flagged as active crypto |",
        f"| **False Negatives (FN)** | {ov.get('fn', 0)} | Active crypto instances missed by scanners |",
        "",
        "---",
        "",
        "## 2. Per-Modality Performance Breakdown",
        "",
        "| Modality | Cases | TP | TN | FP | FN | Precision | Recall | F1 |",
        "|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|",
    ]

    for mod, m in sorted(mods.items()):
        lines.append(
            f"| **{mod}** | {m.get('total', 0)} | {m.get('tp', 0)} | {m.get('tn', 0)} | "
            f"{m.get('fp', 0)} | {m.get('fn', 0)} | {m.get('precision', 0.0):.4f} | "
            f"{m.get('recall', 0.0):.4f} | **{m.get('f1', 0.0):.4f}** |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Confusion Matrix & Error Analysis",
        "",
        f"- **Total False Positives**: {len(result.false_positive_cases)}",
        f"- **Total False Negatives**: {len(result.false_negative_cases)}",
        "",
        "### Categorical Confusion Matrix:",
        "```json",
        json.dumps(conf.get("matrix", {}), indent=2),
        "```",
        "",
        "### Top False Positive Patterns:",
    ])

    if result.false_positive_cases:
        for fp in result.false_positive_cases[:5]:
            lines.append(f"- Case `{fp['case_id']}` ({fp['modality']}): {fp.get('reason', '')}")
    else:
        lines.append("- Zero false positives observed across the benchmark suite.")

    lines.extend([
        "",
        "### Top False Negative Patterns:",
    ])

    if result.false_negative_cases:
        for fn in result.false_negative_cases[:5]:
            lines.append(f"- Case `{fn['case_id']}` ({fn['modality']}): {fn.get('reason', '')}")
    else:
        lines.append("- Zero false negatives observed across the benchmark suite.")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Reproducibility & Provenance",
        "",
        f"- **Benchmark Version**: `{repro.get('benchmark_version')}`",
        f"- **Dataset SHA-256**: `{repro.get('dataset_hash')}`",
        f"- **Knowledge Base SHA-256**: `{repro.get('knowledge_hash')}`",
        f"- **Configuration SHA-256**: `{repro.get('configuration_hash')}`",
        f"- **Evaluation Result SHA-256**: `{repro.get('result_hash')}`",
        f"- **Execution Timestamp (UTC)**: `{repro.get('timestamp')}`",
        "",
    ])

    return "\n".join(lines)


def save_evaluation_reports(
    result: EvaluationResult,
    output_dir: Path | str,
) -> Dict[str, Path]:
    """Saves both evaluation_result.json and evaluation_report.md."""
    out_path = Path(output_dir).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    json_path = out_path / "evaluation_result.json"
    md_path = out_path / "evaluation_report.md"

    # Write JSON
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, sort_keys=False)

    # Write Markdown
    md_content = generate_markdown_report(result)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return {
        "json": json_path,
        "markdown": md_path,
    }
