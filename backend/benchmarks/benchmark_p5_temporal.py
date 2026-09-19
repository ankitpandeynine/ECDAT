"""
ECDAT V4 M3 Temporal Intelligence and Continuous Posture Engine Benchmark.

Measures throughput, latency percentiles (P50, P95, P99), and memory usage
across synthetic scan comparison workloads of size 100, 1000, and 5000 assets.
Exercises:
- Scan comparator and asset identity mapping (compare_scans)
- Change detection across algorithm, key size, library, evidence level
- Temporal risk, PQC, agility, and migration delta evaluations
- Continuous Posture assessment across all 7 orthogonal dimensions
- Posture change evaluations and timeline construction
"""
from __future__ import annotations

import gc
import json
import os
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Any, Dict, List, Tuple

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from engine.temporal import compare_scans
from engine.temporal.evidence_timeline import build_asset_timeline
from engine.posture import evaluate_posture, evaluate_posture_change


def generate_synthetic_scan_pair(n: int) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Generate synthetic Scan A and Scan B datasets with realistic crypto evolution:
    - 60% unchanged assets
    - 15% upgraded assets (e.g. key length increase, PQC migration)
    - 10% downgraded or altered assets
    - 15% new / retired assets
    """
    scan_a: List[Dict[str, Any]] = []
    scan_b: List[Dict[str, Any]] = []

    algorithms = [
        ("RSA", 2048, "ASV-1"),
        ("AES", 128, "ASV-2"),
        ("ECDSA", 256, "ASV-3"),
        ("SHA-256", 256, "ASV-4"),
        ("3DES", 168, "ASV-5"),
        ("ML-KEM", 768, "ASV-6"),
        ("ML-DSA", 65, "ASV-7"),
        ("X25519", 256, "ASV-8"),
    ]

    for i in range(n):
        algo, key_size, asv = algorithms[i % len(algorithms)]
        asset_id = f"asset-{i:06d}"
        path = f"src/crypto/module_{i % 50}/crypto_file_{i}.py"

        # Baseline asset in Scan A
        asset_a = {
            "id": asset_id,
            "scan_id": "scan-base",
            "name": f"{algo}-{key_size}",
            "algorithm": algo,
            "key_size": key_size,
            "source_path": path,
            "file_path": path,
            "line_number": (i % 500) + 1,
            "asv": asv,
            "crypto_period_status": "CURRENT",
            "fips_status": "FIPS_APPROVED" if algo in ["AES", "SHA-256", "ML-KEM", "ML-DSA"] else "NON_COMPLIANT",
            "quantum_risk_level": "CRITICAL" if algo in ["RSA", "ECDSA", "3DES"] else "SAFE",
            "crypto_agility_level": "MODERATE",
            "blast_radius_level": "DIRECT_ONLY",
            "migration_status": "DISCOVERED",
            "confidence": 0.85,
            "evidence_level": "E3",
            "evidence": [
                {
                    "id": f"ev-{i}-a",
                    "level": "E3",
                    "state": "MEASURED",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "description": f"Observed {algo} usage",
                }
            ],
        }

        # Determine transition type for Scan B
        category_slot = i % 100
        if category_slot < 60:
            # 60% Unchanged
            asset_b = dict(asset_a)
            asset_b["scan_id"] = "scan-target"
            scan_a.append(asset_a)
            scan_b.append(asset_b)
        elif category_slot < 75:
            # 15% Upgraded: PQC migration or key upgrade
            asset_b = dict(asset_a)
            asset_b["scan_id"] = "scan-target"
            if algo == "RSA":
                asset_b["algorithm"] = "ML-KEM"
                asset_b["key_size"] = 768
                asset_b["quantum_risk_level"] = "SAFE"
                asset_b["migration_status"] = "VERIFIED"
            elif algo == "3DES":
                asset_b["algorithm"] = "AES"
                asset_b["key_size"] = 256
            scan_a.append(asset_a)
            scan_b.append(asset_b)
        elif category_slot < 85:
            # 10% Downgrade or parameter change
            asset_b = dict(asset_a)
            asset_b["scan_id"] = "scan-target"
            asset_b["key_size"] = 1024 if algo == "RSA" else 128
            scan_a.append(asset_a)
            scan_b.append(asset_b)
        elif category_slot < 92:
            # Removed in Scan B (Only in Scan A)
            scan_a.append(asset_a)
        else:
            # Added in Scan B (Only in Scan B)
            asset_new = dict(asset_a)
            asset_new["id"] = f"asset-new-{i:06d}"
            asset_new["scan_id"] = "scan-target"
            asset_new["source_path"] = f"src/crypto/new_module/new_{i}.py"
            asset_new["file_path"] = f"src/crypto/new_module/new_{i}.py"
            scan_b.append(asset_new)

    return scan_a, scan_b


def run_workload_benchmark(n: int) -> Dict[str, Any]:
    """Execute complete M3 benchmark for workload size n."""
    gc.collect()
    scan_a, scan_b = generate_synthetic_scan_pair(n)

    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()
    start_time = time.perf_counter()

    # Step 1: Scan Comparison (Change Detection, Mapping, Deltas)
    t_comp_start = time.perf_counter()
    comparison = compare_scans(
        project="benchmark_project",
        base_scan_id="scan-base",
        target_scan_id="scan-target",
        base_assets=scan_a,
        target_assets=scan_b,
    )
    t_comp = time.perf_counter() - t_comp_start

    # Step 2: Posture Evaluations & Posture Changes
    posture_latencies_ms: List[float] = []
    posture_assessments = []
    posture_changes = []

    # Benchmark scan-level posture
    t_posture_scan_start = time.perf_counter()
    posture_scan_a = evaluate_posture(project="bench", scan_id="scan-base", assets=scan_a)
    posture_scan_b = evaluate_posture(project="bench", scan_id="scan-target", assets=scan_b)
    posture_scan_change = evaluate_posture_change(posture_scan_a, posture_scan_b)
    t_posture_scan = time.perf_counter() - t_posture_scan_start

    # Benchmark sample asset-level postures
    sample_posture_count = min(100, len(scan_a))
    for asset_a, asset_b in zip(scan_a[:sample_posture_count], scan_b[:sample_posture_count]):
        t0 = time.perf_counter()
        p_a = evaluate_posture(project="bench", scan_id="scan-base", assets=[asset_a], asset_id=asset_a.get("id"))
        p_b = evaluate_posture(project="bench", scan_id="scan-target", assets=[asset_b], asset_id=asset_b.get("id"))
        p_ch = evaluate_posture_change(p_a, p_b)
        t_el = (time.perf_counter() - t0) * 1000.0

        posture_latencies_ms.append(t_el)
        posture_assessments.append(p_b)
        posture_changes.append(p_ch)

    # Step 3: Timeline Construction for subset of assets
    sample_timeline_count = min(100, len(scan_a))
    t_tl_start = time.perf_counter()
    for asset in scan_a[:sample_timeline_count]:
        build_asset_timeline(
            project="bench",
            asset_key=asset.get("algorithm", "RSA"),
            scans_with_evidence=[
                {"scan_id": "scan-1", "timestamp": "2026-01-01T00:00:00Z", "evidence": asset.get("evidence", [])},
                {"scan_id": "scan-2", "timestamp": "2026-02-01T00:00:00Z", "evidence": asset.get("evidence", [])},
            ],
            asset_id=asset.get("id"),
        )
    t_tl = time.perf_counter() - t_tl_start

    total_time = time.perf_counter() - start_time
    mem_after, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Metrics computation
    latencies_sorted = sorted(posture_latencies_ms) if posture_latencies_ms else [0.0]
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
    throughput = n / total_time if total_time > 0 else 0.0

    return {
        "workload_size": n,
        "total_elapsed_sec": round(total_time, 4),
        "throughput_assets_per_sec": round(throughput, 2),
        "comparison_time_sec": round(t_comp, 4),
        "comparison_summary": {
            "added_count": comparison.added_count,
            "removed_count": comparison.removed_count,
            "changed_count": comparison.changed_count,
            "unchanged_count": comparison.unchanged_count,
        },
        "posture_evaluation_latency_ms": {
            "p50": round(p50, 4),
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "mean": round(sum(posture_latencies_ms) / len(posture_latencies_ms), 4) if posture_latencies_ms else 0.0,
            "min": round(latencies_sorted[0], 4),
            "max": round(latencies_sorted[-1], 4),
        },
        "timeline_benchmark": {
            "sample_assets_evaluated": sample_timeline_count,
            "elapsed_sec": round(t_tl, 4),
        },
        "memory_mb": {
            "current_delta": round((mem_after - mem_before) / (1024 * 1024), 2),
            "peak_allocated": round(mem_peak / (1024 * 1024), 2),
        },
    }


def main():
    print("=" * 75)
    print("ECDAT V4 M3 TEMPORAL INTELLIGENCE & CONTINUOUS POSTURE BENCHMARK")
    print("=" * 75)

    workload_sizes = [100, 1000, 5000]
    results = []

    for n in workload_sizes:
        print(f"\n[+] Running Benchmark for Workload N = {n} assets...")
        res = run_workload_benchmark(n)
        results.append(res)
        print(f"    Total Time: {res['total_elapsed_sec']} s")
        print(f"    Comparison Time: {res['comparison_time_sec']} s")
        print(f"    Throughput: {res['throughput_assets_per_sec']} assets/sec")
        print(
            f"    Posture Latency: P50={res['posture_evaluation_latency_ms']['p50']}ms, "
            f"P95={res['posture_evaluation_latency_ms']['p95']}ms, "
            f"P99={res['posture_evaluation_latency_ms']['p99']}ms"
        )
        print(f"    Peak Memory: {res['memory_mb']['peak_allocated']} MB")
        print(f"    Changes Detected: Added={res['comparison_summary']['added_count']}, "
              f"Removed={res['comparison_summary']['removed_count']}, "
              f"Changed={res['comparison_summary']['changed_count']}, "
              f"Unchanged={res['comparison_summary']['unchanged_count']}")

    out_file = Path(__file__).resolve().parent / "p5_temporal_benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "benchmarks": results,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "version": "M3-P5",
            },
            f,
            indent=2,
        )

    print("\n" + "=" * 75)
    print(f"Benchmark run complete. Results saved to: {out_file.name}")
    print("=" * 75)


if __name__ == "__main__":
    main()
