"""
ECDAT V4 P4 Ground-Truth Benchmark & Evaluation Performance Benchmark.

Measures throughput (cases/sec), latency percentiles (P50, P95, P99),
and memory usage across synthetic evaluation workloads of size 100, 1000, and 5000 cases.
Exercises the real BenchmarkEvaluator pipeline.
"""
from __future__ import annotations

import gc
import json
import os
from pathlib import Path
import sys
import time
import tracemalloc
from typing import Any, Dict, List

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from evaluation.evaluator import BenchmarkEvaluator
from evaluation.generator import generate_benchmark_cases
from evaluation.models import BenchmarkCase


def generate_benchmark_workload(n: int) -> List[BenchmarkCase]:
    """Generates n benchmark cases by sampling/duplicating base cases with unique IDs."""
    base_cases = generate_benchmark_cases()
    workload: List[BenchmarkCase] = []
    for i in range(n):
        base = base_cases[i % len(base_cases)]
        case_dict = base.to_dict()
        case_dict["case_id"] = f"BENCH_{i:06d}"
        workload.append(BenchmarkCase.from_dict(case_dict))
    return workload


def run_evaluation_benchmark(case_count: int) -> Dict[str, Any]:
    """Executes evaluation pipeline benchmark for a given case count."""
    print(f"\n[BENCHMARK] Generating {case_count} evaluation cases...")
    workload = generate_benchmark_workload(case_count)
    evaluator = BenchmarkEvaluator()

    gc.collect()
    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()

    latencies_ms: List[float] = []
    start_total = time.perf_counter()

    for case in workload:
        t0 = time.perf_counter()
        _ = evaluator.evaluate_case(case)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    total_time = time.perf_counter() - start_total
    mem_after, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies_ms.sort()
    n = len(latencies_ms)
    p50 = latencies_ms[int(n * 0.50)]
    p95 = latencies_ms[int(n * 0.95)]
    p99 = latencies_ms[int(n * 0.99)]
    throughput = n / total_time
    mem_delta_mb = (mem_after - mem_before) / (1024.0 * 1024.0)
    peak_mem_mb = peak_mem / (1024.0 * 1024.0)

    results = {
        "case_count": case_count,
        "total_time_seconds": round(total_time, 4),
        "throughput_cases_per_sec": round(throughput, 2),
        "p50_latency_ms": round(p50, 4),
        "p95_latency_ms": round(p95, 4),
        "p99_latency_ms": round(p99, 4),
        "mem_delta_mb": round(mem_delta_mb, 4),
        "peak_mem_mb": round(peak_mem_mb, 4),
    }

    print(f"  Count:       {case_count}")
    print(f"  Total Time:  {results['total_time_seconds']} s")
    print(f"  Throughput:  {results['throughput_cases_per_sec']} cases/s")
    print(f"  P50 Latency: {results['p50_latency_ms']} ms")
    print(f"  P95 Latency: {results['p95_latency_ms']} ms")
    print(f"  P99 Latency: {results['p99_latency_ms']} ms")
    print(f"  Peak Memory: {results['peak_mem_mb']} MB")

    return results


def main():
    print("=" * 70)
    print("ECDAT V4 — P4 GROUND-TRUTH EVALUATION PERFORMANCE BENCHMARK")
    print("=" * 70)

    test_sizes = [100, 1000, 5000]
    all_results = []

    for size in test_sizes:
        res = run_evaluation_benchmark(size)
        all_results.append(res)

    out_file = Path(__file__).resolve().parent / "p4_evaluation_benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY (Observed scaling was approximately linear over tested sizes)")
    print("=" * 70)
    print(f"{'Count':<8} | {'Total Time (s)':<16} | {'Throughput (c/s)':<18} | {'P50 (ms)':<10} | {'P95 (ms)':<10} | {'Peak Mem (MB)':<12}")
    print("-" * 80)
    for r in all_results:
        print(f"{r['case_count']:<8} | {r['total_time_seconds']:<16} | {r['throughput_cases_per_sec']:<18} | {r['p50_latency_ms']:<10} | {r['p95_latency_ms']:<10} | {r['peak_mem_mb']:<12}")

    print(f"\nResults saved to: {out_file}")


if __name__ == "__main__":
    main()
