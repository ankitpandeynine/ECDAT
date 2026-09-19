"""
ECDAT V4 P2.3 Blast Radius Intelligence Engine Benchmark.

Measures throughput, latency percentiles (P50, P95, P99), and memory usage
across synthetic asset workloads of size 100, 1000, and 5000 assets.
Exercises bounded traversal, path reconstruction, state classification,
criticality assessment, explainability generation, and provenance hashing.
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

from engine.blast_radius import (
    BlastRadiusAssessment,
    BlastRadiusState,
    build_blast_radius_explainability_report,
    evaluate_blast_radius,
)


def generate_synthetic_blast_radius_assets(n: int) -> List[Dict[str, Any]]:
    """Generate realistic synthetic crypto assets and graph topologies for blast radius evaluation."""
    templates = [
        # 1. Isolated Primitive (Zero dependents)
        {
            "asset": {"name": "DES-EDE3", "algorithm": "3DES", "asset_type": "ALGORITHM"},
            "edges": [],
            "nodes": [],
            "evidence": [{"id": "ev-1", "level": "E3", "state": "MEASURED", "description": "Single function"}],
            "context": {"environment": "dev"},
        },
        # 2. Local Direct Module
        {
            "asset": {"name": "SHA-256", "algorithm": "SHA-256", "asset_type": "ALGORITHM"},
            "edges": [
                {"source_id": "auth-module", "target_id": "target", "relationship": "USES"},
            ],
            "nodes": [
                {"id": "auth-module", "asset_type": "MODULE", "module": "auth"},
            ],
            "evidence": [{"id": "ev-2", "level": "E4", "state": "MEASURED", "description": "AST call"}],
            "context": {},
        },
        # 3. Multi-tier Banking Chain
        {
            "asset": {"name": "RSA-2048", "algorithm": "RSA", "asset_type": "KEY", "is_production": True},
            "edges": [
                {"source_id": "core-lib", "target_id": "target", "relationship": "USES"},
                {"source_id": "payment-api", "target_id": "core-lib", "relationship": "CALLS"},
                {"source_id": "web-gateway", "target_id": "payment-api", "relationship": "CALLS"},
            ],
            "nodes": [
                {"id": "core-lib", "asset_type": "CRYPTO_LIBRARY"},
                {"id": "payment-api", "asset_type": "SERVICE"},
                {"id": "web-gateway", "asset_type": "SERVICE", "is_externally_exposed": True},
            ],
            "evidence": [{"id": "ev-3", "level": "E4", "state": "MEASURED", "description": "Dynamic trace"}],
            "context": {"environment": "production"},
        },
        # 4. Multi-Service Diamond DAG
        {
            "asset": {"name": "libcrypto.so", "asset_type": "CRYPTO_LIBRARY"},
            "edges": [
                {"source_id": "sec-mgr", "target_id": "target", "relationship": "USES"},
                {"source_id": "tls-stack", "target_id": "target", "relationship": "USES"},
                {"source_id": "order-service", "target_id": "sec-mgr", "relationship": "CALLS"},
                {"source_id": "order-service", "target_id": "tls-stack", "relationship": "CALLS"},
            ],
            "nodes": [
                {"id": "sec-mgr", "asset_type": "DEPENDENCY"},
                {"id": "tls-stack", "asset_type": "DEPENDENCY"},
                {"id": "order-service", "asset_type": "SERVICE"},
            ],
            "evidence": [{"id": "ev-4", "level": "E3", "state": "MEASURED", "description": "ELF dynamic link"}],
            "context": {},
        },
        # 5. Cyclic Microservice Mesh
        {
            "asset": {"name": "ECDSA-P256", "algorithm": "ECDSA", "asset_type": "ALGORITHM", "is_production": True},
            "edges": [
                {"source_id": "svc-a", "target_id": "target", "relationship": "USES"},
                {"source_id": "svc-b", "target_id": "svc-a", "relationship": "CALLS"},
                {"source_id": "svc-c", "target_id": "svc-b", "relationship": "CALLS"},
                {"source_id": "svc-a", "target_id": "svc-c", "relationship": "CALLS"},
            ],
            "nodes": [
                {"id": "svc-a", "asset_type": "SERVICE"},
                {"id": "svc-b", "asset_type": "SERVICE"},
                {"id": "svc-c", "asset_type": "SERVICE"},
            ],
            "evidence": [{"id": "ev-5", "level": "E4", "state": "MEASURED", "description": "Network call"}],
            "context": {"is_production": True},
        },
    ]

    assets = []
    for i in range(n):
        tmpl = templates[i % len(templates)]
        target_id = f"asset-{i:05d}"
        asset_obj = dict(tmpl["asset"])
        asset_obj["id"] = target_id

        # Relabel edges to point to unique target_id
        edges = []
        for e in tmpl["edges"]:
            edge_copy = dict(e)
            if edge_copy["target_id"] == "target":
                edge_copy["target_id"] = target_id
            else:
                edge_copy["target_id"] = f"{edge_copy['target_id']}-{i:05d}"
            edge_copy["source_id"] = f"{edge_copy['source_id']}-{i:05d}"
            edges.append(edge_copy)

        nodes = []
        for nd in tmpl["nodes"]:
            node_copy = dict(nd)
            node_copy["id"] = f"{node_copy['id']}-{i:05d}"
            nodes.append(node_copy)

        assets.append({
            "asset": asset_obj,
            "edges": edges,
            "nodes": nodes,
            "evidence": list(tmpl["evidence"]),
            "context": dict(tmpl["context"]),
        })

    return assets


def run_workload_benchmark(n: int) -> Dict[str, Any]:
    """Runs end-to-end blast radius evaluation over N synthetic assets."""
    workload = generate_synthetic_blast_radius_assets(n)

    # Warmup GC
    gc.collect()
    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()

    latencies_ms: List[float] = []
    assessments: List[BlastRadiusAssessment] = []

    start_time = time.perf_counter()

    for item in workload:
        t0 = time.perf_counter()
        assessment = evaluate_blast_radius(
            target_asset=item["asset"],
            raw_edges=item["edges"],
            raw_nodes=item["nodes"],
            evidence_items=item["evidence"],
            context=item["context"],
        )
        report = build_blast_radius_explainability_report(assessment)
        t1 = time.perf_counter()

        latencies_ms.append((t1 - t0) * 1000.0)
        assessments.append(assessment)

    total_time = time.perf_counter() - start_time
    mem_after, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies_sorted = sorted(latencies_ms)
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
    throughput = n / total_time if total_time > 0 else 0.0

    return {
        "workload_size": n,
        "total_elapsed_sec": round(total_time, 4),
        "throughput_assets_per_sec": round(throughput, 2),
        "latency_ms": {
            "p50": round(p50, 4),
            "p95": round(p95, 4),
            "p99": round(p99, 4),
            "mean": round(sum(latencies_ms) / len(latencies_ms), 4),
            "min": round(latencies_sorted[0], 4),
            "max": round(latencies_sorted[-1], 4),
        },
        "memory_mb": {
            "current_delta": round((mem_after - mem_before) / (1024 * 1024), 2),
            "peak_allocated": round(mem_peak / (1024 * 1024), 2),
        },
        "state_distribution": {
            state.value: sum(1 for a in assessments if a.state == state)
            for state in [
                BlastRadiusState.NO_DEPENDENTS_OBSERVED,
                BlastRadiusState.DIRECT_ONLY,
                BlastRadiusState.TRANSITIVE,
                BlastRadiusState.MULTI_PATH,
                BlastRadiusState.CONTAINED,
                BlastRadiusState.WIDESPREAD,
            ]
        },
    }


def main():
    print("=" * 70)
    print("ECDAT V4 P2.3 BLAST RADIUS INTELLIGENCE ENGINE BENCHMARK")
    print("=" * 70)

    workload_sizes = [100, 1000, 5000]
    results = []

    for n in workload_sizes:
        print(f"\n[+] Running Benchmark for Workload N = {n} assets...")
        res = run_workload_benchmark(n)
        results.append(res)
        print(f"    Total Time: {res['total_elapsed_sec']} s")
        print(f"    Throughput: {res['throughput_assets_per_sec']} assets/sec")
        print(f"    Latency: P50={res['latency_ms']['p50']}ms, P95={res['latency_ms']['p95']}ms, P99={res['latency_ms']['p99']}ms")
        print(f"    Peak Memory: {res['memory_mb']['peak_allocated']} MB")

    out_file = Path(__file__).resolve().parent / "p23_blast_radius_benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"benchmarks": results, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f, indent=2)

    print("\n" + "=" * 70)
    print(f"Benchmark run complete. Results saved to: {out_file.name}")
    print("=" * 70)


if __name__ == "__main__":
    main()
