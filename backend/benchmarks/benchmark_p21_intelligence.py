"""
ECDAT V4 P2.1 Intelligence Engine Benchmark.

Measures throughput, latency percentiles (P50, P95, P99), and memory usage
across synthetic asset workloads of size 100, 1000, and 5000 assets.
"""
from __future__ import annotations

import gc
import os
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Dict, List

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from engine.intelligence.intelligence_pipeline import evaluate_asset, IntelligencePipeline
from engine.intelligence.algorithm_registry import normalize_algorithm, lookup_algorithm
from engine.intelligence.risk_engine import evaluate_risk_factors, compute_severity
from engine.intelligence.pqc_readiness import assess_pqc_readiness
from engine.intelligence.hndl_analyzer import assess_hndl
from engine.intelligence.security_strength import assess_security_strength


def generate_synthetic_assets(n: int) -> List[Dict[str, Any]]:
    """Generate diverse, realistic synthetic crypto assets."""
    templates = [
        # Classical Web Server TLS
        {
            "id": "asset-tls-rsa-{}",
            "type": "CIPHER_SUITE",
            "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "algorithm": "RSA",
            "key_size": 2048,
            "roles": ["KEY_ESTABLISHMENT", "SIGNATURE"],
            "network_reachable": True,
            "exposure": "EXTERNAL",
            "data_sensitivity": "HIGH",
            "retention_years": 10,
            "evidence": [
                {"observation_type": "TLS_CIPHER_SUITE", "level": "E3", "state": "NEGOTIATED", "source_engine": "NETWORK"},
                {"observation_type": "X509_CERTIFICATE", "level": "E4", "state": "OBSERVED", "source_engine": "NETWORK"},
            ],
            "context": {"tls_version_negotiated": "TLSv1.2", "public_exposure": True}
        },
        # Modern PQC Hybrid KEX Server
        {
            "id": "asset-tls-hybrid-{}",
            "type": "ALGORITHM",
            "name": "X25519MLKEM768",
            "algorithm": "X25519MLKEM768",
            "key_size": 768,
            "roles": ["KEY_ESTABLISHMENT"],
            "network_reachable": True,
            "exposure": "EXTERNAL",
            "data_sensitivity": "MEDIUM",
            "retention_years": 5,
            "evidence": [
                {"observation_type": "TLS_KEY_EXCHANGE", "level": "E3", "state": "NEGOTIATED", "source_engine": "NETWORK"},
            ],
            "context": {"tls_version_negotiated": "TLSv1.3", "pqc_kex_state": "HYBRID_NEGOTIATED", "pqc_sig_state": "CLASSICAL_ONLY"}
        },
        # Legacy Broken Crypto in Source
        {
            "id": "asset-src-md5-{}",
            "type": "ALGORITHM",
            "name": "MD5",
            "algorithm": "MD5",
            "roles": ["HASH"],
            "network_reachable": False,
            "exposure": "INTERNAL",
            "evidence": [
                {"observation_type": "CODE_PATTERN", "level": "E2", "state": "INFERRED", "source_engine": "SOURCE"},
            ],
            "context": {}
        },
        # Binary Embedded 3DES
        {
            "id": "asset-bin-3des-{}",
            "type": "ALGORITHM",
            "name": "3DES",
            "algorithm": "3DES",
            "roles": ["SYMMETRIC_ENCRYPTION"],
            "network_reachable": False,
            "exposure": "INTERNAL",
            "evidence": [
                {"observation_type": "SYMBOL_REFERENCE", "level": "E2", "state": "INFERRED", "source_engine": "BINARY"},
            ],
            "context": {}
        },
        # SSH Endpoint with legacy KEX
        {
            "id": "asset-ssh-kex-{}",
            "type": "SERVICE",
            "name": "diffie-hellman-group14-sha1",
            "algorithm": "DH",
            "key_size": 2048,
            "roles": ["KEY_ESTABLISHMENT"],
            "network_reachable": True,
            "exposure": "EXTERNAL",
            "data_sensitivity": "HIGH",
            "retention_years": 7,
            "evidence": [
                {"observation_type": "SSH_KEXINIT", "level": "E3", "state": "ADVERTISED", "source_engine": "NETWORK"},
            ],
            "context": {"ssh_kex_algorithms": ["diffie-hellman-group14-sha1", "curve25519-sha256"]}
        },
    ]

    assets = []
    for i in range(n):
        tmpl = templates[i % len(templates)]
        asset = {k: v for k, v in tmpl.items() if k not in ("evidence", "context")}
        asset["id"] = tmpl["id"].format(i)
        asset["_benchmark_evidence"] = tmpl["evidence"]
        asset["_benchmark_context"] = tmpl["context"]
        assets.append(asset)
    return assets


def run_benchmark_batch(batch_size: int) -> Dict[str, Any]:
    """Benchmark full pipeline on batch_size assets."""
    assets = generate_synthetic_assets(batch_size)

    gc.collect()
    tracemalloc.start()
    mem_start, _ = tracemalloc.get_traced_memory()

    latencies_ms: List[float] = []
    start_total = time.perf_counter()

    for asset in assets:
        ev = asset["_benchmark_evidence"]
        ctx = asset["_benchmark_context"]

        t0 = time.perf_counter()
        result = evaluate_asset(asset, ev, ctx)
        t1 = time.perf_counter()

        latencies_ms.append((t1 - t0) * 1000.0)

    total_time_s = time.perf_counter() - start_total
    mem_current, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    latencies_ms.sort()
    n = len(latencies_ms)
    p50 = latencies_ms[int(n * 0.50)]
    p95 = latencies_ms[int(n * 0.95)]
    p99 = latencies_ms[int(n * 0.99)]
    avg_latency = sum(latencies_ms) / n
    throughput = n / total_time_s

    mem_peak_mb = (mem_peak - mem_start) / (1024 * 1024)

    return {
        "batch_size": batch_size,
        "total_time_s": round(total_time_s, 4),
        "throughput_assets_per_s": round(throughput, 1),
        "latency_p50_ms": round(p50, 3),
        "latency_p95_ms": round(p95, 3),
        "latency_p99_ms": round(p99, 3),
        "latency_avg_ms": round(avg_latency, 3),
        "peak_memory_mb": round(mem_peak_mb, 2),
    }


def main():
    print("=" * 65)
    print("ECDAT V4 P2.1 — CRYPTO INTELLIGENCE ENGINE BENCHMARK")
    print("=" * 65)
    print("Evaluating Full Intelligence Pipeline:")
    print("  - Algorithm Registry Normalization")
    print("  - Parameter-Aware Strength Evaluation")
    print("  - Rule Engine (Deterministic Risk Assessment)")
    print("  - Role-Aware PQC Readiness Assessment")
    print("  - HNDL Contextual Analysis")
    print("  - Structured Explainability Chain Generation")
    print("-" * 65)

    batch_sizes = [100, 1000, 5000]
    results = []

    for bs in batch_sizes:
        print(f"Running benchmark with N = {bs} assets...")
        res = run_benchmark_batch(bs)
        results.append(res)
        print(f"  Completed {bs} assets in {res['total_time_s']}s:")
        print(f"    Throughput: {res['throughput_assets_per_s']} assets/sec")
        print(f"    Latency P50: {res['latency_p50_ms']} ms | P95: {res['latency_p95_ms']} ms | P99: {res['latency_p99_ms']} ms")
        print(f"    Peak Memory: {res['peak_memory_mb']} MB")
        print("-" * 65)

    print("\nSUMMARY TABLE:")
    print(f"{'Batch Size':>12} | {'Throughput (a/s)':>18} | {'P50 (ms)':>10} | {'P95 (ms)':>10} | {'P99 (ms)':>10} | {'Peak Mem (MB)':>14}")
    print("-" * 85)
    for r in results:
        print(f"{r['batch_size']:>12} | {r['throughput_assets_per_s']:>18} | {r['latency_p50_ms']:>10} | {r['latency_p95_ms']:>10} | {r['latency_p99_ms']:>10} | {r['peak_memory_mb']:>14}")
    print("=" * 85)


if __name__ == "__main__":
    main()
