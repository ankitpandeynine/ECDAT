"""
ECDAT V4 P2.2 Crypto-Agility Intelligence Engine Benchmark.

Measures throughput, latency percentiles (P50, P95, P99), and memory usage
across synthetic asset workloads of size 100, 1000, and 5000 assets.
Exercises evidence normalization, seven dimensions, change surface calculation,
and explainability report generation.
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

from engine.agility.agility_pipeline import evaluate_agility
from engine.agility.explainability import build_agility_explainability_report
from engine.agility.models import AgilityAssessment


def generate_synthetic_agility_assets(n: int) -> List[Dict[str, Any]]:
    """Generate realistic synthetic crypto assets and evidence for agility evaluation."""
    templates = [
        # 1. Provider-abstracted modern service
        {
            "asset": {"name": "AES-256-GCM", "algorithm": "AES-256-GCM", "asset_type": "ALGORITHM"},
            "evidence": [
                {"id": "ev-abs-1", "observation_type": "SOURCE_API_USE", "description": "provider_abstraction EVP_CIPHER_fetch", "level": "E4", "state": "MEASURED", "file_path": "src/crypto/cipher.c"},
                {"id": "ev-abs-2", "observation_type": "CONFIGURATION", "description": "env_var CIPHER_CHOICE loaded dynamically", "level": "E3", "state": "MEASURED", "file_path": "src/config.c"},
                {"id": "ev-abs-3", "observation_type": "DEPENDENCY_DECLARATION", "description": "package_manager openssl dynamic_library", "level": "E3", "state": "MEASURED"},
                {"id": "ev-abs-4", "observation_type": "DEPLOYMENT_CONFIGURATION", "description": "container_image dockerfile", "level": "E2", "state": "INFERRED"},
                {"id": "ev-abs-5", "observation_type": "CRYPTO_TEST", "description": "crypto_test Wycheproof vectors", "level": "E4", "state": "MEASURED"},
            ],
            "context": {"has_provider_abstraction": True, "uses_config_driven_crypto": True, "has_crypto_tests": True},
            "blast": {"target_node_id": "target", "total_impacted_count": 5, "impacted_assets": [{"id": f"svc-{i}", "asset_type": "SERVICE"} for i in range(5)]}
        },
        # 2. Hardcoded legacy banking module
        {
            "asset": {"name": "DES-EDE3", "algorithm": "3DES", "asset_type": "ALGORITHM"},
            "evidence": [
                {"id": "ev-hc-1", "observation_type": "SOURCE_API_USE", "description": "direct_primitive DES_ede3_cbc_encrypt direct call", "level": "E3", "state": "MEASURED", "file_path": "legacy/pin_crypto.c"},
                {"id": "ev-hc-2", "observation_type": "CONFIGURATION", "description": "hardcoded_key static constant PIN_KEY", "level": "E3", "state": "MEASURED", "file_path": "legacy/keys.h"},
                {"id": "ev-hc-3", "observation_type": "DEPENDENCY_LOCKFILE", "description": "pinned_vendored_dependency in-tree libdes", "level": "E3", "state": "MEASURED"},
                {"id": "ev-hc-4", "observation_type": "TEST_DECLARATION", "description": "no_tests_observed", "level": "E1", "state": "INFERRED"},
            ],
            "context": {"hardcoded_primitives_count": 3},
            "blast": {"target_node_id": "target", "total_impacted_count": 12, "impacted_assets": [{"id": f"app-{i}", "asset_type": "APPLICATION"} for i in range(12)]}
        },
        # 3. Dynamic TLS Endpoint with ACME
        {
            "asset": {"name": "Edge-Gateway-TLS", "asset_type": "ENDPOINT"},
            "evidence": [
                {"id": "ev-tls-1", "observation_type": "TLS_NEGOTIATION", "description": "tls_negotiation dynamic cipher negotiation runtime selection", "level": "E5", "state": "MEASURED"},
                {"id": "ev-tls-2", "observation_type": "PROTOCOL_CONFIGURATION", "description": "tls_configuration ssl_protocols TLSv1.2 TLSv1.3", "level": "E3", "state": "MEASURED"},
                {"id": "ev-tls-3", "observation_type": "ROTATION_MECHANISM", "description": "automated_certificate_rotation via acme integration cert-manager", "level": "E4", "state": "MEASURED"},
                {"id": "ev-tls-4", "observation_type": "RUNTIME_CALL", "description": "runtime_config_reload dynamic reload without restart", "level": "E4", "state": "MEASURED"},
            ],
            "context": {"automated_cert_rotation": True, "has_runtime_reload": True},
            "blast": {"target_node_id": "target", "total_impacted_count": 2, "impacted_assets": [{"id": "gw", "asset_type": "SERVICE"}]}
        },
        # 4. Embedded IoT Device Firmware
        {
            "asset": {"name": "Smart-Sensor-Boot", "asset_type": "FIRMWARE"},
            "evidence": [
                {"id": "ev-fw-1", "observation_type": "FIRMWARE_CONTENT", "description": "static_binary burned in firmware_content", "level": "E3", "state": "MEASURED"},
                {"id": "ev-fw-2", "observation_type": "HARDCODED_KEY", "description": "embedded_private_key hardcoded pem in rom", "level": "E3", "state": "MEASURED"},
                {"id": "ev-fw-3", "observation_type": "TEST_DECLARATION", "description": "no_tests_observed in firmware", "level": "E1", "state": "INFERRED"},
            ],
            "context": {"is_firmware": True},
            "blast": {"target_node_id": "target", "total_impacted_count": 1, "impacted_assets": [{"id": "hw", "asset_type": "FIRMWARE"}]}
        },
    ]

    assets = []
    for i in range(n):
        tpl = templates[i % len(templates)]
        asset_copy = dict(tpl["asset"])
        asset_copy["id"] = f"bench-asset-{i}"
        ev_copy = []
        for e in tpl["evidence"]:
            item = dict(e)
            item["id"] = f"{item['id']}-{i}"
            ev_copy.append(item)
        assets.append({
            "asset": asset_copy,
            "evidence": ev_copy,
            "context": dict(tpl.get("context", {})),
            "blast": dict(tpl.get("blast", {})),
        })
    return assets


def run_benchmark(asset_count: int) -> Dict[str, Any]:
    """Execute agility benchmark for a given asset count."""
    print(f"\n[BENCHMARK] Generating {asset_count} synthetic assets...")
    workload = generate_synthetic_agility_assets(asset_count)

    gc.collect()
    tracemalloc.start()
    mem_before, _ = tracemalloc.get_traced_memory()

    latencies_ms: List[float] = []
    start_total = time.perf_counter()

    for item in workload:
        t0 = time.perf_counter()
        assessment = evaluate_agility(
            asset=item["asset"],
            evidence_items=item["evidence"],
            context=item["context"],
            blast_radius=item["blast"],
        )
        report = build_agility_explainability_report(assessment)
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
        "asset_count": asset_count,
        "total_time_seconds": round(total_time, 3),
        "throughput_assets_per_sec": round(throughput, 1),
        "latency_p50_ms": round(p50, 3),
        "latency_p95_ms": round(p95, 3),
        "latency_p99_ms": round(p99, 3),
        "memory_delta_mb": round(mem_delta_mb, 2),
        "peak_memory_mb": round(peak_mem_mb, 2),
    }

    print(f"Results for N = {asset_count}:")
    print(f"  Total time:   {results['total_time_seconds']} s")
    print(f"  Throughput:   {results['throughput_assets_per_sec']} assets/sec")
    print(f"  P50 latency:  {results['latency_p50_ms']} ms")
    print(f"  P95 latency:  {results['latency_p95_ms']} ms")
    print(f"  P99 latency:  {results['latency_p99_ms']} ms")
    print(f"  Memory delta: {results['memory_delta_mb']} MB")
    print(f"  Peak memory:  {results['peak_memory_mb']} MB")

    return results


if __name__ == "__main__":
    print("=" * 65)
    print("ECDAT V4 — P2.2 CRYPTO-AGILITY INTELLIGENCE BENCHMARK SUITE")
    print("=" * 65)

    res_100 = run_benchmark(100)
    res_1000 = run_benchmark(1000)
    res_5000 = run_benchmark(5000)

    summary = {
        "benchmark": "P2.2 Crypto-Agility Intelligence",
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runs": [res_100, res_1000, res_5000],
    }

    out_path = backend_dir / "benchmarks" / "p22_agility_benchmark_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nBenchmark results saved to: {out_path}")
