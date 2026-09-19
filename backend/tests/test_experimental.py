import pytest
from engine.runtime_tracer import RuntimeTracer
from engine.ebpf_tracer import EbpfTracer
from engine.patch_engine import AutoPatchEngine
from engine.custom_crypto_detector import CustomCryptoDetector
from engine.pcap_engine import PcapEngine
from engine.quantum_estimator import QuantumResourceEstimator
from engine.binary_classifier import BinaryMLClassifier
from engine.standards_mapping import get_all_standards
from fastapi.testclient import TestClient
from main import app


def test_runtime_tracer_execution():
    code = "import hashlib\ndef run(): return hashlib.sha256(b'test').hexdigest()\nrun()\n"
    res = RuntimeTracer.execute_instrumented_run(["python", "-c", code])
    assert res.status in ("success", "partial")
    assert len(res.limitations) > 0
    assert len(RuntimeTracer.get_c_shim_source()) > 100


def test_ebpf_capabilities_and_tracing():
    caps = EbpfTracer.inspect_capabilities()
    assert isinstance(caps.is_linux, bool)
    assert len(caps.limitations) >= 0

    trace_res = EbpfTracer.trace_process(target_pid=1234, simulate_if_unavailable=True)
    assert trace_res.status in ("active", "simulated")
    assert len(trace_res.observed_events) >= 1
    assert len(trace_res.evidence_records) >= 1


def test_autopatch_engine():
    vulnerable_py = "import hashlib\ndef get_token(pwd):\n    return hashlib.md5(pwd.encode()).hexdigest()\n"
    patch = AutoPatchEngine.create_patch(vulnerable_py, "token.py", "python")
    assert patch is not None
    assert patch.pattern_id == "MD5_TO_SHA256_PYTHON"
    assert "hashlib.sha256(" in patch.patched_code
    assert "--- a/token.py" in patch.unified_diff
    assert "+++ b/token.py" in patch.unified_diff

    # Execute generated regression test
    verified_patch = AutoPatchEngine.run_regression_test(patch)
    assert verified_patch.verification_status == "passed"
    assert "TEST PASSED" in (verified_patch.test_output or "")


def test_custom_crypto_detector_and_benchmark():
    # True custom crypto
    xor_code = "def encrypt(data, key):\n    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])\n"
    finding = CustomCryptoDetector.analyze_snippet(xor_code)
    assert finding.is_custom_crypto is True
    assert finding.classification == "CUSTOM_CIPHER"

    # Benign non-crypto
    matmul = "def matmul(A, B):\n    return [[sum(a*b for a,b in zip(row,col)) for col in zip(*B)] for row in A]\n"
    benign_finding = CustomCryptoDetector.analyze_snippet(matmul)
    assert benign_finding.is_custom_crypto is False

    # Run benchmark suite
    bench = CustomCryptoDetector.run_benchmark()
    assert bench.total_samples >= 8
    assert bench.precision >= 0.75
    assert bench.recall >= 0.75
    assert bench.accuracy >= 0.75


def test_pcap_engine_and_ja3():
    # Generate synthetic PCAP with PQC hybrid support
    pcap_bytes = PcapEngine.generate_synthetic_pcap(with_pqc_hybrid=True)
    assert len(pcap_bytes) > 100

    scan_res = PcapEngine.parse_pcap_bytes(pcap_bytes)
    assert scan_res.status == "success"
    assert scan_res.packets_analyzed == 2
    assert len(scan_res.sessions) == 1

    sess = scan_res.sessions[0]
    assert sess.has_pqc_hybrid is True
    assert sess.ja3_fingerprint is not None
    assert len(sess.ja3_fingerprint) == 32
    assert len(scan_res.evidence_records) >= 1


def test_quantum_resource_estimator():
    est = QuantumResourceEstimator.estimate_resources("RSA-2048", physical_error_rate=1e-3, cycle_time_us=1.0)
    assert est.logical_qubits >= 4096
    assert est.physical_qubits_estimate >= 1_000_000
    assert est.estimated_runtime_hours > 0
    assert len(est.literature_citations) >= 2

    # P-256 estimation
    est_ecc = QuantumResourceEstimator.estimate_resources("ECC-P256")
    assert est_ecc.key_size_bits == 256
    assert est_ecc.logical_qubits > 1000


def test_binary_ml_classifier():
    # Construct synthetic data with AES sbox constant and high entropy
    aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]) * 4
    high_ent = bytes([(i * 37 + 11) & 0xFF for i in range(1024)])
    test_bin = aes_sbox + high_ent

    res = BinaryMLClassifier.classify_binary(test_bin, "crypto_module.dll")
    assert res.crypto_probability >= 0.6
    assert res.predicted_category == "SYMMETRIC_CRYPTO"
    assert len(res.evidence_records) >= 1


def test_standards_mapping():
    catalog = get_all_standards()
    assert len(catalog["frameworks"]) >= 3
    assert len(catalog["mappings"]) >= 3
    assert any("FIPS 203" in m["target_standard"] for m in catalog["mappings"])


def test_api_experimental_endpoints(client):
    # Test standards mapping endpoint
    res = client.get("/api/standards/mapping")
    assert res.status_code == 200
    assert "mappings" in res.json()

    # Test custom crypto benchmark endpoint
    res_bench = client.get("/api/experimental/custom-crypto/benchmark")
    assert res_bench.status_code == 200
    assert res_bench.json()["accuracy"] >= 0.7

    # Test quantum estimation endpoint
    res_q = client.post("/api/risk/quantum-estimation", json={"target_algorithm": "RSA-2048"})
    assert res_q.status_code == 200
    assert res_q.json()["physical_qubits_estimate"] > 1_000_000

    # Test autopatch endpoint
    res_patch = client.post("/api/experimental/autopatch", json={
        "source_code": "import hashlib\ndef x(): return hashlib.md5(b'hi').hexdigest()",
        "file_path": "auth.py",
        "language": "python",
        "run_tests": True
    })
    assert res_patch.status_code == 200
    assert res_patch.json()["verification_status"] == "passed"

    # Test direct pcap analysis endpoint
    res_pcap = client.post("/api/experimental/pcap", json={"with_pqc_hybrid": True})
    assert res_pcap.status_code == 200
    assert res_pcap.json()["packets_analyzed"] == 2
    assert len(res_pcap.json()["sessions"]) == 1

    # Test sih-flow endpoint with both GET and POST
    res_sih_post = client.post("/api/demo/sih-flow")
    assert res_sih_post.status_code == 200
    assert res_sih_post.json()["status"] == "completed"

    res_sih_get = client.get("/api/demo/sih-flow")
    assert res_sih_get.status_code == 200
    assert res_sih_get.json()["total_steps"] == 10

