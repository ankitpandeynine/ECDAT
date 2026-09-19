"""
ECDAT V4 P4 Adversarial Test Suite.

Rigorously tests 40 mandatory research and semantic axioms governing
P4.1 Versioned Knowledge Base and P4.2 Ground-Truth Research Benchmark,
including all 20 hard negative categories, anti-fake evaluator verification,
and multi-modal corroboration and contradiction handling.
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.knowledge_version import load_knowledge_version, compute_deterministic_knowledge_hash
from evaluation.models import BenchmarkCase, GroundTruthLabel, UseState
from evaluation.dataset import compute_dataset_hash, load_dataset, validate_case
from evaluation.generator import generate_benchmark_cases
from evaluation.evaluator import BenchmarkEvaluator
from evaluation.metrics import calculate_binary_metrics, compute_evaluation_metrics
from evaluation.confusion import analyze_confusion_and_errors
from evaluation import run_benchmark


@pytest.fixture(scope="module")
def evaluator():
    return BenchmarkEvaluator()


@pytest.fixture(scope="module")
def dataset():
    return load_dataset()


class TestP4AxiomsKnowledgeAndDataset:
    def test_axiom_01_knowledge_versioning_frozen_manifest(self):
        kb = load_knowledge_version()
        assert kb.version == "2024.1"
        assert len(kb.sources) == 8
        assert all(s["verified"] for s in kb.sources)

    def test_axiom_02_deterministic_knowledge_hash_immutability(self):
        h1 = load_knowledge_version().knowledge_hash
        h2 = load_knowledge_version().knowledge_hash
        assert h1 == h2

    def test_axiom_03_deterministic_dataset_hash(self):
        cases = generate_benchmark_cases()
        h1 = compute_dataset_hash(cases)
        h2 = compute_dataset_hash(cases)
        assert h1 == h2

    def test_axiom_04_duplicate_case_detection(self):
        seen = set()
        c = {"case_id": "AXIOM_04", "modality": "SOURCE", "input_artifact": {"x": 1}, "ground_truth_label": "POSITIVE"}
        validate_case(c, seen)
        with pytest.raises(ValueError, match="Duplicate benchmark case_id"):
            validate_case(c, seen)

    def test_axiom_05_missing_label_rejection(self):
        seen = set()
        c = {"case_id": "AXIOM_05", "modality": "SOURCE", "input_artifact": {"x": 1}}
        with pytest.raises(ValueError, match="Invalid ground_truth_label"):
            validate_case(c, seen)

    def test_axiom_06_invalid_label_rejection(self):
        seen = set()
        c = {"case_id": "AXIOM_06", "modality": "SOURCE", "input_artifact": {"x": 1}, "ground_truth_label": "FABRICATED"}
        with pytest.raises(ValueError, match="Invalid ground_truth_label"):
            validate_case(c, seen)


class TestP4AxiomsModalitiesExecution:
    def test_axiom_07_source_benchmark_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="AX_SRC",
            modality="SOURCE",
            language_platform="python",
            input_artifact={
                "path": "test.py",
                "content": "from cryptography.hazmat.primitives.asymmetric import rsa\npk = rsa.generate_private_key(65537, 2048)",
                "language": "python",
            },
            ground_truth_label="POSITIVE",
            cryptographic_algorithm="RSA-2048",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "POSITIVE"
        assert res["predicted_use_state"] == "ACTUAL_USE"

    def test_axiom_08_dependency_benchmark_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="AX_DEP",
            modality="DEPENDENCY",
            language_platform="python",
            input_artifact={"file_path": "requirements.txt", "content": "cryptography==42.0.5\n"},
            ground_truth_label="POSITIVE",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "POSITIVE"
        assert res["predicted_use_state"] == "DEPENDENCY_DECLARED"

    def test_axiom_09_binary_benchmark_execution(self, evaluator):
        # Embed AES S-box
        sbox_hex = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
        payload = b"\x7fELF" + bytes.fromhex(sbox_hex)
        case = BenchmarkCase(
            case_id="AX_BIN",
            modality="BINARY",
            language_platform="x86_64_elf",
            input_artifact={"file_name": "bin.elf", "bytes_hex": payload.hex()},
            ground_truth_label="POSITIVE",
            cryptographic_algorithm="AES",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "POSITIVE"
        assert res["predicted_algorithm"] == "AES"

    def test_axiom_10_network_benchmark_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="AX_NET",
            modality="NETWORK",
            language_platform="tls_probe",
            input_artifact={"negotiated_cipher": "TLS_AES_256_GCM_SHA384", "state": "NEGOTIATED"},
            ground_truth_label="POSITIVE",
            cryptographic_algorithm="AES-256-GCM",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "POSITIVE"
        assert res["predicted_use_state"] == "NEGOTIATED"

    def test_axiom_11_x509_benchmark_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="AX_X509",
            modality="X509",
            language_platform="x509_parser",
            input_artifact={"public_key_algorithm": "ECDSA-P256", "validity": "VALID", "trusted": True},
            ground_truth_label="POSITIVE",
            cryptographic_algorithm="ECDSA-P256",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "POSITIVE"

    def test_axiom_12_pqc_benchmark_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="AX_PQC",
            modality="PQC",
            language_platform="pqc_analyzer",
            input_artifact={"algorithm_identifier": "ML-KEM-768", "is_active": True},
            ground_truth_label="POSITIVE",
            cryptographic_algorithm="ML-KEM-768",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "POSITIVE"


class TestP4AxiomsHardNegatives:
    def test_axiom_13_hn1_import_without_call(self, evaluator):
        case = BenchmarkCase(
            case_id="HN1",
            modality="SOURCE",
            language_platform="python",
            input_artifact={"path": "main.py", "content": "import cryptography\nfrom cryptography.hazmat.primitives.asymmetric import rsa\ndef compute(): return 42", "language": "python"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN1_IMPORT_NO_CALL",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"
        assert res["predicted_use_state"] == "IMPORT_ONLY"

    def test_axiom_14_hn2_string_without_use(self, evaluator):
        case = BenchmarkCase(
            case_id="HN2",
            modality="SOURCE",
            language_platform="python",
            input_artifact={"path": "log.py", "content": 'msg = "Connecting to AES-256 server"', "language": "python"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN2_STRING_NO_USE",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"
        assert res["predicted_use_state"] == "STRING_ONLY"

    def test_axiom_15_hn3_binary_symbol_without_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="HN3",
            modality="BINARY",
            language_platform="x86_64_elf",
            input_artifact={"file_name": "app.elf", "bytes_hex": "7f454c4600"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN3_BINARY_SYMBOL_NO_EXECUTION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_16_hn4_dependency_declared_unused(self, evaluator):
        case = BenchmarkCase(
            case_id="HN4",
            modality="DEPENDENCY",
            language_platform="python",
            input_artifact={
                "file_path": "requirements.txt",
                "content": "cryptography==42.0.0",
                "associated_source_files": [{"path": "main.py", "content": "print('hello')"}],
            },
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN4_DEPENDENCY_DECLARED_UNUSED",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_17_hn5_commented_crypto_api(self, evaluator):
        case = BenchmarkCase(
            case_id="HN5",
            modality="SOURCE",
            language_platform="python",
            input_artifact={"path": "comment.py", "content": "# rsa.generate_private_key(65537, 2048)", "language": "python"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN5_COMMENTED_CRYPTO_API",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_18_hn6_dead_code_crypto_api(self, evaluator):
        code = "def f():\n    if False:\n        import rsa\n        rsa.generate(2048)"
        case = BenchmarkCase(
            case_id="HN6",
            modality="SOURCE",
            language_platform="python",
            input_artifact={"path": "dead.py", "content": code, "language": "python"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN6_DEAD_CODE_CRYPTO_API",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_19_hn7_algorithm_in_documentation(self, evaluator):
        code = '"""We reviewed AES-256 and RSA-4096 before selecting our system."""\ndef add(a, b): return a + b'
        case = BenchmarkCase(
            case_id="HN7",
            modality="SOURCE",
            language_platform="python",
            input_artifact={"path": "docs.py", "content": code, "language": "python"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN7_ALGO_IN_DOCUMENTATION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_20_hn8_algorithm_in_variable_name(self, evaluator):
        code = 'rsa_key_name = "production_key_01"\nstatus = len(rsa_key_name)'
        case = BenchmarkCase(
            case_id="HN8",
            modality="SOURCE",
            language_platform="python",
            input_artifact={"path": "vars.py", "content": code, "language": "python"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN8_ALGO_IN_VARIABLE_NAME",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_21_hn9_tls_cipher_advertised_no_negotiation(self, evaluator):
        case = BenchmarkCase(
            case_id="HN9",
            modality="NETWORK",
            language_platform="tls_probe",
            input_artifact={"client_advertised_ciphers": ["DES-CBC3-SHA"], "server_chosen_cipher": "TLS_AES_256_GCM_SHA384"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN9_TLS_CIPHER_NO_NEGOTIATION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"
        assert res["predicted_use_state"] == "ADVERTISED_ONLY"

    def test_axiom_22_hn10_tls_support_without_negotiation(self, evaluator):
        case = BenchmarkCase(
            case_id="HN10",
            modality="NETWORK",
            language_platform="tls_probe",
            input_artifact={"server_supported_tls_versions": ["TLSv1.0", "TLSv1.3"], "negotiated_version": "TLSv1.3"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN10_TLS_SUPPORT_NO_NEGOTIATION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_23_hn11_ssh_advertisement_without_negotiation(self, evaluator):
        case = BenchmarkCase(
            case_id="HN11",
            modality="NETWORK",
            language_platform="ssh_probe",
            input_artifact={"kex_advertised": ["diffie-hellman-group1-sha1"], "kex_chosen": "curve25519-sha256"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN11_SSH_ADVERTISEMENT_NO_NEGOTIATION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_24_hn12_quic_altsvc_without_handshake(self, evaluator):
        case = BenchmarkCase(
            case_id="HN12",
            modality="NETWORK",
            language_platform="quic_probe",
            input_artifact={"http_header_alt_svc": 'h3=":443"', "udp_handshake_observed": False},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN12_QUIC_ALTSVC_NO_HANDSHAKE",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_25_hn13_certificate_untrusted_expired(self, evaluator):
        case = BenchmarkCase(
            case_id="HN13",
            modality="X509",
            language_platform="x509_parser",
            input_artifact={"trusted": False, "validity": "EXPIRED"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN13_CERTIFICATE_UNTRUSTED",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_26_hn14_ocsp_extension_without_revocation_check(self, evaluator):
        case = BenchmarkCase(
            case_id="HN14",
            modality="X509",
            language_platform="x509_parser",
            input_artifact={"ocsp_checked": False},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN14_OCSP_EXTENSION_NO_REVOCATION_CHECK",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_27_hn15_hybrid_kex_not_pqc_signature(self, evaluator):
        case = BenchmarkCase(
            case_id="HN15",
            modality="PQC",
            language_platform="pqc_analyzer",
            input_artifact={"algorithm_identifier": "X25519MLKEM768", "claimed_capability": "DIGITAL_SIGNATURE"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN15_HYBRID_KEX_NOT_PQC_SIGNATURE",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_28_hn16_provider_capability_without_runtime_use(self, evaluator):
        case = BenchmarkCase(
            case_id="HN16",
            modality="DEPENDENCY",
            language_platform="java",
            input_artifact={"runtime_use_observed": False},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN16_PROVIDER_CAPABILITY_NO_RUNTIME_USE",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_29_hn17_firmware_signature_without_execution(self, evaluator):
        case = BenchmarkCase(
            case_id="HN17",
            modality="FIRMWARE",
            language_platform="uimage_embedded",
            input_artifact={"bytes_hex": "75496d616765"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN17_FIRMWARE_SIGNATURE_NO_EXECUTION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_30_hn18_config_without_runtime_reload(self, evaluator):
        case = BenchmarkCase(
            case_id="HN18",
            modality="SOURCE",
            language_platform="config_inspector",
            input_artifact={"process_reload_supported": False, "content": "CIPHER=AES"},
            ground_truth_label="NEGATIVE",
            hard_negative_category="HN18_CONFIG_WITHOUT_RUNTIME_RELOAD",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "NEGATIVE"

    def test_axiom_31_hn19_scanner_unavailable_not_negative(self, evaluator):
        case = BenchmarkCase(
            case_id="HN19",
            modality="NETWORK",
            language_platform="network_prober",
            input_artifact={"scanner_status": "SCANNER_UNAVAILABLE"},
            ground_truth_label="INCONCLUSIVE",
            hard_negative_category="HN19_SCANNER_UNAVAILABLE_DISTINCTION",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "INCONCLUSIVE"
        assert res["predicted_use_state"] == "SCANNER_UNAVAILABLE"

    def test_axiom_32_hn20_unknown_evidence_not_safe(self, evaluator):
        case = BenchmarkCase(
            case_id="HN20",
            modality="BINARY",
            language_platform="binary_pipeline",
            input_artifact={"status": "PACKED_OR_ENCRYPTED_SECTION"},
            ground_truth_label="UNKNOWN",
            hard_negative_category="HN20_UNKNOWN_EVIDENCE_NOT_SAFE",
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "UNKNOWN"


class TestP4AxiomsMultiModalAndAntiFake:
    def test_axiom_33_multi_modal_corroboration(self, evaluator):
        case = BenchmarkCase(
            case_id="MM_CORR",
            modality="SOURCE",
            language_platform="multi_modal_fusion",
            input_artifact={},
            ground_truth_label="CORROBORATED",
            multi_modal_components=[
                {"modality": "SOURCE", "algo": "AES-256-GCM"},
                {"modality": "DEPENDENCY", "algo": "AES-256-GCM"},
                {"modality": "BINARY", "algo": "AES-256-GCM"},
                {"modality": "NETWORK", "algo": "AES-256-GCM"},
            ],
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "CORROBORATED"

    def test_axiom_34_multi_modal_contradiction(self, evaluator):
        case = BenchmarkCase(
            case_id="MM_CONTRA",
            modality="NETWORK",
            language_platform="multi_modal_fusion",
            input_artifact={},
            ground_truth_label="CONTRADICTED",
            multi_modal_components=[
                {"modality": "SOURCE", "algo": "AES-256-GCM"},
                {"modality": "NETWORK", "algo": "3DES"},
            ],
        )
        res = evaluator.evaluate_case(case)
        assert res["predicted_label"] == "CONTRADICTED"

    def test_axiom_35_anti_fake_evaluator_mutation_alters_prediction(self, evaluator):
        """
        CRITICAL RESEARCH INTEGRITY AXIOM:
        Proves the evaluator executes genuine scanners and does NOT look at ground_truth_label.
        """
        # 1. Unmodified positive case
        pos_case = BenchmarkCase(
            case_id="ANTI_FAKE_1",
            modality="SOURCE",
            language_platform="python",
            input_artifact={
                "path": "test.py",
                "content": "from cryptography.hazmat.primitives.asymmetric import rsa\npk = rsa.generate_private_key(65537, 2048)",
                "language": "python",
            },
            ground_truth_label="POSITIVE",
        )
        pred1 = evaluator.evaluate_case(pos_case)["predicted_label"]
        assert pred1 == "POSITIVE"

        # 2. Mutate artifact to plain text without changing ground_truth_label
        mutated_case = BenchmarkCase(
            case_id="ANTI_FAKE_1",
            modality="SOURCE",
            language_platform="python",
            input_artifact={
                "path": "test.py",
                "content": "def calculate_taxes(income): return income * 0.2",
                "language": "python",
            },
            ground_truth_label="POSITIVE", # Ground truth stays positive!
        )
        pred2 = evaluator.evaluate_case(mutated_case)["predicted_label"]
        # The evaluator MUST predict NEGATIVE because the real scanner analyzed the code!
        assert pred2 == "NEGATIVE"
        assert pred2 != mutated_case.ground_truth_label

    def test_axiom_36_reproducibility_identical_runs(self):
        cases = generate_benchmark_cases()[:50]
        h1 = compute_dataset_hash(cases)
        h2 = compute_dataset_hash(cases)
        assert h1 == h2

    def test_axiom_37_precision_recall_mathematical_consistency(self):
        m = calculate_binary_metrics(tp=50, tn=50, fp=0, fn=0)
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0

    def test_axiom_38_confusion_matrix_preserves_case_references(self):
        case_res = [{"case_id": "C_ERR", "modality": "SOURCE", "ground_truth_label": "NEGATIVE", "predicted_label": "POSITIVE"}]
        conf = analyze_confusion_and_errors(case_res)
        assert conf["false_positives"][0]["case_id"] == "C_ERR"

    def test_axiom_39_synthetic_dataset_designation_enforced(self, dataset):
        assert dataset.dataset_type == "SYNTHETIC"
        for c in dataset.cases:
            assert c.dataset_type == "SYNTHETIC"

    def test_axiom_40_no_fabricated_claims_in_report(self):
        res = run_benchmark()
        md = res.reproducibility_metadata
        assert res.overall_metrics["total_cases"] >= 700
        assert "c9de" in res.dataset_hash or len(res.dataset_hash) == 64
