"""
ECDAT V4 P2.2 Crypto-Agility Intelligence Adversarial Test Suite.

Enforces all 40 mandated research axioms and 6 integration fixtures:
1. hardcoded API != configurable
2. config option != observed runtime replacement
3. abstraction != migration completion
4. dependency pin != immutable dependency
5. graph centrality != agility
6. graph centrality != risk
7. high risk != low agility
8. high risk != high agility
9. no arbitrary score as source of truth
10. unknown != blocked
11. unknown != agile
12. scanner unavailable != poor agility
13. certificate presence != rotation capability
14. certificate externalization != successful rotation
15. ACME presence != successful rotation
16. containerization != runtime reload
17. firmware != automatically blocked
18. tests exist != migration completed
19. dependency != actual crypto use
20. import != actual crypto use
21. string != actual use
22. symbol != actual use
23. provider capability != provider use
24. protocol support != protocol agility
25. TLS support != TLS negotiation
26. SSH advertisement != negotiated KEX
27. QUIC advertisement != negotiated QUIC
28. PQC capability != PQC agility
29. hybrid KEX != PQC signature
30. contradictory evidence preserved
31. evidence provenance preserved
32. historical assessment not overwritten
33. KB version preserved
34. engine version preserved
35. configuration hash preserved
36. evidence hash preserved
37. missing graph edge handled safely
38. malformed evidence handled safely
39. project isolation enforced
40. scanner unavailable handled explicitly

Fixtures A-F:
- Fixture A: Hardcoded classical crypto
- Fixture B: Provider abstraction + external configuration
- Fixture C: Mixed hardcoded + configurable implementation
- Fixture D: Embedded certificate/key
- Fixture E: Firmware crypto without reload
- Fixture F: High centrality with strong abstraction
"""
from __future__ import annotations

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import json
import pytest
from starlette.testclient import TestClient

from main import app
from engine.asset_graph import AssetGraphService, CryptoAsset, AssetType, RelationshipType
from engine.scan_store import ScanStore
from engine.agility.models import (
    AgilityDimension,
    AgilityState,
    AgilityConfidence,
    ChangeComplexity,
    DimensionalAgility,
    CryptoChangeSurface,
    AgilityAssessment,
    AgilityReason,
)
from engine.agility.evidence import AgilityEvidenceItem
from engine.agility.dimensions import (
    assess_algorithm_agility,
    assess_configuration_agility,
    assess_dependency_agility,
    assess_protocol_agility,
    assess_certificate_agility,
    assess_deployment_agility,
    assess_validation_agility,
)
from engine.agility.agility_pipeline import evaluate_agility
from engine.agility.change_surface import calculate_change_surface


@pytest.fixture
def store(tmp_path):
    db_path = str(tmp_path / "test_adversarial_agility.sqlite3")
    s = ScanStore(path=db_path)
    yield s
    s.close()


class TestMandatoryAxioms1to10:
    def test_axiom_1_hardcoded_api_not_configurable(self):
        """Axiom 1: Hardcoded primitive call is CONSTRAINED and never classified as configurable."""
        ev = [AgilityEvidenceItem({
            "id": "ax1", "description": "AES_encrypt called directly with static constant", "level": "E3", "state": "MEASURED"
        })]
        res = assess_algorithm_agility({"id": "a-1"}, ev)
        assert res.state == AgilityState.CONSTRAINED
        assert res.state != AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_2_config_option_not_runtime_replacement(self):
        """Axiom 2: Config option presence yields SUPPORTED, not OBSERVED without runtime execution."""
        ev = [AgilityEvidenceItem({
            "id": "ax2", "description": "env_var CIPHER_ALGO declared in settings", "level": "E2", "state": "INFERRED"
        })]
        res = assess_configuration_agility({"id": "a-2"}, ev)
        assert res.state == AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_3_abstraction_not_migration_completion(self):
        """Axiom 3: Provider abstraction enables agility, but does NOT prove migration completed."""
        ev = [AgilityEvidenceItem({
            "id": "ax3", "description": "EVP provider abstraction in use", "level": "E4", "state": "MEASURED"
        })]
        res = assess_algorithm_agility({"id": "a-3", "algorithm": "RSA-1024"}, ev)
        assert res.state in (AgilityState.OBSERVED, AgilityState.SUPPORTED)
        # Even though algorithm agility is high, the underlying algorithm is still legacy RSA-1024
        assert res.reason_chain[0].rule_id in ("AGL-ALG-001", "AGL-ALG-002")
        assert "target replacement algorithm is installed" in res.limitations[0] or "alternative algorithms was not directly observed" in res.unknowns[0]

    def test_axiom_4_dependency_pin_not_immutable_dependency(self):
        """Axiom 4: Dependency pin is hygiene/friction, NOT an immutability barrier (BLOCKED)."""
        ev = [AgilityEvidenceItem({
            "id": "ax4", "description": "dependency_lock with hash pinning in poetry.lock", "level": "E2", "state": "MEASURED"
        })]
        res = assess_dependency_agility({"id": "a-4"}, ev)
        assert res.state in (AgilityState.CONSTRAINED, AgilityState.PARTIALLY_OBSERVED)
        assert res.state != AgilityState.BLOCKED

    def test_axiom_5_graph_centrality_not_agility(self):
        """Axiom 5: Graph centrality measures coupling/change surface, NOT individual agility."""
        ev = [AgilityEvidenceItem({
            "id": "ax5", "description": "provider_interface EVP_CIPHER_fetch", "level": "E4", "state": "MEASURED"
        })]
        # Pass high centrality in context
        res = assess_dependency_agility({"id": "a-5"}, ev, context={"graph_centrality": 0.95, "blast_radius_count": 42})
        # Provider abstraction keeps state OBSERVED or PARTIALLY_OBSERVED, not collapsed to CONSTRAINED
        assert res.state == AgilityState.OBSERVED
        assert any("High graph coupling" in u for u in res.unknowns)

    def test_axiom_6_graph_centrality_not_risk(self):
        """Axiom 6: Central node in graph can be low-risk (e.g. clean AES-256 wrapper)."""
        asset = {"id": "crypto-core", "algorithm": "AES-256-GCM", "asset_type": "CRYPTO_LIBRARY"}
        ev = [AgilityEvidenceItem({"id": "ax6", "description": "provider_abstraction with clean interfaces", "level": "E4", "state": "MEASURED"})]
        assessment = evaluate_agility(asset, ev, context={"graph_centrality": 0.9, "blast_radius_count": 50})
        # High blast radius, but clean abstraction: change surface captures complexity, agility is agile
        assert assessment.change_surface.complexity in (ChangeComplexity.MEDIUM, ChangeComplexity.HIGH)
        assert assessment.dimensions["AGILITY_ALGORITHM"].state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)

    def test_axiom_7_high_risk_not_low_agility(self):
        """Axiom 7: High/Critical cryptographic risk (MD5) can have HIGH agility if provider-abstracted."""
        asset = {"id": "asset-md5", "algorithm": "MD5", "asset_type": "ALGORITHM"}
        ev = [
            AgilityEvidenceItem({"id": "ax7a", "description": "crypto_factory MessageDigest.getInstance(algo)", "level": "E4", "state": "MEASURED"}),
            AgilityEvidenceItem({"id": "ax7b", "description": "env_var HASH_ALGO overrides default", "level": "E3", "state": "MEASURED"}),
        ]
        assessment = evaluate_agility(asset, ev)
        # MD5 is classically broken (high risk), but algorithm replaceability and configuration agility are high
        assert assessment.dimensions["AGILITY_ALGORITHM"].state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)
        assert assessment.dimensions["AGILITY_CONFIGURATION"].state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)

    def test_axiom_8_high_risk_not_high_agility(self):
        """Axiom 8: High risk does not guarantee high agility (e.g. hardcoded MD5)."""
        asset = {"id": "asset-md5-hardcoded", "algorithm": "MD5", "asset_type": "ALGORITHM"}
        ev = [AgilityEvidenceItem({"id": "ax8", "description": "direct_primitive MD5_Init() in C code", "level": "E3", "state": "MEASURED"})]
        assessment = evaluate_agility(asset, ev)
        assert assessment.dimensions["AGILITY_ALGORITHM"].state == AgilityState.CONSTRAINED

    def test_axiom_9_no_arbitrary_score_as_source_of_truth(self):
        """Axiom 9: Dimensions are the source of truth; composite_score is marked DERIVED."""
        asset = {"id": "ax9-asset", "name": "RSA", "asset_type": "ALGORITHM"}
        ev = [AgilityEvidenceItem({"id": "ax9", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"})]
        assessment = evaluate_agility(asset, ev)
        assert assessment.derived_score_metadata["is_derived"] is True
        assert "unweighted_mean" in assessment.derived_score_metadata["formula"]
        assert assessment.overall_state != ""
        assert len(assessment.dimensions) == 7

    def test_axiom_10_unknown_not_blocked(self):
        """Axiom 10: Missing evidence yields UNKNOWN, never coerced to BLOCKED."""
        asset = {"id": "ax10-asset", "name": "UnknownModule", "asset_type": "APPLICATION"}
        res = assess_algorithm_agility(asset, [])
        assert res.state == AgilityState.UNKNOWN
        assert res.state != AgilityState.BLOCKED
        assert res.state != AgilityState.CONSTRAINED


class TestMandatoryAxioms11to20:
    def test_axiom_11_unknown_not_agile(self):
        """Axiom 11: Missing evidence does not assume safety or agility."""
        asset = {"id": "ax11-asset", "name": "UnknownModule", "asset_type": "APPLICATION"}
        res = assess_configuration_agility(asset, [])
        assert res.state == AgilityState.UNKNOWN
        assert res.state != AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_12_scanner_unavailable_not_poor_agility(self):
        """Axiom 12: Scanner failure yields SCANNER_UNAVAILABLE, not CONSTRAINED or BLOCKED."""
        asset = {"id": "ax12-asset", "name": "UnscannedTarget"}
        res = assess_algorithm_agility(asset, [], context={"scanner_unavailable": True})
        assert res.state == AgilityState.SCANNER_UNAVAILABLE
        assert res.state != AgilityState.BLOCKED
        assert res.state != AgilityState.CONSTRAINED

    def test_axiom_13_certificate_presence_not_rotation_capability(self):
        """Axiom 13: Static certificate presence does NOT prove rotation capability."""
        ev = [AgilityEvidenceItem({
            "id": "ax13", "description": "x509_certificate loaded from disk", "level": "E3", "state": "MEASURED"
        })]
        res = assess_certificate_agility({"id": "a-13", "asset_type": "CERTIFICATE"}, ev)
        assert res.state == AgilityState.PARTIALLY_OBSERVED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_14_certificate_externalization_not_successful_rotation(self):
        """Axiom 14: External cert path allows change, but does not prove automated rotation."""
        ev = [AgilityEvidenceItem({
            "id": "ax14", "description": "cert_externalization via keystore path /etc/ssl/certs", "level": "E2", "state": "INFERRED"
        })]
        res = assess_certificate_agility({"id": "a-14", "asset_type": "CERTIFICATE"}, ev)
        assert res.state == AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_15_acme_presence_not_successful_rotation(self):
        """Axiom 15: ACME client library in dependencies without operational rotation yields SUPPORTED."""
        ev = [AgilityEvidenceItem({
            "id": "ax15", "description": "acme cert_manager dependency declared in package.json", "level": "E2", "state": "DECLARED"
        })]
        res = assess_certificate_agility({"id": "a-15", "asset_type": "CERTIFICATE"}, ev)
        assert res.state == AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_16_containerization_not_runtime_reload(self):
        """Axiom 16: Containerization alone allows redeploy, NOT zero-downtime hot reload."""
        ev = [AgilityEvidenceItem({
            "id": "ax16", "description": "container_image Dockerfile detected", "level": "E2", "state": "INFERRED"
        })]
        res = assess_deployment_agility({"id": "a-16"}, ev)
        assert res.state == AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED
        assert "Service restart or container roll required" in res.limitations[0]

    def test_axiom_17_firmware_not_automatically_blocked(self):
        """Axiom 17: Firmware asset without proven hardware flash lock is UNKNOWN or CONSTRAINED, not BLOCKED."""
        asset = {"id": "ax17-asset", "asset_type": "FIRMWARE"}
        res = assess_deployment_agility(asset, [], context={"is_firmware": True})
        assert res.state != AgilityState.BLOCKED

    def test_axiom_18_tests_exist_not_migration_completed(self):
        """Axiom 18: Cryptographic test harness verifies validation ability, NOT completed migration."""
        ev = [AgilityEvidenceItem({
            "id": "ax18", "description": "crypto_test with Wycheproof test vectors", "level": "E4", "state": "MEASURED"
        })]
        res = assess_validation_agility({"id": "a-18"}, ev)
        assert res.state == AgilityState.OBSERVED
        # Rule text clarifies this measures validation agility, not migration
        assert "new PQC algorithm test cases must be added" in res.limitations[0]

    def test_axiom_19_dependency_not_actual_crypto_use(self):
        """Axiom 19: Dependency declaration in lockfile is not runtime crypto use."""
        ev = [AgilityEvidenceItem({
            "id": "ax19", "description": "dependency_declaration cryptography==41.0.0", "level": "E2", "state": "DECLARED"
        })]
        res = assess_dependency_agility({"id": "a-19"}, ev)
        assert res.confidence == AgilityConfidence.UNVERIFIED or res.confidence == AgilityConfidence.INFERRED

    def test_axiom_20_import_not_actual_crypto_use(self):
        """Axiom 20: Import statement without API invocation is E1 heuristic, low confidence."""
        ev = [AgilityEvidenceItem({
            "id": "ax20", "description": "import cryptography.hazmat", "level": "E1", "state": "INFERRED"
        })]
        res = assess_algorithm_agility({"id": "a-20"}, ev)
        assert res.confidence == AgilityConfidence.INFERRED


class TestMandatoryAxioms21to30:
    def test_axiom_21_string_not_actual_use(self):
        """Axiom 21: String reference alone (e.g. in comment or error message) is not actual use."""
        ev = [AgilityEvidenceItem({
            "id": "ax21", "description": "string literal 'AES-256' in log message", "level": "E1", "state": "INFERRED"
        })]
        res = assess_algorithm_agility({"id": "a-21"}, ev)
        assert res.confidence == AgilityConfidence.INFERRED

    def test_axiom_22_symbol_not_actual_use(self):
        """Axiom 22: Unused symbol reference in binary table is E2, not E4 execution."""
        ev = [AgilityEvidenceItem({
            "id": "ax22", "description": "symbol EVP_EncryptInit present in dynsym", "level": "E2", "state": "INFERRED"
        })]
        res = assess_algorithm_agility({"id": "a-22"}, ev)
        assert res.confidence == AgilityConfidence.INFERRED

    def test_axiom_23_provider_capability_not_provider_use(self):
        """Axiom 23: OpenSSL 3.0 installed does not prove application uses provider abstraction."""
        ev = [AgilityEvidenceItem({
            "id": "ax23", "description": "direct_primitive call to DES_ecb_encrypt despite OpenSSL 3.0 installed in environment", "level": "E3", "state": "MEASURED"
        })]

        res = assess_algorithm_agility({"id": "a-23"}, ev)
        assert res.state == AgilityState.CONSTRAINED

    def test_axiom_24_protocol_support_not_protocol_agility(self):
        """Axiom 24: Protocol capability without configurable ciphers is CONSTRAINED."""
        ev = [AgilityEvidenceItem({
            "id": "ax24", "description": "hardcoded_protocol fixed cipher suite TLS_RSA_WITH_AES_128_CBC_SHA", "level": "E3", "state": "MEASURED"
        })]
        res = assess_protocol_agility({"id": "a-24", "asset_type": "ENDPOINT"}, ev)
        assert res.state == AgilityState.CONSTRAINED

    def test_axiom_25_tls_support_not_tls_negotiation(self):
        """Axiom 25: Static TLS configuration is distinct from live verified negotiation."""
        ev = [AgilityEvidenceItem({
            "id": "ax25", "description": "tls_configuration in nginx.conf ssl_ciphers HIGH:!aNULL", "level": "E2", "state": "INFERRED"
        })]
        res = assess_protocol_agility({"id": "a-25", "asset_type": "ENDPOINT"}, ev)
        assert res.state == AgilityState.SUPPORTED
        assert res.state != AgilityState.OBSERVED

    def test_axiom_26_ssh_advertisement_not_negotiated_kex(self):
        """Axiom 26: SSH KEXINIT advertisement is configuration capability, not negotiated session."""
        ev = [AgilityEvidenceItem({
            "id": "ax26", "description": "protocol_configuration SSH KEXINIT offers diffie-hellman-group14-sha256", "level": "E2", "state": "INFERRED"
        })]
        res = assess_protocol_agility({"id": "a-26", "asset_type": "ENDPOINT"}, ev)
        assert res.state == AgilityState.SUPPORTED

    def test_axiom_27_quic_advertisement_not_negotiated_quic(self):
        """Axiom 27: Alt-Svc QUIC advertisement is not active HTTP/3 negotiation."""
        ev = [AgilityEvidenceItem({
            "id": "ax27", "description": "protocol_configuration Alt-Svc: h3=':443'", "level": "E2", "state": "INFERRED"
        })]
        res = assess_protocol_agility({"id": "a-27", "asset_type": "ENDPOINT"}, ev)
        assert res.state == AgilityState.SUPPORTED

    def test_axiom_28_pqc_capability_not_pqc_agility(self):
        """Axiom 28: A PQC algorithm that is hardcoded has constrained agility despite being quantum-safe."""
        asset = {"id": "ax28-asset", "algorithm": "ML-KEM-768", "asset_type": "ALGORITHM"}
        ev = [AgilityEvidenceItem({"id": "ax28", "description": "direct_primitive call to PQClean_kem_mlkem768_encaps", "level": "E3", "state": "MEASURED"})]
        assessment = evaluate_agility(asset, ev)
        assert assessment.dimensions["AGILITY_ALGORITHM"].state == AgilityState.CONSTRAINED

    def test_axiom_29_hybrid_kex_not_pqc_signature(self):
        """Axiom 29: Hybrid KEX protocol agility does not grant certificate/signature agility."""
        asset = {"id": "ax29-asset", "asset_type": "ENDPOINT"}
        ev = [
            AgilityEvidenceItem({"id": "ax29a", "description": "tls_negotiation with X25519MLKEM768 dynamic kex", "level": "E5", "state": "MEASURED"}),
            AgilityEvidenceItem({"id": "ax29b", "description": "hardcoded_key classical RSA-2048 private key embedded", "level": "E3", "state": "MEASURED"}),
        ]
        assessment = evaluate_agility(asset, ev)
        assert assessment.dimensions["AGILITY_PROTOCOL"].state == AgilityState.OBSERVED
        assert assessment.dimensions["AGILITY_CERTIFICATE"].state == AgilityState.CONSTRAINED

    def test_axiom_30_contradictory_evidence_preserved(self):
        """Axiom 30: Conflicting evidence (configurable option + hardcoded fallback) yields PARTIALLY_OBSERVED."""
        ev = [
            AgilityEvidenceItem({"id": "ax30a", "description": "env_var CIPHER loaded dynamically", "level": "E2", "state": "INFERRED"}),
            AgilityEvidenceItem({"id": "ax30b", "description": "hardcoded_fallback to AES-128", "level": "E2", "state": "INFERRED"}),
        ]
        res = assess_configuration_agility({"id": "a-30"}, ev)
        assert res.state == AgilityState.PARTIALLY_OBSERVED
        assert len(res.supporting_evidence) > 0
        assert len(res.contradicting_evidence) > 0


class TestMandatoryAxioms31to40:
    def test_axiom_31_evidence_provenance_preserved(self, store):
        """Axiom 31: Input evidence IDs are completely preserved in assessment and explainability."""
        asset = {"id": "ax31-asset", "name": "AES"}
        ev = [{"id": "ev-prov-100", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"}]
        assessment = evaluate_agility(asset, ev)
        assert "ev-prov-100" in assessment.dimensions["AGILITY_ALGORITHM"].evidence_refs

    def test_axiom_32_historical_assessment_not_overwritten(self, store):
        """Axiom 32: Multiple scans create non-overwriting historical assessments."""
        asset = {"id": "ax32-asset", "name": "RSA"}
        ev1 = [{"id": "ev-hist-1", "description": "direct_primitive call", "level": "E3", "state": "MEASURED"}]
        ev2 = [{"id": "ev-hist-2", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"}]

        a1 = evaluate_agility(asset, ev1)
        a1.scan_id = "scan-1"
        store.save_agility_assessment(a1)

        a2 = evaluate_agility(asset, ev2)
        a2.scan_id = "scan-2"
        store.save_agility_assessment(a2)

        history = store.get_all_agility_assessments("ax32-asset")
        assert len(history) == 2
        states = {h["overall_state"] for h in history}
        assert AgilityState.CONSTRAINED.value in states
        assert (AgilityState.SUPPORTED.value in states or AgilityState.OBSERVED.value in states)

    def test_axiom_33_kb_version_preserved(self):
        """Axiom 33: Knowledge base version 2024.1 is recorded on every assessment."""
        assessment = evaluate_agility({"id": "ax33-asset"})
        assert assessment.knowledge_base_version == "2024.1"

    def test_axiom_34_engine_version_preserved(self):
        """Axiom 34: Engine version 4.0.0 is preserved in assessment record."""
        assessment = evaluate_agility({"id": "ax34-asset"})
        assert assessment.engine_version == "4.0.0"

    def test_axiom_35_configuration_hash_preserved(self):
        """Axiom 35: Configuration hash is deterministic and non-empty."""
        assessment = evaluate_agility({"id": "ax35-asset"}, context={"strict_mode": True})
        assert len(assessment.configuration_hash) == 64

    def test_axiom_36_evidence_hash_preserved(self):
        """Axiom 36: Evidence hash is deterministic sha256 of sorted evidence IDs."""
        ev = [{"id": "ev-1", "description": "test"}, {"id": "ev-2", "description": "test2"}]
        a1 = evaluate_agility({"id": "ax36-asset"}, ev)
        a2 = evaluate_agility({"id": "ax36-asset"}, list(reversed(ev)))
        assert a1.evidence_hash == a2.evidence_hash
        assert len(a1.evidence_hash) == 64

    def test_axiom_37_missing_graph_edge_handled_safely(self, store):
        """Axiom 37: Missing graph edge or isolated node evaluates without exception."""
        assessment = evaluate_agility({"id": "isolated-node", "name": "Isolated"}, graph_service=store)
        assert assessment.change_surface is not None
        assert assessment.change_surface.call_sites_count == 0

    def test_axiom_38_malformed_evidence_handled_safely(self):
        """Axiom 38: Malformed or partial evidence does not crash pipeline."""
        malformed = ["raw_string_item", {"no_id": True}, {"id": None, "state": "UNKNOWN"}]
        assessment = evaluate_agility({"id": "ax38-asset"}, malformed)
        assert assessment.overall_state is not None

    def test_axiom_39_project_isolation_enforced(self, store):
        """Axiom 39: Assets belonging to different projects remain strictly segregated."""
        store.graph.create_asset("proj-alpha", "ALGORITHM", "Alpha-Cipher", asset_id="asset-alpha")
        store.graph.create_asset("proj-beta", "ALGORITHM", "Beta-Cipher", asset_id="asset-beta")

        assert store.get_asset("asset-alpha", "proj-alpha") is not None
        assert store.get_asset("asset-alpha", "proj-beta") is None

    def test_axiom_40_scanner_unavailable_handled_explicitly(self):
        """Axiom 40: Scanner unavailable is explicit state and does not bias composite score."""
        ev = [{"id": "ev-40", "description": "scan timeout", "state": "SCANNER_UNAVAILABLE", "level": "E0"}]
        assessment = evaluate_agility({"id": "ax40-asset"}, ev, context={"scanner_unavailable": True})
        assert assessment.dimensions["AGILITY_ALGORITHM"].state == AgilityState.SCANNER_UNAVAILABLE
        # Scanner unavailable dimensions must NOT be counted as zero in composite score
        assert assessment.composite_score is None


class TestIntegrationFixturesAtoF:
    def test_fixture_a_hardcoded_classical_crypto(self):
        """Fixture A: Hardcoded classical crypto -> algorithm agility CONSTRAINED."""
        asset = {"id": "fix-a", "name": "Legacy-DES", "asset_type": "ALGORITHM"}
        evidence = [
            {"id": "fa-1", "description": "direct_primitive DES_encrypt called in main loop", "level": "E3", "state": "MEASURED", "file_path": "src/legacy.c"}
        ]
        assessment = evaluate_agility(asset, evidence)
        assert assessment.dimensions["AGILITY_ALGORITHM"].state == AgilityState.CONSTRAINED
        assert assessment.change_surface.complexity in (ChangeComplexity.LOW, ChangeComplexity.MEDIUM)

    def test_fixture_b_provider_abstraction_plus_config(self):
        """Fixture B: Provider abstraction + external configuration -> SUPPORTED / OBSERVED."""
        asset = {"id": "fix-b", "name": "Modern-AES", "asset_type": "ALGORITHM"}
        evidence = [
            {"id": "fb-1", "description": "provider_abstraction EVP_CIPHER_fetch", "level": "E4", "state": "MEASURED", "file_path": "src/crypto.c"},
            {"id": "fb-2", "description": "env_var CRYPTO_ALGO overrides algorithm choice", "level": "E3", "state": "MEASURED", "file_path": "src/config.c"},
        ]
        assessment = evaluate_agility(asset, evidence)
        assert assessment.dimensions["AGILITY_ALGORITHM"].state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)
        assert assessment.dimensions["AGILITY_CONFIGURATION"].state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)
        assert assessment.overall_state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)

    def test_fixture_c_mixed_hardcoded_plus_configurable(self):
        """Fixture C: Mixed hardcoded + configurable implementation -> PARTIALLY_OBSERVED."""
        asset = {"id": "fix-c", "name": "Hybrid-Service", "asset_type": "SERVICE"}
        evidence = [
            {"id": "fc-1", "description": "provider_abstraction used for bulk encryption", "level": "E4", "state": "MEASURED"},
            {"id": "fc-2", "description": "hardcoded_algorithm used for key wrapping", "level": "E3", "state": "MEASURED"},
            {"id": "fc-3", "description": "config_file config.json with hardcoded_fallback", "level": "E2", "state": "INFERRED"},
        ]
        assessment = evaluate_agility(asset, evidence)
        assert assessment.dimensions["AGILITY_ALGORITHM"].state == AgilityState.PARTIALLY_OBSERVED
        assert assessment.dimensions["AGILITY_CONFIGURATION"].state == AgilityState.PARTIALLY_OBSERVED
        assert assessment.overall_state == AgilityState.PARTIALLY_OBSERVED

    def test_fixture_d_embedded_certificate_and_key(self):
        """Fixture D: Embedded certificate/key -> certificate agility CONSTRAINED."""
        asset = {"id": "fix-d", "name": "Embedded-Cert", "asset_type": "CERTIFICATE"}
        evidence = [
            {"id": "fd-1", "description": "embedded_private_key hardcoded PEM string in binary", "level": "E3", "state": "MEASURED", "file_path": "src/keys.c"}
        ]
        assessment = evaluate_agility(asset, evidence)
        assert assessment.dimensions["AGILITY_CERTIFICATE"].state == AgilityState.CONSTRAINED

    def test_fixture_e_firmware_crypto_no_reload(self):
        """Fixture E: Firmware crypto implementation with no reload mechanism -> deployment CONSTRAINED / UNKNOWN."""
        asset = {"id": "fix-e", "name": "IoT-Firmware", "asset_type": "FIRMWARE"}
        evidence = [
            {"id": "fe-1", "description": "firmware_content with static_binary no reload mechanism", "level": "E3", "state": "MEASURED"}
        ]
        assessment = evaluate_agility(asset, evidence, context={"is_firmware": True})
        assert assessment.dimensions["AGILITY_DEPLOYMENT"].state in (AgilityState.CONSTRAINED, AgilityState.UNKNOWN)

    def test_fixture_f_high_centrality_strong_abstraction(self):
        """Fixture F: High graph centrality but strong abstraction -> high change surface, but NOT constrained agility."""
        asset = {"id": "fix-f", "name": "Shared-Crypto-Core", "asset_type": "CRYPTO_LIBRARY"}
        evidence = [
            {"id": "ff-1", "description": "provider_abstraction clean interface layer", "level": "E4", "state": "MEASURED"},
            {"id": "ff-2", "description": "env_var configuration driven", "level": "E3", "state": "MEASURED"},
        ]
        blast_data = {
            "target_node_id": "fix-f",
            "total_impacted_count": 15,
            "impacted_assets": [{"id": f"caller-{i}", "name": f"Service-{i}", "asset_type": "SERVICE"} for i in range(15)]
        }
        assessment = evaluate_agility(asset, evidence, blast_radius=blast_data)
        # Large change surface
        assert len(assessment.change_surface.direct_dependents) == 15
        assert assessment.change_surface.complexity in (ChangeComplexity.MEDIUM, ChangeComplexity.HIGH)
        # But individual algorithm replaceability remains agile
        assert assessment.dimensions["AGILITY_ALGORITHM"].state in (AgilityState.SUPPORTED, AgilityState.OBSERVED)


class TestCompositeScoreAxioms:
    """Critical Score Audit (Section 6): Verify composite_score is strictly DERIVED,
    unweighted, excludes UNKNOWN, excludes NOT_APPLICABLE, never treats UNKNOWN as zero,
    and returns explicit None/UNMEASURED when zero applicable dimensions exist.
    """

    def test_score_all_dimensions_known(self):
        """All 7 dimensions known -> composite_score is unweighted mean of all 7."""
        asset = {"id": "score-all-known", "asset_type": "SERVICE"}
        evidence = [
            {"id": "s1", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"},
            {"id": "s2", "description": "env_var CIPHER_NAME", "level": "E3", "state": "MEASURED"},
            {"id": "s3", "description": "package_manager openssl dynamic", "level": "E3", "state": "MEASURED"},
            {"id": "s4", "description": "tls_negotiation dynamic negotiation", "level": "E5", "state": "MEASURED"},
            {"id": "s5", "description": "automated_certificate_rotation acme", "level": "E4", "state": "MEASURED"},
            {"id": "s6", "description": "container_image docker dynamic reload", "level": "E3", "state": "MEASURED"},
            {"id": "s7", "description": "crypto_test Wycheproof test vectors", "level": "E4", "state": "MEASURED"},
        ]
        res = evaluate_agility(asset, evidence)
        assert res.composite_score is not None
        assert 0.7 <= res.composite_score <= 1.0
        assert res.derived_score_metadata["is_derived"] is True
        assert res.derived_score_metadata["scored_dimensions_count"] == 7
        assert res.derived_score_metadata["excluded_unknown_count"] == 0

    def test_score_one_unknown_dimension(self):
        """1 UNKNOWN dimension -> excluded from numerator and denominator, not treated as 0."""
        asset = {"id": "score-one-unk", "asset_type": "SERVICE"}
        evidence = [
            {"id": "s1", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"},
            {"id": "s2", "description": "env_var CIPHER_NAME", "level": "E3", "state": "MEASURED"},
            {"id": "s3", "description": "package_manager openssl dynamic", "level": "E3", "state": "MEASURED"},
            {"id": "s4", "description": "tls_negotiation dynamic negotiation", "level": "E5", "state": "MEASURED"},
            {"id": "s5", "description": "automated_certificate_rotation acme", "level": "E4", "state": "MEASURED"},
            {"id": "s6", "description": "container_image docker dynamic reload", "level": "E3", "state": "MEASURED"},
        ]
        res = evaluate_agility(asset, evidence)
        assert res.dimensions["AGILITY_VALIDATION"].state == AgilityState.UNKNOWN
        assert res.composite_score is not None
        assert res.derived_score_metadata["scored_dimensions_count"] == 6
        assert res.derived_score_metadata["excluded_unknown_count"] == 1

    def test_score_several_unknown_dimensions(self):
        """Several UNKNOWN dimensions -> mean is computed ONLY over known dimensions."""
        asset = {"id": "score-several-unk", "asset_type": "SERVICE"}
        evidence = [
            {"id": "s1", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"},
            {"id": "s2", "description": "env_var CIPHER_NAME", "level": "E3", "state": "MEASURED"},
        ]
        res = evaluate_agility(asset, evidence)
        assert res.composite_score is not None
        assert res.derived_score_metadata["scored_dimensions_count"] == 2
        assert res.derived_score_metadata["excluded_unknown_count"] == 5

    def test_score_not_applicable_dimension_excluded(self):
        """NOT_APPLICABLE dimension (e.g. Protocol on pure algorithm) is completely excluded."""
        asset = {"id": "score-na", "asset_type": "ALGORITHM"}
        evidence = [
            {"id": "s1", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"},
        ]
        res = evaluate_agility(asset, evidence)
        assert res.dimensions["AGILITY_PROTOCOL"].state == AgilityState.NOT_APPLICABLE
        assert res.composite_score is not None
        assert res.derived_score_metadata["scored_dimensions_count"] == 1

    def test_score_scanner_unavailable_dimension_excluded(self):
        """SCANNER_UNAVAILABLE does not become a negative value and does not penalize score."""
        asset = {"id": "score-scanner-unavail", "asset_type": "SERVICE"}
        evidence = [
            {"id": "s1", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"},
            {"id": "s2", "description": "SCANNER_UNAVAILABLE protocol probe timed out", "level": "E0", "state": "SCANNER_UNAVAILABLE"},
        ]
        res = evaluate_agility(asset, evidence)
        assert res.dimensions["AGILITY_PROTOCOL"].state == AgilityState.SCANNER_UNAVAILABLE
        assert res.composite_score is not None
        assert res.composite_score >= 0.8

    def test_score_contradictory_dimensions(self):
        """Contradictory/mixed evidence yields PARTIALLY_OBSERVED with 0.5 score."""
        asset = {"id": "score-contra", "asset_type": "ALGORITHM"}
        evidence = [
            {"id": "s1", "description": "provider_abstraction EVP", "level": "E4", "state": "MEASURED"},
            {"id": "s2", "description": "hardcoded_algorithm DES_ede3_cbc_encrypt", "level": "E3", "state": "MEASURED"},
        ]
        res = evaluate_agility(asset, evidence)
        assert res.dimensions["AGILITY_ALGORITHM"].state == AgilityState.PARTIALLY_OBSERVED
        assert res.composite_score == 0.50

    def test_score_zero_applicable_dimensions_returns_none(self):
        """Zero applicable dimensions -> returns explicit None, NEVER an apparently precise 0.00."""
        asset = {"id": "score-zero-app", "asset_type": "APPLICATION"}
        res = evaluate_agility(asset, [], context={"scanner_unavailable": True})
        assert res.overall_state == AgilityState.SCANNER_UNAVAILABLE
        assert res.composite_score is None
        assert res.derived_score_metadata["scored_dimensions_count"] == 0
        assert res.derived_score_metadata["note"] == "No dimensions had sufficient concrete evidence for numeric derivation."
