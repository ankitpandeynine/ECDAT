"""
ECDAT V4 P2.1 Adversarial & Boundary Test Suite.

40+ adversarial test cases verifying research-grade cryptographic intelligence:
- Axiom 1: Dependency declaration != actual use
- Axiom 2: Hybrid KEX != PQC signature
- Axiom 3: Certificate presence != trust validated
- Axiom 4: Supported / advertised != negotiated
- Axiom 5: Scanner unavailable != clean / unsupported
- Axiom 6: Missing key size -> UNKNOWN, never guess default
- Axiom 7: Missing data sensitivity / retention -> HNDL_UNKNOWN
- Axiom 8: Severity != Confidence
- Axiom 9: Role distinction (SHA-1 HMAC vs Signature)
- Axiom 10: AES Grover halving & quantum impact
- Axiom 11: Multi-hop blast radius traversal
- Fixtures A through E
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from engine.asset_graph import AssetGraphService, CryptoAsset, AssetType, RelationshipType
from engine.evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, ArtifactType, Provenance
from engine.intelligence.models import (
    RiskSeverity, RiskConfidence, CryptoRole, QuantumImpact,
    PQCReadinessState, HNDLState, StrengthCategory, ParameterStatus,
    RiskFactor, RiskAssessment, PQCReadinessAssessment, HNDLAssessment,
    SecurityStrengthAssessment,
)
from engine.intelligence.algorithm_registry import (
    lookup_algorithm, decompose_hybrid, get_quantum_impact, is_hybrid_kem,
    is_pqc_signature, resolve_hybrid,
)
from engine.intelligence.security_strength import assess_security_strength
from engine.intelligence.evidence_context import derive_confidence_from_evidence
from engine.intelligence.risk_engine import evaluate_risk_factors, compute_severity, compute_confidence
from engine.intelligence.pqc_readiness import assess_pqc_readiness
from engine.intelligence.hndl_analyzer import assess_hndl
from engine.intelligence.protocol_risk import evaluate_tls_risk, evaluate_ssh_risk
from engine.intelligence.certificate_risk import evaluate_certificate_risk
from engine.intelligence.intelligence_pipeline import evaluate_asset


# ============================================================
# AXIOM 1: DEPENDENCY DECLARATION != ACTUAL USE
# ============================================================

class TestAxiom1DependencyNotActualUse:
    def test_pqc_library_in_deps_does_not_imply_negotiated(self):
        asset = {"id": "lib-1", "library": "liboqs", "name": "liboqs"}
        ev = [{"observation_type": "DEPENDENCY", "level": "E1", "state": "DECLARED"}]
        pqc = assess_pqc_readiness(asset, ev)
        assert pqc.library == PQCReadinessState.PQC_CAPABLE
        assert pqc.key_establishment != PQCReadinessState.PQC_NEGOTIATED
        assert pqc.overall != "PQC_READY"

    def test_unused_dependency_has_low_confidence(self):
        asset = {"id": "dep-md5", "algorithm": "MD5", "name": "hashlib"}
        ev = [{"level": "E1", "state": "DECLARED", "observation_type": "DEPENDENCY"}]
        assessment = evaluate_asset(asset, ev)
        assert assessment.confidence in (RiskConfidence.INFERRED, RiskConfidence.UNVERIFIED, RiskConfidence.UNKNOWN)
        assert assessment.confidence != RiskConfidence.MEASURED

    def test_pqc_import_without_runtime_remains_inferred(self):
        asset = {"id": "source-kyber", "algorithm": "ML-KEM-768"}
        ev = [{"level": "E2", "state": "SYNTACTIC_REFERENCE", "observation_type": "SOURCE_CODE"}]
        assessment = evaluate_asset(asset, ev)
        assert assessment.confidence == RiskConfidence.INFERRED


# ============================================================
# AXIOM 2: HYBRID KEX != PQC SIGNATURE
# ============================================================

class TestAxiom2HybridKexNotPQCSignature:
    def test_hybrid_kex_resolve_has_is_signature_false(self):
        h = resolve_hybrid("X25519MLKEM768")
        assert h is not None
        assert h.is_signature is False
        assert h.is_kem is True
        assert h.role == CryptoRole.KEY_ESTABLISHMENT

    def test_hybrid_kex_does_not_satisfy_pqc_signature(self):
        asset = {"id": "endpoint-1", "algorithm": "X25519MLKEM768"}
        ev = [{"observation_type": "TLS_KEY_EXCHANGE", "state": "NEGOTIATED"}]
        pqc = assess_pqc_readiness(asset, ev)
        assert pqc.key_establishment == PQCReadinessState.HYBRID_NEGOTIATED
        assert pqc.signature != PQCReadinessState.PQC_NEGOTIATED

    def test_hybrid_kex_with_rsa_cert_flags_quantum_signature(self):
        asset = {
            "id": "tls-srv-1",
            "algorithm": "X25519MLKEM768",
            "roles": ["KEY_ESTABLISHMENT"],
        }
        ev = [
            {"observation_type": "TLS_KEY_EXCHANGE", "state": "NEGOTIATED", "level": "E4"},
            {
                "observation_type": "X509_CERTIFICATE",
                "state": "RESOLVED",
                "level": "E4",
                "raw_details": {"signature_algorithm": "SHA256withRSA", "is_expired": False, "trust_validated": True}
            }
        ]
        assessment = evaluate_asset(asset, ev)
        assert RiskFactor.QUANTUM_VULNERABLE_SIGNATURE in assessment.risk_factors

    def test_is_pqc_signature_returns_false_for_hybrid_kex(self):
        assert is_pqc_signature("X25519MLKEM768") is False
        assert is_pqc_signature("ML-DSA-65") is True


# ============================================================
# AXIOM 3: CERTIFICATE PRESENCE != TRUST VALIDATED
# ============================================================

class TestAxiom3CertificatePresenceNotTrust:
    def test_untrusted_cert_triggers_risk_factor(self):
        cert = {"signature_algorithm": "SHA256withRSA", "is_expired": False, "trust_validated": False}
        factors, sev = evaluate_certificate_risk(cert)
        assert RiskFactor.UNVERIFIED_CERTIFICATE_TRUST in factors

    def test_trusted_cert_does_not_trigger_unverified_trust(self):
        cert = {"signature_algorithm": "SHA256withRSA", "is_expired": False, "trust_validated": True}
        factors, sev = evaluate_certificate_risk(cert)
        assert RiskFactor.UNVERIFIED_CERTIFICATE_TRUST not in factors

    def test_expired_cert_triggers_expired_risk(self):
        cert = {"signature_algorithm": "SHA256withRSA", "is_expired": True, "trust_validated": True}
        factors, sev = evaluate_certificate_risk(cert)
        assert RiskFactor.EXPIRED_CERTIFICATE in factors
        assert sev in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)

    def test_md5_signed_cert_triggers_weak_cert_sig(self):
        cert = {"signature_algorithm": "MD5withRSA", "is_expired": False, "trust_validated": True}
        factors, sev = evaluate_certificate_risk(cert)
        assert RiskFactor.WEAK_CERTIFICATE_SIGNATURE in factors


# ============================================================
# AXIOM 4: SUPPORTED / ADVERTISED != NEGOTIATED
# ============================================================

class TestAxiom4SupportedNotNegotiated:
    def test_ssh_kexinit_advertised_not_negotiated(self):
        asset = {"id": "ssh-1", "algorithm": "sntrup761x25519-sha512@openssh.com"}
        ev = [{"observation_type": "SSH_KEXINIT", "state": "ADVERTISED", "level": "E3"}]
        pqc = assess_pqc_readiness(asset, ev)
        assert pqc.key_establishment == PQCReadinessState.PQC_ADVERTISED
        assert pqc.key_establishment != PQCReadinessState.PQC_NEGOTIATED

    def test_client_hello_offered_not_negotiated(self):
        asset = {"id": "tls-client-1", "algorithm": "X25519MLKEM768"}
        ev = [{"observation_type": "TLS_CLIENT_HELLO", "state": "OFFERED", "level": "E3"}]
        pqc = assess_pqc_readiness(asset, ev)
        assert pqc.key_establishment == PQCReadinessState.PQC_OFFERED
        assert pqc.key_establishment != PQCReadinessState.HYBRID_NEGOTIATED

    def test_pqc_not_negotiated_factor_when_classical_negotiated(self):
        factors, sev = evaluate_tls_risk("TLSv1.3", "TLS_AES_256_GCM_SHA384", negotiated_kex="X25519")
        assert RiskFactor.PQC_NOT_NEGOTIATED in factors

    def test_hybrid_negotiated_does_not_flag_pqc_not_negotiated(self):
        factors, sev = evaluate_tls_risk("TLSv1.3", "TLS_AES_256_GCM_SHA384", negotiated_kex="X25519MLKEM768")
        assert RiskFactor.PQC_NOT_NEGOTIATED not in factors


# ============================================================
# AXIOM 5: SCANNER UNAVAILABLE != CLEAN / UNSUPPORTED
# ============================================================

class TestAxiom5ScannerUnavailable:
    def test_scanner_unavailable_returns_explicit_state(self):
        asset = {"id": "unreach-host", "algorithm": "TLS"}
        pqc = assess_pqc_readiness(asset, [], scanner_unavailable=True)
        assert pqc.key_establishment == PQCReadinessState.SCANNER_UNAVAILABLE
        assert pqc.overall == "SCANNER_UNAVAILABLE"

    def test_scanner_unavailable_does_not_mark_classical_only(self):
        asset = {"id": "unreach-host", "algorithm": "TLS"}
        pqc = assess_pqc_readiness(asset, [], scanner_unavailable=True)
        assert pqc.key_establishment != PQCReadinessState.CLASSICAL_ONLY

    def test_scanner_unavailable_adds_limitation_to_assessment(self):
        asset = {"id": "unreach-host", "algorithm": "TLS"}
        assessment = evaluate_asset(asset, [], context={"scanner_unavailable": True})
        assert any("scanner" in lim.lower() or "unreach" in lim.lower() for lim in assessment.limitations)

    def test_scanner_unavailable_does_not_produce_severity_none(self):
        asset = {"id": "unreach-host", "algorithm": "TLS"}
        assessment = evaluate_asset(asset, [], context={"scanner_unavailable": True})
        assert assessment.severity != RiskSeverity.NONE


# ============================================================
# AXIOM 6: MISSING KEY SIZE -> UNKNOWN, NEVER GUESS DEFAULT
# ============================================================

class TestAxiom6MissingKeySizeUnknown:
    def test_rsa_none_key_size_returns_unknown_status(self):
        strength = assess_security_strength("RSA", parameter=None)
        assert strength.parameter_status == ParameterStatus.UNKNOWN
        assert strength.classical_strength_bits is None
        assert strength.strength_category == StrengthCategory.UNKNOWN

    def test_dh_none_key_size_returns_unknown_status(self):
        strength = assess_security_strength("Diffie-Hellman", parameter=None)
        assert strength.parameter_status == ParameterStatus.UNKNOWN
        assert strength.classical_strength_bits is None

    def test_missing_parameter_flags_unknown_parameters_factor(self):
        asset = {"id": "a-rsa-noparam", "algorithm": "RSA"}
        factors, unknowns = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert RiskFactor.UNKNOWN_PARAMETERS in factor_names
        assert any(u.field == "key_size" for u in unknowns)

    def test_explicit_key_size_does_not_flag_unknown_parameters(self):
        asset = {"id": "a-rsa-2048", "algorithm": "RSA", "key_size": 2048}
        factors, unknowns = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert RiskFactor.UNKNOWN_PARAMETERS not in factor_names


# ============================================================
# AXIOM 7: MISSING RETENTION / SENSITIVITY -> HNDL_UNKNOWN
# ============================================================

class TestAxiom7MissingHNDLContextUnknown:
    def test_classical_kex_without_context_is_hndl_unknown(self):
        asset = {"id": "a-kex", "algorithm": "ECDH", "roles": ["KEY_ESTABLISHMENT"]}
        hndl = assess_hndl(asset, [], context={})
        assert hndl.state == HNDLState.HNDL_UNKNOWN
        assert len(hndl.unknowns) > 0

    def test_missing_sensitivity_only_is_hndl_unknown(self):
        asset = {"id": "a-kex", "algorithm": "ECDH", "roles": ["KEY_ESTABLISHMENT"]}
        hndl = assess_hndl(asset, [], context={"retention_years": 10})
        assert hndl.state == HNDLState.HNDL_UNKNOWN

    def test_missing_retention_only_is_hndl_unknown(self):
        asset = {"id": "a-kex", "algorithm": "ECDH", "roles": ["KEY_ESTABLISHMENT"]}
        hndl = assess_hndl(asset, [], context={"sensitivity": "HIGH"})
        assert hndl.state == HNDLState.HNDL_UNKNOWN

    def test_complete_context_resolves_hndl_definitively(self):
        asset = {"id": "a-kex", "algorithm": "ECDH", "roles": ["KEY_ESTABLISHMENT"]}
        hndl = assess_hndl(asset, [], context={"retention_years": 10, "sensitivity": "HIGH", "exposure": "INTERNET"})
        assert hndl.state == HNDLState.HNDL_RELEVANT


# ============================================================
# AXIOM 8: SEVERITY != CONFIDENCE
# ============================================================

class TestAxiom8SeverityDistinctFromConfidence:
    def test_high_severity_with_unknown_confidence(self):
        asset = {"id": "a-des", "algorithm": "DES", "roles": ["SYMMETRIC_ENCRYPTION"]}
        # No evidence items provided
        assessment = evaluate_asset(asset, evidence_items=[])
        assert assessment.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)
        assert assessment.confidence == RiskConfidence.UNKNOWN

    def test_high_severity_with_corroborated_confidence(self):
        asset = {"id": "a-des", "algorithm": "DES", "roles": ["SYMMETRIC_ENCRYPTION"]}
        ev = [
            {"id": "e1", "level": "E3", "state": "CORROBORATED"},
            {"id": "e2", "level": "E4", "state": "CORROBORATED"}
        ]
        assessment = evaluate_asset(asset, evidence_items=ev)
        assert assessment.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)
        assert assessment.confidence == RiskConfidence.CORROBORATED

    def test_low_severity_with_measured_confidence(self):
        asset = {"id": "a-aes", "algorithm": "AES-256", "roles": ["SYMMETRIC_ENCRYPTION"]}
        ev = [{"id": "e1", "level": "E4", "state": "RESOLVED"}]
        assessment = evaluate_asset(asset, evidence_items=ev)
        assert assessment.severity in (RiskSeverity.NONE, RiskSeverity.LOW, RiskSeverity.INFO)
        assert assessment.confidence == RiskConfidence.MEASURED

    def test_contradicted_evidence_produces_contradicted_confidence(self):
        ev = [{"id": "e1", "level": "E3", "state": "CONTRADICTED"}]
        conf = derive_confidence_from_evidence(ev)
        assert conf == RiskConfidence.CONTRADICTED


# ============================================================
# AXIOM 9: ROLE DISTINCTION
# ============================================================

class TestAxiom9RoleDistinction:
    def test_sha1_for_hmac_is_acceptable_legacy(self):
        asset = {"id": "a-hmac-sha1", "algorithm": "SHA-1", "roles": ["MAC"]}
        factors, sev = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert RiskFactor.WEAK_ALGORITHM not in factor_names

    def test_sha1_for_signatures_is_weak(self):
        asset = {"id": "a-sig-sha1", "algorithm": "SHA-1", "roles": ["SIGNATURE"]}
        factors, sev = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert (RiskFactor.WEAK_ALGORITHM in factor_names or RiskFactor.DEPRECATED_ALGORITHM in factor_names)

    def test_aes_for_encryption_vs_mac(self):
        strength = assess_security_strength("AES-256")
        assert strength.strength_category == StrengthCategory.STRONG
        assert strength.classical_strength_bits == 256

    def test_chacha20_aead_role_recognized(self):
        algo = lookup_algorithm("ChaCha20-Poly1305")
        assert algo is not None
        assert CryptoRole.AEAD in algo.roles


# ============================================================
# AXIOM 10: AES GROVER HALVING & QUANTUM IMPACT
# ============================================================

class TestAxiom10AESGroverHalving:
    def test_aes128_grover_halving(self):
        impact = get_quantum_impact("AES-128")
        assert impact == QuantumImpact.GROVER_HALVING
        strength = assess_security_strength("AES-128")
        assert strength.quantum_strength_bits == 64

    def test_aes256_pqc_safe_symmetric(self):
        algo = lookup_algorithm("AES-256")
        assert algo is not None
        assert algo.pqc_status == "PQC_SAFE_SYMMETRIC"
        strength = assess_security_strength("AES-256")
        assert strength.quantum_strength_bits == 128

    def test_rsa_broken_by_shor(self):
        impact = get_quantum_impact("RSA")
        assert impact == QuantumImpact.SHOR_BREAKS


# ============================================================
# AXIOM 11: MULTI-HOP BLAST RADIUS TRAVERSAL
# ============================================================

class TestAxiom11MultiHopBlastRadius:
    @pytest.fixture
    def populated_graph(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("""CREATE TABLE crypto_assets (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT,
            asset_type TEXT NOT NULL, name TEXT NOT NULL, algorithm TEXT,
            variant TEXT, key_size INTEGER, library TEXT, version TEXT,
            artifact_id TEXT, status TEXT NOT NULL DEFAULT 'ACTIVE',
            fused_status TEXT NOT NULL DEFAULT 'SINGLE_SOURCE',
            highest_evidence_level TEXT NOT NULL DEFAULT 'E0',
            confidence REAL NOT NULL DEFAULT 0.0, explanation TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE graph_edges (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT,
            source_id TEXT NOT NULL, source_type TEXT NOT NULL,
            relationship TEXT NOT NULL, target_id TEXT NOT NULL,
            target_type TEXT NOT NULL, evidence_id TEXT,
            confidence REAL NOT NULL DEFAULT 1.0, created_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE evidence (
            id TEXT PRIMARY KEY, asset_id TEXT, scan_id TEXT NOT NULL,
            project TEXT NOT NULL, state TEXT NOT NULL, level TEXT NOT NULL,
            confidence REAL NOT NULL, source_engine TEXT NOT NULL,
            engine_version TEXT NOT NULL, rule_id TEXT, rule_version TEXT,
            observation_type TEXT NOT NULL, artifact_type TEXT NOT NULL,
            file_path TEXT, line_start INTEGER, line_end INTEGER,
            byte_offset TEXT, symbol TEXT, description TEXT NOT NULL,
            data TEXT NOT NULL, created_at TEXT NOT NULL
        )""")
        svc = AssetGraphService(lambda: conn)
        # Setup: App -> Service -> Library -> Weak Primitive (DES)
        svc.create_asset("p1", AssetType.APPLICATION, "PaymentGateway", asset_id="app-1")
        svc.create_asset("p1", AssetType.SERVICE, "AuthService", asset_id="svc-1")
        svc.create_asset("p1", AssetType.CRYPTO_LIBRARY, "pycryptodome", asset_id="lib-1")
        svc.create_asset("p1", AssetType.ALGORITHM, "DES", algorithm="DES", asset_id="algo-des")

        svc.add_relationship("p1", "app-1", "APPLICATION", RelationshipType.DEPENDS_ON, "svc-1", "SERVICE")
        svc.add_relationship("p1", "svc-1", "SERVICE", RelationshipType.USES, "lib-1", "CRYPTO_LIBRARY")
        svc.add_relationship("p1", "lib-1", "CRYPTO_LIBRARY", RelationshipType.PROVIDES, "algo-des", "ALGORITHM")
        return svc

    def test_blast_radius_reaches_upstream_callers(self, populated_graph):
        blast = populated_graph.get_blast_radius("algo-des")
        impacted_ids = [a["id"] for a in blast["impacted_assets"]]
        assert "lib-1" in impacted_ids
        assert "svc-1" in impacted_ids
        assert "app-1" in impacted_ids
        assert blast["total_impacted_count"] == 3

    def test_blast_radius_isolated_node_has_zero_impact(self, populated_graph):
        populated_graph.create_asset("p1", AssetType.ALGORITHM, "IsolatedAlgo", asset_id="algo-iso")
        blast = populated_graph.get_blast_radius("algo-iso")
        assert blast["total_impacted_count"] == 0

    def test_why_risk_includes_reason_chain(self, populated_graph):
        why = populated_graph.get_why_risk("algo-des")
        assert why is not None
        assert "severity" in why
        assert "reason_chain" in why
        assert why["asset_id"] == "algo-des"


# ============================================================
# INTEGRATION FIXTURES A THROUGH E
# ============================================================

class TestIntegrationFixtures:
    def test_fixture_a_legacy_banking_app(self):
        """Fixture A: 3DES, MD5, TLS 1.0, RSA-1024 -> CRITICAL risk across all axes."""
        asset = {"id": "bank-core", "algorithm": "3DES", "key_size": 112, "roles": ["SYMMETRIC_ENCRYPTION"]}
        ev = [
            {"id": "ev-tls-10", "observation_type": "TLS_PROTOCOL", "level": "E4", "state": "NEGOTIATED", "raw_details": {"version": "TLSv1.0"}},
            {"id": "ev-3des", "observation_type": "STATIC_ANALYSIS", "level": "E3", "state": "RESOLVED"}
        ]
        context = {"retention_years": 20, "sensitivity": "CRITICAL", "exposure": "INTERNET"}
        assessment = evaluate_asset(asset, ev, context)

        assert assessment.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)
        assert RiskFactor.WEAK_ALGORITHM in assessment.risk_factors or RiskFactor.LEGACY_PROTOCOL in assessment.risk_factors

    def test_fixture_b_modern_cloud_app(self):
        """Fixture B: TLS 1.3, AES-256-GCM, X25519 KEX, P-256 cert, 15-year retention -> HNDL Relevant."""
        asset = {"id": "cloud-api", "algorithm": "X25519", "roles": ["KEY_ESTABLISHMENT"]}
        ev = [
            {"id": "ev-tls-13", "observation_type": "TLS_KEY_EXCHANGE", "level": "E4", "state": "NEGOTIATED", "raw_details": {"named_group": "X25519"}},
        ]
        context = {"retention_years": 15, "sensitivity": "HIGH", "exposure": "INTERNET"}
        assessment = evaluate_asset(asset, ev, context)

        assert assessment.hndl is not None
        assert assessment.hndl.state == HNDLState.HNDL_RELEVANT
        assert RiskFactor.QUANTUM_VULNERABLE_KEX in assessment.risk_factors

    def test_fixture_c_pqc_early_adopter(self):
        """Fixture C: OQS-OpenSSL library in deps, but runtime negotiated classical X25519 -> partial readiness."""
        asset = {"id": "early-adopt", "algorithm": "X25519", "library": "liboqs"}
        ev = [
            {"observation_type": "DEPENDENCY", "level": "E1", "state": "DECLARED", "raw_details": {"name": "liboqs"}},
            {"observation_type": "TLS_KEY_EXCHANGE", "level": "E4", "state": "NEGOTIATED", "raw_details": {"named_group": "X25519"}}
        ]
        pqc = assess_pqc_readiness(asset, ev)
        assert pqc.library == PQCReadinessState.PQC_CAPABLE
        assert pqc.key_establishment == PQCReadinessState.CLASSICAL_ONLY

    def test_fixture_d_network_scanner_failure(self):
        """Fixture D: Network scan failed/unreachable -> explicit SCANNER_UNAVAILABLE."""
        asset = {"id": "failed-target", "algorithm": "TLS"}
        assessment = evaluate_asset(asset, [], context={"scanner_unavailable": True})
        assert assessment.pqc_readiness is not None
        assert assessment.pqc_readiness.overall == "SCANNER_UNAVAILABLE"
        assert assessment.severity != RiskSeverity.NONE

    def test_fixture_e_classical_rsa_cert_with_hybrid_kex(self):
        """
        Fixture E:
        Verifies the core architectural axiom:
        A hybrid KEX handshake (X25519MLKEM768) presenting an RSA certificate
        must report:
        - Key establishment: HYBRID_NEGOTIATED
        - Signature / Certificate: CLASSICAL_ONLY & QUANTUM_VULNERABLE_SIGNATURE
        - It must NEVER mark certificate or signature as PQC!
        """
        asset = {
            "id": "fixture-e-hybrid-tls",
            "name": "Hybrid TLS Server",
            "algorithm": "X25519MLKEM768",
            "roles": ["KEY_ESTABLISHMENT"],
        }
        ev = [
            {
                "id": "ev-hybrid-kex",
                "observation_type": "TLS_KEY_EXCHANGE",
                "level": "E4",
                "state": "NEGOTIATED",
                "raw_details": {"named_group": "X25519MLKEM768"}
            },
            {
                "id": "ev-rsa-cert",
                "observation_type": "X509_CERTIFICATE",
                "level": "E4",
                "state": "RESOLVED",
                "raw_details": {
                    "signature_algorithm": "SHA256withRSA",
                    "subject": "CN=hybrid-server.example.com",
                    "is_expired": False,
                    "trust_validated": True,
                }
            }
        ]
        context = {
            "exposure": "INTERNET",
            "retention_years": 5,
            "sensitivity": "MEDIUM",
        }
        assessment = evaluate_asset(asset, ev, context)

        # 1. KEX is HYBRID_NEGOTIATED
        assert assessment.pqc_readiness is not None
        assert assessment.pqc_readiness.key_establishment == PQCReadinessState.HYBRID_NEGOTIATED

        # 2. Signature & Certificate are CLASSICAL_ONLY (NOT PQC!)
        assert assessment.pqc_readiness.signature != PQCReadinessState.PQC_NEGOTIATED
        assert assessment.pqc_readiness.certificate != PQCReadinessState.PQC_NEGOTIATED

        # 3. QUANTUM_VULNERABLE_SIGNATURE is triggered
        assert RiskFactor.QUANTUM_VULNERABLE_SIGNATURE in assessment.risk_factors

        # 4. QUANTUM_VULNERABLE_KEX is NOT triggered (hybrid protected)
        assert RiskFactor.QUANTUM_VULNERABLE_KEX not in assessment.risk_factors


# ============================================================
# EXPLICIT AUDIT AXIOMS: STRING, SYMBOL, OCSP, HISTORICAL KB
# ============================================================

class TestAxiomExplicitVerifications:
    def test_string_reference_remains_inferred(self):
        """Axiom 3: String literal in binary/source is E2 (INFERRED), not actual use (MEASURED)."""
        asset = {"id": "bin-str", "algorithm": "AES-256"}
        ev = [{"id": "ev-str", "level": "E2", "state": "STRING_MATCH", "observation_type": "BINARY_STRING"}]
        assessment = evaluate_asset(asset, ev)
        assert assessment.confidence == RiskConfidence.INFERRED
        assert assessment.confidence != RiskConfidence.MEASURED

    def test_symbol_reference_remains_inferred(self):
        """Axiom 4: Imported ELF/PE symbol is E2 (INFERRED), not active execution (MEASURED)."""
        asset = {"id": "bin-sym", "algorithm": "RSA"}
        ev = [{"id": "ev-sym", "level": "E2", "state": "RESOLVED", "observation_type": "SYMBOL_IMPORT"}]
        assessment = evaluate_asset(asset, ev)
        assert assessment.confidence == RiskConfidence.INFERRED
        assert assessment.confidence != RiskConfidence.MEASURED

    def test_ocsp_extension_present_does_not_imply_revocation_checked(self):
        """Axiom 10: OCSP extension in X.509 cert does NOT imply revocation check was executed."""
        from engine.intelligence.certificate_risk import extract_cert_risk_context
        cert_data = {"extensions": {"ocsp": "http://ocsp.example.com"}, "ocsp_url": "http://ocsp.example.com"}
        ctx = extract_cert_risk_context(cert_data)
        assert ctx["ocsp_present"] is True
        assert ctx["revocation_checked"] is False

    def test_historical_assessments_not_overwritten(self):
        """Axiom 18 & 19: Multiple scans on the same asset preserve historical assessments with KB versions."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        svc = AssetGraphService(lambda: conn)

        a1 = {"assessment_id": "aid-1", "asset_id": "srv-prod", "scan_id": "scan-2024", "knowledge_base_version": "2024.1", "risk": {"severity": "HIGH", "confidence": "MEASURED"}}
        a2 = {"assessment_id": "aid-2", "asset_id": "srv-prod", "scan_id": "scan-2025", "knowledge_base_version": "2025.1", "risk": {"severity": "CRITICAL", "confidence": "CORROBORATED"}}
        svc.save_risk_assessment(a1)
        svc.save_risk_assessment(a2)

        res_2024 = svc.get_risk_assessment("srv-prod", scan_id="scan-2024")
        res_2025 = svc.get_risk_assessment("srv-prod", scan_id="scan-2025")
        all_hist = svc.get_all_risk_assessments("srv-prod")

        assert res_2024 is not None and res_2024["knowledge_base_version"] == "2024.1"
        assert res_2025 is not None and res_2025["knowledge_base_version"] == "2025.1"
        assert len(all_hist) == 2

