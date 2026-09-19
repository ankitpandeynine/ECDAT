"""
ECDAT V4 P2.1 Crypto Risk Intelligence & PQC Readiness Engine Test Suite.

Validates:
- Intelligence models, severities, confidences, enums
- Algorithm registry, aliases, hybrid decomposition
- Parameter-aware security strength (never guessing defaults)
- Evidence context & confidence derivation
- Deterministic risk engine & YAML rule evaluation
- Role-aware PQC readiness
- Harvest-Now-Decrypt-Later (HNDL) analyzer
- Protocol & certificate risk evaluators
- Machine-readable explainability reason chains
- Asset graph & scan store persistence
- FastAPI REST endpoints
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from main import app
from engine.asset_graph import AssetGraphService, CryptoAsset, AssetType
from engine.evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, ArtifactType, Provenance
from engine.intelligence.models import (
    RiskSeverity, RiskConfidence, CryptoRole, QuantumImpact,
    PQCReadinessState, HNDLState, StrengthCategory, ParameterStatus,
    RiskFactor, RiskAssessment, PQCReadinessAssessment, HNDLAssessment,
    SecurityStrengthAssessment, EvidenceReference, RuleReference, AssessmentReason,
)
from engine.intelligence.algorithm_registry import (
    lookup_algorithm, decompose_hybrid, get_quantum_impact, knowledge_base_version,
)
from engine.intelligence.security_strength import assess_security_strength
from engine.intelligence.evidence_context import derive_confidence_from_evidence, evidence_to_ref
from engine.intelligence.risk_engine import evaluate_risk_factors, compute_severity, compute_confidence
from engine.intelligence.pqc_readiness import assess_pqc_readiness
from engine.intelligence.hndl_analyzer import assess_hndl
from engine.intelligence.protocol_risk import evaluate_tls_risk, evaluate_ssh_risk
from engine.intelligence.certificate_risk import evaluate_certificate_risk, extract_cert_risk_context
from engine.intelligence.explainability import build_reason_chain, format_risk_explanation
from engine.intelligence.intelligence_pipeline import evaluate_asset, IntelligencePipeline


# ============================================================
# 1. MODELS & ENUMS
# ============================================================

class TestP2Models:
    def test_risk_severity_ranks_and_ordering(self):
        assert RiskSeverity.NONE.rank == 0
        assert RiskSeverity.INFO.rank == 1
        assert RiskSeverity.LOW.rank == 2
        assert RiskSeverity.MEDIUM.rank == 3
        assert RiskSeverity.HIGH.rank == 4
        assert RiskSeverity.CRITICAL.rank == 5
        assert RiskSeverity.UNKNOWN.rank == -1

    def test_risk_severity_worst(self):
        assert RiskSeverity.worst([]) == RiskSeverity.NONE
        assert RiskSeverity.worst([RiskSeverity.UNKNOWN]) == RiskSeverity.UNKNOWN
        assert RiskSeverity.worst([RiskSeverity.LOW, RiskSeverity.HIGH, RiskSeverity.UNKNOWN]) == RiskSeverity.HIGH
        assert RiskSeverity.worst([RiskSeverity.MEDIUM, RiskSeverity.CRITICAL]) == RiskSeverity.CRITICAL

    def test_risk_confidence_values(self):
        values = {c.value for c in RiskConfidence}
        assert "CORROBORATED" in values
        assert "MEASURED" in values
        assert "INFERRED" in values
        assert "UNVERIFIED" in values
        assert "CONTRADICTED" in values
        assert "UNKNOWN" in values

    def test_pqc_readiness_state_values(self):
        states = {s.value for s in PQCReadinessState}
        assert "UNKNOWN" in states
        assert "CLASSICAL_ONLY" in states
        assert "PQC_CAPABLE" in states
        assert "HYBRID_NEGOTIATED" in states
        assert "PQC_NEGOTIATED" in states
        assert "SCANNER_UNAVAILABLE" in states

    def test_hndl_states(self):
        states = {h.value for h in HNDLState}
        assert "HNDL_RELEVANT" in states
        assert "HNDL_POSSIBLE" in states
        assert "HNDL_NOT_APPLICABLE" in states
        assert "HNDL_UNKNOWN" in states

    def test_risk_assessment_serialization(self):
        assessment = RiskAssessment(
            asset_id="asset-test-1",
            scan_id="scan-123",
            severity=RiskSeverity.HIGH,
            confidence=RiskConfidence.MEASURED,
            risk_factors=[RiskFactor.WEAK_ALGORITHM],
        )
        d = assessment.to_dict()
        assert d["asset_id"] == "asset-test-1"
        assert d["risk"]["severity"] == "HIGH"
        assert d["risk"]["confidence"] == "MEASURED"
        assert d["risk"]["factors"] == ["WEAK_ALGORITHM"]
        assert "reason_chain" in d
        assert "knowledge_base_version" in d


# ============================================================
# 2. ALGORITHM REGISTRY & KNOWLEDGE BASE
# ============================================================

class TestP2AlgorithmRegistry:
    def test_lookup_canonical_algorithms(self):
        algo = lookup_algorithm("AES-256")
        assert algo is not None
        assert algo.canonical_name == "AES-256"
        assert algo.classical_security_bits == 256
        assert algo.quantum_security_bits == 128

    def test_lookup_by_aliases(self):
        algo_aes = lookup_algorithm("aes256")
        assert algo_aes is not None
        assert algo_aes.canonical_name == "AES-256"

        algo_3des = lookup_algorithm("3des")
        assert algo_3des is not None
        assert algo_3des.canonical_name == "3DES"

        algo_des_cbc3 = lookup_algorithm("DES-CBC3-SHA")
        assert algo_des_cbc3 is not None
        assert algo_des_cbc3.canonical_name == "3DES"

    def test_hybrid_decomposition(self):
        parts = decompose_hybrid("X25519MLKEM768")
        assert parts is not None
        assert len(parts) == 2
        names = [p.canonical_name for p in parts]
        assert "X25519" in names
        assert "ML-KEM-768" in names

    def test_unknown_algorithm(self):
        algo = lookup_algorithm("SUPER_SECRET_CIPHER_9000")
        assert algo is None

    def test_quantum_impact_lookup(self):
        assert get_quantum_impact("RSA") == QuantumImpact.SHOR_BREAKS
        assert get_quantum_impact("AES-128") == QuantumImpact.GROVER_HALVING
        assert get_quantum_impact("ML-KEM-768") == QuantumImpact.NONE_PQC_SECURE


# ============================================================
# 3. PARAMETER-AWARE SECURITY STRENGTH
# ============================================================

class TestP2SecurityStrength:
    def test_rsa_strength_known_parameters(self):
        # RSA-1024 -> INSUFFICIENT (80-bit)
        s1024 = assess_security_strength("RSA", parameter=1024)
        assert s1024.strength_category == StrengthCategory.INSUFFICIENT
        assert s1024.classical_strength_bits == 80
        assert s1024.parameter_status == ParameterStatus.KNOWN

        # RSA-2048 -> ACCEPTABLE (112-bit)
        s2048 = assess_security_strength("RSA", parameter=2048)
        assert s2048.strength_category == StrengthCategory.ACCEPTABLE
        assert s2048.classical_strength_bits == 112

        # RSA-3072 -> STRONG (128-bit)
        s3072 = assess_security_strength("RSA", parameter=3072)
        assert s3072.strength_category == StrengthCategory.STRONG
        assert s3072.classical_strength_bits == 128

    def test_rsa_missing_parameter_never_guesses_default(self):
        s_unknown = assess_security_strength("RSA", parameter=None)
        assert s_unknown.parameter_status == ParameterStatus.UNKNOWN
        assert s_unknown.strength_category == StrengthCategory.UNKNOWN
        assert s_unknown.classical_strength_bits is None
        assert any("key size is unknown" in lim.lower() for lim in s_unknown.limitations)

    def test_symmetric_grover_halving(self):
        s_aes128 = assess_security_strength("AES-128")
        assert s_aes128.classical_strength_bits == 128
        assert s_aes128.quantum_strength_bits == 64
        assert s_aes128.quantum_impact == QuantumImpact.GROVER_HALVING

        s_aes256 = assess_security_strength("AES-256")
        assert s_aes256.classical_strength_bits == 256
        assert s_aes256.quantum_strength_bits == 128

    def test_broken_hash_strength(self):
        s_md5 = assess_security_strength("MD5")
        assert s_md5.strength_category == StrengthCategory.INSUFFICIENT
        assert s_md5.quantum_impact == QuantumImpact.GROVER_HALVING_COLLISION


# ============================================================
# 4. EVIDENCE CONTEXT & CONFIDENCE
# ============================================================

class TestP2EvidenceContext:
    def test_confidence_from_evidence_levels(self):
        # Empty evidence -> UNKNOWN
        assert derive_confidence_from_evidence([]) == RiskConfidence.UNKNOWN

        # E0 -> UNKNOWN
        e0 = [{"level": "E0", "state": "DECLARED"}]
        assert derive_confidence_from_evidence(e0) == RiskConfidence.UNKNOWN

        # E1 / E2 -> INFERRED
        e1 = [{"level": "E1", "state": "STATIC_MATCH"}]
        assert derive_confidence_from_evidence(e1) == RiskConfidence.INFERRED

        # E3 / E4 / E5 -> MEASURED
        e3 = [{"level": "E3", "state": "RESOLVED"}]
        assert derive_confidence_from_evidence(e3) == RiskConfidence.MEASURED

    def test_confidence_from_fusion_states(self):
        e_corr = [{"level": "E3", "state": "CORROBORATED"}]
        assert derive_confidence_from_evidence(e_corr) == RiskConfidence.CORROBORATED

        e_contra = [{"level": "E3", "state": "CONTRADICTED"}]
        assert derive_confidence_from_evidence(e_contra) == RiskConfidence.CONTRADICTED


# ============================================================
# 5. RISK ENGINE & RULE EVALUATION
# ============================================================

class TestP2RiskEngine:
    def test_legacy_algorithm_rule_evaluation(self):
        asset = {"id": "a1", "algorithm": "MD5", "roles": ["HASH"]}
        factors, unknowns = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert RiskFactor.WEAK_ALGORITHM in factor_names
        sev = compute_severity(factors)
        assert sev in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)

    def test_quantum_kex_rule_evaluation(self):
        asset = {"id": "a2", "algorithm": "RSA", "roles": ["KEY_ESTABLISHMENT"], "key_size": 2048}
        factors, _ = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert RiskFactor.QUANTUM_VULNERABLE_KEX in factor_names

    def test_unknown_parameters_trigger(self):
        asset = {"id": "a3", "algorithm": "RSA"}  # Missing key_size
        factors, unknowns = evaluate_risk_factors(asset, [], {})
        factor_names = [f for f, _ in factors]
        assert RiskFactor.UNKNOWN_PARAMETERS in factor_names
        assert any(u.field == "key_size" for u in unknowns)


# ============================================================
# 6. PQC READINESS ENGINE
# ============================================================

class TestP2PQCReadiness:
    def test_hybrid_kex_does_not_imply_pqc_signature(self):
        asset = {"id": "a4", "algorithm": "X25519MLKEM768"}
        ev = [{
            "observation_type": "TLS_KEY_EXCHANGE",
            "state": "NEGOTIATED",
            "raw_details": {"named_group": "X25519MLKEM768"}
        }]
        pqc = assess_pqc_readiness(asset, ev)
        # KEX is hybrid negotiated
        assert pqc.key_establishment == PQCReadinessState.HYBRID_NEGOTIATED
        # Signature is NOT negotiated as PQC
        assert pqc.signature != PQCReadinessState.PQC_NEGOTIATED

    def test_pqc_capable_does_not_equal_negotiated(self):
        asset = {"id": "a5", "library": "liboqs", "version": "0.10.0"}
        ev = [{
            "observation_type": "DEPENDENCY",
            "level": "E1",
            "state": "DECLARED",
        }]
        pqc = assess_pqc_readiness(asset, ev)
        assert pqc.library == PQCReadinessState.PQC_CAPABLE
        assert pqc.key_establishment != PQCReadinessState.PQC_NEGOTIATED

    def test_scanner_unavailable(self):
        asset = {"id": "a6", "algorithm": "TLS_AES_256_GCM_SHA384"}
        pqc = assess_pqc_readiness(asset, [], scanner_unavailable=True)
        assert pqc.overall == "SCANNER_UNAVAILABLE"


# ============================================================
# 7. HARVEST-NOW-DECRYPT-LATER (HNDL) ANALYZER
# ============================================================

class TestP2HNDL:
    def test_hndl_relevant_for_vulnerable_kex_and_long_retention(self):
        asset = {"id": "a7", "algorithm": "RSA", "roles": ["KEY_ESTABLISHMENT"], "key_size": 2048}
        context = {
            "retention_years": 10,
            "sensitivity": "HIGH",
            "exposure": "INTERNET",
        }
        hndl = assess_hndl(asset, [], context)
        assert hndl.state == HNDLState.HNDL_RELEVANT

    def test_hndl_not_applicable_for_signatures(self):
        asset = {"id": "a8", "algorithm": "RSA", "roles": ["SIGNATURE"], "key_size": 2048}
        context = {"retention_years": 10, "sensitivity": "HIGH"}
        hndl = assess_hndl(asset, [], context)
        assert hndl.state == HNDLState.HNDL_NOT_APPLICABLE

    def test_hndl_unknown_when_retention_missing(self):
        asset = {"id": "a9", "algorithm": "RSA", "roles": ["KEY_ESTABLISHMENT"]}
        # No retention_years or sensitivity provided
        hndl = assess_hndl(asset, [], {})
        assert hndl.state == HNDLState.HNDL_UNKNOWN
        assert len(hndl.unknowns) > 0


# ============================================================
# 8. PROTOCOL & CERTIFICATE RISK
# ============================================================

class TestP2ProtocolAndCertRisk:
    def test_tls_legacy_protocol_detection(self):
        factors, sev = evaluate_tls_risk("TLSv1.0", "TLS_RSA_WITH_AES_128_CBC_SHA")
        assert RiskFactor.LEGACY_PROTOCOL in factors
        assert sev in (RiskSeverity.HIGH, RiskSeverity.CRITICAL)

    def test_cert_presence_distinct_from_trust(self):
        cert_info = {
            "signature_algorithm": "SHA256withRSA",
            "is_expired": False,
            "trust_validated": False,  # Untrusted or self-signed
        }
        factors, sev = evaluate_certificate_risk(cert_info)
        assert RiskFactor.UNVERIFIED_CERTIFICATE_TRUST in factors


# ============================================================
# 9. EXPLAINABILITY REASON CHAINS
# ============================================================

class TestP2Explainability:
    def test_reason_chain_linking_evidence_and_rules(self):
        asset = {"id": "a10", "algorithm": "DES", "roles": ["SYMMETRIC_ENCRYPTION"]}
        ev = [{
            "id": "ev-des-1",
            "level": "E3",
            "state": "RESOLVED",
            "observation_type": "STATIC_ANALYSIS",
            "source_engine": "ast_scanner",
        }]
        assessment = evaluate_asset(asset, ev)
        assert len(assessment.reason_chain) > 0
        step = assessment.reason_chain[0]
        assert isinstance(step, AssessmentReason)
        assert step.observation != ""
        assert step.interpretation != ""


# ============================================================
# 10. ASSET GRAPH PERSISTENCE
# ============================================================

class TestP2AssetGraphPersistence:
    @pytest.fixture
    def test_graph(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        # Create base tables
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
        return svc

    def test_save_and_retrieve_risk_assessment(self, test_graph):
        assessment = RiskAssessment(
            asset_id="asset-persisted-1",
            scan_id="scan-p1",
            severity=RiskSeverity.HIGH,
            confidence=RiskConfidence.MEASURED,
            risk_factors=[RiskFactor.WEAK_ALGORITHM],
        )
        aid = test_graph.save_risk_assessment(assessment)
        assert aid is not None

        retrieved = test_graph.get_risk_assessment("asset-persisted-1")
        assert retrieved is not None
        assert retrieved["asset_id"] == "asset-persisted-1"
        assert retrieved["risk"]["severity"] == "HIGH"
        assert retrieved["risk"]["confidence"] == "MEASURED"

    def test_save_and_retrieve_pqc_readiness(self, test_graph):
        pqc = PQCReadinessAssessment(
            asset_id="asset-persisted-2",
            key_establishment=PQCReadinessState.HYBRID_NEGOTIATED,
            overall="HYBRID",
        )
        aid = test_graph.save_pqc_readiness(pqc)
        assert aid is not None

        retrieved = test_graph.get_pqc_readiness("asset-persisted-2")
        assert retrieved is not None
        assert retrieved["key_establishment"] == "HYBRID_NEGOTIATED"
        assert retrieved["overall"] == "HYBRID"

    def test_save_and_retrieve_hndl(self, test_graph):
        hndl = HNDLAssessment(
            asset_id="asset-persisted-3",
            state=HNDLState.HNDL_RELEVANT,
            reason="Vulnerable KEX with 10 year retention",
        )
        test_graph.save_hndl_assessment(hndl)

        retrieved = test_graph.get_hndl_assessment("asset-persisted-3")
        assert retrieved is not None
        assert retrieved["state"] == "HNDL_RELEVANT"


# ============================================================
# 11. REST API ENDPOINTS
# ============================================================

class TestP2APIEndpoints:
    @pytest.fixture
    def client(self):
        with TestClient(app) as c:
            yield c

    def test_evaluate_endpoint(self, client):
        payload = {
            "asset": {
                "id": "asset-api-test",
                "name": "RSA-2048",
                "algorithm": "RSA",
                "key_size": 2048,
                "roles": ["KEY_ESTABLISHMENT"]
            },
            "evidence": [
                {
                    "id": "ev-api-1",
                    "level": "E3",
                    "state": "RESOLVED",
                    "observation_type": "TLS_CIPHER_SUITE",
                    "source_engine": "network_prober"
                }
            ],
            "context": {
                "retention_years": 10,
                "sensitivity": "HIGH"
            }
        }
        res = client.post("/api/intelligence/evaluate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["asset_id"] == "asset-api-test"
        assert "risk" in data
        assert "pqc_readiness" in data
        assert "hndl" in data
        assert "reason_chain" in data

    def test_asset_intelligence_not_found(self, client):
        res = client.get("/api/assets/non-existent-asset-9999/intelligence")
        assert res.status_code == 404
