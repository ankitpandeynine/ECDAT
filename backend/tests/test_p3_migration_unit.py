"""
ECDAT V4 P3 Unit Test Suite.

Tests MigrationContext normalization, Target Selection, Topological Sequencing,
Priority Derivation, Step Generation, Verification Engine, Explainability,
AssetGraph persistence, and REST API endpoints.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


from engine.migration.models import (
    MigrationContext,
    MigrationPlan,
    MigrationPriority,
    MigrationStep,
    MigrationStepAction,
    MigrationTarget,
    MigrationVerification,
    TransitionMode,
    VerificationState,
)
from engine.migration.normalizer import (
    build_migration_context,
    compute_migration_config_hash,
    compute_migration_evidence_hash,
    normalize_cryptographic_role,
)
from engine.migration.target_selector import select_migration_target
from engine.migration.dependency_planner import plan_migration_dependency_order
from engine.migration.planner import derive_migration_priority, generate_migration_steps
from engine.migration.verification import verify_migration
from engine.migration.evidence import correlate_migration_evidence, detect_evidence_discrepancies
from engine.migration.explainability import (
    build_migration_explainability_report,
    generate_migration_reason_chain,
)
from engine.migration.migration_pipeline import (
    execute_migration_verification,
    generate_migration_plan,
)
from engine.asset_graph import AssetGraphService


class TestP3Models:
    def test_enums_and_values(self):
        assert TransitionMode.DIRECT_REPLACEMENT.value == "DIRECT_REPLACEMENT"
        assert TransitionMode.HYBRID_TRANSITION.value == "HYBRID_TRANSITION"
        assert MigrationPriority.CRITICAL.value == "CRITICAL"
        assert VerificationState.VERIFIED.value == "VERIFIED"
        assert VerificationState.PARTIALLY_VERIFIED.value == "PARTIALLY_VERIFIED"
        assert VerificationState.SCANNER_UNAVAILABLE.value == "SCANNER_UNAVAILABLE"
        assert MigrationStepAction.REPLACE_PRIMITIVE.value == "REPLACE_PRIMITIVE"

    def test_serialization_round_trip(self):
        target = MigrationTarget(
            current_algorithm="RSA-2048",
            current_role="KEY_ESTABLISHMENT",
            target_algorithm="ML-KEM-768",
            target_role="KEY_ESTABLISHMENT",
            transition_mode=TransitionMode.DIRECT_REPLACEMENT,
            rationale="Test rationale",
        )
        d = target.to_dict()
        assert d["current_algorithm"] == "RSA-2048"
        assert d["transition_mode"] == "DIRECT_REPLACEMENT"
        obj = MigrationTarget.from_dict(d)
        assert obj.target_algorithm == "ML-KEM-768"
        assert obj.transition_mode == TransitionMode.DIRECT_REPLACEMENT


class TestP3NormalizerAndContext:
    def test_normalize_cryptographic_role(self):
        assert normalize_cryptographic_role("RSA", "kex") == "KEY_ESTABLISHMENT"
        assert normalize_cryptographic_role("ECDSA", "signature") == "SIGNATURE"
        assert normalize_cryptographic_role("AES-256-GCM") == "SYMMETRIC_ENCRYPTION"
        assert normalize_cryptographic_role("SHA-256") == "HASHING"
        assert normalize_cryptographic_role("X509_CERT") == "CERTIFICATE_SIGNATURE"
        assert normalize_cryptographic_role("UNKNOWN_CIPHER") == "UNKNOWN"

    def test_build_migration_context(self):
        asset = {
            "id": "ast-001",
            "name": "tls_server",
            "algorithm": "ECDH-P256",
            "role": "KEY_ESTABLISHMENT",
            "parameters": {"curve": "prime256v1"},
        }
        risk = {"severity": "HIGH", "confidence": "HIGH"}
        pqc = {"state": "CLASSICAL_ONLY"}
        agility = {"overall_state": "CONSTRAINED"}
        blast = {"state": "TRANSITIVE_CALLERS", "affected_assets": [{"id": "svc-001"}]}
        evidence = [{"id": "ev-01", "level": "E2", "file_path": "server.py"}]

        ctx = build_migration_context(asset, risk, agility, pqc, blast, evidence)
        assert ctx.asset_id == "ast-001"
        assert ctx.algorithm == "ECDH-P256"
        assert ctx.cryptographic_role == "KEY_ESTABLISHMENT"
        assert ctx.risk_assessment["severity"] == "HIGH"
        assert len(ctx.evidence_refs) == 1

    def test_deterministic_hashes(self):
        items = [{"id": "ev-1", "algo": "RSA"}, {"id": "ev-2", "algo": "AES"}]
        h1 = compute_migration_evidence_hash(items)
        h2 = compute_migration_evidence_hash(items)
        assert h1 == h2
        assert len(h1) == 64
        # Empty inputs
        h_empty = compute_migration_evidence_hash([])
        assert len(h_empty) == 64
        assert h_empty != h1


class TestP3TargetSelector:
    def test_kem_target_selection(self):
        ctx = MigrationContext(
            asset_id="a1",
            algorithm="RSA-2048",
            cryptographic_role="KEY_ESTABLISHMENT",
            pqc_readiness={"state": "CLASSICAL_ONLY"},
            parameters={"prefer_hybrid": True},
        )
        target, limitations = select_migration_target(ctx)
        assert target.current_algorithm == "RSA-2048"
        assert target.target_algorithm == "X25519MLKEM768"
        assert target.transition_mode == TransitionMode.HYBRID_TRANSITION

    def test_signature_target_selection(self):
        ctx = MigrationContext(
            asset_id="a2",
            algorithm="ECDSA-P256",
            cryptographic_role="SIGNATURE",
            pqc_readiness={"state": "CLASSICAL_ONLY"},
        )
        target, limitations = select_migration_target(ctx)
        assert "ML-DSA" in target.target_algorithm
        assert target.target_role == "SIGNATURE"

    def test_certificate_signature_target_selection(self):
        ctx = MigrationContext(
            asset_id="a3",
            algorithm="RSA-4096",
            cryptographic_role="CERTIFICATE_SIGNATURE",
            pqc_readiness={"state": "CLASSICAL_ONLY"},
        )
        target, limitations = select_migration_target(ctx)
        assert target.transition_mode == TransitionMode.CERTIFICATE_MIGRATION
        assert "ML-DSA" in target.target_algorithm

    def test_symmetric_grover_halving(self):
        # AES-128 needs upgrade to AES-256
        ctx128 = MigrationContext(asset_id="a4", algorithm="AES-128-CBC", cryptographic_role="SYMMETRIC_ENCRYPTION")
        t128, _ = select_migration_target(ctx128)
        assert "AES-256" in t128.target_algorithm
        assert t128.transition_mode == TransitionMode.DIRECT_REPLACEMENT

        # AES-256 needs no change
        ctx256 = MigrationContext(asset_id="a5", algorithm="AES-256-GCM", cryptographic_role="SYMMETRIC_ENCRYPTION")
        t256, lim256 = select_migration_target(ctx256)
        assert t256.target_algorithm == "AES-256-GCM"
        assert any("Grover" in t256.rationale for t256 in [t256])


    def test_unknown_role(self):
        ctx_unk = MigrationContext(asset_id="a6", algorithm="UNKNOWN_ALGO", cryptographic_role="UNKNOWN")
        t_unk, lim_unk = select_migration_target(ctx_unk)
        assert t_unk.target_algorithm == "UNKNOWN"
        assert len(lim_unk) > 0


class TestP3DependencyPlanner:
    def test_leaf_to_root_ordering(self):
        ctx = MigrationContext(
            asset_id="crypto_primitive_rsa",
            blast_radius={
                "affected_assets": [
                    {"id": "lib_crypto", "depth": 1, "type": "LIBRARY"},
                    {"id": "app_auth", "depth": 2, "type": "APPLICATION"},
                    {"id": "svc_gateway", "depth": 3, "type": "SERVICE"},
                ]
            },
        )
        order = plan_migration_dependency_order(ctx)
        assert order[0] == "crypto_primitive_rsa"
        assert order[1] == "lib_crypto"
        assert order[2] == "app_auth"
        assert order[3] == "svc_gateway"


class TestP3PriorityAndSteps:
    def test_priority_critical_for_vulnerable_production_kex(self):
        ctx = MigrationContext(
            asset_id="prod_tls",
            algorithm="RSA-2048",
            cryptographic_role="KEY_ESTABLISHMENT",
            risk_assessment={"severity": "CRITICAL", "is_production": True},
            pqc_readiness={"state": "CLASSICAL_ONLY"},
            blast_radius={"criticality": "CRITICAL"},
        )
        target = MigrationTarget(
            current_algorithm="RSA-2048",
            current_role="KEY_ESTABLISHMENT",
            target_algorithm="ML-KEM-768",
            target_role="KEY_ESTABLISHMENT",
        )
        prio, factors = derive_migration_priority(ctx, target)
        assert prio == MigrationPriority.CRITICAL

    def test_step_chain_ordering(self):
        ctx = MigrationContext(
            asset_id="ast-1",
            algorithm="RSA-2048",
            cryptographic_role="KEY_ESTABLISHMENT",
        )
        target = MigrationTarget(
            current_algorithm="RSA-2048",
            current_role="KEY_ESTABLISHMENT",
            target_algorithm="X25519MLKEM768",
            target_role="KEY_ESTABLISHMENT",
            transition_mode=TransitionMode.HYBRID_TRANSITION,
        )
        steps = generate_migration_steps(ctx, target, ["ast-1", "lib_ssl", "app_web"])
        assert len(steps) >= 4
        # Verify prerequisite ordering
        for i in range(1, len(steps)):
            assert len(steps[i].prerequisite_steps) == 1
            assert steps[i].prerequisite_steps[0] == steps[i - 1].step_id


class TestP3VerificationEngine:
    def test_verified_migration(self):
        plan = MigrationPlan(
            plan_id="plan-test-01",
            asset_id="ast-tls",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="X25519MLKEM768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.HYBRID_TRANSITION,
            ),
        )
        before_scan = {"scan_id": "sc-before", "algorithms": ["RSA-2048"], "ciphersuites": ["TLS_RSA_WITH_AES_256_GCM_SHA384"]}
        after_scan = {
            "scan_id": "sc-after",
            "algorithms": ["X25519MLKEM768"],
            "ciphersuites": ["TLS_AES_256_GCM_SHA384"],
            "active_negotiation_verified": True,
        }
        res = verify_migration(plan=plan, before_scan=before_scan, after_scan=after_scan)
        assert res.verification_state == VerificationState.VERIFIED
        assert len(res.observed_changes) > 0

    def test_scanner_unavailable(self):
        plan = MigrationPlan(
            plan_id="plan-test-02",
            asset_id="ast-fail",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
            ),
        )
        after_scan = {"scan_id": "sc-after-fail", "scanner_unavailable": True, "error": "Connection timed out"}
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.SCANNER_UNAVAILABLE
        assert len(res.discrepancies) > 0

    def test_not_verified_target_missing(self):
        plan = MigrationPlan(
            plan_id="plan-test-03",
            asset_id="ast-missing",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
            ),
        )
        after_scan = {"scan_id": "sc-after", "algorithms": ["RSA-2048"]}
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.NOT_VERIFIED


class TestP3AssetGraphPersistence:
    def test_save_and_retrieve_migration_plan(self):
        import sqlite3
        conn = sqlite3.connect("file:p3test?mode=memory&cache=shared", uri=True)
        try:
            graph = AssetGraphService(lambda: sqlite3.connect("file:p3test?mode=memory&cache=shared", uri=True))
            plan = MigrationPlan(
                plan_id="plan-persist-01",
                asset_id="ast-persist",
                migration_target=MigrationTarget(
                    current_algorithm="ECDSA",
                    current_role="SIGNATURE",
                    target_algorithm="ML-DSA-65",
                    target_role="SIGNATURE",
                ),
            )
            saved_id = graph.save_pqc_migration_plan(plan)
            assert saved_id == "plan-persist-01"

            retrieved = graph.get_pqc_migration_plan("ast-persist")
            assert retrieved is not None
            assert retrieved["plan_id"] == "plan-persist-01"
            assert retrieved["migration_target"]["target_algorithm"] == "ML-DSA-65"
        finally:
            conn.close()


class TestP3FastAPIEndpoints:
    @pytest.fixture
    def client(self):
        from main import app
        with TestClient(app) as c:
            yield c

    def test_post_migration_plan_endpoint(self, client):
        payload = {
            "asset": {
                "id": "ast-api-01",
                "name": "login_service",
                "algorithm": "RSA-2048",
                "role": "KEY_ESTABLISHMENT",
            },
            "risk_assessment": {"severity": "HIGH"},
            "pqc_readiness": {"state": "CLASSICAL_ONLY"},
            "blast_radius": {"state": "NO_DEPENDENTS"},
        }
        res = client.post("/api/migration/plan", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "plan_id" in data
        assert data["asset_id"] == "ast-api-01"
        assert any(k in data["migration_target"]["target_algorithm"] for k in ("ML-KEM", "X25519MLKEM768"))
        assert len(data["steps"]) >= 3

    def test_post_migration_verify_endpoint(self, client):
        payload = {
            "asset_id": "ast-api-02",
            "plan": {
                "plan_id": "plan-api-verify",
                "asset_id": "ast-api-02",
                "migration_target": {
                    "current_algorithm": "RSA-2048",
                    "current_role": "KEY_ESTABLISHMENT",
                    "target_algorithm": "ML-KEM-768",
                    "target_role": "KEY_ESTABLISHMENT",
                    "transition_mode": "DIRECT_REPLACEMENT",
                },
            },
            "before_scan": {"scan_id": "sc-1", "algorithms": ["RSA-2048"]},
            "after_scan": {"scan_id": "sc-2", "algorithms": ["ML-KEM-768"], "active_negotiation_verified": True},
        }
        res = client.post("/api/migration/verify", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["verification_state"] == "VERIFIED"
        assert len(data["observed_changes"]) > 0

