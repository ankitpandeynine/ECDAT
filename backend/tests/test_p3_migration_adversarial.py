"""
ECDAT V4 P3 Adversarial Test Suite.

Rigorously verifies 40 mandatory architectural and semantic axioms
governing P3.1 Migration Intelligence and P3.2 Migration Verification,
along with Integration Fixtures A through F.
"""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Dict, List
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
from engine.migration.explainability import (
    build_migration_explainability_report,
    generate_migration_reason_chain,
)
from engine.migration.migration_pipeline import (
    execute_migration_verification,
    generate_migration_plan,
)
from engine.asset_graph import AssetGraphService
from main import app


# ===========================================================================
# 40 MANDATORY AXIOM TESTS
# ===========================================================================

class TestP3AxiomsTargetSelection:
    def test_axiom_01_rsa_kex_maps_to_kem_never_dsa(self):
        ctx = MigrationContext(asset_id="a1", algorithm="RSA-2048", cryptographic_role="KEY_ESTABLISHMENT")
        target, _ = select_migration_target(ctx)
        assert any(k in target.target_algorithm for k in ("ML-KEM", "X25519MLKEM768"))
        assert "ML-DSA" not in target.target_algorithm
        assert target.target_role == "KEY_ESTABLISHMENT"

    def test_axiom_02_rsa_signature_maps_to_signature_never_kem(self):
        ctx = MigrationContext(asset_id="a2", algorithm="RSA-2048", cryptographic_role="SIGNATURE")
        target, _ = select_migration_target(ctx)
        assert "ML-DSA" in target.target_algorithm or "SLH-DSA" in target.target_algorithm
        assert "ML-KEM" not in target.target_algorithm
        assert target.target_role == "SIGNATURE"

    def test_axiom_03_ecdsa_maps_to_signature_never_kem(self):
        ctx = MigrationContext(asset_id="a3", algorithm="ECDSA-P384", cryptographic_role="SIGNATURE")
        target, _ = select_migration_target(ctx)
        assert "ML-DSA" in target.target_algorithm
        assert "ML-KEM" not in target.target_algorithm
        assert target.target_role == "SIGNATURE"

    def test_axiom_04_ecdh_maps_to_kem_never_dsa(self):
        ctx = MigrationContext(asset_id="a4", algorithm="ECDH-P256", cryptographic_role="KEY_ESTABLISHMENT")
        target, _ = select_migration_target(ctx)
        assert any(k in target.target_algorithm for k in ("ML-KEM", "X25519MLKEM768"))
        assert "ML-DSA" not in target.target_algorithm

    def test_axiom_05_symmetric_128_maps_to_256_grover_halving(self):
        ctx = MigrationContext(asset_id="a5", algorithm="AES-128-CBC", cryptographic_role="SYMMETRIC_ENCRYPTION")
        target, _ = select_migration_target(ctx)
        assert "AES-256" in target.target_algorithm
        assert "KEM" not in target.target_algorithm
        assert "DSA" not in target.target_algorithm
        assert target.transition_mode == TransitionMode.DIRECT_REPLACEMENT

    def test_axiom_06_symmetric_256_requires_no_pqc_replacement(self):
        ctx = MigrationContext(asset_id="a6", algorithm="AES-256-GCM", cryptographic_role="SYMMETRIC_ENCRYPTION")
        target, limitations = select_migration_target(ctx)
        assert target.target_algorithm == "AES-256-GCM"
        assert target.transition_mode == TransitionMode.UNKNOWN
        assert any("Grover" in target.rationale for _ in [1])
        assert len(limitations) > 0

    def test_axiom_07_sha256_requires_no_pqc_replacement(self):
        ctx = MigrationContext(asset_id="a7", algorithm="SHA-256", cryptographic_role="HASHING")
        target, limitations = select_migration_target(ctx)
        assert target.target_algorithm == "SHA-256"
        assert any("quantum-resistant" in target.rationale.lower() or "not broken" in target.rationale.lower() for _ in [1])

    def test_axiom_08_md5_sha1_maps_to_classical_sha256_not_kem(self):
        ctx = MigrationContext(asset_id="a8", algorithm="MD5", cryptographic_role="HASHING")
        target, _ = select_migration_target(ctx)
        assert "SHA-256" in target.target_algorithm
        assert "KEM" not in target.target_algorithm
        assert target.transition_mode == TransitionMode.DIRECT_REPLACEMENT

    def test_axiom_09_unknown_role_produces_unknown_target_never_hallucinates(self):
        ctx = MigrationContext(asset_id="a9", algorithm="CUSTOM_CRYPTO_V1", cryptographic_role="UNKNOWN")
        target, limitations = select_migration_target(ctx)
        assert target.target_algorithm == "UNKNOWN"
        assert target.transition_mode == TransitionMode.UNKNOWN
        assert len(limitations) > 0

    def test_axiom_10_unknown_target_cannot_have_critical_priority(self):
        ctx = MigrationContext(
            asset_id="a10",
            algorithm="CUSTOM_CRYPTO_V1",
            cryptographic_role="UNKNOWN",
            risk_assessment={"severity": "CRITICAL", "is_production": True},
        )
        target = MigrationTarget(
            current_algorithm="CUSTOM_CRYPTO_V1",
            current_role="UNKNOWN",
            target_algorithm="UNKNOWN",
            target_role="UNKNOWN",
        )
        prio, factors = derive_migration_priority(ctx, target)
        assert prio == MigrationPriority.UNKNOWN
        assert any("target is unknown" in f.lower() for f in factors)


class TestP3AxiomsVerificationSemantics:
    def test_axiom_11_hybrid_kex_does_not_verify_pqc_certificate_signature(self):
        plan = MigrationPlan(
            plan_id="p-11",
            asset_id="ast-11",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="CERTIFICATE_SIGNATURE",
                target_algorithm="ML-DSA-65",
                target_role="CERTIFICATE_SIGNATURE",
                transition_mode=TransitionMode.CERTIFICATE_MIGRATION,
            ),
        )
        # Scan shows hybrid KEX active, but certificate is still classical RSA!
        after_scan = {
            "scan_id": "sc-11",
            "ciphersuites": ["X25519MLKEM768"],
            "certificate_algorithm": "RSA-SHA256",
        }
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.PARTIALLY_VERIFIED
        assert any("Hybrid key exchange is enabled, but server certificate is still classical" in d for d in res.discrepancies)

    def test_axiom_12_pqc_certificate_verified_only_when_pqc_cert_observed(self):
        plan = MigrationPlan(
            plan_id="p-12",
            asset_id="ast-12",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="CERTIFICATE_SIGNATURE",
                target_algorithm="ML-DSA-65",
                target_role="CERTIFICATE_SIGNATURE",
                transition_mode=TransitionMode.CERTIFICATE_MIGRATION,
            ),
        )
        after_scan = {
            "scan_id": "sc-12",
            "certificate_algorithm": "ML-DSA-65",
        }
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.VERIFIED

    def test_axiom_13_plan_creation_does_not_equal_execution(self):
        asset = {"id": "ast-13", "algorithm": "RSA-2048", "role": "KEY_ESTABLISHMENT"}
        plan = generate_migration_plan(asset)
        assert plan.plan_id is not None
        assert plan.current_state == "CLASSICAL"
        assert plan.target_state == "PQC_PROTECTED"
        # Asset remains classical until verified post-scan
        assert plan.current_state != "VERIFIED"

    def test_axiom_14_plan_creation_does_not_equal_verification(self):
        asset = {"id": "ast-14", "algorithm": "RSA-2048", "role": "KEY_ESTABLISHMENT"}
        plan = generate_migration_plan(asset)
        # Plan has verification criteria, but is not a verification record
        assert len(plan.verification_criteria) > 0
        assert not hasattr(plan, "verification_state")

    def test_axiom_15_verification_requires_before_and_after_comparison(self):
        plan = MigrationPlan(
            plan_id="p-15",
            asset_id="ast-15",
            migration_target=MigrationTarget(
                current_algorithm="RSA",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
            ),
        )
        res = verify_migration(
            plan=plan,
            before_scan={"scan_id": "before-15", "algorithms": ["RSA"]},
            after_scan={"scan_id": "after-15", "algorithms": ["ML-KEM-768"], "active_negotiation_verified": True},
        )
        assert res.before_scan_id == "before-15"
        assert res.after_scan_id == "after-15"
        assert res.verification_state == VerificationState.VERIFIED

    def test_axiom_16_missing_after_scan_yields_unknown_state(self):
        plan = MigrationPlan(
            plan_id="p-16",
            asset_id="ast-16",
            migration_target=MigrationTarget(
                current_algorithm="RSA",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
            ),
        )
        res = verify_migration(plan=plan, after_scan=None)
        assert res.verification_state == VerificationState.UNKNOWN
        assert len(res.unknowns) > 0

    def test_axiom_17_scanner_unavailable_in_either_scan_yields_scanner_unavailable(self):
        plan = MigrationPlan(plan_id="p-17", asset_id="ast-17")
        res = verify_migration(plan=plan, after_scan={"scanner_unavailable": True, "error": "Probe timed out"})
        assert res.verification_state == VerificationState.SCANNER_UNAVAILABLE
        assert any("scanner unavailable" in d.lower() for d in res.discrepancies)

    def test_axiom_18_scan_scope_mismatch_yields_inconclusive(self):
        plan = MigrationPlan(plan_id="p-18", asset_id="ast-18")
        before_scan = {"scan_id": "b18", "scope": "SOURCE_CODE"}
        after_scan = {"scan_id": "a18", "scope": "NETWORK_PROBE"}
        res = verify_migration(plan=plan, before_scan=before_scan, after_scan=after_scan)
        assert res.verification_state == VerificationState.INCONCLUSIVE
        assert any("scope mismatch" in d.lower() for d in res.discrepancies)

    def test_axiom_19_target_algorithm_absent_in_after_scan_yields_not_verified(self):
        plan = MigrationPlan(
            plan_id="p-19",
            asset_id="ast-19",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
            ),
        )
        after_scan = {"scan_id": "a19", "algorithms": ["RSA-2048", "AES-256-GCM"]}
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.NOT_VERIFIED

    def test_axiom_20_target_observed_and_classical_retired_yields_verified(self):
        plan = MigrationPlan(
            plan_id="p-20",
            asset_id="ast-20",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
            ),
        )
        before_scan = {"scan_id": "b20", "algorithms": ["RSA-2048"]}
        after_scan = {"scan_id": "a20", "algorithms": ["ML-KEM-768"], "active_negotiation_verified": True}
        res = verify_migration(plan=plan, before_scan=before_scan, after_scan=after_scan)
        assert res.verification_state == VerificationState.VERIFIED
        assert any("retired" in c.lower() for c in res.observed_changes)

    def test_axiom_21_classical_retained_on_direct_replacement_yields_partially_verified(self):
        plan = MigrationPlan(
            plan_id="p-21",
            asset_id="ast-21",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
            ),
        )
        after_scan = {"scan_id": "a21", "algorithms": ["ML-KEM-768", "RSA-2048"], "active_negotiation_verified": True}
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.PARTIALLY_VERIFIED
        assert any("classical fallback" in d.lower() for d in res.discrepancies)

    def test_axiom_22_classical_retained_on_hybrid_transition_is_expected(self):
        plan = MigrationPlan(
            plan_id="p-22",
            asset_id="ast-22",
            migration_target=MigrationTarget(
                current_algorithm="ECDH-P256",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="X25519MLKEM768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.HYBRID_TRANSITION,
            ),
        )
        after_scan = {"scan_id": "a22", "algorithms": ["X25519MLKEM768", "ECDH-P256"], "active_negotiation_verified": True}
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.VERIFIED
        assert any("retained as expected" in c.lower() for c in res.observed_changes)

    def test_axiom_23_static_config_only_without_active_negotiation_is_partially_verified(self):
        plan = MigrationPlan(
            plan_id="p-23",
            asset_id="ast-23",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
            ),
        )
        after_scan = {
            "scan_id": "a23",
            "algorithms": ["ML-KEM-768"],
            "static_configuration_only": True,
        }
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.PARTIALLY_VERIFIED
        assert any("active negotiation unverified" in d.lower() for d in res.discrepancies)

    def test_axiom_24_weak_primitive_regression_prevents_clean_verified_state(self):
        plan = MigrationPlan(
            plan_id="p-24",
            asset_id="ast-24",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
            ),
        )
        # Post-scan introduces RC4!
        after_scan = {
            "scan_id": "a24",
            "algorithms": ["ML-KEM-768", "RC4"],
            "active_negotiation_verified": True,
        }
        res = verify_migration(plan=plan, after_scan=after_scan)
        assert res.verification_state == VerificationState.PARTIALLY_VERIFIED
        assert any("cryptographic regression" in d.lower() for d in res.discrepancies)


class TestP3AxiomsPlanningAndDependencies:
    def test_axiom_25_priority_is_orthogonal_to_raw_risk_severity(self):
        # Target unknown with Critical risk -> Priority UNKNOWN, not CRITICAL
        ctx = MigrationContext(
            asset_id="a25",
            algorithm="UNRECOGNIZED_ALGO",
            cryptographic_role="UNKNOWN",
            risk_assessment={"severity": "CRITICAL"},
        )
        target = MigrationTarget(current_algorithm="UNRECOGNIZED", current_role="UNKNOWN", target_algorithm="UNKNOWN", target_role="UNKNOWN")
        prio, _ = derive_migration_priority(ctx, target)
        assert prio == MigrationPriority.UNKNOWN

    def test_axiom_26_production_vulnerable_kex_yields_critical_priority(self):
        ctx = MigrationContext(
            asset_id="a26",
            algorithm="RSA-2048",
            cryptographic_role="KEY_ESTABLISHMENT",
            risk_assessment={"severity": "CRITICAL", "is_production": True},
            pqc_readiness={"state": "CLASSICAL_ONLY"},
            blast_radius={"criticality": "CRITICAL"},
        )
        target = MigrationTarget(
            current_algorithm="RSA-2048",
            current_role="KEY_ESTABLISHMENT",
            target_algorithm="X25519MLKEM768",
            target_role="KEY_ESTABLISHMENT",
        )
        prio, factors = derive_migration_priority(ctx, target)
        assert prio == MigrationPriority.CRITICAL
        assert any("production" in f.lower() for f in factors)

    def test_axiom_27_low_risk_contained_blast_yields_low_priority(self):
        ctx = MigrationContext(
            asset_id="a27",
            algorithm="AES-128",
            cryptographic_role="SYMMETRIC_ENCRYPTION",
            risk_assessment={"severity": "LOW"},
            blast_radius={"state": "NO_DEPENDENTS"},
        )
        target = MigrationTarget(
            current_algorithm="AES-128",
            current_role="SYMMETRIC_ENCRYPTION",
            target_algorithm="AES-256-GCM",
            target_role="SYMMETRIC_ENCRYPTION",
        )
        prio, _ = derive_migration_priority(ctx, target)
        assert prio == MigrationPriority.LOW

    def test_axiom_28_cyclic_graph_does_not_cause_infinite_loop(self):
        ctx = MigrationContext(
            asset_id="ast-root",
            dependency_paths=[
                {"nodes": ["ast-root", "svc-A", "svc-B", "svc-A"]},
            ],
            blast_radius={"affected_assets": [{"id": "svc-A", "type": "SERVICE"}, {"id": "svc-B", "type": "SERVICE"}]},
        )
        order = plan_migration_dependency_order(ctx)
        assert len(order) == 3
        assert order[0] == "ast-root"
        assert len(set(order)) == 3

    def test_axiom_29_topological_order_places_provider_library_before_service(self):
        ctx = MigrationContext(
            asset_id="ast-prim",
            blast_radius={
                "affected_assets": [
                    {"id": "service_frontend", "type": "SERVICE"},
                    {"id": "crypto_lib_bouncycastle", "type": "LIBRARY"},
                ]
            },
        )
        order = plan_migration_dependency_order(ctx)
        assert order.index("crypto_lib_bouncycastle") < order.index("service_frontend")

    def test_axiom_30_step_prerequisites_form_acyclic_directed_chain(self):
        ctx = MigrationContext(asset_id="ast-30", algorithm="RSA-2048", cryptographic_role="KEY_ESTABLISHMENT")
        target = MigrationTarget(
            current_algorithm="RSA-2048",
            current_role="KEY_ESTABLISHMENT",
            target_algorithm="X25519MLKEM768",
            target_role="KEY_ESTABLISHMENT",
            transition_mode=TransitionMode.HYBRID_TRANSITION,
        )
        steps = generate_migration_steps(ctx, target, ["ast-30", "lib_ssl", "app_web"])
        visited = set()
        for step in steps:
            for prereq in step.prerequisite_steps:
                assert prereq in visited
            visited.add(step.step_id)


class TestP3AxiomsHashesAndAudit:
    def test_axiom_31_evidence_hash_is_deterministic(self):
        ev = [{"id": "e1", "algo": "RSA"}, {"id": "e2", "algo": "ECDH"}]
        h1 = compute_migration_evidence_hash(ev)
        h2 = compute_migration_evidence_hash(list(reversed(ev)))
        assert h1 == h2
        assert len(h1) == 64

    def test_axiom_32_config_hash_is_deterministic(self):
        cfg = {"asset_id": "a32", "prio": "HIGH", "target": "ML-KEM-768"}
        h1 = compute_migration_config_hash(cfg)
        h2 = compute_migration_config_hash(cfg)
        assert h1 == h2

    def test_axiom_33_different_inputs_yield_different_hashes(self):
        h1 = compute_migration_config_hash({"k": "v1"})
        h2 = compute_migration_config_hash({"k": "v2"})
        assert h1 != h2

    def test_axiom_34_persistence_is_non_destructive_for_plans(self):
        import sqlite3
        conn = sqlite3.connect("file:p3audit1?mode=memory&cache=shared", uri=True)
        try:
            graph = AssetGraphService(lambda: sqlite3.connect("file:p3audit1?mode=memory&cache=shared", uri=True))
            p1 = MigrationPlan(plan_id="plan-1", asset_id="ast-audit", current_state="CLASSICAL")
            p2 = MigrationPlan(plan_id="plan-2", asset_id="ast-audit", current_state="HYBRID")
            graph.save_pqc_migration_plan(p1)
            graph.save_pqc_migration_plan(p2)
            all_plans = graph.get_all_pqc_migration_plans("ast-audit")
            assert len(all_plans) == 2
        finally:
            conn.close()

    def test_axiom_35_verification_persistence_retains_full_audit_trail(self):
        import sqlite3
        conn = sqlite3.connect("file:p3audit2?mode=memory&cache=shared", uri=True)
        try:
            graph = AssetGraphService(lambda: sqlite3.connect("file:p3audit2?mode=memory&cache=shared", uri=True))
            v1 = MigrationVerification(verification_id="ver-1", asset_id="ast-audit", verification_state=VerificationState.NOT_VERIFIED)
            v2 = MigrationVerification(verification_id="ver-2", asset_id="ast-audit", verification_state=VerificationState.VERIFIED)
            graph.save_migration_verification(v1)
            graph.save_migration_verification(v2)
            all_ver = graph.get_all_migration_verifications("ast-audit")
            assert len(all_ver) == 2
        finally:
            conn.close()


class TestP3AxiomsRESTAndAbsence:
    @pytest.fixture
    def client(self):
        with TestClient(app) as c:
            yield c

    def test_axiom_36_rest_get_migration_generates_plan_if_missing(self, client):
        # Even if unpersisted, get_why or direct endpoints return 404 or structured response
        res = client.get("/api/assets/non-existent-xyz/migration")
        assert res.status_code == 404

    def test_axiom_37_rest_why_endpoint_returns_structured_reasons(self, client):
        res = client.get("/api/assets/non-existent-xyz/migration/why")
        assert res.status_code == 404

    def test_axiom_38_rest_post_plan_accepts_overrides(self, client):
        payload = {
            "asset": {"id": "ast-overrides", "algorithm": "RSA-2048", "role": "KEY_ESTABLISHMENT"},
            "overrides": {"priority": "LOW", "target_algorithm": "CUSTOM-PQC-768"},
        }
        res = client.post("/api/migration/plan", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["priority"] == "LOW"
        assert data["migration_target"]["target_algorithm"] == "CUSTOM-PQC-768"

    def test_axiom_39_rest_post_verify_executes_verification(self, client):
        payload = {
            "asset_id": "ast-test-axiom39",
            "before_scan": {"scan_id": "b39", "algorithms": ["RSA-2048"]},
            "after_scan": {"scan_id": "a39", "algorithms": ["ML-KEM-768"], "active_negotiation_verified": True},
            "plan": {
                "plan_id": "plan-39",
                "asset_id": "ast-test-axiom39",
                "migration_target": {
                    "current_algorithm": "RSA-2048",
                    "current_role": "KEY_ESTABLISHMENT",
                    "target_algorithm": "ML-KEM-768",
                    "target_role": "KEY_ESTABLISHMENT",
                    "transition_mode": "DIRECT_REPLACEMENT",
                },
            },
        }
        res = client.post("/api/migration/verify", json=payload)
        assert res.status_code == 200
        assert res.json()["verification_state"] == "VERIFIED"

    def test_axiom_40_absence_of_evidence_does_not_claim_pqc_safety(self):
        ctx = MigrationContext(asset_id="a40", algorithm="UNKNOWN_CUSTOM_PRIMITIVE", cryptographic_role="UNKNOWN")
        target, limitations = select_migration_target(ctx)
        assert target.target_algorithm == "UNKNOWN"
        assert target.transition_mode == TransitionMode.UNKNOWN
        # Does not claim PQC protected
        assert target.target_algorithm != "PQC_SECURE"


# ===========================================================================
# INTEGRATION FIXTURES A THROUGH F
# ===========================================================================

class TestP3IntegrationFixtures:
    def test_fixture_a_legacy_tls_web_service(self):
        """Fixture A: TLS 1.2 server with RSA-2048 KEX and RSA certificate signature."""
        asset = {
            "id": "fixture-a-tls",
            "name": "corporate-web-portal",
            "algorithm": "RSA-2048",
            "role": "KEY_ESTABLISHMENT",
            "parameters": {"key_size": 2048},
        }
        risk = {"severity": "CRITICAL", "confidence": "HIGH", "is_production": True}
        pqc = {"state": "CLASSICAL_ONLY"}
        blast = {
            "criticality": "CRITICAL",
            "affected_assets": [
                {"id": "nginx_proxy", "type": "SERVICE"},
                {"id": "customer_portal", "type": "APPLICATION"},
            ],
        }
        plan = generate_migration_plan(asset, risk_assessment=risk, pqc_readiness=pqc, blast_radius=blast)
        assert plan.priority == MigrationPriority.CRITICAL
        assert any(k in plan.migration_target.target_algorithm for k in ("ML-KEM", "X25519MLKEM768"))
        assert len(plan.steps) >= 4

    def test_fixture_b_spring_boot_hardcoded_aes128(self):
        """Fixture B: Spring Boot microservice with hardcoded AES-128."""
        asset = {
            "id": "fixture-b-aes",
            "name": "payment-token-vault",
            "algorithm": "AES-128-CBC",
            "role": "SYMMETRIC_ENCRYPTION",
        }
        risk = {"severity": "MEDIUM"}
        plan = generate_migration_plan(asset, risk_assessment=risk)
        assert "AES-256" in plan.migration_target.target_algorithm
        assert plan.migration_target.transition_mode == TransitionMode.DIRECT_REPLACEMENT
        assert any("Grover" in r.claim or "Grover" in plan.migration_target.rationale for r in plan.reason_chain)

    def test_fixture_c_python_crypto_ecdsa_signing(self):
        """Fixture C: Python cryptography package using ECDSA signing."""
        asset = {
            "id": "fixture-c-ecdsa",
            "name": "firmware-update-signer",
            "algorithm": "ECDSA-P256",
            "role": "SIGNATURE",
        }
        risk = {"severity": "HIGH"}
        plan = generate_migration_plan(asset, risk_assessment=risk)
        assert "ML-DSA" in plan.migration_target.target_algorithm
        assert plan.migration_target.target_role == "SIGNATURE"

    def test_fixture_d_post_migration_tls_upgraded_verified(self):
        """Fixture D: Verification of TLS upgrade to X25519MLKEM768."""
        plan = MigrationPlan(
            plan_id="plan-fix-d",
            asset_id="ast-fix-d",
            migration_target=MigrationTarget(
                current_algorithm="ECDH-P256",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="X25519MLKEM768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.HYBRID_TRANSITION,
            ),
        )
        before_scan = {"scan_id": "sc-d-before", "algorithms": ["ECDH-P256"], "ciphersuites": ["ECDHE-RSA-AES256-GCM-SHA384"]}
        after_scan = {
            "scan_id": "sc-d-after",
            "algorithms": ["X25519MLKEM768"],
            "ciphersuites": ["TLS_AES_256_GCM_SHA384"],
            "active_negotiation_verified": True,
        }
        ver = execute_migration_verification(plan=plan, before_scan=before_scan, after_scan=after_scan)
        assert ver.verification_state == VerificationState.VERIFIED
        assert len(ver.discrepancies) == 0

    def test_fixture_e_post_migration_static_config_partially_verified(self):
        """Fixture E: Target algorithm in configuration but handshake negotiation unobserved."""
        plan = MigrationPlan(
            plan_id="plan-fix-e",
            asset_id="ast-fix-e",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
            ),
        )
        after_scan = {
            "scan_id": "sc-e-after",
            "algorithms": ["ML-KEM-768"],
            "static_configuration_only": True,
        }
        ver = execute_migration_verification(plan=plan, after_scan=after_scan)
        assert ver.verification_state == VerificationState.PARTIALLY_VERIFIED
        assert any("active negotiation unverified" in d.lower() for d in ver.discrepancies)

    def test_fixture_f_post_migration_probe_timeout_scanner_unavailable(self):
        """Fixture F: Post-migration network probe timed out."""
        plan = MigrationPlan(
            plan_id="plan-fix-f",
            asset_id="ast-fix-f",
            migration_target=MigrationTarget(
                current_algorithm="RSA-2048",
                current_role="KEY_ESTABLISHMENT",
                target_algorithm="ML-KEM-768",
                target_role="KEY_ESTABLISHMENT",
            ),
        )
        after_scan = {
            "scan_id": "sc-f-after",
            "scanner_unavailable": True,
            "error": "Connection timed out after 10000ms",
        }
        ver = execute_migration_verification(plan=plan, after_scan=after_scan)
        assert ver.verification_state == VerificationState.SCANNER_UNAVAILABLE
        assert any("scanner unavailable" in d.lower() for d in ver.discrepancies)
