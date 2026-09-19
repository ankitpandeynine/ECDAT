"""
ECDAT V4 P3.2 Migration Verification Engine.

Performs deterministic, evidence-grounded verification comparing pre-migration
and post-migration scan evidence against expected plan changes.
"""
from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    MigrationPlan,
    MigrationReason,
    MigrationTarget,
    MigrationVerification,
    TransitionMode,
    VerificationState,
)
from .normalizer import compute_migration_config_hash, compute_migration_evidence_hash


def verify_migration(
    plan: Optional[MigrationPlan] = None,
    before_scan: Optional[Dict[str, Any]] = None,
    after_scan: Optional[Dict[str, Any]] = None,
    asset_id: Optional[str] = None,
    evidence_items: Optional[List[Dict[str, Any]]] = None,
) -> MigrationVerification:
    """
    Evaluates migration completion by comparing before_scan and after_scan.
    Derives VerificationState, observed changes, discrepancies, limitations,
    and a structured MigrationReason chain.
    """
    verification_id = f"mver-{uuid.uuid4().hex[:12]}"
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    evidence_items = evidence_items or []
    before_scan = before_scan or {}
    after_scan = after_scan or {}

    # Resolve asset_id and plan references
    target_asset_id = asset_id or (plan.asset_id if plan else "")
    plan_id = plan.plan_id if plan else None
    before_scan_id = before_scan.get("scan_id") or (plan.scan_id if plan else None)
    after_scan_id = after_scan.get("scan_id")

    expected_changes: List[str] = []
    if plan and plan.steps:
        for s in plan.steps:
            if s.expected_change:
                expected_changes.append(s.expected_change)
    elif plan and plan.migration_target:
        expected_changes.append(
            f"Migrate from {plan.migration_target.current_algorithm} to {plan.migration_target.target_algorithm}"
        )

    observed_changes: List[str] = []
    discrepancies: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    evidence_refs: List[str] = []
    reasons: List[MigrationReason] = []

    # 1. Check for Scanner Availability / Execution Failure
    if before_scan.get("scanner_unavailable") or after_scan.get("scanner_unavailable"):
        v_state = VerificationState.SCANNER_UNAVAILABLE
        err = after_scan.get("error") or before_scan.get("error") or "Target scanner probe unavailable"
        discrepancies.append(f"Verification aborted: scanner unavailable ({err}).")
        reasons.append(
            MigrationReason(
                step="scanner_availability",
                claim="Scanner probe failed or was unreachable during verification scan.",
                contradicting=[err],
                limitations=["Verification cannot be completed without a functional probe."],
            )
        )
        return MigrationVerification(
            verification_id=verification_id,
            migration_plan_id=plan_id,
            asset_id=target_asset_id,
            before_scan_id=before_scan_id,
            after_scan_id=after_scan_id,
            expected_changes=expected_changes,
            observed_changes=observed_changes,
            verification_state=v_state,
            evidence_refs=evidence_refs,
            discrepancies=discrepancies,
            unknowns=unknowns,
            limitations=limitations,
            reason_chain=reasons,
            evidence_hash=compute_migration_evidence_hash(evidence_items),
            configuration_hash=compute_migration_config_hash({"plan_id": plan_id, "asset_id": target_asset_id}),
            created_at=created_at,
        )

    # 2. Check for missing scan data or unexecuted post-scan
    if not after_scan or (not after_scan.get("scan_completed", True) and not after_scan.get("algorithms")):
        v_state = VerificationState.UNKNOWN
        unknowns.append("No post-migration scan evidence provided.")
        reasons.append(
            MigrationReason(
                step="post_scan_presence",
                claim="Verification cannot be performed because post-migration scan has not occurred.",
                unknowns=["Missing after_scan payload."],
            )
        )
        return MigrationVerification(
            verification_id=verification_id,
            migration_plan_id=plan_id,
            asset_id=target_asset_id,
            before_scan_id=before_scan_id,
            after_scan_id=after_scan_id,
            expected_changes=expected_changes,
            observed_changes=observed_changes,
            verification_state=v_state,
            evidence_refs=evidence_refs,
            discrepancies=discrepancies,
            unknowns=unknowns,
            limitations=limitations,
            reason_chain=reasons,
            evidence_hash=compute_migration_evidence_hash(evidence_items),
            configuration_hash=compute_migration_config_hash({"plan_id": plan_id, "asset_id": target_asset_id}),
            created_at=created_at,
        )

    # 3. Scope and Target Inconclusive Checks
    before_scope = before_scan.get("scope", "ALL")
    after_scope = after_scan.get("scope", "ALL")
    if before_scope != after_scope and before_scope != "ALL" and after_scope != "ALL":
        v_state = VerificationState.INCONCLUSIVE
        discrepancies.append(f"Scan scope mismatch: before_scan was '{before_scope}' while after_scan was '{after_scope}'.")
        reasons.append(
            MigrationReason(
                step="scope_consistency",
                claim="Scans were executed under non-comparable scopes.",
                contradicting=[f"Scope mismatch: {before_scope} vs {after_scope}"],
            )
        )
        return MigrationVerification(
            verification_id=verification_id,
            migration_plan_id=plan_id,
            asset_id=target_asset_id,
            before_scan_id=before_scan_id,
            after_scan_id=after_scan_id,
            expected_changes=expected_changes,
            observed_changes=observed_changes,
            verification_state=v_state,
            evidence_refs=evidence_refs,
            discrepancies=discrepancies,
            unknowns=unknowns,
            limitations=limitations,
            reason_chain=reasons,
            evidence_hash=compute_migration_evidence_hash(evidence_items),
            configuration_hash=compute_migration_config_hash({"plan_id": plan_id, "asset_id": target_asset_id}),
            created_at=created_at,
        )

    # 4. Extract Before & After Observed State
    before_algos = [str(a).strip().upper() for a in before_scan.get("algorithms", [])]
    after_algos = [str(a).strip().upper() for a in after_scan.get("algorithms", [])]

    before_ciphers = [str(c).strip().upper() for c in before_scan.get("ciphersuites", [])]
    after_ciphers = [str(c).strip().upper() for c in after_scan.get("ciphersuites", [])]

    target_algo = (plan.migration_target.target_algorithm if (plan and plan.migration_target) else "").upper()
    current_algo = (plan.migration_target.current_algorithm if (plan and plan.migration_target) else "").upper()
    trans_mode = plan.migration_target.transition_mode if (plan and plan.migration_target) else TransitionMode.UNKNOWN

    # Gather evidence references
    for e in before_scan.get("evidence_refs", []):
        evidence_refs.append(f"before:{e}")
    for e in after_scan.get("evidence_refs", []):
        evidence_refs.append(f"after:{e}")

    # Check presence of Target Algorithm in After Scan
    target_clean = target_algo.replace("-", "").replace(" ", "").replace("_", "")
    target_observed_in_algos = any(target_clean in a.replace("-", "").replace(" ", "").replace("_", "") for a in after_algos) if target_clean else False
    target_observed_in_ciphers = any(target_clean in c.replace("-", "").replace(" ", "").replace("_", "") for c in after_ciphers) if target_clean else False
    target_present = target_observed_in_algos or target_observed_in_ciphers

    # Check presence of Current/Classical Algorithm in After Scan
    curr_clean = current_algo.replace("-", "").replace(" ", "").replace("_", "")
    classical_still_present_in_algos = any(curr_clean in a.replace("-", "").replace(" ", "").replace("_", "") for a in after_algos) if curr_clean else False
    classical_still_present_in_ciphers = any(curr_clean in c.replace("-", "").replace(" ", "").replace("_", "") for c in after_ciphers) if curr_clean else False
    classical_present = classical_still_present_in_algos or classical_still_present_in_ciphers

    # Static configuration vs Active live negotiation
    static_configured_only = bool(after_scan.get("static_configuration_only"))
    active_negotiated = bool(after_scan.get("active_negotiation_verified", not static_configured_only))

    # Certificate vs KEM Distinction (Axiom: Hybrid KEX != PQC Certificate Signature)
    is_cert_plan = (trans_mode == TransitionMode.CERTIFICATE_MIGRATION) or (
        plan and plan.migration_target and "CERT" in plan.migration_target.current_role
    )
    after_cert_algo = str(after_scan.get("certificate_algorithm", "")).upper()

    # Track observed changes
    if target_present:
        observed_changes.append(f"Target algorithm {target_algo} successfully detected in post-migration scan.")
        reasons.append(
            MigrationReason(
                step="target_detection",
                claim=f"Target algorithm {target_algo} observed in post-migration scan.",
                supporting=[f"Detected in algorithms/ciphersuites: {after_algos + after_ciphers}"],
            )
        )
    else:
        reasons.append(
            MigrationReason(
                step="target_detection",
                claim=f"Expected target algorithm {target_algo} was NOT detected in post-migration scan.",
                contradicting=[f"Post-scan observed algorithms: {after_algos}"],
            )
        )

    if classical_present:
        if trans_mode in (TransitionMode.HYBRID_TRANSITION, TransitionMode.DUAL_SUPPORT):
            observed_changes.append(f"Classical primitive {current_algo} retained as expected for hybrid/dual support.")
        else:
            discrepancies.append(f"Classical algorithm {current_algo} was not retired; still active in post-scan.")
            reasons.append(
                MigrationReason(
                    step="classical_retirement",
                    claim=f"Classical algorithm {current_algo} is still present in post-migration environment.",
                    contradicting=[f"Found in after_scan: {after_algos}"],
                )
            )
    else:
        observed_changes.append(f"Classical algorithm {current_algo} retired / removed from post-scan.")
        reasons.append(
            MigrationReason(
                step="classical_retirement",
                claim=f"Classical algorithm {current_algo} successfully retired.",
                supporting=["Not detected in post-migration algorithms or ciphers."],
            )
        )

    # 5. Evaluate Verification State
    if is_cert_plan:
        cert_clean = target_clean
        cert_matched = cert_clean in after_cert_algo.replace("-", "").replace(" ", "").replace("_", "") if cert_clean else False
        has_pqc_kex = any(
            any(p in c for p in ("MLKEM", "KYBER", "X25519MLKEM768", "HYBRID"))
            for c in after_ciphers + after_algos
        )
        if cert_matched:
            observed_changes.append(f"Post-quantum certificate verified: {after_cert_algo}.")
            v_state = VerificationState.VERIFIED
        elif (target_observed_in_ciphers or has_pqc_kex) and not cert_matched:
            # Hybrid KEX enabled, but certificate not migrated!
            discrepancies.append(
                f"Hybrid key exchange is enabled, but server certificate is still classical ({after_cert_algo or 'RSA/ECDSA'}). Hybrid KEX does not verify Certificate Migration."
            )
            v_state = VerificationState.PARTIALLY_VERIFIED
        else:
            v_state = VerificationState.NOT_VERIFIED


    elif not target_present:
        v_state = VerificationState.NOT_VERIFIED
        discrepancies.append(f"Target algorithm {target_algo} not found in after-scan.")

    elif static_configured_only:
        # Configured in configuration files, but live handshake / execution did not negotiate target
        v_state = VerificationState.PARTIALLY_VERIFIED
        discrepancies.append(f"Target algorithm {target_algo} configured statically, but active negotiation unverified.")
        reasons.append(
            MigrationReason(
                step="handshake_negotiation",
                claim="Target is statically configured but active runtime handshake negotiation was unobserved.",
                contradicting=["static_configuration_only=True"],
            )
        )

    elif classical_present and trans_mode not in (TransitionMode.HYBRID_TRANSITION, TransitionMode.DUAL_SUPPORT):
        # Target present, but classical was supposed to be completely replaced
        v_state = VerificationState.PARTIALLY_VERIFIED
        discrepancies.append(f"Target {target_algo} is present, but classical fallback {current_algo} remains active.")

    else:
        # Target present and negotiated, classical retired or appropriately hybrid
        v_state = VerificationState.VERIFIED

    # Check for unexpected regressions (e.g. weaker cipher introduced)
    weak_algos = [a for a in after_algos if any(w in a for w in ("RC4", "MD5", "DES", "NULL"))]
    if weak_algos:
        discrepancies.append(f"Unexpected cryptographic regression: deprecated primitive(s) detected {weak_algos}.")
        limitations.append("Regression detected in post-migration scan.")
        if v_state == VerificationState.VERIFIED:
            v_state = VerificationState.PARTIALLY_VERIFIED

    return MigrationVerification(
        verification_id=verification_id,
        migration_plan_id=plan_id,
        asset_id=target_asset_id,
        before_scan_id=before_scan_id,
        after_scan_id=after_scan_id,
        expected_changes=expected_changes,
        observed_changes=observed_changes,
        verification_state=v_state,
        evidence_refs=evidence_refs,
        discrepancies=discrepancies,
        unknowns=unknowns,
        limitations=limitations,
        reason_chain=reasons,
        evidence_hash=compute_migration_evidence_hash(evidence_items),
        configuration_hash=compute_migration_config_hash({"plan_id": plan_id, "asset_id": target_asset_id}),
        created_at=created_at,
    )
