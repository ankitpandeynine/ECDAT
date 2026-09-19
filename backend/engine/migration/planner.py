"""
ECDAT V4 P3 Migration Planner & Priority Derivation.

Constructs concrete, phased MigrationSteps and derives actionable MigrationPriority
by synthesizing P2.1 Risk, P2.1 PQC Readiness, P2.2 Agility, and P2.3 Blast Radius.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

from .dependency_planner import plan_migration_dependency_order
from .models import (
    MigrationContext,
    MigrationPriority,
    MigrationStep,
    MigrationStepAction,
    MigrationTarget,
    TransitionMode,
)


def derive_migration_priority(
    context: MigrationContext,
    target: MigrationTarget,
) -> Tuple[MigrationPriority, List[str]]:
    """
    Derives MigrationPriority from risk, readiness, agility constraints, and blast radius.
    Priority is a derived operational attribute; it NEVER overwrites raw risk severity.
    """
    factors: List[str] = []
    risk_sev = str(context.risk_assessment.get("severity", "")).upper()
    pqc_state = str(context.pqc_readiness.get("state", "")).upper()
    agility_state = str(context.agility_assessment.get("overall_state", "")).upper()
    blast_state = str(context.blast_radius.get("state", "")).upper()
    crit_level = str(context.blast_radius.get("criticality", "")).upper()

    # Rule: If target is unknown, priority cannot be CRITICAL (unsolvable without target)
    if target.target_algorithm == "UNKNOWN":
        factors.append("Migration target is unknown; priority deferred to UNKNOWN pending target specification.")
        return MigrationPriority.UNKNOWN, factors

    # Rule: Production asset with vulnerable classical key establishment or critical risk
    is_prod = (
        crit_level == "CRITICAL"
        or context.parameters.get("is_production")
        or context.risk_assessment.get("is_production")
    )

    if (risk_sev in ("CRITICAL", "HIGH") or "CLASSICAL_ONLY" in pqc_state) and is_prod:
        factors.append("High risk classical primitive deployed in verified production environment.")
        if agility_state in ("BLOCKED", "CONSTRAINED"):
            factors.append("Agility constraints increase migration urgency and planning lead-time.")
        return MigrationPriority.CRITICAL, factors

    if risk_sev in ("CRITICAL", "HIGH") or blast_state in ("WIDESPREAD", "MULTI_PATH"):
        factors.append("Substantial risk severity or widespread downstream blast radius.")
        return MigrationPriority.HIGH, factors

    if risk_sev == "MEDIUM" or "TRANSITIVE" in blast_state or "CONSTRAINED" in agility_state:
        factors.append("Moderate risk with intermediate multi-hop impact.")
        return MigrationPriority.MEDIUM, factors

    if risk_sev in ("LOW", "NEGLIGIBLE") or "NO_DEPENDENTS" in blast_state:
        factors.append("Low risk with contained or zero observed blast radius.")
        return MigrationPriority.LOW, factors

    factors.append("Insufficient operational indicators to classify priority.")
    return MigrationPriority.UNKNOWN, factors


def generate_migration_steps(
    context: MigrationContext,
    target: MigrationTarget,
    dependency_order: List[str],
) -> List[MigrationStep]:
    """
    Generates an actionable sequence of concrete MigrationSteps.
    A plan is NOT execution; each step defines actions, prerequisites, and verification methods.
    """
    steps: List[MigrationStep] = []
    role = context.cryptographic_role
    trans_mode = target.transition_mode
    step_num = 1

    # Step 1: Upstream dependency upgrade (if library dependency observed)
    has_lib = any("lib" in comp.lower() or "crypto" in comp.lower() for comp in dependency_order[1:])
    step_1_id = f"step-{step_num:02d}"
    if has_lib or trans_mode in (TransitionMode.DEPENDENCY_UPGRADE, TransitionMode.HYBRID_TRANSITION):
        steps.append(
            MigrationStep(
                step_id=step_1_id,
                order=step_num,
                action=MigrationStepAction.UPGRADE_DEPENDENCY.value,
                target_component=dependency_order[1] if len(dependency_order) > 1 else context.asset_id,
                prerequisite_steps=[],
                expected_change=f"Upgrade cryptographic provider to support {target.target_algorithm}.",
                verification_method="Verify provider version and algorithm availability via package manifest/API probe.",
            )
        )
        prev_id = step_1_id
        step_num += 1
    else:
        prev_id = None

    # Step 2: Implementation replacement / Refactoring
    step_2_id = f"step-{step_num:02d}"
    if trans_mode == TransitionMode.CERTIFICATE_MIGRATION:
        action_name = MigrationStepAction.MIGRATE_CERTIFICATE.value
        exp_change = f"Issue and bind post-quantum certificate signed using {target.target_algorithm}."
    elif trans_mode == TransitionMode.HYBRID_TRANSITION:
        action_name = MigrationStepAction.ENABLE_HYBRID_KEX.value
        exp_change = f"Enable hybrid key establishment ({target.target_algorithm}) in protocol configuration."
    elif trans_mode == TransitionMode.APPLICATION_REFACTOR:
        action_name = MigrationStepAction.REFACTOR_CALL_SITES.value
        exp_change = f"Refactor call sites from {context.algorithm} to {target.target_algorithm}."
    else:
        action_name = MigrationStepAction.REPLACE_PRIMITIVE.value
        exp_change = f"Replace {context.algorithm} invocation with {target.target_algorithm}."

    steps.append(
        MigrationStep(
            step_id=step_2_id,
            order=step_num,
            action=action_name,
            target_component=context.asset_id,
            prerequisite_steps=[prev_id] if prev_id else [],
            expected_change=exp_change,
            verification_method="Static AST analysis or binary symbol check confirming new primitive usage.",
        )
    )
    prev_id = step_2_id
    step_num += 1

    # Step 3: Protocol Configuration Update (if applicable)
    if role in ("KEY_ESTABLISHMENT", "SIGNATURE") or "TLS" in context.algorithm.upper():
        step_3_id = f"step-{step_num:02d}"
        steps.append(
            MigrationStep(
                step_id=step_3_id,
                order=step_num,
                action=MigrationStepAction.UPDATE_PROTOCOL_CONFIG.value,
                target_component="protocol_config",
                prerequisite_steps=[prev_id],
                expected_change=f"Update TLS cipher suites and key exchange groups to prefer {target.target_algorithm}.",
                verification_method="Probe protocol handshake to verify cipher suite preference negotiation.",
            )
        )
        prev_id = step_3_id
        step_num += 1

    # Step 4: Staging Deployment
    step_4_id = f"step-{step_num:02d}"
    steps.append(
        MigrationStep(
            step_id=step_4_id,
            order=step_num,
            action=MigrationStepAction.DEPLOY_TO_STAGING.value,
            target_component="staging_environment",
            prerequisite_steps=[prev_id],
            expected_change="Deploy migrated binaries, certificates, and configuration to non-production staging environment.",
            verification_method="Health check and end-to-end integration test execution.",
        )
    )
    prev_id = step_4_id
    step_num += 1

    # Step 5: Verification Scan
    step_5_id = f"step-{step_num:02d}"
    steps.append(
        MigrationStep(
            step_id=step_5_id,
            order=step_num,
            action=MigrationStepAction.PERFORM_VERIFICATION_SCAN.value,
            target_component="verification_engine",
            prerequisite_steps=[prev_id],
            expected_change="Trigger ECDAT V4 verification scan to compare pre- and post-migration evidence.",
            verification_method="Execute POST /api/migration/verify comparing before_scan_id with after_scan_id.",
        )
    )

    return steps
