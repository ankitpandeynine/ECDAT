"""
ECDAT V4 P3 Master Migration Pipeline.

Integrates Context Normalization, Target Selection, Topological Sequencing,
Priority Derivation, Step Generation, Explainability, and Verification.
"""
from __future__ import annotations

import datetime
import uuid
from typing import Any, Dict, List, Optional

from .dependency_planner import plan_migration_dependency_order
from .explainability import generate_migration_reason_chain
from .migration_rules import MigrationRulesEngine
from .models import (
    MigrationContext,
    MigrationPlan,
    MigrationPriority,
    MigrationVerification,
    TransitionMode,
)
from .normalizer import (
    build_migration_context,
    compute_migration_config_hash,
    compute_migration_evidence_hash,
)
from .planner import derive_migration_priority, generate_migration_steps
from .target_selector import select_migration_target
from .verification import verify_migration


def generate_migration_plan(
    asset: Dict[str, Any],
    risk_assessment: Optional[Dict[str, Any]] = None,
    agility_assessment: Optional[Dict[str, Any]] = None,
    pqc_readiness: Optional[Dict[str, Any]] = None,
    blast_radius: Optional[Dict[str, Any]] = None,
    evidence_items: Optional[List[Dict[str, Any]]] = None,
    rules_engine: Optional[MigrationRulesEngine] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> MigrationPlan:
    """
    Generates a deterministic, explainable PQC MigrationPlan for an individual cryptographic asset.
    """
    rules_engine = rules_engine or MigrationRulesEngine()
    overrides = overrides or {}

    # 1. Build unified migration context
    context = build_migration_context(
        asset=asset,
        risk_assessment=risk_assessment,
        agility_assessment=agility_assessment,
        pqc_readiness=pqc_readiness,
        blast_radius=blast_radius,
        evidence_items=evidence_items,
    )

    # 2. Select migration target
    target, target_limitations = select_migration_target(context, rules_engine=rules_engine)

    # Apply any explicit overrides if provided
    if "target_algorithm" in overrides:
        target.target_algorithm = overrides["target_algorithm"]
    if "transition_mode" in overrides:
        target.transition_mode = TransitionMode(overrides["transition_mode"])

    # 3. Plan dependency ordering
    dependency_order = plan_migration_dependency_order(context)

    # 4. Derive operational migration priority
    priority, priority_factors = derive_migration_priority(context, target)
    if "priority" in overrides:
        priority = MigrationPriority(overrides["priority"])

    # 5. Generate migration steps
    steps = generate_migration_steps(context, target, dependency_order)

    # 6. Generate explainable reason chain
    reason_chain = generate_migration_reason_chain(
        context=context,
        target=target,
        steps=steps,
        priority=priority,
        priority_factors=priority_factors,
        rules_engine=rules_engine,
    )

    # 7. Collect affected assets and summaries
    affected_assets = context.blast_radius.get("affected_assets", [])
    dependencies = dependency_order

    verification_criteria = [
        f"Confirm retirement or deprecation of {context.algorithm}.",
        f"Confirm successful negotiation of {target.target_algorithm}.",
        "Verify absence of cryptographic regressions (e.g. fallback to weak ciphers).",
    ]

    all_limitations = list(context.limitations) + list(target_limitations)
    unknowns: List[str] = []
    if target.target_algorithm == "UNKNOWN":
        unknowns.append("Target algorithm unspecified for asset role.")
    if not affected_assets and "blast_radius" not in asset:
        unknowns.append("Downstream blast radius not fully enumerated.")

    evidence_hash = compute_migration_evidence_hash(evidence_items or [])
    config_hash = compute_migration_config_hash({
        "asset_id": context.asset_id,
        "algorithm": context.algorithm,
        "target_algorithm": target.target_algorithm,
        "priority": priority.value,
    })

    plan_id = f"plan-{uuid.uuid4().hex[:12]}"
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return MigrationPlan(
        plan_id=plan_id,
        asset_id=context.asset_id,
        scan_id=context.scan_id,
        project_id=context.project_id,
        current_state="CLASSICAL" if "CLASSICAL" in str(context.pqc_readiness.get("state", "CLASSICAL")) else "HYBRID",
        target_state="PQC_PROTECTED",
        priority=priority,
        migration_target=target,
        steps=steps,
        dependencies=dependencies,
        affected_assets=affected_assets,
        blast_radius_summary=context.blast_radius,
        risk_summary=context.risk_assessment,
        agility_summary=context.agility_assessment,
        pqc_summary=context.pqc_readiness,
        verification_criteria=verification_criteria,
        evidence_refs=list(context.evidence_refs),
        unknowns=unknowns,
        limitations=all_limitations,
        reason_chain=reason_chain,
        evidence_hash=evidence_hash,
        configuration_hash=config_hash,
        knowledge_base_version=context.knowledge_base_version,
        engine_version=context.engine_version,
        created_at=created_at,
    )


def execute_migration_verification(
    plan: Optional[MigrationPlan] = None,
    before_scan: Optional[Dict[str, Any]] = None,
    after_scan: Optional[Dict[str, Any]] = None,
    asset_id: Optional[str] = None,
    evidence_items: Optional[List[Dict[str, Any]]] = None,
) -> MigrationVerification:
    """
    Executes audit verification comparing before_scan against after_scan.
    """
    return verify_migration(
        plan=plan,
        before_scan=before_scan,
        after_scan=after_scan,
        asset_id=asset_id,
        evidence_items=evidence_items,
    )
