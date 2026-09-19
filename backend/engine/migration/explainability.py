"""
ECDAT V4 P3 Migration Explainability Engine.

Generates structured, step-by-step reasoning chains for migration plans and targets,
exposing clear supporting evidence, contradicting indicators, unknowns, and limitations.
Powers GET /api/assets/{asset_id}/migration/why.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .migration_rules import MigrationRulesEngine
from .models import (
    MigrationContext,
    MigrationPlan,
    MigrationPriority,
    MigrationReason,
    MigrationStep,
    MigrationTarget,
    TransitionMode,
)


def generate_migration_reason_chain(
    context: MigrationContext,
    target: MigrationTarget,
    steps: List[MigrationStep],
    priority: MigrationPriority,
    priority_factors: List[str],
    rules_engine: Optional[MigrationRulesEngine] = None,
) -> List[MigrationReason]:
    """
    Constructs a traceable sequence of MigrationReason objects detailing every
    decision point in the migration plan.
    """
    rules_engine = rules_engine or MigrationRulesEngine()
    reasons: List[MigrationReason] = []

    # Reason 1: Role Identification & Classification
    reasons.append(
        MigrationReason(
            step="cryptographic_role_identification",
            claim=f"Asset algorithm '{context.algorithm}' classified under cryptographic role '{context.cryptographic_role}'.",
            rule_id="RULE-ROLE-01",
            rule_version=context.knowledge_base_version,
            evidence_refs=list(context.evidence_refs),
            supporting=[f"Determined from primitive parameters and AST usage for {context.algorithm}"],
            unknowns=["Role inferred from naming if call site ast is ambiguous"] if context.cryptographic_role == "UNKNOWN" else [],
            limitations=["Cryptographic role is strictly decoupled from cipher mode."],
        )
    )

    # Reason 2: Target Selection
    target_rule = rules_engine.get_target_for_role(context.cryptographic_role)
    supporting_reasons: List[str] = [target.rationale] if target.rationale else []
    contradicting: List[str] = []
    if target.target_algorithm == "UNKNOWN":
        contradicting.append(f"No standardized PQC alternative cataloged for role {context.cryptographic_role}.")

    reasons.append(
        MigrationReason(
            step="target_algorithm_selection",
            claim=f"Selected target algorithm '{target.target_algorithm}' with transition mode '{target.transition_mode.value}'.",
            rule_id=target_rule.get("rule_id", "RULE-TARGET-01") if target_rule else "RULE-TARGET-DEFAULT",
            rule_version=context.knowledge_base_version,
            evidence_refs=list(target.evidence_refs),
            supporting=supporting_reasons,
            contradicting=contradicting,
            limitations=list(target.limitations),
        )
    )

    # Reason 3: Operational Priority Assignment
    reasons.append(
        MigrationReason(
            step="migration_priority_derivation",
            claim=f"Assigned migration priority '{priority.value}'.",
            rule_id="RULE-PRIORITY-01",
            rule_version=context.knowledge_base_version,
            supporting=priority_factors,
            limitations=[
                "Migration priority is an operational planning indicator and does NOT alter raw vulnerability risk severity."
            ],
        )
    )

    # Reason 4: Dependency & Blast Radius Ordering
    blast_state = str(context.blast_radius.get("state", "NO_DEPENDENTS"))
    affected_count = len(context.blast_radius.get("affected_assets", []))
    reasons.append(
        MigrationReason(
            step="dependency_sequencing",
            claim=f"Generated {len(steps)} sequenced migration steps based on topological blast radius traversal ({blast_state}, {affected_count} affected assets).",
            rule_id="RULE-DEPS-01",
            rule_version=context.knowledge_base_version,
            supporting=[f"Step sequence respects leaf-to-root provider ordering ({len(steps)} steps generated)."],
            limitations=["Topological sort guarantees acyclic prerequisite dependencies."],
        )
    )

    return reasons


def build_migration_explainability_report(plan: MigrationPlan) -> Dict[str, Any]:
    """
    Assembles a comprehensive, human-readable explainability report for an asset's migration plan.
    """
    target = plan.migration_target
    return {
        "asset_id": plan.asset_id,
        "plan_id": plan.plan_id,
        "current_state": plan.current_state,
        "target_state": plan.target_state,
        "priority": plan.priority.value if hasattr(plan.priority, "value") else str(plan.priority),
        "target_algorithm": target.target_algorithm if target else "UNKNOWN",
        "target_role": target.target_role if target else "UNKNOWN",
        "transition_mode": target.transition_mode.value if (target and hasattr(target.transition_mode, "value")) else "UNKNOWN",
        "rationale": target.rationale if target else "",
        "steps_count": len(plan.steps),
        "steps_summary": [
            {
                "order": s.order,
                "action": s.action,
                "target_component": s.target_component,
                "prerequisites": s.prerequisite_steps,
                "expected_change": s.expected_change,
            }
            for s in plan.steps
        ],
        "blast_radius_summary": plan.blast_radius_summary,
        "risk_summary": plan.risk_summary,
        "agility_summary": plan.agility_summary,
        "pqc_summary": plan.pqc_summary,
        "evidence_refs": plan.evidence_refs,
        "unknowns": plan.unknowns,
        "limitations": plan.limitations,
        "reason_chain": [r.to_dict() if hasattr(r, "to_dict") else r for r in plan.reason_chain],
        "evidence_hash": plan.evidence_hash,
        "configuration_hash": plan.configuration_hash,
        "knowledge_base_version": plan.knowledge_base_version,
        "engine_version": plan.engine_version,
        "created_at": plan.created_at,
    }
