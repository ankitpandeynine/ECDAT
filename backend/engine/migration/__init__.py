"""
ECDAT V4 P3.1 + P3.2 Migration Intelligence & Migration Verification.
"""
from .dependency_planner import plan_migration_dependency_order
from .evidence import correlate_migration_evidence, detect_evidence_discrepancies
from .explainability import build_migration_explainability_report, generate_migration_reason_chain
from .migration_pipeline import execute_migration_verification, generate_migration_plan
from .migration_rules import MigrationRulesEngine
from .models import (
    MigrationContext,
    MigrationPlan,
    MigrationPriority,
    MigrationReason,
    MigrationStep,
    MigrationStepAction,
    MigrationTarget,
    MigrationVerification,
    TransitionMode,
    VerificationState,
)
from .normalizer import (
    build_migration_context,
    compute_migration_config_hash,
    compute_migration_evidence_hash,
    normalize_cryptographic_role,
)
from .planner import derive_migration_priority, generate_migration_steps
from .target_selector import select_migration_target
from .verification import verify_migration

__all__ = [
    "TransitionMode",
    "MigrationPriority",
    "VerificationState",
    "MigrationStepAction",
    "MigrationTarget",
    "MigrationStep",
    "MigrationReason",
    "MigrationContext",
    "MigrationPlan",
    "MigrationVerification",
    "MigrationRulesEngine",
    "normalize_cryptographic_role",
    "build_migration_context",
    "compute_migration_evidence_hash",
    "compute_migration_config_hash",
    "select_migration_target",
    "plan_migration_dependency_order",
    "derive_migration_priority",
    "generate_migration_steps",
    "generate_migration_reason_chain",
    "build_migration_explainability_report",
    "verify_migration",
    "correlate_migration_evidence",
    "detect_evidence_discrepancies",
    "generate_migration_plan",
    "execute_migration_verification",
]
