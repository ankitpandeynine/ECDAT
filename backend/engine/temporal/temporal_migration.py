"""
ECDAT V4 Temporal Migration Tracking Evaluator.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from .models import MigrationChange


def evaluate_temporal_migration(
    base_plan_or_ver: Optional[Dict[str, Any]],
    target_plan_or_ver: Optional[Dict[str, Any]],
) -> Tuple[MigrationChange, str]:
    """
    Evaluates migration progression between scans.
    Returns (MigrationChange, explanation).
    """
    if base_plan_or_ver is None and target_plan_or_ver is None:
        return MigrationChange.MIGRATION_UNKNOWN, "No migration plan or verification available."

    if base_plan_or_ver is None and target_plan_or_ver is not None:
        state = target_plan_or_ver.get("verification_state") or target_plan_or_ver.get("status", "STARTED")
        if state in ("VERIFIED", "MIGRATION_SUCCESSFUL"):
            return MigrationChange.MIGRATION_VERIFIED, "Migration plan was executed and verified."
        return MigrationChange.MIGRATION_STARTED, f"Migration planning initiated with status {state}."

    if target_plan_or_ver is None:
        return MigrationChange.MIGRATION_UNKNOWN, "Migration progress unobserved in target scan."

    target_state = str(target_plan_or_ver.get("verification_state") or target_plan_or_ver.get("status", "")).upper()
    base_state = str(base_plan_or_ver.get("verification_state") or base_plan_or_ver.get("status", "")).upper()

    if target_state in ("VERIFIED", "SUCCESS", "MIGRATION_SUCCESSFUL"):
        return MigrationChange.MIGRATION_VERIFIED, "Migration successfully verified in target scan."
    elif target_state in ("FAILED", "REGRESSED", "VERIFICATION_FAILED"):
        return MigrationChange.MIGRATION_FAILED, f"Migration verification failed: {target_plan_or_ver.get('notes', 'Incomplete transition')}."
    elif target_state in ("IN_PROGRESS", "PARTIAL", "HYBRID"):
        return MigrationChange.MIGRATION_PROGRESSING, f"Migration currently in progress ({target_state})."
    elif target_state == base_state and target_state:
        return MigrationChange.MIGRATION_UNCHANGED, f"Migration state remained {target_state}."

    return MigrationChange.MIGRATION_UNCHANGED, "Migration plan unchanged."
