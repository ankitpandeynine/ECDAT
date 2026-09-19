"""
ECDAT V4 P3 Migration Rules Engine.

Loads backend/knowledge/pqc_migration_knowledge.yaml without mutating P2.1 semantics
and provides rule matching for role-aware target selection and priority calculation.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


KNOWLEDGE_PATH = Path(__file__).resolve().parents[2] / "knowledge" / "pqc_migration_knowledge.yaml"


class MigrationRulesEngine:
    """Provides access to authoritative PQC replacement rules and hybrid semantics."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or KNOWLEDGE_PATH
        self.rules: Dict[str, Any] = {}
        self.version = "2024.1"
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as f:
                self.rules = yaml.safe_load(f) or {}
                self.version = str(self.rules.get("version", "2024.1"))
        else:
            self.rules = {
                "version": "2024.1",
                "migration_targets": {
                    "KEY_ESTABLISHMENT": {
                        "pqc_target": "ML-KEM-768 (FIPS 203)",
                        "hybrid_target": "X25519MLKEM768",
                        "rationale": "ML-KEM provides PQC key encapsulation.",
                    },
                    "SIGNATURE": {
                        "pqc_target": "ML-DSA-65 (FIPS 204)",
                        "alternative_target": "SLH-DSA (FIPS 205)",
                        "rationale": "ML-DSA provides lattice-based signatures.",
                    },
                    "SYMMETRIC_ENCRYPTION": {
                        "pqc_target": "AES-256 with authenticated mode (AES-256-GCM)",
                        "rationale": "Grover halving: AES-256 retains ~128-bit post-quantum security.",
                    },
                },
            }

    def get_target_for_role(self, role: str) -> Optional[Dict[str, Any]]:
        """Looks up the authoritative replacement mapping for a given cryptographic role."""
        targets = self.rules.get("migration_targets", {})
        return targets.get(role.upper())

    def get_hybrid_semantics(self) -> List[Dict[str, Any]]:
        """Returns hybrid KEX definitions."""
        return self.rules.get("hybrid_semantics", [])
