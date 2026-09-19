"""
ECDAT V4 Agility Rules Engine.

Loads crypto_agility_rules.yaml and provides a deterministic evaluator.
Rules are matched against observable evidence signals and context.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import yaml

from .models import AgilityDimension, AgilityReason, AgilityState


_KB_PATH = Path(__file__).resolve().parent.parent.parent / "knowledge" / "crypto_agility_rules.yaml"


class AgilityRulesEngine:
    """Generic deterministic evaluator for crypto_agility_rules.yaml."""

    def __init__(self, kb_path: Optional[str] = None):
        self.path = Path(kb_path) if kb_path else _KB_PATH
        self.version = "2024.1"
        self.rules: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            self.version = data.get("version", "2024.1")
            self.rules = data.get("rules", [])

    def get_rules_for_dimension(self, dimension: AgilityDimension) -> List[Dict[str, Any]]:
        dim_str = dimension.value if hasattr(dimension, "value") else str(dimension)
        return [r for r in self.rules if r.get("dimension") == dim_str]

    def match_rule(self, rule: Dict[str, Any], signals: Set[str]) -> bool:
        """Determines if the rule's required evidence signals are satisfied."""
        req = rule.get("required_evidence", [])
        if not req:
            return False
        # Rule matches if any/all required evidence is present depending on condition definition
        # By default, all required evidence tokens in the rule list must be present in signals
        return all(s in signals for s in req)
