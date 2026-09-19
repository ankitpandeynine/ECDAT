"""
ECDAT V4 Deep Cryptographic Property Change Detector.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


def detect_property_changes(base: Dict[str, Any], target: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares two instances of an asset across scans to detect fine-grained cryptographic changes:
    - Algorithm transitions (e.g. RSA -> ML-KEM)
    - Key size changes (e.g. 1024 -> 2048)
    - Library version bumps
    - Evidence level promotions/demotions
    - Confidence shifts
    - Status transitions
    """
    diff: Dict[str, Any] = {
        "has_changes": False,
        "changed_properties": [],
        "details": {},
    }

    fields_to_track = [
        ("algorithm", "Algorithm"),
        ("key_size", "Key Size"),
        ("library", "Crypto Library"),
        ("version", "Library Version"),
        ("highest_evidence_level", "Highest Evidence Level"),
        ("status", "Status"),
        ("fused_status", "Fused Corroboration Status"),
    ]

    for field_name, label in fields_to_track:
        val_base = base.get(field_name)
        val_target = target.get(field_name)

        if val_base != val_target:
            diff["has_changes"] = True
            diff["changed_properties"].append(field_name)
            diff["details"][field_name] = {
                "label": label,
                "before": val_base,
                "after": val_target,
            }

    # Numeric delta for confidence
    conf_base = float(base.get("confidence", 0.0))
    conf_target = float(target.get("confidence", 0.0))
    if round(conf_base, 3) != round(conf_target, 3):
        diff["has_changes"] = True
        diff["changed_properties"].append("confidence")
        diff["details"]["confidence"] = {
            "label": "Confidence",
            "before": conf_base,
            "after": conf_target,
            "delta": round(conf_target - conf_base, 4),
        }

    return diff
