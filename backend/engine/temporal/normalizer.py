"""
ECDAT V4 Deterministic Asset Key Normalizer.

Ensures crypto assets observed across different scans are uniquely and
deterministically bound across time.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Optional

from ..asset_graph import CryptoAsset
from ..evidence_fusion import extract_primitive_canonical_name


def compute_asset_key(asset: Dict[str, Any] | CryptoAsset) -> str:
    """
    Computes a deterministic, collision-resistant asset key.
    Derived from:
    - asset_type
    - canonical algorithm
    - key size (if present)
    - canonical name / location context
    Never uses random UUIDs or database IDs.
    """
    if hasattr(asset, "to_dict"):
        data = asset.to_dict()
    else:
        data = dict(asset)

    asset_type = str(data.get("asset_type", "UNKNOWN")).strip().upper()
    name = str(data.get("name", "")).strip()
    raw_algo = str(data.get("algorithm", "") or "").strip()
    key_size = data.get("key_size")

    # If algorithm is not explicit, extract from name
    if not raw_algo and name:
        extracted_algo, extracted_size = extract_primitive_canonical_name(name)
        canon_algo = extracted_algo
        if key_size is None:
            key_size = extracted_size
    else:
        canon_algo, extracted_size = extract_primitive_canonical_name(raw_algo)
        if key_size is None:
            key_size = extracted_size

    # Clean name of dynamic session tokens or random IDs
    clean_name = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "", name, flags=re.I)
    clean_name = clean_name.strip().lower()

    # Deployment or path context if available
    path_context = (
        data.get("file_path")
        or data.get("artifact_id")
        or data.get("library")
        or ""
    ).strip().lower()

    tokens = [
        f"type={asset_type}",
        f"name={clean_name}",
        f"algo={canon_algo.upper() if canon_algo else 'UNKNOWN'}",
    ]
    if path_context:
        tokens.append(f"ctx={path_context}")

    token_str = "|".join(tokens)
    key_hash = hashlib.sha256(token_str.encode("utf-8")).hexdigest()[:16]
    
    # Return human-readable prefix with deterministic hash
    type_tag = asset_type.lower()
    algo_tag = (canon_algo or "unknown").lower().replace(" ", "-").replace("/", "-")
    return f"{type_tag}:{algo_tag}:{key_hash}"


def normalize_asset(asset: Dict[str, Any] | CryptoAsset) -> Dict[str, Any]:
    """Ensures asset dict has canonical fields and computed asset_key."""
    if hasattr(asset, "to_dict"):
        data = asset.to_dict()
    else:
        data = dict(asset)

    if "asset_key" not in data or not data["asset_key"]:
        data["asset_key"] = compute_asset_key(data)

    algo, ksize = extract_primitive_canonical_name(str(data.get("algorithm") or data.get("name") or ""))
    if not data.get("algorithm"):
        data["algorithm"] = algo
    if data.get("key_size") is None:
        data["key_size"] = ksize

    return data
