"""
ECDAT V4 P3 Migration Normalizer & Context Synthesizer.

Canonicalizes cryptographic roles, synthesizes inputs from P0/P1/P2 assessments,
and computes deterministic SHA-256 evidence and configuration hashes.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from .models import MigrationContext


ROLE_MAP = {
    # Key Establishment / KEM
    "KEY_ESTABLISHMENT": "KEY_ESTABLISHMENT",
    "KEY_EXCHANGE": "KEY_ESTABLISHMENT",
    "KEX": "KEY_ESTABLISHMENT",
    "KEM": "KEY_ESTABLISHMENT",
    "KEY_ENCAPSULATION": "KEY_ESTABLISHMENT",
    "KEY_AGREEMENT": "KEY_ESTABLISHMENT",

    # Digital Signatures
    "SIGNATURE": "SIGNATURE",
    "DIGITAL_SIGNATURE": "SIGNATURE",
    "AUTHENTICATION": "SIGNATURE",
    "CERTIFICATE_SIGNATURE": "CERTIFICATE_SIGNATURE",
    "CERT_SIGNATURE": "CERTIFICATE_SIGNATURE",

    # Symmetric Encryption
    "ENCRYPTION": "SYMMETRIC_ENCRYPTION",
    "SYMMETRIC": "SYMMETRIC_ENCRYPTION",
    "SYMMETRIC_ENCRYPTION": "SYMMETRIC_ENCRYPTION",
    "BLOCK_CIPHER": "SYMMETRIC_ENCRYPTION",

    # Hashing
    "HASH": "HASHING",
    "HASHING": "HASHING",
    "DIGEST": "HASHING",
    "MESSAGE_DIGEST": "HASHING",
}


def normalize_cryptographic_role(role: Any, algorithm: str = "") -> str:
    """Canonicalizes a cryptographic role, inferring from algorithm or role string."""
    raw = str(role or "").strip().upper().replace("-", "_").replace(" ", "_")
    algo = str(algorithm or "").strip().upper().replace("-", "_").replace(" ", "_")

    combined = f"{raw}_{algo}"
    if "UNKNOWN" in combined:
        return "UNKNOWN"

    if raw in ROLE_MAP:
        return ROLE_MAP[raw]
    if algo in ROLE_MAP:
        return ROLE_MAP[algo]

    if any(k in combined for k in ("CERT", "X509")):
        return "CERTIFICATE_SIGNATURE"
    if any(k in combined for k in ("KEM", "DH", "ECDH", "X25519", "KYBER", "KEX", "KEY_EXCHANGE")):
        return "KEY_ESTABLISHMENT"
    if any(k in combined for k in ("DSA", "ECDSA", "ED25519", "DILITHIUM", "SPHINCS", "FALCON", "SIGN")):
        return "SIGNATURE"
    if any(k in combined for k in ("AES", "DES", "CHACHA", "3DES", "RC4", "BLOCK_CIPHER", "SYMMETRIC")):
        return "SYMMETRIC_ENCRYPTION"
    if any(k in combined for k in ("SHA", "MD5", "BLAKE", "HASH", "DIGEST")):
        return "HASHING"

    return "UNKNOWN"


def build_migration_context(
    asset: Dict[str, Any],
    risk_assessment: Optional[Dict[str, Any]] = None,
    pqc_readiness: Optional[Dict[str, Any]] = None,
    agility_assessment: Optional[Dict[str, Any]] = None,
    blast_radius: Optional[Dict[str, Any]] = None,
    evidence_items: Optional[List[Any]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> MigrationContext:
    """Synthesizes all authoritative upstream intelligence into a single MigrationContext."""
    asset_id = str(asset.get("id") or asset.get("asset_id") or "UNKNOWN")
    scan_id = asset.get("scan_id")
    project_id = asset.get("project") or asset.get("project_id")
    algo = str(asset.get("algorithm") or asset.get("name") or "")

    raw_role = asset.get("cryptographic_role") or asset.get("role") or (context or {}).get("cryptographic_role")
    role = normalize_cryptographic_role(raw_role, algorithm=algo)

    # Collect evidence references
    ev_refs = set()
    if evidence_items:
        for e in evidence_items:
            eid = e.get("id") if isinstance(e, dict) else getattr(e, "id", None)
            if eid:
                ev_refs.add(str(eid))

    if blast_radius and "evidence_refs" in blast_radius:
        ev_refs.update(blast_radius["evidence_refs"])
    if risk_assessment and "evidence_refs" in risk_assessment:
        ev_refs.update(risk_assessment["evidence_refs"])

    # Extract dependency paths from blast radius
    dep_paths = []
    if blast_radius and "dependency_paths" in blast_radius:
        for p in blast_radius["dependency_paths"]:
            dep_paths.append(p if isinstance(p, dict) else p.to_dict())

    params = dict(asset.get("parameters") or (context or {}).get("parameters") or {})
    if asset.get("key_size"):
        params["key_size"] = asset["key_size"]

    return MigrationContext(
        asset_id=asset_id,
        scan_id=scan_id,
        project_id=project_id,
        algorithm=algo,
        cryptographic_role=role,
        parameters=params,
        risk_assessment=dict(risk_assessment or {}),
        pqc_readiness=dict(pqc_readiness or {}),
        agility_assessment=dict(agility_assessment or {}),
        blast_radius=dict(blast_radius or {}),
        dependency_paths=dep_paths,
        evidence_refs=sorted(list(ev_refs)),
        limitations=list((context or {}).get("limitations") or []),
        knowledge_base_version="2024.1",
        engine_version="4.0.0",
    )


def compute_migration_evidence_hash(evidence_refs: List[Any]) -> str:
    """Deterministic SHA-256 hash over sorted evidence identifiers."""
    cleaned: List[str] = []
    for item in evidence_refs:
        if isinstance(item, dict):
            cid = item.get("id") or item.get("evidence_id")
            cleaned.append(str(cid) if cid else json.dumps(item, sort_keys=True))
        else:
            cleaned.append(str(item))
    encoded = json.dumps(sorted(list(set(cleaned)))).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()



def compute_migration_config_hash(context: Dict[str, Any]) -> str:
    """Deterministic SHA-256 hash over migration planning inputs."""
    encoded = json.dumps(context, sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
