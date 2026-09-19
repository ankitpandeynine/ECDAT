"""
ECDAT V4 Versioned Cryptographic Knowledge Base.

Provides federated knowledge base loading, verification, rule counting,
and deterministic knowledge hash computation across all referenced YAML files.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


_DEFAULT_MANIFEST = Path(__file__).resolve().parent.parent / "knowledge" / "crypto_knowledge.yaml"


@dataclass
class KnowledgeSource:
    id: str
    file: str
    description: str
    content_type: str
    expected_sha256: str
    actual_sha256: str
    verified: bool
    version: Optional[str] = None
    items_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class KnowledgeBaseVersion:
    knowledge_base_id: str
    version: str
    schema_version: str
    engine_version: str
    knowledge_hash: str
    rule_count: int
    algorithm_count: int
    migration_mapping_count: int
    sources: List[Dict[str, Any]]
    compatibility_notes: List[str]
    provenance: Dict[str, Any]

    @property
    def knowledge_base_version(self) -> str:
        return self.version

    @property
    def checksum(self) -> str:
        return self.knowledge_hash

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["knowledge_base_version"] = self.version
        res["checksum"] = self.knowledge_hash
        return res


def compute_file_sha256(path: Path) -> str:
    """Computes standard SHA-256 hex digest of file contents (LF normalized for cross-platform reproducibility)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        data = f.read()
    data = data.replace(b"\r\n", b"\n")
    h.update(data)
    return h.hexdigest()


def compute_deterministic_knowledge_hash(
    kb_id: str,
    kb_version: str,
    schema_version: str,
    sources_summary: List[Dict[str, Any]],
) -> str:
    """
    Computes deterministic SHA-256 over canonical knowledge metadata.
    Excludes machine paths, timestamps, and platform differences.
    """
    canonical_sources = []
    for s in sorted(sources_summary, key=lambda x: x["id"]):
        canonical_sources.append({
            "id": s["id"],
            "file": s["file"],
            "version": s.get("version"),
            "content_type": s.get("content_type"),
            "sha256": s.get("actual_sha256") or s.get("sha256"),
        })

    payload = {
        "knowledge_base_id": kb_id,
        "knowledge_base_version": kb_version,
        "schema_version": schema_version,
        "sources": canonical_sources,
    }
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def load_knowledge_version(manifest_path: Optional[Path | str] = None) -> KnowledgeBaseVersion:
    """
    Loads and validates the federated knowledge base manifest.
    Verifies existence and checksums of all referenced source files,
    aggregates counts, and returns a verified KnowledgeBaseVersion.
    """
    if manifest_path is None:
        target_path = _DEFAULT_MANIFEST
    else:
        target_path = Path(manifest_path).resolve()

    if not target_path.exists():
        raise FileNotFoundError(f"Knowledge manifest not found: {target_path}")

    kb_dir = target_path.parent.resolve()

    with open(target_path, "r", encoding="utf-8") as f:
        manifest_data = yaml.safe_load(f) or {}

    kb_id = manifest_data.get("knowledge_base_id", "ecdat-v4-crypto-knowledge")
    kb_version = str(manifest_data.get("knowledge_base_version", "2024.1"))
    schema_ver = str(manifest_data.get("schema_version", "1.0.0"))
    engine_ver = str(manifest_data.get("engine_version", "4.0.0"))
    provenance = manifest_data.get("provenance", {})
    compat_notes = list(manifest_data.get("compatibility_notes", []))

    raw_sources = manifest_data.get("sources", [])
    verified_sources: List[Dict[str, Any]] = []

    total_algorithms = 0
    total_migration_mappings = 0
    total_rules = 0

    for src in raw_sources:
        src_id = src.get("id", "")
        filename = src.get("file", "")
        # Prevent directory traversal
        if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
            raise ValueError(f"Path traversal detected in knowledge manifest source: {filename}")

        source_file_path = (kb_dir / filename).resolve()
        # Verify it stays strictly within the knowledge base directory
        try:
            source_file_path.relative_to(kb_dir)
        except ValueError:
            raise ValueError(f"Knowledge source escapes knowledge directory: {filename}")

        if not source_file_path.exists():
            raise FileNotFoundError(f"Referenced knowledge source does not exist: {source_file_path}")

        actual_hash = compute_file_sha256(source_file_path)
        expected_hash = src.get("sha256", "")
        is_verified = (actual_hash == expected_hash) if expected_hash else True

        # Parse source to aggregate counts
        with open(source_file_path, "r", encoding="utf-8") as sf:
            content = yaml.safe_load(sf) or {}

        item_count = 0
        if "algorithms" in content and isinstance(content["algorithms"], list):
            count = len(content["algorithms"])
            total_algorithms += count
            item_count += count
        if "migration_targets" in content and isinstance(content["migration_targets"], dict):
            count = len(content["migration_targets"])
            total_migration_mappings += count
            item_count += count
        if "hybrid_semantics" in content and isinstance(content["hybrid_semantics"], list):
            count = len(content["hybrid_semantics"])
            total_migration_mappings += count
            item_count += count
        if "sinks" in content and isinstance(content["sinks"], list):
            count = len(content["sinks"])
            total_rules += count
            item_count += count
        if "signatures" in content and isinstance(content["signatures"], list):
            count = len(content["signatures"])
            total_rules += count
            item_count += count
        if "tls_versions" in content and isinstance(content["tls_versions"], list):
            count = len(content["tls_versions"])
            total_rules += count
            item_count += count
        if "rules" in content:
            r = content["rules"]
            if isinstance(r, list):
                count = len(r)
            elif isinstance(r, dict):
                count = sum(len(v) if isinstance(v, list) else 1 for v in r.values())
            else:
                count = 1
            total_rules += count
            item_count += count
        if "blast_radius_rules" in content and isinstance(content["blast_radius_rules"], list):
            count = len(content["blast_radius_rules"])
            total_rules += count
            item_count += count

        src_record = {
            "id": src_id,
            "file": filename,
            "description": src.get("description", ""),
            "version": src.get("version"),
            "content_type": src.get("content_type", ""),
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash,
            "sha256": actual_hash,
            "verified": is_verified,
            "items_count": item_count,
        }
        verified_sources.append(src_record)

    kb_hash = compute_deterministic_knowledge_hash(
        kb_id=kb_id,
        kb_version=kb_version,
        schema_version=schema_ver,
        sources_summary=verified_sources,
    )

    return KnowledgeBaseVersion(
        knowledge_base_id=kb_id,
        version=kb_version,
        schema_version=schema_ver,
        engine_version=engine_ver,
        knowledge_hash=kb_hash,
        rule_count=total_rules,
        algorithm_count=total_algorithms,
        migration_mapping_count=total_migration_mappings,
        sources=verified_sources,
        compatibility_notes=compat_notes,
        provenance=provenance,
    )
