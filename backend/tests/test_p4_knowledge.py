"""
ECDAT V4 P4.1 Knowledge Base Versioning & Provenance Tests.

Verifies:
- Federated knowledge base loading
- Deterministic knowledge hash computation
- File existence and SHA-256 integrity verification
- Rule, algorithm, and migration mapping counting
- Path traversal protection in manifest source paths
- REST API endpoint contracts for knowledge base metadata
"""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine.knowledge_version import (
    KnowledgeBaseVersion,
    compute_deterministic_knowledge_hash,
    compute_file_sha256,
    load_knowledge_version,
)
from main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    return TestClient(app)


class TestKnowledgeBaseVersioning:
    def test_knowledge_base_version_loads_successfully(self):
        kb = load_knowledge_version()
        assert kb.version == "2024.1"
        assert kb.knowledge_base_version == "2024.1"
        assert kb.knowledge_base_id == "ecdat-v4-crypto-knowledge"
        assert kb.schema_version == "1.0.0"
        assert kb.engine_version == "4.0.0"

    def test_all_sources_verified_and_exist(self):
        kb = load_knowledge_version()
        assert len(kb.sources) == 8
        for src in kb.sources:
            assert src["verified"] is True
            assert len(src["sha256"]) == 64
            assert src["items_count"] > 0

    def test_algorithm_and_rule_counts(self):
        kb = load_knowledge_version()
        assert kb.algorithm_count >= 30
        assert kb.migration_mapping_count >= 5
        assert kb.rule_count >= 100

    def test_deterministic_knowledge_hash(self):
        kb1 = load_knowledge_version()
        kb2 = load_knowledge_version()
        assert kb1.knowledge_hash == kb2.knowledge_hash
        assert kb1.checksum == kb2.checksum
        assert len(kb1.knowledge_hash) == 64

    def test_knowledge_hash_changes_if_source_modified(self):
        orig_hash = compute_deterministic_knowledge_hash(
            kb_id="test",
            kb_version="2024.1",
            schema_version="1.0.0",
            sources_summary=[{"id": "s1", "file": "f1.yaml", "version": "1", "content_type": "t", "actual_sha256": "aaaa"}],
        )
        mod_hash = compute_deterministic_knowledge_hash(
            kb_id="test",
            kb_version="2024.1",
            schema_version="1.0.0",
            sources_summary=[{"id": "s1", "file": "f1.yaml", "version": "1", "content_type": "t", "actual_sha256": "bbbb"}],
        )
        assert orig_hash != mod_hash

    def test_path_traversal_in_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            malicious_manifest = tmp_path / "bad_manifest.yaml"
            data = {
                "knowledge_base_id": "bad-kb",
                "knowledge_base_version": "2024.1",
                "sources": [
                    {"id": "exploit", "file": "../../etc/passwd", "sha256": "0000"}
                ]
            }
            with open(malicious_manifest, "w", encoding="utf-8") as f:
                yaml.dump(data, f)

            with pytest.raises(ValueError, match="Path traversal"):
                load_knowledge_version(malicious_manifest)

    def test_missing_source_file_raises_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            manifest = tmp_path / "manifest.yaml"
            data = {
                "knowledge_base_id": "test",
                "knowledge_base_version": "2024.1",
                "sources": [
                    {"id": "nonexistent", "file": "ghost_file.yaml", "sha256": "1234"}
                ]
            }
            with open(manifest, "w", encoding="utf-8") as f:
                yaml.dump(data, f)

            with pytest.raises(FileNotFoundError):
                load_knowledge_version(manifest)

    def test_api_knowledge_version_endpoint(self, client):
        resp = client.get("/api/knowledge/version")
        assert resp.status_code == 200
        data = resp.json()
        assert data["knowledge_base_version"] == "2024.1"
        assert len(data["knowledge_hash"]) == 64
        assert "provenance" in data
        assert "compatibility_notes" in data

    def test_api_knowledge_summary_endpoint(self, client):
        resp = client.get("/api/knowledge/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["knowledge_base_version"] == "2024.1"
        assert data["algorithm_count"] >= 30
        assert data["rule_count"] >= 100
        assert len(data["sources"]) == 8
