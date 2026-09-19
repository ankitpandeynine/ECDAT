import os
import json
import sqlite3
import tempfile
import time
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

from engine.evidence_model import (
    EvidenceState,
    EvidenceLevel,
    ObservationType,
    ArtifactType,
    Provenance,
    Evidence,
    LEVEL_RANK,
)
from engine.scan_manifest import (
    ScanManifest,
    canonical_json,
    compute_sha256,
    sanitize_secrets,
)
from engine.asset_graph import (
    AssetGraphService,
    CryptoAsset,
    RelationshipType,
)
from engine.evidence_fusion import (
    EvidenceFusionEngine,
    CorroborationStatus,
)
from engine.sandbox import (
    SandboxExecutor,
    SandboxConfig,
    SandboxStatus,
)
from engine.scan_store import ScanStore
from engine.source_scan import scan_sources
from engine.binary_deep import scan_upload
from engine.network_prober import probe_tls_endpoint
from main import app


def insert_test_scan(store: ScanStore, scan_id: str, project: str = "p1") -> None:
    with store.connect() as db:
        db.execute(
            """INSERT OR IGNORE INTO scans (
                id, project, kind, status, created_at, input_hash
            ) VALUES (?, ?, 'code', 'completed', ?, 'test-hash')""",
            (scan_id, project, "2026-09-17T00:00:00Z"),
        )


# ---------------------------------------------------------------------------
# Test 1: Evidence State Enum
# ---------------------------------------------------------------------------
def test_evidence_state_enum():
    expected_states = {
        "MEASURED", "INFERRED", "ESTIMATED", "DECLARED",
        "UNMEASURED", "EXTRAPOLATED", "NOT_APPLICABLE"
    }
    actual_states = {s.value for s in EvidenceState}
    assert expected_states.issubset(actual_states)


# ---------------------------------------------------------------------------
# Test 2: Evidence Level Enum
# ---------------------------------------------------------------------------
def test_evidence_level_enum():
    expected_levels = ["E0", "E1", "E2", "E3", "E4", "E5"]
    actual_levels = [l.value for l in EvidenceLevel]
    assert actual_levels == expected_levels

    # Verify monotonic ranking order
    ranks = [LEVEL_RANK[l] for l in EvidenceLevel]
    assert ranks == sorted(ranks)
    assert LEVEL_RANK[EvidenceLevel.E0] < LEVEL_RANK[EvidenceLevel.E1] < LEVEL_RANK[EvidenceLevel.E5]


# ---------------------------------------------------------------------------
# Test 3: Observation Type Enum
# ---------------------------------------------------------------------------
def test_observation_type_enum():
    expected_types = {
        "TLS_NEGOTIATION", "X509_CERTIFICATE", "PQC_NEGOTIATION",
        "BINARY_SIGNATURE", "BINARY_REFERENCE", "HARDCODED_KEY",
        "SOURCE_API_USE", "SOURCE_PATTERN", "DEPENDENCY_DECLARATION",
        "PROTOCOL_OBSERVATION", "RUNTIME_CALL", "CONFIGURATION"
    }
    actual_types = {t.value for t in ObservationType}
    assert expected_types.issubset(actual_types)


# ---------------------------------------------------------------------------
# Test 4: Confidence Independent of Evidence Level
# ---------------------------------------------------------------------------
def test_confidence_independent_of_level():
    prov = Provenance(scan_id="scan-123", engine_version="4.0.0")

    # High confidence heuristic pattern (E1, 0.95)
    e_low_level_high_conf = Evidence(
        id="e-1",
        state=EvidenceState.INFERRED,
        level=EvidenceLevel.E1,
        confidence=0.95,
        observation_type=ObservationType.SOURCE_PATTERN,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="source_pattern_matcher",
        description="Regex pattern match",
        provenance=prov,
    )

    # Low confidence dynamic probe (E5, 0.40, e.g. noisy network observation)
    e_high_level_low_conf = Evidence(
        id="e-2",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E5,
        confidence=0.40,
        observation_type=ObservationType.TLS_NEGOTIATION,
        artifact_type=ArtifactType.NETWORK_ENDPOINT,
        source_engine="network_prober",
        description="Weak noisy TLS probe",
        provenance=prov,
    )

    assert e_low_level_high_conf.level == EvidenceLevel.E1
    assert e_low_level_high_conf.confidence == 0.95

    assert e_high_level_low_conf.level == EvidenceLevel.E5
    assert e_high_level_low_conf.confidence == 0.40

    # Ensure to_dict keeps them strictly separate
    d1 = e_low_level_high_conf.to_dict()
    d2 = e_high_level_low_conf.to_dict()
    assert d1["level"] == "E1" and d1["confidence"] == 0.95
    assert d2["level"] == "E5" and d2["confidence"] == 0.40


# ---------------------------------------------------------------------------
# Test 5: Provenance Immutability & Fields
# ---------------------------------------------------------------------------
def test_provenance_immutability():
    prov = Provenance(
        scan_id="scan-abc",
        scanner_version="4.0.0",
        engine_version="4.0.0",
        rule_version="2026.09",
        environment={"os": "Linux", "arch": "x86_64"},
        parameters={"depth": 3},
    )
    assert prov.scan_id == "scan-abc"
    assert prov.scanner_version == "4.0.0"
    assert prov.environment["os"] == "Linux"
    assert prov.parameters["depth"] == 3


# ---------------------------------------------------------------------------
# Test 6: Evidence Serialization Roundtrip
# ---------------------------------------------------------------------------
def test_evidence_serialization():
    prov = Provenance(
        scan_id="scan-xyz",
        scanner_version="4.0.0",
        engine_version="4.0.0",
        rule_version="1.0",
        environment={"os": "Windows"},
        parameters={"timeout": 10},
    )
    ev = Evidence(
        id="ev-test-1",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E5,
        confidence=0.99,
        observation_type=ObservationType.TLS_NEGOTIATION,
        artifact_type=ArtifactType.NETWORK_ENDPOINT,
        source_engine="network_prober",
        engine_version="4.0.0",
        rule_id="RULE-TLS-001",
        rule_version="1.0",
        file_path="example.com:443",
        line_start=None,
        line_end=None,
        byte_offset=None,
        symbol=None,
        description="Negotiated TLS_AES_256_GCM_SHA384",
        provenance=prov,
        metadata={"cipher": "TLS_AES_256_GCM_SHA384"},
    )
    d = ev.to_dict()
    restored = Evidence.from_dict(d)

    assert restored.id == ev.id
    assert restored.state == ev.state
    assert restored.level == ev.level
    assert restored.confidence == ev.confidence
    assert restored.observation_type == ev.observation_type
    assert restored.description == ev.description
    assert restored.provenance.scan_id == "scan-xyz"
    assert restored.metadata["cipher"] == "TLS_AES_256_GCM_SHA384"


# ---------------------------------------------------------------------------
# Test 7: Manifest Creation
# ---------------------------------------------------------------------------
def test_manifest_creation():
    manifest = ScanManifest.create(
        scan_id="scan-001",
        scan_kind="code",
        input_data={"files": [{"path": "main.py", "content": "import hashlib"}]},
        config={"target": "default", "timeout": 30},
        toolchain={"python": "3.14.0", "engine": "4.0.0"},
    )
    assert manifest.scan_id == "scan-001"
    assert manifest.scan_kind == "code"
    assert manifest.input_hash.startswith("sha256:")
    assert manifest.configuration_hash.startswith("sha256:")
    assert manifest.environment.os_name != ""
    assert manifest.environment.python_version != ""
    assert manifest.result_hash == ""  # Not finalized yet


# ---------------------------------------------------------------------------
# Test 8: Manifest Deterministic Hashing
# ---------------------------------------------------------------------------
def test_manifest_hashing():
    input_data = {"b": 2, "a": 1, "nested": {"z": 10, "y": 20}}
    h1 = compute_sha256(canonical_json(input_data))

    # Permuted key order in dictionary
    input_data_permuted = {"nested": {"y": 20, "z": 10}, "a": 1, "b": 2}
    h2 = compute_sha256(canonical_json(input_data_permuted))

    assert h1 == h2
    assert len(h1) == 64


# ---------------------------------------------------------------------------
# Test 9: Manifest Reproducibility
# ---------------------------------------------------------------------------
def test_manifest_reproducibility():
    payload = {"target": "localhost", "port": 443}
    m1 = ScanManifest.create(scan_id="s1", scan_kind="network", input_data=payload)
    m2 = ScanManifest.create(scan_id="s2", scan_kind="network", input_data=payload)

    # Different scan IDs, but identical input payload produces identical input_hash
    assert m1.input_hash == m2.input_hash

    # Finalizing both with identical results produces identical result_hash
    res = {"cipher": "AES_256_GCM", "pqc": False}
    m1.finalize_result(res)
    m2.finalize_result(res)
    assert m1.result_hash == m2.result_hash


# ---------------------------------------------------------------------------
# Test 10: Manifest Secret Scrubbing
# ---------------------------------------------------------------------------
def test_manifest_secret_scrubbing():
    sensitive_config = {
        "api_token": "secret-token-123456",
        "password": "SuperSecretPassword!",
        "auth_header": "Bearer my-secret-jwt",
        "nested": {
            "private_key": "-----BEGIN PRIVATE KEY-----...",
            "safe_param": 42
        }
    }
    scrubbed = sanitize_secrets(sensitive_config)
    assert scrubbed["api_token"] == "[REDACTED]"
    assert scrubbed["password"] == "[REDACTED]"
    assert scrubbed["auth_header"] == "[REDACTED]"
    assert scrubbed["nested"]["private_key"] == "[REDACTED]"
    assert scrubbed["nested"]["safe_param"] == 42


# ---------------------------------------------------------------------------
# Test 11: SQLite Foreign Keys Enforced
# ---------------------------------------------------------------------------
def test_sqlite_foreign_keys_enforced(tmp_path):
    db_path = str(tmp_path / "test_fk.db")
    store = ScanStore(path=db_path)

    with store.connect() as db:
        # Check foreign_keys pragma is 1 (ON)
        fk_status = db.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk_status == 1

        # Attempting to insert an evidence row with a non-existent asset_id must fail
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("""
                INSERT INTO evidence (
                    id, asset_id, scan_id, project, state, level, confidence,
                    source_engine, engine_version, observation_type, artifact_type,
                    description, data, created_at
                ) VALUES (
                    'ev-orphan', 'non-existent-asset-id', 'scan-1', 'default',
                    'MEASURED', 'E5', 0.9, 'test', '4.0.0', 'TLS_NEGOTIATION',
                    'NETWORK_ENDPOINT', 'desc', '{}', '2026-09-17T00:00:00Z'
                )
            """)
    store.close()


# ---------------------------------------------------------------------------
# Test 12: SQLite WAL Mode Enforced
# ---------------------------------------------------------------------------
def test_sqlite_wal_mode(tmp_path):
    db_path = str(tmp_path / "test_wal.db")
    store = ScanStore(path=db_path)
    with store.connect() as db:
        journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        assert journal_mode.lower() == "wal"
    store.close()


# ---------------------------------------------------------------------------
# Test 13: Crypto Asset Creation & Storage
# ---------------------------------------------------------------------------
def test_asset_creation(tmp_path):
    db_path = str(tmp_path / "test_asset.db")
    store = ScanStore(path=db_path)
    insert_test_scan(store, "scan-xyz", "proj-1")
    graph = store.graph

    asset = graph.create_asset(
        project="proj-1",
        asset_type="ALGORITHM",
        name="RSA-2048",
        algorithm="RSA",
        key_size=2048,
        library="cryptography",
        scan_id="scan-xyz",
        status="ACTIVE",
        fused_status="CORROBORATED",
        highest_evidence_level="E3",
        confidence=0.92,
        explanation="Detected via AST call"
    )

    fetched = graph.get_asset(asset.id, project="proj-1")
    assert fetched is not None
    assert fetched.name == "RSA-2048"
    assert fetched.algorithm == "RSA"
    assert fetched.key_size == 2048
    assert fetched.library == "cryptography"
    assert fetched.highest_evidence_level == "E3"
    assert fetched.confidence == 0.92
    assert fetched.fused_status == "CORROBORATED"
    store.close()


# ---------------------------------------------------------------------------
# Test 14: Asset Evidence Association
# ---------------------------------------------------------------------------
def test_asset_evidence_association(tmp_path):
    db_path = str(tmp_path / "test_assoc.db")
    store = ScanStore(path=db_path)
    insert_test_scan(store, "scan-1", "proj-1")
    graph = store.graph

    asset = graph.create_asset(
        project="proj-1",
        asset_type="ALGORITHM",
        name="AES-256",
        algorithm="AES",
        key_size=256,
        scan_id="scan-1",
    )

    e1 = Evidence(
        id="ev-ast-1",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E3,
        confidence=0.95,
        observation_type=ObservationType.SOURCE_API_USE,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="python_ast_visitor",
        description="AES.new call in cipher.py",
        file_path="cipher.py",
        line_start=10,
        provenance=Provenance(scan_id="scan-1"),
    )
    e2 = Evidence(
        id="ev-dep-2",
        state=EvidenceState.DECLARED,
        level=EvidenceLevel.E2,
        confidence=0.85,
        observation_type=ObservationType.DEPENDENCY_DECLARATION,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="dependency_analyzer",
        description="pycryptodome in requirements.txt",
        file_path="requirements.txt",
        provenance=Provenance(scan_id="scan-1"),
    )

    graph.add_evidence(asset.id, e1, project="proj-1")
    graph.add_evidence(asset.id, e2, project="proj-1")

    evidence_list = graph.get_asset_evidence(asset.id)
    assert len(evidence_list) == 2
    ids = {item["id"] for item in evidence_list}
    assert ids == {"ev-ast-1", "ev-dep-2"}
    store.close()


# ---------------------------------------------------------------------------
# Test 15: Graph Edge Creation with Various Relationship Types
# ---------------------------------------------------------------------------
def test_graph_edge_creation(tmp_path):
    db_path = str(tmp_path / "test_edges.db")
    store = ScanStore(path=db_path)
    graph = store.graph

    # Create 3 entities
    app = graph.create_asset("p1", "APPLICATION", "PaymentApp")
    serv = graph.create_asset("p1", "SERVICE", "AuthService")
    algo = graph.create_asset("p1", "ALGORITHM", "RSA-2048")

    # Connect with relationships: Application DEPENDS_ON Service; Service USES Algorithm
    graph.add_relationship("p1", app.id, "APPLICATION", RelationshipType.DEPENDS_ON, serv.id, "SERVICE")
    graph.add_relationship("p1", serv.id, "SERVICE", RelationshipType.USES, algo.id, "ALGORITHM")

    edges = graph.get_relationships(project="p1")
    assert len(edges) == 2
    assert {e["relationship"] for e in edges} == {"DEPENDS_ON", "USES"}
    store.close()


# ---------------------------------------------------------------------------
# Test 16: Graph Cycle Handling (Blast Radius Does Not Infinite Loop)
# ---------------------------------------------------------------------------
def test_graph_cycle_handling(tmp_path):
    db_path = str(tmp_path / "test_cycle.db")
    store = ScanStore(path=db_path)
    graph = store.graph

    # A -> B -> C -> A (cyclic dependency)
    a = graph.create_asset("p1", "SERVICE", "NodeA")
    b = graph.create_asset("p1", "SERVICE", "NodeB")
    c = graph.create_asset("p1", "SERVICE", "NodeC")

    # A depends on B, B depends on C, C depends on A
    graph.add_relationship("p1", a.id, "SERVICE", "DEPENDS_ON", b.id, "SERVICE")
    graph.add_relationship("p1", b.id, "SERVICE", "DEPENDS_ON", c.id, "SERVICE")
    graph.add_relationship("p1", c.id, "SERVICE", "DEPENDS_ON", a.id, "SERVICE")

    blast = graph.get_blast_radius(c.id)
    assert blast["target_node_id"] == c.id
    assert blast["total_impacted_count"] == 2
    impacted_ids = {n["id"] for n in blast["impacted_assets"]}
    assert {a.id, b.id} == impacted_ids
    store.close()


# ---------------------------------------------------------------------------
# Test 17: Blast Radius Traversal from Single Leaf Asset
# ---------------------------------------------------------------------------
def test_blast_radius_single_asset(tmp_path):
    db_path = str(tmp_path / "test_blast.db")
    store = ScanStore(path=db_path)
    graph = store.graph

    # App -> uses -> Lib -> implements -> Primitive
    app = graph.create_asset("p1", "APPLICATION", "Portal")
    lib = graph.create_asset("p1", "LIBRARY", "crypto-core")
    prim = graph.create_asset("p1", "ALGORITHM", "DES-56")

    graph.add_relationship("p1", app.id, "APPLICATION", "DEPENDS_ON", lib.id, "LIBRARY")
    graph.add_relationship("p1", lib.id, "LIBRARY", "USES", prim.id, "ALGORITHM")

    # Blast radius of vulnerable primitive DES-56
    blast = graph.get_blast_radius(prim.id)
    impacted_ids = {n["id"] for n in blast["impacted_assets"]}
    assert lib.id in impacted_ids
    assert app.id in impacted_ids
    assert blast["total_impacted_count"] == 2
    store.close()


# ---------------------------------------------------------------------------
# Test 18: Blast Radius for Shared Library (Fan-Out)
# ---------------------------------------------------------------------------
def test_blast_radius_shared_library(tmp_path):
    db_path = str(tmp_path / "test_shared.db")
    store = ScanStore(path=db_path)
    graph = store.graph

    # OpenSSL shared library used by multiple services
    openssl = graph.create_asset("p1", "LIBRARY", "OpenSSL-1.0.2")
    service1 = graph.create_asset("p1", "SERVICE", "Gateway")
    service2 = graph.create_asset("p1", "SERVICE", "BackendAPI")
    service3 = graph.create_asset("p1", "SERVICE", "AuthServer")

    graph.add_relationship("p1", service1.id, "SERVICE", "DEPENDS_ON", openssl.id, "LIBRARY")
    graph.add_relationship("p1", service2.id, "SERVICE", "DEPENDS_ON", openssl.id, "LIBRARY")
    graph.add_relationship("p1", service3.id, "SERVICE", "DEPENDS_ON", openssl.id, "LIBRARY")

    blast = graph.get_blast_radius(openssl.id)
    impacted_ids = {n["id"] for n in blast["impacted_assets"]}
    assert {service1.id, service2.id, service3.id}.issubset(impacted_ids)
    assert blast["total_impacted_count"] == 3
    store.close()


# ---------------------------------------------------------------------------
# Test 19: Evidence Fusion Single Source
# ---------------------------------------------------------------------------
def test_fusion_single_source(tmp_path):
    db_path = str(tmp_path / "test_fusion_single.db")
    store = ScanStore(path=db_path)
    insert_test_scan(store, "s1", "p1")
    fusion = store.fusion

    e = Evidence(
        id="e-single",
        state=EvidenceState.INFERRED,
        level=EvidenceLevel.E1,
        confidence=0.80,
        observation_type=ObservationType.SOURCE_PATTERN,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="source_pattern_matcher",
        description="Pattern match for RSA",
        provenance=Provenance(scan_id="s1"),
    )

    asset_dict = fusion.fuse_asset_findings(
        project="p1",
        scan_id="s1",
        asset_name="RSA",
        algorithm="RSA",
        evidence_items=[e],
    )

    assert asset_dict["fused_status"] == CorroborationStatus.SINGLE_SOURCE.value
    assert asset_dict["highest_evidence_level"] == "E1"
    assert asset_dict["confidence"] == 0.80
    assert "Single-source observation" in asset_dict["explanation"]
    store.close()


# ---------------------------------------------------------------------------
# Test 20: Evidence Fusion Corroboration
# ---------------------------------------------------------------------------
def test_fusion_corroboration(tmp_path):
    db_path = str(tmp_path / "test_fusion_corrob.db")
    store = ScanStore(path=db_path)
    insert_test_scan(store, "s1", "p1")
    fusion = store.fusion

    e1 = Evidence(
        id="e-ast",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E3,
        confidence=0.90,
        observation_type=ObservationType.SOURCE_API_USE,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="python_ast_visitor",
        description="AST parse detected RSA key gen",
        provenance=Provenance(scan_id="s1"),
    )
    e2 = Evidence(
        id="e-pat",
        state=EvidenceState.INFERRED,
        level=EvidenceLevel.E1,
        confidence=0.85,
        observation_type=ObservationType.SOURCE_PATTERN,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="source_pattern_matcher",
        description="Regex pattern detected RSA",
        provenance=Provenance(scan_id="s1"),
    )

    asset_dict = fusion.fuse_asset_findings(
        project="p1",
        scan_id="s1",
        asset_name="RSA",
        algorithm="RSA",
        evidence_items=[e1, e2],
    )

    assert asset_dict["fused_status"] == CorroborationStatus.CORROBORATED.value
    assert asset_dict["highest_evidence_level"] == "E3"
    # Combined confidence must exceed single engine confidence
    assert asset_dict["confidence"] > 0.90
    assert "Corroborated across 2 sources" in asset_dict["explanation"]
    store.close()


# ---------------------------------------------------------------------------
# Test 21: Evidence Fusion Static + Dynamic Corroboration
# ---------------------------------------------------------------------------
def test_fusion_static_dynamic_corroboration(tmp_path):
    db_path = str(tmp_path / "test_static_dyn.db")
    store = ScanStore(path=db_path)
    insert_test_scan(store, "s-static", "p1")
    insert_test_scan(store, "s-dynamic", "p1")
    fusion = store.fusion

    # Static AST (E3) + Dynamic TLS negotiation (E5)
    e_static = Evidence(
        id="e-static-ast",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E3,
        confidence=0.92,
        observation_type=ObservationType.SOURCE_API_USE,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="python_ast_visitor",
        description="Static config specifies TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        provenance=Provenance(scan_id="s-static"),
    )
    e_dynamic = Evidence(
        id="e-dyn-tls",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E5,
        confidence=0.99,
        observation_type=ObservationType.TLS_NEGOTIATION,
        artifact_type=ArtifactType.NETWORK_ENDPOINT,
        source_engine="network_prober",
        description="Live TLS handshake confirmed ECDHE-RSA-AES256-GCM-SHA384",
        provenance=Provenance(scan_id="s-dynamic"),
    )

    asset_dict = fusion.fuse_asset_findings(
        project="p1",
        scan_id="s-dynamic",
        asset_name="ECDHE-RSA-AES256",
        algorithm="ECDHE-RSA-AES256",
        evidence_items=[e_static, e_dynamic],
    )

    assert asset_dict["fused_status"] == CorroborationStatus.CORROBORATED.value
    assert asset_dict["highest_evidence_level"] == "E5"
    assert asset_dict["confidence"] >= 0.99
    assert "python_ast_visitor" in asset_dict["explanation"]
    assert "network_prober" in asset_dict["explanation"]
    store.close()


# ---------------------------------------------------------------------------
# Test 22: Evidence Fusion Contradiction Detection
# ---------------------------------------------------------------------------
def test_fusion_contradiction(tmp_path):
    db_path = str(tmp_path / "test_contradiction.db")
    store = ScanStore(path=db_path)
    insert_test_scan(store, "s1", "p1")
    insert_test_scan(store, "s2", "p1")
    fusion = store.fusion

    # Static says RSA, Dynamic observes ECDSA certificate
    e_static = Evidence(
        id="e-static-rsa",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E3,
        confidence=0.88,
        observation_type=ObservationType.SOURCE_API_USE,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="python_ast_visitor",
        description="Source code configures RSA key",
        metadata={"primitive": "RSA"},
        provenance=Provenance(scan_id="s1"),
    )
    e_dynamic = Evidence(
        id="e-dyn-ecdsa",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E5,
        confidence=0.99,
        observation_type=ObservationType.X509_CERTIFICATE,
        artifact_type=ArtifactType.NETWORK_ENDPOINT,
        source_engine="network_prober",
        description="Dynamic endpoint serves ECDSA certificate",
        metadata={"primitive": "ECDSA"},
        provenance=Provenance(scan_id="s2"),
    )

    asset_dict = fusion.fuse_asset_findings(
        project="p1",
        scan_id="s2",
        asset_name="EndpointCrypto",
        algorithm="MULTI",
        evidence_items=[e_static, e_dynamic],
    )

    assert asset_dict["fused_status"] == CorroborationStatus.CONTRADICTED.value
    assert "CONTRADICTION DETECTED" in asset_dict["explanation"]
    store.close()


# ---------------------------------------------------------------------------
# Test 23: Evidence Fusion Confidence Computation
# ---------------------------------------------------------------------------
def test_fusion_confidence_computation():
    fusion = EvidenceFusionEngine(graph_service=None)

    c_single = 0.80
    e1 = Evidence(
        id="1", state=EvidenceState.MEASURED, level=EvidenceLevel.E1,
        confidence=c_single, observation_type=ObservationType.SOURCE_PATTERN,
        artifact_type=ArtifactType.SOURCE_FILE, source_engine="engine_a",
        description="test", provenance=Provenance(scan_id="s"),
    )
    e2 = Evidence(
        id="2", state=EvidenceState.MEASURED, level=EvidenceLevel.E2,
        confidence=c_single, observation_type=ObservationType.BINARY_SIGNATURE,
        artifact_type=ArtifactType.BINARY, source_engine="engine_b",
        description="test", provenance=Provenance(scan_id="s"),
    )

    res = fusion.compute_corroboration([e1, e2])
    assert res.fused_status == CorroborationStatus.CORROBORATED
    assert res.combined_confidence > c_single
    assert pytest.approx(res.combined_confidence, 0.001) == 0.96


# ---------------------------------------------------------------------------
# Test 24: Explanation String Generation
# ---------------------------------------------------------------------------
def test_explanation_generation():
    fusion = EvidenceFusionEngine(graph_service=None)
    e1 = Evidence(
        id="e-rule",
        state=EvidenceState.MEASURED,
        level=EvidenceLevel.E3,
        confidence=0.91,
        observation_type=ObservationType.SOURCE_API_USE,
        artifact_type=ArtifactType.SOURCE_FILE,
        source_engine="python_ast_visitor",
        rule_id="RULE-PY-042",
        description="AST detected RSA",
        provenance=Provenance(scan_id="s1"),
    )
    explanation = fusion.generate_explanation([e1], CorroborationStatus.SINGLE_SOURCE)

    assert "python_ast_visitor" in explanation
    assert "E3" in explanation
    assert "RULE-PY-042" in explanation
    assert "Single-source observation" in explanation


# ---------------------------------------------------------------------------
# Test 25: Scanner Normalization — Source Scanner
# ---------------------------------------------------------------------------
def test_scanner_normalization_source():
    code = """
import hashlib
def do_hash(data):
    return hashlib.md5(data).hexdigest()
"""
    result = scan_sources([{"path": "hash.py", "content": code, "language": "python"}])
    assert "evidence" in result
    evidence_list = result["evidence"]
    assert len(evidence_list) >= 1

    # Python AST should emit E3 level with SOURCE_API_USE
    ast_items = [e for e in evidence_list if e["level"] == "E3"]
    assert len(ast_items) >= 1
    assert ast_items[0]["observation_type"] == "SOURCE_API_USE"
    assert ast_items[0]["file_path"] == "hash.py"


# ---------------------------------------------------------------------------
# Test 26: Scanner Normalization — Binary Scanner
# ---------------------------------------------------------------------------
def test_scanner_normalization_binary():
    from engine.binary_scanner import AES_SBOX_PREFIX, MD5_IV_LITTLE

    raw_payload = b"HEADER" + bytes(AES_SBOX_PREFIX) + b"MIDDLE" + bytes(MD5_IV_LITTLE) + b"FOOTER"
    result = scan_upload(raw_payload, "test.bin")

    assert "evidence" in result
    evidence_list = result["evidence"]
    assert len(evidence_list) >= 2

    for item in evidence_list:
        assert item["level"] in ("E1", "E2", "E3")
        assert item["observation_type"] in ("BINARY_SIGNATURE", "BINARY_REFERENCE")
        assert item["state"] in ("MEASURED", "INFERRED")


# ---------------------------------------------------------------------------
# Test 27: Scanner Normalization — Network Prober
# ---------------------------------------------------------------------------
def test_scanner_normalization_network(monkeypatch):
    import engine.network_prober as prober
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timezone, timedelta

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=90)).sign(key, hashes.SHA256())
    der_bytes = cert.public_bytes(serialization.Encoding.DER)

    class MockConn:
        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        def version(self):
            return "TLSv1.3"
        def getpeercert(self, binary_form=True):
            return der_bytes
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass

    monkeypatch.setattr(prober, 'resolve_target', lambda *a: (2, ('127.0.0.1', 443)))
    monkeypatch.setattr(prober, '_handshake', lambda *a, **k: MockConn())
    monkeypatch.setattr(prober, 'probe_pqc', lambda *a, **k: {"status": "scanner_unavailable", "pqc_hybrid_supported": False, "tests": []})

    result = prober.probe_tls_endpoint("localhost", 443)
    assert result['status'] == 'success'
    assert 'evidence' in result
    evidence_list = result['evidence']
    assert len(evidence_list) >= 2
    assert any(e['level'] == 'E5' and e['observation_type'] == 'TLS_NEGOTIATION' for e in evidence_list)
    assert any(e['level'] == 'E5' and e['observation_type'] == 'X509_CERTIFICATE' for e in evidence_list)


# ---------------------------------------------------------------------------
# Test 28: Sandbox Workspace Isolation
# ---------------------------------------------------------------------------
def test_sandbox_workspace_isolation():
    sandbox = SandboxExecutor(SandboxConfig(timeout_seconds=5))

    def worker(workspace: Path) -> dict:
        test_file = workspace / "sandbox_test.txt"
        test_file.write_text("isolated content")
        assert test_file.exists()
        return {"created_file": str(test_file), "exists": test_file.exists()}

    result = sandbox.run_isolated(worker)
    assert result.status == SandboxStatus.SUCCESS
    created_path = Path(result.result["created_file"])
    # Workspace directory must be deleted/cleaned up after execution
    assert not created_path.exists()
    assert not created_path.parent.exists()


# ---------------------------------------------------------------------------
# Test 29: Sandbox Timeout
# ---------------------------------------------------------------------------
def test_sandbox_timeout():
    sandbox = SandboxExecutor(SandboxConfig(timeout_seconds=1))

    # A command that sleeps longer than timeout
    cmd = [sys.executable, "-c", "import time; time.sleep(5)"]
    result = sandbox.run_command(cmd)

    assert result.status == SandboxStatus.TIMEOUT
    assert "timed out" in result.error.lower()


# ---------------------------------------------------------------------------
# Test 30: Sandbox Output Limits
# ---------------------------------------------------------------------------
def test_sandbox_output_limits():
    max_bytes = 500
    sandbox = SandboxExecutor(SandboxConfig(timeout_seconds=5, max_output_bytes=max_bytes))

    cmd = [sys.executable, "-c", "print('A' * 5000)"]
    result = sandbox.run_command(cmd)

    assert result.status == SandboxStatus.OUTPUT_LIMIT_EXCEEDED
    assert len(result.stdout) <= max_bytes + 200  # Including truncation notice
    assert "truncated" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Test 31: API Endpoints — Scan Evidence & Manifest
# ---------------------------------------------------------------------------
def test_api_scans_evidence_and_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_DB", str(tmp_path / "api_test.sqlite3"))
    monkeypatch.delenv("ECDAT_API_TOKEN", raising=False)

    with TestClient(app) as client:
        # Submit a code scan with MD5
        code = "import hashlib\ndef h(x): return hashlib.md5(x).digest()"
        resp = client.post("/api/scan/code?project=p_api", json={"source_code": code, "language": "python"})
        assert resp.status_code == 202
        scan_id = resp.json()["id"]

        # Wait for scan completion
        for _ in range(100):
            r = client.get(f"/api/scans/{scan_id}?project=p_api").json()
            if r["status"] == "completed":
                break
            time.sleep(0.05)

        # 1. Test GET /api/scans/{scan_id}/evidence
        ev_resp = client.get(f"/api/scans/{scan_id}/evidence?project=p_api")
        assert ev_resp.status_code == 200
        ev_list = ev_resp.json()
        assert isinstance(ev_list, list)
        assert len(ev_list) >= 1

        # 2. Test GET /api/scans/{scan_id}/manifest
        man_resp = client.get(f"/api/scans/{scan_id}/manifest?project=p_api")
        assert man_resp.status_code == 200
        manifest = man_resp.json()
        assert manifest["scan_id"] == scan_id
        assert manifest["input_hash"].startswith("sha256:")
        assert manifest["result_hash"].startswith("sha256:")

        # 3. Test GET /api/scans/{scan_id}/graph
        graph_resp = client.get(f"/api/scans/{scan_id}/graph?project=p_api")
        assert graph_resp.status_code == 200
        graph_data = graph_resp.json()
        assert "nodes" in graph_data
        assert "links" in graph_data


# ---------------------------------------------------------------------------
# Test 32: API Endpoints — Assets & Blast Radius
# ---------------------------------------------------------------------------
def test_api_assets_and_blast_radius(tmp_path, monkeypatch):
    monkeypatch.setenv("ECDAT_DB", str(tmp_path / "api_test2.sqlite3"))
    monkeypatch.delenv("ECDAT_API_TOKEN", raising=False)

    with TestClient(app) as client:
        # Submit code scan to populate assets
        code = "import hashlib\ndef h(x): return hashlib.md5(x).digest()"
        resp = client.post("/api/scan/code?project=proj_assets", json={"source_code": code, "language": "python"})
        scan_id = resp.json()["id"]

        for _ in range(100):
            r = client.get(f"/api/scans/{scan_id}?project=proj_assets").json()
            if r["status"] == "completed":
                break
            time.sleep(0.05)

        # 1. GET /api/assets
        assets_resp = client.get("/api/assets?project=proj_assets")
        assert assets_resp.status_code == 200
        assets = assets_resp.json()
        assert len(assets) >= 1
        asset_id = assets[0]["id"]

        # 2. GET /api/assets/{asset_id}
        asset_detail = client.get(f"/api/assets/{asset_id}?project=proj_assets")
        assert asset_detail.status_code == 200
        assert asset_detail.json()["id"] == asset_id

        # 3. GET /api/assets/{asset_id}/evidence
        asset_ev = client.get(f"/api/assets/{asset_id}/evidence?project=proj_assets")
        assert asset_ev.status_code == 200
        assert isinstance(asset_ev.json(), list)

        # 4. GET /api/assets/{asset_id}/relationships
        asset_rel = client.get(f"/api/assets/{asset_id}/relationships?project=proj_assets")
        assert asset_rel.status_code == 200
        assert "outbound" in asset_rel.json()
        assert "inbound" in asset_rel.json()

        # 5. GET /api/assets/{asset_id}/blast-radius
        blast_resp = client.get(f"/api/assets/{asset_id}/blast-radius?project=proj_assets")
        assert blast_resp.status_code == 200
        blast = blast_resp.json()
        assert blast["target_node_id"] == asset_id
        assert "impacted_assets" in blast
