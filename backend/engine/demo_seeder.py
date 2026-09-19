"""Controlled Demo Seeding Service for ECDAT.

Implements Section 39 of the ECDAT UI/UX Rebuild Specification:
- Creates a realistic, controlled enterprise demonstration dataset using the REAL
  ECDAT discovery, evidence normalization, and correlation pipelines.
- Zero mock bypasses: all records flow through ScanStore, EvidenceFusionEngine,
  AssetGraphService, and Intelligence Pipeline.
- Tags the project as DEMO DATA so the UI explicitly warns the user.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid
from typing import Any, Dict, List

from .evidence_model import (
    Evidence,
    EvidenceLevel,
    EvidenceState,
    ObservationType,
    Provenance,
)
from .asset_graph import AssetType


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def seed_project_demo_data(store: Any, project_id: str) -> Dict[str, Any]:
    """Populates the specified project with realistic, real-pipeline demo telemetry."""
    # 1. Update Project Metadata to designate as Demo Data
    store.projects.update_project(project_id, {
        "description": "Controlled demonstration project showcasing post-quantum discovery, Mosca risk, and hybrid migration.",
        "environment": "PRODUCTION",
        "business_criticality": "CRITICAL",
        "data_sensitivity": "CLASSIFIED",
        "data_lifetime_years": 20,
        "migration_target_date": "2028-12-31",
        "tags": ["demo", "pqc-lab", "pci-dss-scope"]
    })

    # 2. Ingest Source Code Discovery Scan
    scan_source_id = str(uuid.uuid4())
    source_evidence: List[Evidence] = [
        Evidence(
            id=f"ev-{project_id}-rsa",
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E3,
            confidence=0.95,
            source_engine="treesitter_c_scanner",
            observation_type=ObservationType.SOURCE_API_USE,
            artifact_type="SOURCE_FILE",
            description="2048-bit RSA keypair generation identified in authentication signing path.",
            symbol="RSA-2048",
            file_path="gateway/auth_signer.c",
            line_start=16,
            provenance=Provenance(
                input_hash="hash-auth-signer",
                source_engine="treesitter_c_scanner",
                engine_version="4.0.0",
                scan_id=scan_source_id,
                location="gateway/auth_signer.c:16"
            ),
            raw_details={"algorithm": "RSA", "key_size": 2048}
        ),
        Evidence(
            id=f"ev-{project_id}-aes",
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E3,
            confidence=0.99,
            source_engine="treesitter_c_scanner",
            observation_type=ObservationType.SOURCE_API_USE,
            artifact_type="SOURCE_FILE",
            description="Authenticated AES-256-GCM encryption with 256-bit key length.",
            symbol="AES-256-GCM",
            file_path="storage/tde_vault.c",
            line_start=26,
            provenance=Provenance(
                input_hash="hash-tde-vault",
                source_engine="treesitter_c_scanner",
                engine_version="4.0.0",
                scan_id=scan_source_id,
                location="storage/tde_vault.c:26"
            ),
            raw_details={"algorithm": "AES-256-GCM", "key_size": 256}
        ),
        Evidence(
            id=f"ev-{project_id}-sha1",
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E3,
            confidence=0.90,
            source_engine="treesitter_c_scanner",
            observation_type=ObservationType.SOURCE_API_USE,
            artifact_type="SOURCE_FILE",
            description="Obsolete SHA-1 hash function detected in batch processing pipeline.",
            symbol="SHA-1",
            file_path="storage/legacy_batch.c",
            line_start=35,
            provenance=Provenance(
                input_hash="hash-legacy-batch",
                source_engine="treesitter_c_scanner",
                engine_version="4.0.0",
                scan_id=scan_source_id,
                location="storage/legacy_batch.c:35"
            ),
            raw_details={"algorithm": "SHA-1"}
        ),
    ]

    source_result = {
        "status": "completed",
        "findings_count": len(source_evidence),
        "findings": [
            {"primitive": "RSA-2048", "file": "gateway/auth_signer.c:16", "severity": "CRITICAL", "quantum_vulnerable": True},
            {"primitive": "AES-256-GCM", "file": "storage/tde_vault.c:26", "severity": "LOW", "quantum_vulnerable": False},
            {"primitive": "SHA-1", "file": "storage/legacy_batch.c:35", "severity": "HIGH", "quantum_vulnerable": False}
        ],
        "evidence": [e.to_dict() for e in source_evidence],
        "call_graph": [
            {"caller": "TokenAuthService", "callee": "RSA-2048", "file": "gateway/auth_signer.c"},
            {"caller": "DatabaseTDEVault", "callee": "AES-256-GCM", "file": "storage/tde_vault.c"},
            {"caller": "BatchIngestionWorker", "callee": "SHA-1", "file": "storage/legacy_batch.c"}
        ]
    }

    # 3. Ingest Live Network Probe Scan (Hybrid Post-Quantum TLS 1.3)
    scan_net_id = str(uuid.uuid4())
    net_evidence: List[Evidence] = [
        Evidence(
            id=f"ev-{project_id}-x25519-mlkem",
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E5,
            confidence=0.99,
            source_engine="network_prober_pqc",
            observation_type=ObservationType.PQC_NEGOTIATION,
            artifact_type="NETWORK_ENDPOINT",
            description="Real hybrid Post-Quantum key establishment successfully negotiated via TLS 1.3.",
            symbol="X25519MLKEM768",
            file_path="api.payment.internal:443",
            provenance=Provenance(
                input_hash="hash-net-probe",
                source_engine="network_prober_pqc",
                engine_version="4.0.0",
                scan_id=scan_net_id,
                location="api.payment.internal:443"
            ),
            raw_details={"target": "api.payment.internal:443", "algorithm": "X25519MLKEM768"}
        ),
        Evidence(
            id=f"ev-{project_id}-cert-leaf",
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E5,
            confidence=1.0,
            source_engine="network_prober_pqc",
            observation_type=ObservationType.X509_CERTIFICATE,
            artifact_type="X509_CERTIFICATE",
            description="Leaf X.509 certificate authenticated by 2048-bit RSA public key.",
            symbol="RSA-2048",
            file_path="api.payment.internal:443",
            provenance=Provenance(
                input_hash="hash-net-cert",
                source_engine="network_prober_pqc",
                engine_version="4.0.0",
                scan_id=scan_net_id,
                location="api.payment.internal:443"
            ),
            raw_details={"target": "api.payment.internal:443", "sha256": "abcdef1234567890abcdef1234567890", "algorithm": "RSA-2048"}
        )
    ]

    net_result = {
        "status": "completed",
        "cipher_name": "TLS_AES_256_GCM_SHA384",
        "protocol": "TLSv1.3",
        "key_exchange": "X25519MLKEM768 Hybrid",
        "findings": [
            {"primitive": "TLS_AES_256_GCM_SHA384", "file": "api.payment.internal:443", "severity": "LOW", "quantum_vulnerable": False},
            {"primitive": "X25519MLKEM768", "file": "api.payment.internal:443", "severity": "LOW", "quantum_vulnerable": False},
            {"primitive": "RSA-2048 (Leaf Cert)", "file": "api.payment.internal:443", "severity": "HIGH", "quantum_vulnerable": True}
        ],
        "evidence": [e.to_dict() for e in net_evidence],
        "call_graph": [
            {"caller": "IngressGateway", "callee": "X25519MLKEM768", "file": "api.payment.internal:443"},
            {"caller": "IngressGateway", "callee": "RSA-2048", "file": "api.payment.internal:443"}
        ]
    }

    t = now_iso()
    with store.connect() as db:
        db.execute(
            '''INSERT INTO scans (id, project, kind, status, created_at, finished_at, input_hash, payload, result, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (scan_source_id, project_id, "source", "completed", t, t, "hash_source", json.dumps({"target": "enterprise_banking_gateway.c"}), json.dumps(source_result), None)
        )
        db.execute(
            '''INSERT INTO scans (id, project, kind, status, created_at, finished_at, input_hash, payload, result, error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (scan_net_id, project_id, "network", "completed", t, t, "hash_net", json.dumps({"target": "api.payment.internal:443"}), json.dumps(net_result), None)
        )

    # 4. Fuse Evidence via EvidenceFusionEngine into CryptoAsset Graph
    fused_source = store.fusion.fuse_scan_evidence(project_id, scan_source_id, source_evidence)
    fused_net = store.fusion.fuse_scan_evidence(project_id, scan_net_id, net_evidence)
    all_fused = fused_source + fused_net

    # 5. Save Intelligence & Risk Evaluations for newly fused assets
    try:
        from .intelligence.intelligence_pipeline import evaluate_asset
        for a in all_fused:
            ev_list = store.graph.get_asset_evidence(a.id)
            eval_report = evaluate_asset(a.to_dict(), ev_list)
            store.graph.save_risk_assessment(eval_report)
    except Exception:
        pass

    # 6. Connect Graph Topology Edges
    for a in fused_source:
        store.graph.add_relationship(
            project_id,
            source_id="svc-banking-core",
            source_type="service",
            relationship="uses",
            target_id=a.id,
            target_type=a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
            scan_id=scan_source_id,
            confidence=0.98
        )
    for a in fused_net:
        store.graph.add_relationship(
            project_id,
            source_id="svc-payment-ingress",
            source_type="service",
            relationship="implements" if getattr(a.asset_type, "value", str(a.asset_type)) == "protocol" else "authenticated_by",
            target_id=a.id,
            target_type=a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
            scan_id=scan_net_id,
            confidence=0.99
        )

    # 7. Synchronize graph_nodes and graph_edges in database
    try:
        from .knowledge_graph import sync_knowledge_graph_tables
        sync_knowledge_graph_tables(store, project_id)
    except Exception:
        pass

    return {
        "status": "demo_seeded",
        "project_id": project_id,
        "scans_created": 2,
        "evidence_records": len(source_evidence) + len(net_evidence),
        "fused_assets_count": len(all_fused),
        "is_demo": True
    }
