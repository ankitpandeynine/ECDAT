"""Tests for Google AI Studio / Gemini API Cryptographic Security Assistant."""
from fastapi.testclient import TestClient
import pytest

from main import app
from engine.gemini_assistant import (
    GeminiSecurityAssistant,
    AITriageRequest,
    AIExplainRequest,
    AIMigrationAdvisoryRequest,
)

client = TestClient(app)


def test_triage_custom_crypto_fallback():
    """Test custom crypto triage engine with deterministic fallback."""
    # Hand-rolled cipher with XOR and shift
    custom_code = """
def hand_rolled_encrypt(data, key):
    out = []
    for i, b in enumerate(data):
        out.append((b ^ key) << 2)
    return bytes(out)
"""
    req = AITriageRequest(code_snippet=custom_code, file_path="crypto_util.py")
    res = GeminiSecurityAssistant.triage_custom_crypto(req)
    assert res.verdict == "CUSTOM_CIPHER"
    assert res.is_authoritative is False
    assert res.confidence >= 0.70
    assert "CUSTOM_CIPHER" in str(res.technical_details)

    # Standard benign code
    benign_code = """
def compute_average(items):
    return sum(items) / len(items) if items else 0.0
"""
    b_req = AITriageRequest(code_snippet=benign_code, file_path="stats.py")
    b_res = GeminiSecurityAssistant.triage_custom_crypto(b_req)
    assert b_res.verdict == "NON_CRYPTO"
    assert b_res.is_authoritative is False


def test_explain_asset_quantum_risk():
    """Test asset explainability for Shor-vulnerable vs symmetric algorithms."""
    # RSA-2048
    rsa_req = AIExplainRequest(
        algorithm="RSA-2048",
        cryptographic_role="AUTHENTICATION",
        key_size=2048,
        quantum_vulnerable=True,
        data_lifetime_years=15,
        business_criticality="CRITICAL"
    )
    rsa_res = GeminiSecurityAssistant.explain_asset_quantum_risk(rsa_req)
    assert rsa_res.verdict == "CRITICAL"
    assert "Shor" in rsa_res.summary
    assert "ML-DSA" in str(rsa_res.technical_details) or "ML-KEM" in str(rsa_res.technical_details)

    # AES-256
    aes_req = AIExplainRequest(
        algorithm="AES-256-GCM",
        cryptographic_role="BULK_ENCRYPTION",
        key_size=256,
        quantum_vulnerable=False,
        data_lifetime_years=10,
        business_criticality="HIGH"
    )
    aes_res = GeminiSecurityAssistant.explain_asset_quantum_risk(aes_req)
    assert aes_res.verdict == "LOW"
    assert "Grover" in aes_res.summary


def test_generate_migration_advisory():
    """Test architecture-level PQC migration advisory formulation."""
    req = AIMigrationAdvisoryRequest(
        current_algorithm="ECDH-P256",
        cryptographic_role="KEY_EXCHANGE",
        data_lifetime_years=20,
        environment="PRODUCTION"
    )
    res = GeminiSecurityAssistant.generate_migration_advisory(req)
    assert res.verdict == "PQC_MIGRATION_ADVISORY_READY"
    assert "X25519 + ML-KEM-768 Hybrid" in res.technical_details["target_primitive"]
    assert len(res.technical_details["phases"]) == 4


def test_ai_api_endpoints():
    """Test AI REST API endpoints in backend/main.py."""
    # Triage endpoint
    t_resp = client.post("/api/ai/triage", json={
        "code_snippet": "for i in data: out.append(i ^ 0x42)",
        "file_path": "xor_cipher.py"
    })
    assert t_resp.status_code == 200
    t_data = t_resp.json()
    assert t_data["is_authoritative"] is False
    assert "provider" in t_data

    # Explain endpoint
    e_resp = client.post("/api/ai/explain", json={
        "algorithm": "ECDSA-P256",
        "cryptographic_role": "DIGITAL_SIGNATURE",
        "quantum_vulnerable": True,
        "data_lifetime_years": 10
    })
    assert e_resp.status_code == 200
    e_data = e_resp.json()
    assert "NIST" in str(e_data["nist_references"])

    # Migration advisory endpoint
    m_resp = client.post("/api/ai/migration-advisory", json={
        "current_algorithm": "RSA-3072",
        "cryptographic_role": "DIGITAL_SIGNATURE",
        "data_lifetime_years": 12,
        "environment": "PRODUCTION"
    })
    assert m_resp.status_code == 200
    m_data = m_resp.json()
    assert "phases" in m_data["technical_details"]
