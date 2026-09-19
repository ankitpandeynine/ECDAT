"""Google AI Studio / Gemini API Cryptographic Security Assistant.

Implements Section 46 and Experimental Phase 5/8 of the ECDAT specification:
- AI-assisted explanations, natural-language posture summaries, custom crypto triage,
  and migration advisories using Google AI Studio / Gemini API.
- STRICT ADHERENCE TO ECDAT CRYPTO EPISTEMOLOGY:
  - LLM is an assistive advisor, NOT authoritative ground truth.
  - Outputs are explicitly tagged as INFERENCE or ADVISORY.
  - Graceful fallback: If GEMINI_API_KEY is not configured or network is unavailable,
    deterministic cryptographic knowledge rules are used instead.
"""
from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AITriageRequest(BaseModel):
    code_snippet: str
    file_path: Optional[str] = "unknown_source.py"
    api_key: Optional[str] = None


class AIExplainRequest(BaseModel):
    algorithm: str
    cryptographic_role: Optional[str] = "GENERAL"
    key_size: Optional[int] = None
    quantum_vulnerable: Optional[bool] = None
    data_lifetime_years: Optional[int] = 10
    business_criticality: Optional[str] = "CRITICAL"
    api_key: Optional[str] = None


class AIMigrationAdvisoryRequest(BaseModel):
    current_algorithm: str
    cryptographic_role: str
    data_lifetime_years: int = 15
    environment: str = "PRODUCTION"
    api_key: Optional[str] = None


class AIAnalysisResult(BaseModel):
    provider: str  # "google_ai_studio_gemini" or "deterministic_engine"
    model: str
    verdict: str
    confidence: float
    summary: str
    technical_details: Dict[str, Any] = Field(default_factory=dict)
    recommendation: str
    nist_references: List[str] = Field(default_factory=list)
    is_authoritative: bool = False  # Always False per ECDAT Section 46


class GeminiSecurityAssistant:
    """Enterprise Cryptographic Assistant powered by Google AI Studio / Gemini API."""

    DEFAULT_MODEL = "gemini-1.5-flash"

    @classmethod
    def get_api_key(cls, explicit_key: Optional[str] = None) -> Optional[str]:
        return explicit_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    @classmethod
    def call_gemini_api(
        cls,
        prompt: str,
        system_instruction: str,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL
    ) -> Optional[str]:
        """Invokes Google AI Studio Gemini API via HTTPS REST with strict timeouts."""
        key = cls.get_api_key(api_key)
        if not key:
            return None

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": prompt}
                    ]
                }
            ],
            "systemInstruction": {
                "parts": [
                    {"text": system_instruction}
                ]
            },
            "generationConfig": {
                "temperature": 0.1,
                "topP": 0.95,
                "maxOutputTokens": 1024,
                "responseMimeType": "application/json"
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    candidates = resp_data.get("candidates", [])
                    if candidates:
                        content_parts = candidates[0].get("content", {}).get("parts", [])
                        if content_parts:
                            return content_parts[0].get("text", "")
        except Exception:
            return None
        return None

    @classmethod
    def triage_custom_crypto(cls, request: AITriageRequest) -> AIAnalysisResult:
        """Triages potentially hand-rolled or non-standard cryptographic code."""
        code = request.code_snippet
        sys_prompt = (
            "You are an enterprise cryptographic audit AI assistant for ECDAT. "
            "Analyze the provided code snippet for ad-hoc, hand-rolled cryptography vs benign non-cryptographic logic. "
            "Return JSON matching keys: is_custom_crypto (bool), classification (str: CUSTOM_CIPHER, CUSTOM_PRNG, "
            "CUSTOM_HASH, or NON_CRYPTO), confidence (float 0.0-1.0), summary (str), "
            "technical_risks (list of str), recommendation (str)."
        )
        prompt = f"File: {request.file_path}\nCode:\n```\n{code}\n```"

        raw_json = cls.call_gemini_api(prompt, sys_prompt, request.api_key)
        if raw_json:
            try:
                data = json.loads(raw_json)
                return AIAnalysisResult(
                    provider="google_ai_studio_gemini",
                    model=cls.DEFAULT_MODEL,
                    verdict=data.get("classification", "CUSTOM_CRYPTO_SUSPECT"),
                    confidence=float(data.get("confidence", 0.85)),
                    summary=data.get("summary", "Gemini detected potential custom cryptographic constructs."),
                    technical_details={
                        "is_custom_crypto": data.get("is_custom_crypto", True),
                        "classification": data.get("classification", "CUSTOM_CIPHER"),
                        "technical_risks": data.get("technical_risks", [])
                    },
                    recommendation=data.get("recommendation", "Refactor to standard FIPS-approved primitives."),
                    nist_references=["NIST SP 800-175B", "NIST SP 800-56A/B"],
                    is_authoritative=False
                )
            except Exception:
                pass

        # Deterministic Fallback Engine
        has_xor = "^" in code
        has_shift = "<<" in code or ">>" in code
        has_sbox = "sbox" in code.lower() or "s_box" in code.lower()
        has_crypto_words = any(w in code.lower() for w in ["encrypt", "decrypt", "cipher", "keystream"])

        if (has_xor and (has_shift or has_sbox)) or (has_crypto_words and has_xor):
            return AIAnalysisResult(
                provider="deterministic_engine",
                model="ecdat_semantic_triage_v4",
                verdict="CUSTOM_CIPHER",
                confidence=0.85,
                summary="Suspicious bitwise permutation, XOR mixing, and custom cryptographic loop detected.",
                technical_details={
                    "is_custom_crypto": True,
                    "classification": "CUSTOM_CIPHER",
                    "indicators": ["xor_operation", "bitwise_shift" if has_shift else "sbox_reference"]
                },
                recommendation="Replace custom mixing routines with standard primitives (e.g. AES-GCM or ChaCha20-Poly1305 via standard library).",
                nist_references=["NIST SP 800-38D", "FIPS 197"],
                is_authoritative=False
            )

        return AIAnalysisResult(
            provider="deterministic_engine",
            model="ecdat_semantic_triage_v4",
            verdict="NON_CRYPTO",
            confidence=0.90,
            summary="No custom cryptographic primitives or unapproved cipher constructs identified in snippet.",
            technical_details={"is_custom_crypto": False, "classification": "NON_CRYPTO"},
            recommendation="Standard code pattern; no cryptographic remediation required.",
            nist_references=[],
            is_authoritative=False
        )

    @classmethod
    def explain_asset_quantum_risk(cls, request: AIExplainRequest) -> AIAnalysisResult:
        """Explains quantum and classical vulnerability context for an asset."""
        algo = request.algorithm.upper()
        role = request.cryptographic_role or "GENERAL"

        sys_prompt = (
            "You are a post-quantum cryptographic migration specialist for ECDAT. "
            "Explain the quantum risk, Mosca timeline relevance, and transition path for this cryptographic asset. "
            "Return JSON matching keys: vulnerability_summary (str), shor_grover_impact (str), "
            "recommended_pqc_target (str), migration_urgency (str: CRITICAL, HIGH, MEDIUM, LOW), "
            "guidance (str)."
        )
        prompt = (
            f"Algorithm: {algo}\n"
            f"Role: {role}\n"
            f"Key Size: {request.key_size}\n"
            f"Quantum Vulnerable: {request.quantum_vulnerable}\n"
            f"Data Lifetime Years: {request.data_lifetime_years}\n"
            f"Business Criticality: {request.business_criticality}"
        )

        raw_json = cls.call_gemini_api(prompt, sys_prompt, request.api_key)
        if raw_json:
            try:
                data = json.loads(raw_json)
                return AIAnalysisResult(
                    provider="google_ai_studio_gemini",
                    model=cls.DEFAULT_MODEL,
                    verdict=data.get("migration_urgency", "HIGH"),
                    confidence=0.92,
                    summary=data.get("vulnerability_summary", f"{algo} assessed for quantum exposure."),
                    technical_details={
                        "shor_grover_impact": data.get("shor_grover_impact", ""),
                        "recommended_pqc_target": data.get("recommended_pqc_target", ""),
                        "migration_urgency": data.get("migration_urgency", "HIGH")
                    },
                    recommendation=data.get("guidance", "Stage migration to NIST FIPS 203/204 standards."),
                    nist_references=["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "NIST SP 800-227"],
                    is_authoritative=False
                )
            except Exception:
                pass

        # Deterministic Knowledge Rules
        is_asymmetric_shor = any(k in algo for k in ["RSA", "ECDSA", "ECDH", "DSA", "DH", "ED25519", "SECP"])
        if is_asymmetric_shor:
            target = "ML-KEM-768 / X25519 Hybrid" if "KEM" in role or "KEY" in role or "DH" in algo else "ML-DSA-65 (Dilithium3)"
            urgency = "CRITICAL" if (request.data_lifetime_years or 10) >= 10 else "HIGH"
            return AIAnalysisResult(
                provider="deterministic_engine",
                model="ecdat_knowledge_v4",
                verdict=urgency,
                confidence=0.98,
                summary=f"{algo} relies on number-theoretic hardness assumptions completely broken by Shor's algorithm on Cryptanalytically Relevant Quantum Computers (CRQCs).",
                technical_details={
                    "threat_mechanism": "Shor's Algorithm (polynomial time discrete log / factoring)",
                    "hndl_relevance": "High exposure if traffic can be passively intercepted and stored.",
                    "pqc_target": target,
                    "migration_mode": "HYBRID_TRANSITION"
                },
                recommendation=f"Implement hybrid key establishment or dual signature wrappers transitioning to {target}.",
                nist_references=["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST SP 800-56C Rev 2"],
                is_authoritative=False
            )

        return AIAnalysisResult(
            provider="deterministic_engine",
            model="ecdat_knowledge_v4",
            verdict="LOW",
            confidence=0.95,
            summary=f"{algo} is a symmetric or hashing primitive subject only to Grover's quadratic speedup (effective security halved).",
            technical_details={
                "threat_mechanism": "Grover's Algorithm (O(2^(n/2)) complexity)",
                "pqc_target": "AES-256-GCM / SHA-384 / SHA-512",
                "hndl_relevance": "Negligible for 256-bit symmetric primitives."
            },
            recommendation="Ensure 256-bit key length is enforced for post-quantum security margin.",
            nist_references=["NIST SP 800-131A Rev 2", "NIST IR 8413"],
            is_authoritative=False
        )

    @classmethod
    def generate_migration_advisory(cls, request: AIMigrationAdvisoryRequest) -> AIAnalysisResult:
        """Provides architecture-level PQC migration advisory."""
        algo = request.current_algorithm.upper()
        role = request.cryptographic_role.upper()

        sys_prompt = (
            "You are a Senior Cryptographic Architect advising an enterprise on PQC migration. "
            "Produce an actionable, phased migration plan covering prerequisites, target primitives, "
            "deployment mode, and rollback considerations. "
            "Return JSON matching keys: target_primitive (str), migration_mode (str), "
            "prerequisites (list of str), phases (list of dict with 'name' and 'action'), "
            "rollback_strategy (str), advisory_summary (str)."
        )
        prompt = (
            f"Current Algorithm: {algo}\n"
            f"Role: {role}\n"
            f"Data Lifetime Years: {request.data_lifetime_years}\n"
            f"Environment: {request.environment}"
        )

        raw_json = cls.call_gemini_api(prompt, sys_prompt, request.api_key)
        if raw_json:
            try:
                data = json.loads(raw_json)
                return AIAnalysisResult(
                    provider="google_ai_studio_gemini",
                    model=cls.DEFAULT_MODEL,
                    verdict="PQC_MIGRATION_ADVISORY_READY",
                    confidence=0.94,
                    summary=data.get("advisory_summary", f"Migration path formulated for {algo}."),
                    technical_details=data,
                    recommendation=f"Deploy {data.get('target_primitive', 'ML-KEM/ML-DSA')} using {data.get('migration_mode', 'HYBRID_TRANSITION')}.",
                    nist_references=["NIST FIPS 203", "NIST FIPS 204", "NIST FIPS 205"],
                    is_authoritative=False
                )
            except Exception:
                pass

        # Deterministic Advisory Model
        is_kem = "EXCHANGE" in role or "AGREEMENT" in role or "KEM" in role or "ENCRYPTION" in role or "DH" in algo
        target = "X25519 + ML-KEM-768 Hybrid" if is_kem else "ML-DSA-65 (Dilithium) / Composite Signature"
        mode = "HYBRID_TRANSITION" if request.environment == "PRODUCTION" else "DIRECT_REPLACEMENT"

        return AIAnalysisResult(
            provider="deterministic_engine",
            model="ecdat_migration_advisor_v4",
            verdict="PQC_MIGRATION_ADVISORY_READY",
            confidence=0.96,
            summary=f"Staged transition from legacy {algo} to {target} utilizing {mode}.",
            technical_details={
                "target_primitive": target,
                "migration_mode": mode,
                "prerequisites": [
                    "Audit dependent crypto libraries for liboqs / OpenSSL 3.2+ support.",
                    "Verify transport MTU handles increased ciphertext/public key size (~1,184 bytes for ML-KEM-768).",
                    "Establish baseline cryptographic inventory and closed-loop verification scans."
                ],
                "phases": [
                    {"phase": 1, "name": "Discovery & Baseline", "action": "Lock inventory and verify baseline scan."},
                    {"phase": 2, "name": "Dual/Hybrid Staging", "action": f"Deploy {mode} alongside legacy {algo}."},
                    {"phase": 3, "name": "Closed-Loop Verification", "action": "Run verification re-scan to prove legacy removal."},
                    {"phase": 4, "name": "Full PQC Cutover", "action": "Decommission legacy key material and archive proof."}
                ],
                "rollback_strategy": "Maintain fallback to classical suite during Phase 2 via crypto-agility negotiation headers."
            },
            recommendation=f"Adopt {target} via {mode} to preserve FIPS compliance while mitigating quantum HNDL risks.",
            nist_references=["NIST FIPS 203", "NIST SP 800-56C Rev 2", "IETF RFC 9180"],
            is_authoritative=False
        )
