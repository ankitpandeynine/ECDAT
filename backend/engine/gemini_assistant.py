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

    DEFAULT_MODEL = "gemini-2.0-flash"
    GEMINI_CANDIDATE_MODELS = [
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-1.5-flash-latest",
        "gemini-2.5-flash",
        "gemini-1.5-pro",
        "gemini-pro",
    ]

    @classmethod
    def get_api_key(cls, explicit_key: Optional[str] = None) -> Optional[str]:
        return explicit_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

    @classmethod
    def get_gemini_api_key(cls, explicit_key: Optional[str] = None) -> Optional[str]:
        return cls.get_api_key(explicit_key)

    @classmethod
    def call_gemini_api(
        cls,
        prompt: str,
        system_instruction: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Optional[str]:
        """Invokes Google AI Studio Gemini API via HTTPS REST with strict timeouts and model fallbacks."""
        key = cls.get_api_key(api_key)
        if not key:
            return None

        models_to_try = [model] if model else []
        for m in cls.GEMINI_CANDIDATE_MODELS:
            if m not in models_to_try:
                models_to_try.append(m)

        for mod in models_to_try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{mod}:generateContent?key={key}"
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
            except urllib.error.HTTPError as e:
                # If 404 (model deprecated or not provisioned in project), try next candidate
                if e.code == 404:
                    continue
                return None
            except Exception:
                continue

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

    # =========================================================================
    # NVIDIA NIM API Integration & Conversational Project Context Assistant
    # =========================================================================

    DEFAULT_NVIDIA_MODEL = "nvidia/llama-3.1-nemotron-70b-instruct"
    NVIDIA_CANDIDATE_MODELS = [
        "nvidia/llama-3.1-nemotron-70b-instruct",
        "mistralai/mistral-large-2-instruct",
        "meta/llama-3.2-11b-vision-instruct",
        "nv-mistralai/mistral-nemo-12b-instruct",
    ]
    NVIDIA_NIM_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

    @classmethod
    def get_nvidia_api_key(cls, explicit_key: Optional[str] = None) -> Optional[str]:
        return explicit_key or os.environ.get("NVIDIA_API_KEY") or os.environ.get("NVIDIA_NIM_API_KEY")

    @classmethod
    def call_nvidia_api(
        cls,
        prompt: str,
        system_instruction: str,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> Optional[str]:
        """Invokes NVIDIA NIM API via OpenAI-compatible REST endpoint with model fallback."""
        key = cls.get_nvidia_api_key(api_key)
        if not key:
            return None

        messages = [{"role": "system", "content": system_instruction}]
        if history:
            for m in history:
                messages.append({"role": m.get("role", "user"), "content": m.get("content", "")})
        messages.append({"role": "user", "content": prompt})

        models_to_try = [model] if model else []
        for m in cls.NVIDIA_CANDIDATE_MODELS:
            if m not in models_to_try:
                models_to_try.append(m)

        for mod in models_to_try:
            payload = {
                "model": mod,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": 1024,
                "top_p": 0.95
            }

            req = urllib.request.Request(
                cls.NVIDIA_NIM_URL,
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {key}"
                },
                method="POST"
            )

            try:
                with urllib.request.urlopen(req, timeout=12.0) as resp:
                    if resp.status == 200:
                        resp_data = json.loads(resp.read().decode("utf-8"))
                        choices = resp_data.get("choices", [])
                        if choices:
                            return choices[0].get("message", {}).get("content", "")
            except urllib.error.HTTPError as e:
                # If 410 Gone (model reached EOL) or 404, try next candidate model!
                if e.code in (404, 410):
                    continue
                return None
            except Exception:
                continue

        return None

    @classmethod
    def test_api_key(cls, provider: str, api_key: str) -> Dict[str, Any]:
        """Tests an API key for Gemini or NVIDIA."""
        if not api_key or not api_key.strip():
            return {"ok": False, "error": "API key cannot be empty"}

        cleaned_key = api_key.strip()

        if provider == "gemini":
            # 1. Fetch available models for this specific key via official endpoint
            models_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={cleaned_key}"
            available_models = []
            try:
                req = urllib.request.Request(models_url, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=8.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        for m in data.get("models", []):
                            name = m.get("name", "").replace("models/", "")
                            methods = m.get("supportedGenerationMethods", [])
                            if "generateContent" in methods:
                                available_models.append(name)
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")
                try:
                    err_json = json.loads(err_body)
                    msg = err_json.get("error", {}).get("message")
                    if msg:
                        return {"ok": False, "error": msg}
                except Exception:
                    pass
                return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
            except Exception as e:
                return {"ok": False, "error": f"Connection error: {str(e)}"}

            # Choose best active model
            best_model = None
            for cand in cls.GEMINI_CANDIDATE_MODELS:
                if cand in available_models:
                    best_model = cand
                    break
            if not best_model and available_models:
                best_model = available_models[0]

            display_name = best_model or "gemini-2.0-flash"
            return {
                "ok": True,
                "message": f"Google Gemini API verified ({display_name})",
                "active_model": display_name
            }

        elif provider == "nvidia":
            errors = []
            for cand_model in cls.NVIDIA_CANDIDATE_MODELS:
                try:
                    payload = {
                        "model": cand_model,
                        "messages": [{"role": "user", "content": "Reply with 'OK'"}],
                        "max_tokens": 5
                    }
                    req = urllib.request.Request(
                        cls.NVIDIA_NIM_URL,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {cleaned_key}"
                        },
                        method="POST"
                    )
                    with urllib.request.urlopen(req, timeout=8.0) as resp:
                        if resp.status == 200:
                            return {
                                "ok": True,
                                "message": f"NVIDIA NIM API verified ({cand_model})",
                                "active_model": cand_model
                            }
                        errors.append(f"HTTP {resp.status}")
                except urllib.error.HTTPError as e:
                    err_body = e.read().decode("utf-8", errors="ignore")
                    if e.code in (404, 410):
                        # Retired or not found, try next candidate model
                        continue
                    try:
                        err_json = json.loads(err_body)
                        detail = err_json.get("detail") or err_json.get("message")
                        if detail:
                            return {"ok": False, "error": f"{detail} (HTTP {e.code})"}
                    except Exception:
                        pass
                    return {"ok": False, "error": f"HTTP {e.code}: {e.reason}"}
                except Exception as e:
                    return {"ok": False, "error": f"Connection error: {str(e)}"}

            return {"ok": False, "error": errors[0] if errors else "Authorization failed. Check your NVIDIA API key."}

        return {"ok": False, "error": f"Unsupported provider: {provider}"}

    @classmethod
    def chat_with_context(
        cls,
        question: str,
        context: Optional[Dict[str, Any]] = None,
        history: Optional[List[Dict[str, str]]] = None,
        provider: str = "auto",
        gemini_api_key: Optional[str] = None,
        nvidia_api_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """Conversational security agent with comprehensive project and active-page context."""
        ctx = context or {}
        active_page = ctx.get("active_page", "General Project Overview")
        proj_name = ctx.get("project_name", "Enterprise Cryptographic Inventory")
        total_assets = ctx.get("total_assets", 0)
        quantum_vuln = ctx.get("quantum_vulnerable_assets", 0)
        critical_count = ctx.get("critical_assets", 0)
        findings = ctx.get("recent_findings", [])
        score = ctx.get("security_score", "N/A")
        deficit = ctx.get("mosca_deficit", "N/A")

        system_instruction = (
            "You are the ECDAT Security Intelligence Copilot, an elite post-quantum cryptography (PQC) and cryptographic inventory auditor. "
            "You are assisting a user operating the ECDAT enterprise platform.\n\n"
            f"--- ACTIVE WORKSPACE CONTEXT ---\n"
            f"Active Page/Tab: {active_page}\n"
            f"Project: {proj_name}\n"
            f"Total Discovered Assets: {total_assets}\n"
            f"Quantum-Vulnerable Assets: {quantum_vuln}\n"
            f"Critical/Broken Primitives: {critical_count}\n"
            f"Current Security Score: {score}/100\n"
            f"Mosca Quantum Deficit: {deficit}\n"
            f"Recent Findings/Weaknesses: {json.dumps(findings[:6])}\n\n"
            "--- INSTRUCTIONS ---\n"
            "1. Tailor your answer directly to the user's active page and their specific project metrics when relevant.\n"
            "2. Cite standard standards where applicable: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), NSA CNSA 2.0, RFC 9180 (HPKE).\n"
            "3. Provide direct, highly technical, and actionable guidance.\n"
            "4. Adhere strictly to ECDAT Section 46 epistemology: your response is assistive and advisory, not authoritative ground truth."
        )

        chosen_provider = provider.lower()
        if chosen_provider == "auto":
            if cls.get_gemini_api_key(gemini_api_key):
                chosen_provider = "gemini"
            elif cls.get_nvidia_api_key(nvidia_api_key):
                chosen_provider = "nvidia"
            else:
                chosen_provider = "deterministic"

        reply_text = None
        used_model = "deterministic_rules"
        used_provider = "deterministic_engine"

        if chosen_provider == "gemini":
            reply_text = cls.call_gemini_api(question, system_instruction, gemini_api_key)
            if reply_text:
                used_provider = "google_ai_studio_gemini"
                used_model = cls.DEFAULT_MODEL
            else:
                # Fallback to NVIDIA if available
                if cls.get_nvidia_api_key(nvidia_api_key):
                    reply_text = cls.call_nvidia_api(question, system_instruction, nvidia_api_key, history=history)
                    if reply_text:
                        used_provider = "nvidia_nim"
                        used_model = cls.DEFAULT_NVIDIA_MODEL

        elif chosen_provider == "nvidia":
            reply_text = cls.call_nvidia_api(question, system_instruction, nvidia_api_key, history=history)
            if reply_text:
                used_provider = "nvidia_nim"
                used_model = cls.DEFAULT_NVIDIA_MODEL
            else:
                # Fallback to Gemini if available
                if cls.get_gemini_api_key(gemini_api_key):
                    reply_text = cls.call_gemini_api(question, system_instruction, gemini_api_key)
                    if reply_text:
                        used_provider = "google_ai_studio_gemini"
                        used_model = cls.DEFAULT_MODEL

        # Fallback to Deterministic Expert System if no API keys or calls failed
        if not reply_text:
            used_provider = "deterministic_engine"
            used_model = "ecdat_expert_knowledge_v4"
            q_lower = question.lower()

            if "active page" in q_lower or "where am i" in q_lower or "current page" in q_lower:
                reply_text = (
                    f"You are currently viewing the **{active_page}** page.\n\n"
                    f"**Project Summary ({proj_name})**:\n"
                    f"- **Total Cryptographic Assets**: {total_assets}\n"
                    f"- **Quantum-Exposed Assets**: {quantum_vuln} (Subject to Shor's algorithm)\n"
                    f"- **Critical Vulnerabilities**: {critical_count}\n"
                    f"- **Current Posture Score**: {score}/100\n\n"
                    f"On this page, you can analyze your inventory, track migration progress, or trigger automated remediation."
                )
            elif "quantum" in q_lower or "shor" in q_lower or "pqc" in q_lower:
                reply_text = (
                    f"### Quantum Vulnerability Analysis for {proj_name}\n\n"
                    f"Currently, **{quantum_vuln} of your {total_assets} cryptographic assets** are vulnerable to Cryptanalytically Relevant Quantum Computers (CRQCs):\n\n"
                    f"1. **Public Key Infrastructure (RSA / ECC)**: Broken by Shor's algorithm (polynomial time period finding). Immediate Harvest Now, Decrypt Later (HNDL) risk.\n"
                    f"2. **Target Standards**: Migrate to **NIST FIPS 203 (ML-KEM)** for key encapsulation and **NIST FIPS 204 (ML-DSA)** for digital signatures.\n"
                    f"3. **Symmetric Crypto**: AES-128 security is halved by Grover's algorithm (effective 64 bits). Ensure minimum **AES-256-GCM**."
                )
            elif "remediation" in q_lower or "fix" in q_lower or "patch" in q_lower or "loop" in q_lower:
                reply_text = (
                    f"### Autonomous Cryptographic Remediation Guidance\n\n"
                    f"To remediate the {critical_count} critical primitives detected in your project:\n\n"
                    f"1. Navigate to **Auto-Patch Engine** or **Autonomous Loop**.\n"
                    f"2. Upload your source files, directory, or select an active scan.\n"
                    f"3. Choose your migration profile (e.g., *NIST FIPS 203/204 Hybrid* or *Transitional Classical Hardening*).\n"
                    f"4. Run the autonomous loop to scan, generate AST-safe patches, run closed-loop verification, and download the remediated archive."
                )
            elif "mosca" in q_lower or "timeline" in q_lower or "hndl" in q_lower:
                reply_text = (
                    f"### Mosca's Theorem & Exposure Assessment\n\n"
                    f"Mosca's Theorem: If **Shelf-life (X) + Migration Time (Y) > Time to Quantum Computer (Z)**, your data is compromised today under HNDL.\n\n"
                    f"- Project Mosca Deficit: **{deficit}**\n"
                    f"- High-risk data with shelf-life >= 10 years must immediately adopt quantum-resistant key exchange (ML-KEM-768 hybrid)."
                )
            else:
                reply_text = (
                    f"### ECDAT Cryptographic Copilot Advisory\n\n"
                    f"Context for **{active_page}** in **{proj_name}**:\n"
                    f"- Monitored Primitives: {total_assets} total | {quantum_vuln} quantum-vulnerable | {critical_count} critical\n\n"
                    f"Regarding your query *\"{question}\"*:\n"
                    f"All cryptographic operations in this project should follow NIST Post-Quantum Cryptography standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA) "
                    f"and eliminate legacy primitives (MD5, SHA-1, DES, RC4, RSA-1024/2048) in accordance with Section 46 recommendations.\n\n"
                    f"*Tip: Configure your Gemini or NVIDIA API key in AI Settings for live multi-turn reasoning.*"
                )

        return {
            "reply": reply_text,
            "provider": used_provider,
            "model": used_model,
            "active_page": active_page,
            "is_authoritative": False  # Section 46 mandate
        }

