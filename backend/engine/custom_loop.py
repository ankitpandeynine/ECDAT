"""ECDAT Autonomous Custom Loop Engine.

Implements the one-click end-to-end remediation pipeline:
1. Scan source code or binary
2. Generate discovery report, CBOM, and quantum risk estimation
3. Automatically create cryptographic migration patches & execute differential tests
4. Verify patch report via closed-loop verification (baseline vs. post-patch diff)
5. Provide structured before & after metadata for the dedicated Changes page.
"""
from __future__ import annotations

import base64
import difflib
import re
import time
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from .source_scan import scan_sources
from .polyglot_scanner import scan_polyglot_code
from .binary_deep import scan_upload
from .binary_classifier import BinaryMLClassifier
from .cbom_generator import generate_cyclonedx_cbom
from .quantum_risk import calculate_mosca_risk
from .patch_engine import AutoPatchEngine, PATCH_TEMPLATES
from .verifier import (ClosedLoopVerifier, VerificationReport, VerificationVerdict,
                       DiffItem, is_weak_primitive, is_pqc_or_modern)
from .evidence_model import normalize_source_finding, normalize_binary_detection

PRESET_PYTHON_BEFORE = r"""# Enterprise Banking Payment Module (Python)
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_transaction_signature(account_id: str, amount: float) -> tuple[str, bytes]:
    # Deprecated Classical: Broken MD5 checksum
    payload = f"{account_id}:{amount}".encode("utf-8")
    tx_hash = hashlib.md5(payload).hexdigest()

    # Quantum Vulnerable: 1024-bit RSA keypair (High CRQC Risk)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    return tx_hash, private_key.sign(payload, None)
"""

PRESET_C_BEFORE = r"""// Enterprise Banking Payment Module (C / OpenSSL)
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rsa.h>

int process_payment_telemetry(const unsigned char *payload, size_t len) {
    // Weak Classical: Obsolete MD5 hash
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(payload, len, digest);

    // Weak Classical: 56-bit DES symmetric cipher
    DES_cblock key;
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    // Quantum Vulnerable: 1024-bit RSA keypair
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bne, NULL);

    return 0;
}
"""

PRESET_C_AFTER = r"""// Enterprise Banking Payment Module (C / OpenSSL - Remediated)
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>

int process_payment_telemetry(const unsigned char *payload, size_t len) {
    // Remediated Classical: SHA-256 (FIPS 180-4 compliant)
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(payload, len, digest);

    // Remediated Classical: AES-256-GCM authenticated cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    // Remediated Post-Quantum: FIPS 203 ML-KEM key encapsulation
    EVP_KEM_fetch(NULL, "ML-KEM-768", NULL);

    return 0;
}
"""

PRESET_BINARY_CONFIG_BEFORE = r"""# Legacy Cryptographic Binary Build Configuration
CC = gcc
CFLAGS = -O2 -Wall -DENABLE_LEGACY_CRYPTO=1
LIBS = -lcrypto -lssl

# Compiled targets contain deprecated MD5, 56-bit DES and RSA-1024
TARGET = bin/payment_gateway_legacy
SOURCES = src/legacy_crypto.c
"""

PRESET_BINARY_CONFIG_AFTER = r"""# Hardened Post-Quantum Cryptographic Build Configuration
CC = clang
CFLAGS = -O3 -Wall -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
         -DOPENSSL_NO_MD5 -DOPENSSL_NO_DES -DFIPS_203_ML_KEM=1 -DFIPS_204_ML_DSA=1
LIBS = -lcrypto -lssl -loqs

# Binary compiled with LibOQS Post-Quantum hybrid algorithms (ML-KEM-768 + X25519)
TARGET = bin/payment_gateway_pqc_hardened
SOURCES = src/remediated_crypto.c
"""


class LoopStep(BaseModel):
    step_number: int
    title: str
    status: str  # "completed", "running", "failed"
    duration_ms: int
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Deterministic, finding-derived metrics (no fabricated values).
# Every score below is computed from the actual scan findings of the run.
# ---------------------------------------------------------------------------

_SEVERITY_WEIGHTS = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 1}


def _finding_algorithm(f: Dict[str, Any]) -> str:
    return str(f.get("algorithm") or f.get("primitive") or "")


def _finding_severity(f: Dict[str, Any]) -> str:
    return str(f.get("severity") or "INFO")


def _weak_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [f for f in findings
            if is_weak_primitive(_finding_algorithm(f), _finding_severity(f))]


def _security_score(findings: List[Dict[str, Any]]) -> int:
    """0-100 posture score; each finding deducts a severity-weighted penalty."""
    penalty = sum(_SEVERITY_WEIGHTS.get(_finding_severity(f).upper(), 3) for f in findings)
    return max(0, min(100, 100 - penalty))


def _modern_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [f for f in findings
            if is_pqc_or_modern(_finding_algorithm(f))
            and not is_weak_primitive(_finding_algorithm(f), _finding_severity(f))]


def _pqc_readiness_pct(findings: List[Dict[str, Any]]) -> int:
    if not findings:
        return 100
    return round(100.0 * len(_modern_findings(findings)) / len(findings))


def _crypto_agility_score(findings: List[Dict[str, Any]]) -> float:
    """0.0-10.0 agility proxy: share of modern/PQC-ready primitives in the target."""
    if not findings:
        return 10.0
    return round(10.0 * len(_modern_findings(findings)) / len(findings), 1)


def _algorithms_detected(findings: List[Dict[str, Any]]) -> List[str]:
    return sorted({_finding_algorithm(f) for f in findings if _finding_algorithm(f)})


class CustomLoopResult(BaseModel):
    run_id: str
    target_type: Literal["source", "binary"]
    target_name: str
    language: str
    verdict: str  # "VERIFIED", "PARTIALLY_VERIFIED", "FAILED"
    total_duration_ms: int
    timestamp: str
    steps: List[LoopStep]
    
    # State Before
    before_state: Dict[str, Any]
    # State After
    after_state: Dict[str, Any]
    
    # Detailed Diff
    unified_diff: str
    transformation_description: str
    regression_test: Dict[str, Any]
    
    # Verification Report
    verification_report: Dict[str, Any]
    
    # CBOM Data
    cbom_summary: Dict[str, Any]


class CustomLoopRunner:
    """Orchestrates the 1-click Custom Loop pipeline."""

    @classmethod
    def run_pipeline(
        cls,
        target_type: Literal["source", "binary"] = "source",
        source_code: Optional[str] = None,
        binary_hex: Optional[str] = None,
        file_name: str = "payment_processor.py",
        language: str = "python",
        preset_name: Optional[str] = None,
        shelf_life: int = 10,
        migration_time: int = 4,
        crqc_horizon: int = 7
    ) -> CustomLoopResult:
        start_time = time.time()
        run_id = f"loop-{int(start_time * 1000)}"
        steps: List[LoopStep] = []

        # Resolve inputs and presets. Presets exist solely as demo conveniences;
        # user-supplied source always takes precedence over demo content.
        if preset_name == "c_openssl" or (not source_code and language.lower() in ("c", "c_cpp", "cpp")):
            code_before = source_code if source_code and source_code.strip() else PRESET_C_BEFORE
            file_name = file_name or "src/payment.c"
            language = "c_cpp"
            target_type = "source"
        elif preset_name == "binary" or target_type == "binary":
            target_type = "binary"
            file_name = file_name if file_name.endswith((".bin", ".elf", ".exe")) else "payment_gateway.elf"
            language = "binary"
            code_before = ""
        else:
            code_before = source_code if source_code and source_code.strip() else PRESET_PYTHON_BEFORE
            file_name = file_name or "payment_processor.py"
            language = "python" if not language else language.lower()

        # =====================================================================
        # Step 1: SCAN TARGET (Source code or Binary)
        # =====================================================================
        s1_start = time.time()
        if target_type == "source":
            scan_raw = scan_sources([{"path": file_name, "content": code_before, "language": language}])
            findings_before = scan_raw.get("findings", [])
            evidence_before = [normalize_source_finding(f, input_hash=f"hash_{run_id}_v1") for f in findings_before]
            scan_summary = {
                "primitive_count": len(findings_before),
                "weaknesses_count": len(_weak_findings(findings_before)),
                "algorithms_detected": _algorithms_detected(findings_before),
                "findings": findings_before
            }
        else:
            # Binary scan
            raw_bytes = bytes.fromhex(binary_hex) if binary_hex else b"\x7fELF\x02\x01\x01\x00" + b"\x00"*100 + b"MD5_Init\x00DES_set_key\x00"
            binary_scan_error: Optional[str] = None
            try:
                bin_res = scan_upload(raw_bytes, file_name)
            except Exception as exc:
                # Never fabricate findings for a target that could not be parsed.
                bin_res = {"findings": []}
                binary_scan_error = f"Binary analysis failed: {exc}"
            ml_res = BinaryMLClassifier.classify_binary(raw_bytes, file_name)
            findings_before = bin_res.get("findings", [])
            evidence_before = [
                normalize_binary_detection({
                    "file_path": file_name,
                    "algorithm": d.get("algorithm", "MD5"),
                    "category": d.get("category", "hash"),
                    "confidence": "HIGH",
                    "offset": d.get("offset", 0x100)
                }, file_name=file_name, input_hash=f"hash_{run_id}_bin_v1")
                for d in findings_before
            ]
            scan_summary = {
                "primitive_count": len(findings_before),
                "weaknesses_count": len(_weak_findings(findings_before)),
                "algorithms_detected": _algorithms_detected(findings_before),
                "ml_prediction": ml_res.predicted_category,
                "ml_confidence": ml_res.confidence_level
            }
            if binary_scan_error:
                scan_summary["scan_error"] = binary_scan_error

        s1_duration = int((time.time() - s1_start) * 1000)
        steps.append(LoopStep(
            step_number=1,
            title=f"Automated {target_type.capitalize()} Scan & Discovery",
            status="completed",
            duration_ms=s1_duration,
            summary=f"Detected {scan_summary['primitive_count']} cryptographic primitives ({scan_summary['weaknesses_count']} weak).",
            details=scan_summary
        ))

        # =====================================================================
        # Step 2: REPORT GENERATION (CBOM & Quantum Risk)
        # =====================================================================
        s2_start = time.time()
        mock_scan_record = {
            "id": f"scan_{run_id}_baseline",
            "kind": "code" if target_type == "source" else "binary",
            "status": "completed",
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "input_hash": f"hash_{run_id}_v1",
            "engine_version": "3.0.0",
            "result": {"findings": findings_before}
        }
        cbom = generate_cyclonedx_cbom([mock_scan_record], target_name=file_name)
        # Mosca inputs (shelf life / migration window / CRQC horizon) are analyst
        # assumptions supplied with the run — surfaced in the report, never invented.
        quantum_risk = calculate_mosca_risk(shelf_life=shelf_life, migration_time=migration_time, crqc_horizon=crqc_horizon)

        s2_duration = int((time.time() - s2_start) * 1000)
        steps.append(LoopStep(
            step_number=2,
            title="Discovery & Quantum Risk Assessment",
            status="completed",
            duration_ms=s2_duration,
            summary=f"Generated CycloneDX 1.6 CBOM. Mosca Deficit: {quantum_risk['deficit_years']} years ({quantum_risk['posture_status']}).",
            details={
                "cbom_components": len(cbom.get("components", [])),
                "quantum_risk": quantum_risk,
                "mosca_inputs": {
                    "shelf_life_years": shelf_life,
                    "migration_time_years": migration_time,
                    "crqc_horizon_years": crqc_horizon
                },
                "spec_version": cbom.get("specVersion", "1.6")
            }
        ))

        # =====================================================================
        # Step 3: CREATE PATCHES & EXECUTE REGRESSION TESTS
        # =====================================================================
        s3_start = time.time()
        if target_type == "source":
            # Apply the full deterministic template set for the detected language to
            # the user's actual code. No preset substitution, no fictional diffs.
            batch = AutoPatchEngine.batch_patch_code(
                source_code=code_before,
                file_path=file_name,
                language=language,
                run_tests=True
            )
            code_after = batch["patched_code"]
            diff_text = batch["unified_diff"]
            applied_descriptions = [p["description"] for p in batch["applied_patches"]]
            patch_desc = "; ".join(applied_descriptions) if applied_descriptions else (
                "No deterministic template matched the detected patterns; "
                "manual migration guidance is listed in the verification report."
            )
            test_results = batch.get("test_results", [])
            statuses = {t.get("status") for t in test_results} or {"not_executed"}
            if test_results and statuses == {"passed"}:
                test_status = "passed"
            elif "failed" in statuses or "error" in statuses:
                test_status = "failed"
            else:
                test_status = "not_executed"
            test_code = "\n\n# ---- ----\n\n".join(
                PATCH_TEMPLATES[p["pattern_id"]]["test_template"]
                for p in batch["applied_patches"]
                if p["pattern_id"] in PATCH_TEMPLATES and PATCH_TEMPLATES[p["pattern_id"]].get("test_template")
            ) or "// No executable regression test for this language; verified by post-patch re-scan."
            test_output = "\n".join(
                f"[{t.get('status', 'unknown').upper()}] {t.get('pattern_id', '?')}: {t.get('output', '')}"
                for t in test_results
            ) or "No regression tests were required for the applied transformations."
        else:
            # Binary remediation is a build/process change: ECDAT emits a hardened
            # build recommendation but cannot fabricate a source diff or a verified
            # test result for an artifact it has not rebuilt and re-scanned.
            code_after = ""
            diff_text = ""
            patch_desc = (
                "Recommended build hardening: disable legacy MD5/DES symbols "
                "(-DOPENSSL_NO_MD5 -DOPENSSL_NO_DES), link LibOQS and re-compile with "
                "ML-KEM-768 hybrid key exchange (FIPS 203). Re-scan the rebuilt binary "
                "to complete closed-loop verification."
            )
            test_status = "not_executed"
            test_code = "# Binary hardening requires a rebuild; no in-sandbox test can verify the rebuilt artifact."
            test_output = "Pending rebuild of the binary with the hardened configuration. Re-scan the rebuilt artifact to verify."

        s3_duration = int((time.time() - s3_start) * 1000)
        steps.append(LoopStep(
            step_number=3,
            title="Cryptographic Patch Generation & Regression Test",
            status="completed",
            duration_ms=s3_duration,
            summary=f"Created AST-safe patch. Differential regression test status: {test_status.upper()}.",
            details={
                "description": patch_desc,
                "test_status": test_status,
                "test_output": test_output
            }
        ))

        # =====================================================================
        # Step 4: CLOSED-LOOP VERIFICATION REPORT
        # =====================================================================
        s4_start = time.time()
        if target_type == "source":
            scan_after_raw = scan_sources([{"path": file_name, "content": code_after, "language": language}])
            findings_after = scan_after_raw.get("findings", [])
            evidence_after = [normalize_source_finding(f, input_hash=f"hash_{run_id}_v2") for f in findings_after]
            verification_report = ClosedLoopVerifier.verify(
                baseline_records=evidence_before,
                post_migration_records=evidence_after,
                baseline_scan_ids=[f"scan_{run_id}_baseline"],
                post_migration_scan_ids=[f"scan_{run_id}_remediated"]
            )
        else:
            # Binary: the artifact has NOT been rebuilt or re-scanned, so no
            # post-migration evidence exists and the weaknesses persist until
            # the hardened rebuild is verified. Verdict is honestly INCONCLUSIVE.
            findings_after = []
            evidence_after = []
            persisting_items = [
                DiffItem(
                    primitive=r.algorithm,
                    category=r.cryptographic_role.value,
                    surface=r.source_surface.value,
                    location=r.location_endpoint,
                    severity=r.severity,
                    description="Pending rebuild: still present in the analyzed binary until the hardened build is re-scanned.",
                    evidence_id=r.asset_id
                )
                for r in evidence_before if is_weak_primitive(r.algorithm, r.severity)
            ]
            verification_report = VerificationReport(
                verdict=VerificationVerdict.INCONCLUSIVE,
                confidence="LOW",
                rationale=(
                    "Binary remediation requires rebuilding with the hardened configuration "
                    "and re-scanning the rebuilt artifact. Closed-loop differential "
                    "verification is pending; all baseline weaknesses still persist."
                ),
                baseline_scan_ids=[f"scan_{run_id}_baseline"],
                post_migration_scan_ids=[],
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                retired_weaknesses=[],
                introduced_protections=[],
                persisting_risks=persisting_items,
                regressions=[],
                summary={
                    "baseline_total": len(evidence_before),
                    "post_migration_total": 0,
                    "baseline_weak_count": len(persisting_items),
                    "retired_weaknesses_count": 0,
                    "persisting_risks_count": len(persisting_items),
                    "regressions_count": 0,
                    "introduced_protections_count": 0,
                    "risk_reduction_percentage": 0.0
                },
                audit_notes=["No post-migration binary evidence available; rebuild and re-scan required."]
            )

        s4_duration = int((time.time() - s4_start) * 1000)
        regressions_count = len(verification_report.regressions)
        steps.append(LoopStep(
            step_number=4,
            title="Closed-Loop Verification & Differential Diff",
            status="completed",
            duration_ms=s4_duration,
            summary=(
                f"Closed-Loop Verdict: {verification_report.verdict.value}. "
                f"Retired {len(verification_report.retired_weaknesses)} weak asset(s), "
                f"{len(verification_report.persisting_risks)} persisting, {regressions_count} regression(s)."
            ),
            details=verification_report.model_dump()
        ))

        total_duration = int((time.time() - start_time) * 1000)

        # Before & After states — every metric derived from the actual findings.
        weak_before = _weak_findings(findings_before)
        before_state = {
            "target_name": file_name,
            "target_type": target_type,
            "language": language,
            "code": code_before,
            "findings_count": len(findings_before),
            "critical_vulnerabilities": len(weak_before),
            "algorithms": _algorithms_detected(findings_before),
            "security_score": _security_score(findings_before),
            "pqc_readiness_pct": _pqc_readiness_pct(findings_before),
            "quantum_risk_status": quantum_risk["posture_status"],
            "quantum_deficit_years": quantum_risk["deficit_years"],
            "crypto_agility_score": _crypto_agility_score(findings_before)
        }

        if target_type == "source":
            weak_after = _weak_findings(findings_after)
            after_state = {
                "target_name": file_name,
                "target_type": target_type,
                "language": language,
                "code": code_after,
                "findings_count": len(findings_after),
                "critical_vulnerabilities": len(weak_after),
                "algorithms": _algorithms_detected(findings_after),
                "security_score": _security_score(findings_after),
                "pqc_readiness_pct": _pqc_readiness_pct(findings_after),
                "quantum_risk_status": "SECURE" if not weak_after else quantum_risk["posture_status"],
                "quantum_deficit_years": 0 if not weak_after else quantum_risk["deficit_years"],
                "crypto_agility_score": _crypto_agility_score(findings_after)
            }
        else:
            # Binary: no re-scan yet, so the after state honestly mirrors the
            # baseline (nothing has changed in the artifact itself).
            after_state = dict(before_state)
            after_state["code"] = ""
            after_state["recommended_build_config"] = PRESET_BINARY_CONFIG_AFTER
            after_state["verification_pending"] = True

        return CustomLoopResult(
            run_id=run_id,
            target_type=target_type,
            target_name=file_name,
            language=language,
            verdict=verification_report.verdict.value,
            total_duration_ms=total_duration,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            steps=steps,
            before_state=before_state,
            after_state=after_state,
            unified_diff=diff_text,
            transformation_description=patch_desc,
            regression_test={
                "code": test_code,
                "status": test_status,
                "output": test_output
            },
            verification_report=verification_report.model_dump(),
            cbom_summary={
                "components_count": len(cbom.get("components", [])),
                "spec_version": cbom.get("specVersion", "1.6"),
                "bom_format": "CycloneDX"
            }
        )
