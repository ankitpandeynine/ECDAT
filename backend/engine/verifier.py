"""Closed-Loop Re-Scan Verification Engine.

Implements Section 10 of the specification:
After a migration, ECDAT scans again and compares the resulting evidence
against the baseline.
  BEFORE: RSA-2048 observed; PQC/hybrid not observed
  AFTER: RSA-2048 no longer observed; PQC/hybrid observed
  RESULT: VERIFIED / NOT VERIFIED / INCONCLUSIVE

Creates an auditable closed loop without equating a checked task with proof.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from .evidence_model import EvidenceRecord, is_quantum_vulnerable


class VerificationVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"


class DiffItem(BaseModel):
    primitive: str
    category: str
    surface: str
    location: str
    severity: str
    description: str = ""
    evidence_id: Optional[str] = None


class VerificationReport(BaseModel):
    verdict: VerificationVerdict
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    rationale: str
    baseline_scan_ids: List[str]
    post_migration_scan_ids: List[str]
    timestamp: str

    retired_weaknesses: List[DiffItem] = Field(default_factory=list)
    introduced_protections: List[DiffItem] = Field(default_factory=list)
    persisting_risks: List[DiffItem] = Field(default_factory=list)
    regressions: List[DiffItem] = Field(default_factory=list)

    summary: Dict[str, Any] = Field(default_factory=dict)
    audit_notes: List[str] = Field(default_factory=list)


def is_weak_primitive(primitive: str, severity: str = "") -> bool:
    upper = primitive.upper()
    if severity.upper() in ("CRITICAL", "HIGH"):
        return True
    weak_tokens = ("MD5", "SHA-1", "SHA1", "DES", "RC4", "3DES", "RSA-1024", "RSA-512", "TLSV1", "TLSV1_1", "TLSV1.0", "TLSV1.1")
    return any(tok in upper for tok in weak_tokens)


def is_pqc_or_modern(primitive: str) -> bool:
    upper = primitive.upper()
    pqc_tokens = ("ML-KEM", "MLKEM", "ML-DSA", "MLDSA", "SLH-DSA", "SLHDSA", "KYBER", "DILITHIUM", "SPHINCS", "HYBRID", "AES-256", "SHA-256", "TLSV1.3")
    return any(tok in upper for tok in pqc_tokens)


class ClosedLoopVerifier:
    """Compares baseline cryptographic evidence with post-migration evidence."""

    @staticmethod
    def verify(
        baseline_records: List[EvidenceRecord],
        post_migration_records: List[EvidenceRecord],
        baseline_scan_ids: Optional[List[str]] = None,
        post_migration_scan_ids: Optional[List[str]] = None,
        target_weakness_filter: Optional[List[str]] = None
    ) -> VerificationReport:
        from datetime import datetime, timezone
        now_str = datetime.now(timezone.utc).isoformat()

        # Build signatures for matching: (surface, algorithm, location_prefix)
        def record_key(r: EvidenceRecord) -> str:
            loc = r.location_endpoint.split(":")[0].split("@")[0]
            return f"{r.source_surface.value}|{r.algorithm.upper()}|{loc}"

        baseline_map = {record_key(r): r for r in baseline_records}
        post_map = {record_key(r): r for r in post_migration_records}

        baseline_keys = set(baseline_map.keys())
        post_keys = set(post_map.keys())

        retired_keys = baseline_keys - post_keys
        introduced_keys = post_keys - baseline_keys
        common_keys = baseline_keys & post_keys

        retired_weaknesses: List[DiffItem] = []
        for k in retired_keys:
            r = baseline_map[k]
            if is_weak_primitive(r.algorithm, r.severity) or (target_weakness_filter and any(t.upper() in r.algorithm.upper() for t in target_weakness_filter)):
                retired_weaknesses.append(DiffItem(
                    primitive=r.algorithm,
                    category=r.cryptographic_role.value,
                    surface=r.source_surface.value,
                    location=r.location_endpoint,
                    severity=r.severity,
                    description=f"Retired: previously observed at {r.location_endpoint}",
                    evidence_id=r.asset_id
                ))

        introduced_protections: List[DiffItem] = []
        regressions: List[DiffItem] = []
        for k in introduced_keys:
            r = post_map[k]
            if is_pqc_or_modern(r.algorithm):
                introduced_protections.append(DiffItem(
                    primitive=r.algorithm,
                    category=r.cryptographic_role.value,
                    surface=r.source_surface.value,
                    location=r.location_endpoint,
                    severity=r.severity,
                    description=f"Introduced protection: {r.description or r.algorithm}",
                    evidence_id=r.asset_id
                ))
            elif is_weak_primitive(r.algorithm, r.severity):
                regressions.append(DiffItem(
                    primitive=r.algorithm,
                    category=r.cryptographic_role.value,
                    surface=r.source_surface.value,
                    location=r.location_endpoint,
                    severity=r.severity,
                    description=f"Regression: newly introduced weak primitive",
                    evidence_id=r.asset_id
                ))

        persisting_risks: List[DiffItem] = []
        for k in common_keys:
            r = post_map[k]
            if is_weak_primitive(r.algorithm, r.severity):
                persisting_risks.append(DiffItem(
                    primitive=r.algorithm,
                    category=r.cryptographic_role.value,
                    surface=r.source_surface.value,
                    location=r.location_endpoint,
                    severity=r.severity,
                    description=f"Persisting risk: still detected after migration",
                    evidence_id=r.asset_id
                ))

        # Evaluate verdict
        audit_notes: List[str] = []
        total_baseline_weak = sum(1 for r in baseline_records if is_weak_primitive(r.algorithm, r.severity))

        if not baseline_records and not post_migration_records:
            verdict = VerificationVerdict.INCONCLUSIVE
            confidence = "LOW"
            rationale = "No evidence records provided in baseline or post-migration scans."
            audit_notes.append("Empty dataset.")

        elif regressions:
            verdict = VerificationVerdict.NOT_VERIFIED
            confidence = "HIGH"
            rationale = f"Migration failed: {len(regressions)} new cryptographic regression(s) detected in post-migration scan."
            audit_notes.append("New weak primitives were introduced into the environment.")

        elif persisting_risks:
            verdict = VerificationVerdict.NOT_VERIFIED
            confidence = "HIGH"
            rationale = f"Migration incomplete: {len(persisting_risks)} weak cryptographic asset(s) persist in post-migration evidence."
            audit_notes.append("Target weak assets remain observable.")

        elif retired_weaknesses or introduced_protections:
            verdict = VerificationVerdict.VERIFIED
            confidence = "HIGH"
            rationale = (
                f"Migration verified! {len(retired_weaknesses)} weak asset(s) retired and "
                f"{len(introduced_protections)} modern/PQC protection(s) observed. Zero persisting weak assets."
            )
            audit_notes.append("Closed-loop verification confirmed absence of target weaknesses.")

        elif total_baseline_weak == 0:
            # Baseline had no weaknesses, post has no weaknesses
            verdict = VerificationVerdict.VERIFIED
            confidence = "MEDIUM"
            rationale = "Baseline and post-migration states both maintain compliant cryptography with no regressions."
            audit_notes.append("No active vulnerabilities in either scan.")

        else:
            verdict = VerificationVerdict.INCONCLUSIVE
            confidence = "LOW"
            rationale = "Insufficient differential evidence between baseline and post-migration scans."
            audit_notes.append("Inconclusive observation window.")

        risk_reduction = 0.0
        if total_baseline_weak > 0:
            eliminated = len(retired_weaknesses)
            risk_reduction = round((eliminated / total_baseline_weak) * 100.0, 1)

        summary = {
            "baseline_total": len(baseline_records),
            "post_migration_total": len(post_migration_records),
            "baseline_weak_count": total_baseline_weak,
            "retired_weaknesses_count": len(retired_weaknesses),
            "persisting_risks_count": len(persisting_risks),
            "regressions_count": len(regressions),
            "introduced_protections_count": len(introduced_protections),
            "risk_reduction_percentage": risk_reduction
        }

        return VerificationReport(
            verdict=verdict,
            confidence=confidence,
            rationale=rationale,
            baseline_scan_ids=baseline_scan_ids or [],
            post_migration_scan_ids=post_migration_scan_ids or [],
            timestamp=now_str,
            retired_weaknesses=retired_weaknesses,
            introduced_protections=introduced_protections,
            persisting_risks=persisting_risks,
            regressions=regressions,
            summary=summary,
            audit_notes=audit_notes
        )
