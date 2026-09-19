"""
ECDAT V4 Agility Dimension 7: Validation Agility (AGILITY_VALIDATION).

Evaluates the existence and rigor of cryptographic test suites, test vectors,
and interoperability harnesses to validate post-quantum and agile upgrades.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from ..evidence import (
    AgilityEvidenceItem,
    extract_confidence,
    is_dimension_scanner_unavailable,
)
from ..models import (
    AgilityConfidence,
    AgilityDimension,
    AgilityReason,
    AgilityState,
    DimensionalAgility,
)


def assess_validation_agility(
    asset: Dict[str, Any],
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> DimensionalAgility:
    context = context or {}
    dimension = AgilityDimension.AGILITY_VALIDATION

    if is_dimension_scanner_unavailable(dimension, evidence_items, context):
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.SCANNER_UNAVAILABLE,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Test/validation analyzer was unavailable."],
            limitations=["Scanner execution failed or timed out."],
            derived_score=None,
        )

    supporting: List[str] = []
    contradicting: List[str] = []
    evidence_refs: List[str] = []
    unknowns: List[str] = []
    limitations: List[str] = []
    reasons: List[AgilityReason] = []

    has_crypto_tests = False
    has_general_tests = False
    has_interop_tests = False
    has_no_tests = False

    for item in evidence_items:
        evidence_refs.append(item.id)
        if item.has_text("crypto_test", "wycheproof", "cavp", "known_answer_test", "test_vectors_verified"):
            has_crypto_tests = True
            supporting.append(f"Dedicated cryptographic test harness observed: {item.description}")

        if item.has_text("unit_test", "integration_test", "pytest", "junit"):
            has_general_tests = True
            supporting.append(f"Automated unit or integration tests observed: {item.description}")

        if item.has_text("interoperability_test", "interop_test", "protocol_test"):
            has_interop_tests = True
            supporting.append(f"Interoperability / multi-peer test harness observed: {item.description}")

        if item.has_text("no_tests_observed", "missing_test_suite"):
            has_no_tests = True
            contradicting.append("No automated test suites detected in the scanned repository.")

    if context.get("has_crypto_tests"):
        has_crypto_tests = True
        supporting.append("Context confirms dedicated cryptographic test harness.")
    if context.get("has_unit_tests"):
        has_general_tests = True
        supporting.append("Context confirms automated unit test coverage.")

    confidence = extract_confidence(evidence_items)

    if not evidence_refs and not context:
        return DimensionalAgility(
            dimension=dimension,
            state=AgilityState.UNKNOWN,
            confidence=AgilityConfidence.UNKNOWN,
            unknowns=["Test directories or CI test manifests were not scanned."],
            limitations=["Validation capability unobserved."],
            derived_score=None,
        )

    # Determine State
    if has_crypto_tests:
        # AXIOM: Dedicated crypto tests observed != migration complete; measures validation capability
        state = AgilityState.OBSERVED
        score = 1.0
        claim = "Dedicated cryptographic test harness with test vectors actively verified."
        limitations.append("Tests validate existing algorithms; new PQC algorithm test cases must be added during migration.")

    elif has_general_tests and has_interop_tests:
        state = AgilityState.SUPPORTED
        score = 0.85
        claim = "General unit tests and protocol interoperability tests supported across codebase."
    elif has_general_tests:
        state = AgilityState.SUPPORTED
        score = 0.75
        claim = "General unit and integration testing present; regression detection supported during refactoring."
        limitations.append("General tests may lack rigorous cryptographic edge-case vectors (e.g. Wycheproof).")
    elif has_interop_tests:
        state = AgilityState.PARTIALLY_OBSERVED
        score = 0.50
        claim = "Interoperability tests present, but low-level primitive unit tests are absent."
    elif has_no_tests:
        state = AgilityState.CONSTRAINED
        score = 0.20
        claim = "No automated test suites detected; cryptographic refactoring cannot be safely validated without manual verification."
    else:
        state = AgilityState.UNKNOWN
        score = None
        claim = "Validation agility could not be determined from available evidence."
        unknowns.append("No test runners or test files identified.")

    reasons.append(
        AgilityReason(
            dimension=dimension.value,
            step="VALIDATION_AGILITY_ANALYSIS",
            claim=claim,
            rule_id="AGL-VAL-001" if state == AgilityState.OBSERVED else ("AGL-VAL-002" if state == AgilityState.SUPPORTED else ("AGL-VAL-003" if state == AgilityState.PARTIALLY_OBSERVED else ("AGL-VAL-004" if state == AgilityState.CONSTRAINED else None))),
            rule_version="1.0",
            evidence_refs=evidence_refs,
            supporting=supporting,
            contradicting=contradicting,
            unknowns=unknowns,
            limitations=limitations,
        )
    )

    return DimensionalAgility(
        dimension=dimension,
        state=state,
        confidence=confidence,
        evidence_refs=evidence_refs,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        unknowns=unknowns,
        limitations=limitations,
        reason_chain=reasons,
        derived_score=score,
    )
