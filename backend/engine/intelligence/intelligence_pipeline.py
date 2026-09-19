"""
ECDAT V4 P2.1 Intelligence Pipeline.

Main evaluation pipeline. Orchestrates:
normalize -> role -> strength -> pqc_readiness -> hndl -> rules -> explainability

AXIOM: Deterministic given same inputs + knowledge base version.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from .algorithm_registry import knowledge_base_version
from .certificate_risk import extract_cert_risk_context
from .evidence_context import derive_confidence_from_evidence, evidence_to_ref
from .explainability import build_reason_chain, format_risk_explanation
from .hndl_analyzer import assess_hndl
from .intelligence_normalizer import normalize_algorithm_from_evidence
from .models import (
    EvidenceReference, RiskAssessment, RiskFactor, RiskSeverity, UnknownFactor,
)
from .pqc_readiness import assess_pqc_readiness
from .risk_engine import compute_confidence, compute_severity, evaluate_risk_factors
from .security_strength import assess_security_strength


class IntelligencePipeline:
    """Evidence-driven crypto risk intelligence pipeline."""

    def evaluate(
        self,
        asset: Dict[str, Any],
        evidence_items: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """
        Evaluate a crypto asset against P0 evidence and produce a full RiskAssessment.

        Steps:
        1. Normalize algorithm name
        2. Assess security strength
        3. Assess PQC readiness (role-aware)
        4. Assess HNDL
        5. Evaluate risk rules -> factors + rule refs
        6. Compute severity + confidence
        7. Build evidence refs
        8. Build reason chain
        """
        context = context or {}
        assessment = RiskAssessment(
            asset_id=asset.get("id", ""),
            scan_id=asset.get("scan_id"),
            knowledge_base_version=knowledge_base_version(),
        )

        # 1. Normalize
        algo_raw = asset.get("algorithm") or asset.get("name") or ""
        obs_type = asset.get("observation_type", "")
        algo_normalized = normalize_algorithm_from_evidence(algo_raw, obs_type)

        # 2. Security strength
        param = asset.get("key_size") or asset.get("parameter")
        ev_level = "E0"
        if evidence_items:
            # Take highest evidence level present
            level_rank = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5}
            ev_level = max(
                (ev.get("level", "E0") for ev in evidence_items),
                key=lambda l: level_rank.get(str(l), 0),
                default="E0"
            )
        strength = assess_security_strength(
            algo_normalized,
            parameter=param,
            evidence_level=ev_level,
            parameter_source=obs_type or "UNKNOWN",
        )
        assessment.security_strength = strength

        # 3. PQC readiness
        scanner_unavail = context.get("scanner_unavailable", False)
        pqc = assess_pqc_readiness(asset, evidence_items, scanner_unavailable=scanner_unavail)
        assessment.pqc_readiness = pqc

        # Enrich context with PQC readiness states for rule engine
        ctx_enriched = dict(context)
        ctx_enriched["pqc_kex_state"] = pqc.key_establishment.value
        ctx_enriched["pqc_sig_state"] = pqc.signature.value

        # Certificate risk context (from evidence)
        cert_ev = None
        for ev in evidence_items:
            if str(ev.get("observation_type", "")).upper() == "X509_CERTIFICATE":
                cert_ev = ev.get("raw_details") or ev.get("metadata") or {}
                break
        if cert_ev:
            cert_ctx = extract_cert_risk_context(cert_ev)
            ctx_enriched.update(cert_ctx)

        # 4. HNDL
        hndl = assess_hndl(asset, evidence_items, ctx_enriched)
        assessment.hndl = hndl

        # 5. Risk rules
        factor_rule_pairs, _ = evaluate_risk_factors(
            {"algorithm": algo_normalized, **asset},
            evidence_items,
            ctx_enriched,
        )
        assessment.risk_factors = [f for f, _ in factor_rule_pairs]
        assessment.rule_refs = [r for _, r in factor_rule_pairs]

        # 6. Severity + confidence
        assessment.severity = compute_severity(factor_rule_pairs)
        assessment.confidence = compute_confidence(evidence_items)

        # 7. Evidence refs
        assessment.evidence_refs = [
            EvidenceReference(**evidence_to_ref(ev)) for ev in evidence_items
        ]

        # 8. Limitations + unknowns
        if scanner_unavail:
            assessment.limitations.append(
                "Scanner was unavailable or host unreachable. Security capabilities could not be verified."
            )

        if not evidence_items:
            assessment.unknowns.append(
                UnknownFactor(
                    field="evidence",
                    reason="No evidence items provided. Assessment is purely registry-based."
                )
            )
            assessment.limitations.append(
                "Assessment derived from algorithm name only, not observed behavior."
            )

        # 9. Reason chain
        assessment.reason_chain = build_reason_chain(assessment, evidence_items)

        return assessment


def evaluate_asset(
    asset: Dict[str, Any],
    evidence_items: Optional[List[Dict[str, Any]]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> RiskAssessment:
    """Module-level convenience function."""
    pipeline = IntelligencePipeline()
    return pipeline.evaluate(asset, evidence_items or [], context or {})
