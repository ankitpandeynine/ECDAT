"""
ECDAT V4 Multi-Modal Evidence Fusion Engine.

Principles:
1. Associates multi-source observations (source, dependency, binary, TLS, X.509, PQC) into unified CryptoAssets.
2. Distinct corroboration statuses: SINGLE_SOURCE, CORROBORATED, CONTRADICTED, INCONCLUSIVE.
3. NEVER averages confidence into an opaque score.
4. Preserves highest evidence level (E0..E5) independently of confidence.
5. Emits deterministic, transparent "Why Was This Detected?" explanations based on real evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import re

from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType
from .asset_graph import AssetGraphService, AssetType, CryptoAsset, RelationshipType


class CorroborationStatus(str, Enum):
    SINGLE_SOURCE = "SINGLE_SOURCE"
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class CorroborationResult:
    fused_status: CorroborationStatus
    highest_level: EvidenceLevel
    combined_confidence: float
    explanation: str
    contradictions: List[str] = field(default_factory=list)


class EvidenceFreshness(str, Enum):
    CURRENT = "CURRENT"
    STALE = "STALE"
    SUPERSEDED = "SUPERSEDED"
    UNKNOWN = "UNKNOWN"


@dataclass
class EvidenceLineage:
    scan_id: str
    parent_evidence_id: Optional[str] = None
    superseded_by_id: Optional[str] = None
    superseded_at: Optional[str] = None
    created_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "parent_evidence_id": self.parent_evidence_id,
            "superseded_by_id": self.superseded_by_id,
            "superseded_at": self.superseded_at,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


@dataclass
class MultiScanCorroboration:
    asset_key: str
    fused_status: CorroborationStatus
    highest_level: EvidenceLevel
    combined_confidence: float
    scan_count: int
    scans_observed: List[str]
    freshness: EvidenceFreshness
    active_evidence_count: int
    superseded_evidence_count: int
    explanation: str
    contradictions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_key": self.asset_key,
            "fused_status": self.fused_status.value if hasattr(self.fused_status, "value") else str(self.fused_status),
            "highest_level": self.highest_level.value if hasattr(self.highest_level, "value") else str(self.highest_level),
            "combined_confidence": self.combined_confidence,
            "scan_count": self.scan_count,
            "scans_observed": self.scans_observed,
            "freshness": self.freshness.value if hasattr(self.freshness, "value") else str(self.freshness),
            "active_evidence_count": self.active_evidence_count,
            "superseded_evidence_count": self.superseded_evidence_count,
            "explanation": self.explanation,
            "contradictions": self.contradictions,
        }


def extract_primitive_canonical_name(text: str) -> Tuple[str, Optional[int]]:
    """Normalizes cryptographic names into canonical algorithm and key size."""
    upper = text.strip().upper()
    key_size = None

    # Key size extraction
    m_bits = re.search(r"(\d{3,4})", upper)
    if m_bits:
        val = int(m_bits.group(1))
        if val in (56, 64, 112, 128, 192, 256, 384, 512, 1024, 2048, 3072, 4096):
            key_size = val

    if "MD5" in upper:
        return "MD5", 128
    if "SHA-1" in upper or "SHA1" in upper:
        return "SHA-1", 160
    if "SHA-256" in upper or "SHA256" in upper:
        return "SHA-256", 256
    if "SHA-384" in upper or "SHA384" in upper:
        return "SHA-384", 384
    if "SHA-512" in upper or "SHA512" in upper:
        return "SHA-512", 512
    if "SHA-3" in upper or "SHA3" in upper:
        return "SHA-3", 256
    if "3DES" in upper or "TRIPLEDES" in upper or "DES3" in upper or "DESEDE" in upper:
        return "3DES", 112
    if "DES" in upper and "3DES" not in upper:
        return "DES", 56
    if "RC4" in upper or "ARC4" in upper:
        return "RC4", 128
    if "AES-GCM" in upper or "AES_256_GCM" in upper:
        return "AES-GCM", key_size or 256
    if "AES-CBC" in upper or "AES_256_CBC" in upper:
        return "AES-CBC", key_size or 256
    if "AES-ECB" in upper or "ECB" in upper:
        return "AES-ECB", key_size or 128
    if "AES" in upper:
        return "AES", key_size or 256
    if "RSA" in upper:
        return f"RSA-{key_size}" if key_size else "RSA", key_size
    if "ECDSA" in upper:
        return "ECDSA", key_size or 256
    if "ED25519" in upper:
        return "Ed25519", 256
    if "X25519" in upper:
        return "X25519", 256
    if "ML-KEM" in upper or "MLKEM" in upper:
        return "ML-KEM", key_size or 768
    if "ML-DSA" in upper or "MLDSA" in upper:
        return "ML-DSA", key_size or 65
    if "SLH-DSA" in upper or "SLHDSA" in upper:
        return "SLH-DSA", key_size or 128

    return text.strip(), key_size


@dataclass
class FusedAssetCandidate:
    canonical_name: str
    asset_type: AssetType
    algorithm: str
    key_size: Optional[int]
    evidence_items: List[Evidence] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)

    @property
    def highest_level(self) -> EvidenceLevel:
        if not self.evidence_items:
            return EvidenceLevel.E0
        return max(self.evidence_items, key=lambda e: e.level.rank).level

    @property
    def max_confidence(self) -> float:
        if not self.evidence_items:
            return 0.0
        return max(e.confidence for e in self.evidence_items)

    @property
    def source_engines(self) -> Set[str]:
        return {e.source_engine for e in self.evidence_items}

    @property
    def status(self) -> str:
        if self.contradictions:
            return "CONTRADICTED"
        if len(self.source_engines) >= 2:
            return "CORROBORATED"
        if len(self.evidence_items) == 1:
            return "SINGLE_SOURCE"
        return "SINGLE_SOURCE"


class EvidenceFusionEngine:
    def __init__(self, graph_service: Optional[AssetGraphService] = None):
        self.graph = graph_service

    def fuse_scan_evidence(
        self,
        project: str,
        scan_id: str,
        evidence_list: List[Evidence],
    ) -> List[CryptoAsset]:
        """
        Groups evidence into coherent CryptoAssets, identifies corroboration or
        contradictions, updates graph nodes and relationships.
        """
        # Step 1: Bucket evidence by canonical target
        asset_buckets: Dict[str, FusedAssetCandidate] = {}

        for ev in evidence_list:
            raw_target = ev.symbol or ev.description
            # Detect observation category
            if ev.observation_type == ObservationType.X509_CERTIFICATE:
                cert_fingerprint = ev.raw_details.get("sha256") or ev.symbol or "x509_cert"
                bucket_key = f"cert:{cert_fingerprint}"
                name = ev.symbol or f"Certificate ({cert_fingerprint[:16]}...)"
                algo, key_size = extract_primitive_canonical_name(ev.description)
                a_type = AssetType.CERTIFICATE
            elif ev.observation_type in (ObservationType.TLS_NEGOTIATION, ObservationType.PQC_NEGOTIATION):
                endpoint = ev.raw_details.get("target") or "endpoint"
                algo, key_size = extract_primitive_canonical_name(ev.symbol or ev.description)
                bucket_key = f"tls:{algo}:{endpoint}"
                name = f"{algo} ({endpoint})"
                a_type = AssetType.PROTOCOL
            elif ev.observation_type in (ObservationType.DEPENDENCY_DECLARATION, ObservationType.DEPENDENCY_LOCKFILE):
                dep_name = ev.symbol or "dependency"
                bucket_key = f"dep:{dep_name.lower()}"
                name = dep_name
                algo, key_size = extract_primitive_canonical_name(dep_name)
                a_type = AssetType.DEPENDENCY
            else:
                algo, key_size = extract_primitive_canonical_name(raw_target)
                bucket_key = f"algo:{algo}"
                name = algo
                a_type = AssetType.ALGORITHM

            if bucket_key not in asset_buckets:
                asset_buckets[bucket_key] = FusedAssetCandidate(
                    canonical_name=name,
                    asset_type=a_type,
                    algorithm=algo,
                    key_size=key_size,
                )
            asset_buckets[bucket_key].evidence_items.append(ev)

        # Step 2: Cross-check for contradictions between static and dynamic observations
        # Example: static source code configures RSA while live TLS negotiation observed ECDSA
        tls_algos = {
            c.algorithm for c in asset_buckets.values()
            if c.asset_type == AssetType.PROTOCOL and c.highest_level == EvidenceLevel.E5
        }
        for bucket in asset_buckets.values():
            if bucket.asset_type == AssetType.ALGORITHM and "RSA" in bucket.algorithm:
                if any("ECDSA" in t or "Ed25519" in t for t in tls_algos) and not any("RSA" in t for t in tls_algos):
                    contradiction_note = (
                        "Static configuration/source references RSA, but live TLS endpoint "
                        f"negotiated modern elliptic curve keys ({', '.join(tls_algos)})."
                    )
                    bucket.contradictions.append(contradiction_note)

        # Step 3: Persist fused assets into AssetGraph
        created_assets: List[CryptoAsset] = []

        for bucket in asset_buckets.values():
            explanation = self._build_why_detected_explanation(bucket)
            asset = self.graph.upsert_asset(
                project=project,
                asset_type=bucket.asset_type,
                name=bucket.canonical_name,
                algorithm=bucket.algorithm,
                key_size=bucket.key_size,
                scan_id=scan_id,
                fused_status=bucket.status,
                highest_evidence_level=bucket.highest_level.value,
                confidence=bucket.max_confidence,
                explanation=explanation,
            )

            # Bind evidence to the asset
            for ev in bucket.evidence_items:
                self.graph.add_evidence(asset.id, ev, project)
                # Link asset with evidence via graph edge
                self.graph.add_relationship(
                    project=project,
                    source_id=asset.id,
                    source_type=asset.asset_type,
                    relationship=RelationshipType.EVIDENCED_BY,
                    target_id=ev.id,
                    target_type="EVIDENCE",
                    scan_id=scan_id,
                    evidence_id=ev.id,
                    confidence=ev.confidence,
                )

            # Link contextual relationships between dependencies, algorithms, and endpoints
            if bucket.asset_type == AssetType.CERTIFICATE and bucket.algorithm:
                # Find matching algorithm asset
                algo_matches = self.graph.find_assets_by_algorithm(bucket.algorithm, project)
                for matched in algo_matches:
                    if matched.id != asset.id:
                        self.graph.add_relationship(
                            project=project,
                            source_id=asset.id,
                            source_type=asset.asset_type,
                            relationship=RelationshipType.IMPLEMENTS,
                            target_id=matched.id,
                            target_type=matched.asset_type,
                            scan_id=scan_id,
                            confidence=1.0,
                        )

            created_assets.append(asset)

        return created_assets

    def _build_why_detected_explanation(self, candidate: FusedAssetCandidate) -> str:
        """Generates evidence-backed 'Why Was This Detected?' rationale."""
        reasons = []
        for ev in candidate.evidence_items:
            loc = f" in {ev.file_path}:{ev.line_start}" if ev.file_path and ev.line_start else (
                f" at offset {ev.byte_offset}" if ev.byte_offset else ""
            )
            reasons.append(
                f"• [{ev.level.value} | {ev.state.value}] {ev.source_engine}: {ev.description}{loc} "
                f"(confidence: {int(ev.confidence * 100)}%)"
            )

        if candidate.contradictions:
            reasons.append("\nContradictory Observations:")
            for c in candidate.contradictions:
                reasons.append(f"⚠️ {c}")

        summary = (
            f"Detected {candidate.canonical_name} ({candidate.status}) with highest evidence "
            f"{candidate.highest_level.label} across {len(candidate.source_engines)} independent engine(s).\n"
            + "\n".join(reasons)
        )
        return summary

    def compute_corroboration(self, evidence_items: List[Evidence]) -> CorroborationResult:
        if not evidence_items:
            return CorroborationResult(
                fused_status=CorroborationStatus.INCONCLUSIVE,
                highest_level=EvidenceLevel.E0,
                combined_confidence=0.0,
                explanation="No evidence provided.",
                contradictions=[],
            )

        contradictions: List[str] = []
        # Check metadata contradictions
        primitives = {e.metadata.get("primitive") for e in evidence_items if e.metadata and e.metadata.get("primitive")}
        if len(primitives) > 1:
            contradictions.append(f"Contradictory cryptographic primitives observed: {', '.join(sorted(str(p) for p in primitives))}")

        # Check static vs dynamic contradictions
        static_texts = [e.description for e in evidence_items if e.level in (EvidenceLevel.E1, EvidenceLevel.E2, EvidenceLevel.E3)]
        dynamic_texts = [e.description for e in evidence_items if e.level in (EvidenceLevel.E4, EvidenceLevel.E5)]
        if any("RSA" in s for s in static_texts) and any("ECDSA" in d for d in dynamic_texts) and not any("RSA" in d for d in dynamic_texts):
            contradictions.append("Static observation references RSA while live dynamic observation detected ECDSA")

        source_engines = {e.source_engine for e in evidence_items}
        highest_level = max((e.level for e in evidence_items), key=lambda l: l.rank)

        # Independent probability fusion: 1 - product(1 - c_i)
        unconf = 1.0
        for e in evidence_items:
            unconf *= (1.0 - min(max(e.confidence, 0.0), 1.0))
        combined_confidence = round(1.0 - unconf, 4)

        if contradictions:
            status = CorroborationStatus.CONTRADICTED
        elif len(source_engines) >= 2 or len(evidence_items) >= 2:
            status = CorroborationStatus.CORROBORATED
        elif len(evidence_items) == 1:
            status = CorroborationStatus.SINGLE_SOURCE
        else:
            status = CorroborationStatus.INCONCLUSIVE

        explanation = self.generate_explanation(evidence_items, status, contradictions)
        return CorroborationResult(
            fused_status=status,
            highest_level=highest_level,
            combined_confidence=combined_confidence,
            explanation=explanation,
            contradictions=contradictions,
        )

    def generate_explanation(
        self,
        evidence_items: List[Evidence],
        status: CorroborationStatus | str,
        contradictions: Optional[List[str]] = None,
    ) -> str:
        status_val = status.value if isinstance(status, CorroborationStatus) else str(status)
        lines: List[str] = []

        if status_val == CorroborationStatus.CONTRADICTED.value or contradictions:
            lines.append("⚠️ CONTRADICTION DETECTED across multi-modal observations.")
            if contradictions:
                for c in contradictions:
                    lines.append(f"  • {c}")
        elif status_val == CorroborationStatus.CORROBORATED.value:
            lines.append(f"Corroborated across {len({e.source_engine for e in evidence_items})} sources.")
        elif status_val == CorroborationStatus.SINGLE_SOURCE.value:
            lines.append("Single-source observation.")

        for ev in evidence_items:
            rule_str = f" [{ev.rule_id}]" if ev.rule_id else ""
            loc = f" in {ev.file_path}:{ev.line_start}" if ev.file_path and ev.line_start else ""
            lines.append(
                f"• [{ev.level.value} | {ev.state.value}] {ev.source_engine}{rule_str}: {ev.description}{loc} "
                f"(confidence: {int(ev.confidence * 100)}%)"
            )

        return "\n".join(lines)

    def fuse_asset_findings(
        self,
        project: str,
        scan_id: str,
        asset_name: str,
        algorithm: str,
        evidence_items: List[Evidence],
        asset_type: AssetType = AssetType.ALGORITHM,
    ) -> Dict[str, Any]:
        result = self.compute_corroboration(evidence_items)
        asset_dict = {
            "project": project,
            "scan_id": scan_id,
            "name": asset_name,
            "algorithm": algorithm,
            "asset_type": asset_type.value if hasattr(asset_type, "value") else str(asset_type),
            "fused_status": result.fused_status.value,
            "highest_evidence_level": result.highest_level.value,
            "confidence": result.combined_confidence,
            "explanation": result.explanation,
            "contradictions": result.contradictions,
        }
        if self.graph:
            asset = self.graph.upsert_asset(
                project=project,
                asset_type=asset_type,
                name=asset_name,
                algorithm=algorithm,
                scan_id=scan_id,
                fused_status=result.fused_status.value,
                highest_evidence_level=result.highest_level.value,
                confidence=result.combined_confidence,
                explanation=result.explanation,
            )
            for ev in evidence_items:
                self.graph.add_evidence(asset.id, ev, project)
            asset_dict["id"] = asset.id
        return asset_dict

    def evaluate_freshness(
        self,
        evidence: Evidence,
        as_of_time: Optional[datetime | str] = None,
        ttl_days: int = 90,
    ) -> EvidenceFreshness:
        """
        Evaluates evidence freshness against a point in time.
        NEVER mutates evidence.state.
        """
        if getattr(evidence, "lineage", None) and getattr(evidence.lineage, "superseded_by_id", None):
            return EvidenceFreshness.SUPERSEDED
        if isinstance(evidence.raw_details, dict):
            if evidence.raw_details.get("superseded_by") or evidence.raw_details.get("is_superseded"):
                return EvidenceFreshness.SUPERSEDED

        # Resolve as_of_time
        if as_of_time is None:
            as_of = datetime.now(timezone.utc)
        elif isinstance(as_of_time, str):
            try:
                as_of = datetime.fromisoformat(as_of_time.replace("Z", "+00:00"))
            except Exception:
                as_of = datetime.now(timezone.utc)
        else:
            as_of = as_of_time

        if as_of.tzinfo is None:
            as_of = as_of.replace(tzinfo=timezone.utc)

        ts_str = getattr(evidence, "timestamp", None)
        if not ts_str and isinstance(evidence.raw_details, dict):
            ts_str = evidence.raw_details.get("timestamp")

        if not ts_str:
            return EvidenceFreshness.UNKNOWN

        try:
            ev_dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if ev_dt.tzinfo is None:
                ev_dt = ev_dt.replace(tzinfo=timezone.utc)
        except Exception:
            return EvidenceFreshness.UNKNOWN

        delta = as_of - ev_dt
        if delta.days > ttl_days:
            return EvidenceFreshness.STALE
        return EvidenceFreshness.CURRENT

    def track_supersession(
        self,
        old_evidence: Evidence,
        new_evidence: Evidence,
    ) -> EvidenceLineage:
        """
        Tracks evidence supersession cleanly without mutating old_evidence.state.
        """
        now_ts = datetime.now(timezone.utc).isoformat()
        if not isinstance(old_evidence.raw_details, dict):
            old_evidence.raw_details = {}
        old_evidence.raw_details["superseded_by"] = new_evidence.id
        old_evidence.raw_details["superseded_at"] = now_ts

        lineage = EvidenceLineage(
            scan_id=getattr(new_evidence, "scan_id", None) or getattr(old_evidence, "scan_id", None) or "unknown",
            parent_evidence_id=old_evidence.id,
            superseded_by_id=new_evidence.id,
            superseded_at=now_ts,
            created_at=getattr(old_evidence, "timestamp", None) or now_ts,
            metadata={"superseded_reason": "newer_observation"},
        )
        return lineage

    def corroborate_multi_scan(
        self,
        project: str,
        asset_key: str,
        scans: List[Dict[str, Any]],
        as_of_time: Optional[datetime | str] = None,
        ttl_days: int = 90,
    ) -> MultiScanCorroboration:
        """
        Corroborates evidence for a given asset_key across multiple scans.
        Considers freshness and supersession without mutating evidence states.
        """
        all_evidence: List[Evidence] = []
        scans_observed: List[str] = []

        for scan_entry in scans:
            scan_id = scan_entry.get("scan_id") or scan_entry.get("id") or "unknown"
            items = scan_entry.get("evidence") or scan_entry.get("evidence_items") or []
            matched = False
            for it in items:
                ev: Optional[Evidence] = None
                if isinstance(it, Evidence):
                    ev = it
                elif isinstance(it, dict):
                    # Convert dict to Evidence if possible
                    try:
                        ev = Evidence.from_dict(it)
                    except Exception:
                        pass
                if ev:
                    # Check if evidence matches asset_key or is relevant dynamic protocol observation
                    ev_text = f"{ev.symbol or ''} {ev.description or ''} {(ev.raw_details.get('asset_key', '') if isinstance(ev.raw_details, dict) else '')}".lower()
                    key_target = asset_key.strip().lower()
                    if not key_target or key_target in ev_text or ev_text in key_target or ev.observation_type in (ObservationType.TLS_NEGOTIATION, ObservationType.PQC_NEGOTIATION):
                        all_evidence.append(ev)
                        matched = True
            if matched and scan_id not in scans_observed:
                scans_observed.append(scan_id)

        active_evidence: List[Evidence] = []
        superseded_count = 0
        current_count = 0
        stale_count = 0

        for ev in all_evidence:
            fr = self.evaluate_freshness(ev, as_of_time=as_of_time, ttl_days=ttl_days)
            if fr == EvidenceFreshness.SUPERSEDED:
                superseded_count += 1
            else:
                active_evidence.append(ev)
                if fr == EvidenceFreshness.CURRENT:
                    current_count += 1
                elif fr == EvidenceFreshness.STALE:
                    stale_count += 1

        if not all_evidence:
            overall_freshness = EvidenceFreshness.UNKNOWN
        elif current_count > 0:
            overall_freshness = EvidenceFreshness.CURRENT
        elif stale_count > 0:
            overall_freshness = EvidenceFreshness.STALE
        elif superseded_count > 0:
            overall_freshness = EvidenceFreshness.SUPERSEDED
        else:
            overall_freshness = EvidenceFreshness.UNKNOWN

        evidence_to_fuse = active_evidence if active_evidence else all_evidence
        corrob_result = self.compute_corroboration(evidence_to_fuse)

        multi_explanation = (
            f"Multi-Scan Corroboration for {asset_key}: observed in {len(scans_observed)} scan(s) "
            f"({current_count} current, {stale_count} stale, {superseded_count} superseded). "
            f"Overall Freshness: {overall_freshness.value}.\n"
            f"{corrob_result.explanation}"
        )

        return MultiScanCorroboration(
            asset_key=asset_key,
            fused_status=corrob_result.fused_status,
            highest_level=corrob_result.highest_level,
            combined_confidence=corrob_result.combined_confidence,
            scan_count=len(scans_observed),
            scans_observed=scans_observed,
            freshness=overall_freshness,
            active_evidence_count=len(active_evidence),
            superseded_evidence_count=superseded_count,
            explanation=multi_explanation,
            contradictions=corrob_result.contradictions,
        )


CorroborationEngine = EvidenceFusionEngine

