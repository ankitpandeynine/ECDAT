"""
ECDAT V4 Binary Cryptographic Signature & Constant Matcher.

Matches byte signatures, IVs, S-Boxes, NTT constants, and ASN.1 OIDs
against binary data buffers using the knowledge base.

Research Axiom:
Compiled byte constants (e.g. AES S-box, Kyber NTT factors) prove cryptographic
capability is statically linked/embedded, but DO NOT prove dynamic execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from .binary_metadata import SectionInfo


@dataclass
class SignatureMatch:
    rule_id: str
    name: str
    family: str
    algorithm: str
    category: str
    offset: int
    matched_length: int
    byte_order: str  # "native" or "reversed-word-order"
    severity: str
    confidence: float
    pqc_status: str
    description: str
    section: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "family": self.family,
            "algorithm": self.algorithm,
            "category": self.category,
            "offset": f"0x{self.offset:08x}",
            "matched_length": self.matched_length,
            "byte_order": self.byte_order,
            "severity": self.severity,
            "confidence": self.confidence,
            "pqc_status": self.pqc_status,
            "description": self.description,
            "section": self.section,
        }


def _load_signatures_kb() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Loads signature rules and ASN.1 OIDs from YAML file."""
    yaml_path = Path(__file__).resolve().parent.parent.parent / "knowledge" / "binary_crypto_signatures.yaml"
    if not yaml_path.exists():
        return [], []
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            return data.get("signatures", []), data.get("asn1_oids", [])
    except Exception:
        return [], []


class BinarySignatureMatcher:
    """Scans binary buffers for cryptographic byte patterns, constants, and OIDs."""

    _cached_patterns: Optional[List[Tuple[Dict[str, Any], bytes, str]]] = None

    @classmethod
    def _initialize_patterns(cls) -> List[Tuple[Dict[str, Any], bytes, str]]:
        if cls._cached_patterns is not None:
            return cls._cached_patterns

        sigs, oids = _load_signatures_kb()
        patterns: List[Tuple[Dict[str, Any], bytes, str]] = []

        for sig in sigs:
            raw_hex = sig.get("canonical_hex") or sig.get("bytes_hex", "")
            if not raw_hex:
                continue
            try:
                pat_bytes = bytes.fromhex(raw_hex)
                patterns.append((sig, pat_bytes, "native"))
                # If word reversal supported, generate 32-bit reversed words pattern
                if sig.get("supports_word_reversal", False) and len(pat_bytes) % 4 == 0:
                    rev_bytes = b"".join(pat_bytes[i:i + 4][::-1] for i in range(0, len(pat_bytes), 4))
                    if rev_bytes != pat_bytes:
                        patterns.append((sig, rev_bytes, "reversed-word-order"))
            except ValueError:
                continue

        for oid in oids:
            raw_hex = oid.get("bytes_hex", "")
            if not raw_hex:
                continue
            try:
                oid_bytes = bytes.fromhex(raw_hex)
                meta = {
                    "id": oid["id"],
                    "name": oid["name"],
                    "family": oid["algorithm"],
                    "algorithm": oid["algorithm"],
                    "category": oid["category"],
                    "severity": oid.get("severity", "MEDIUM"),
                    "confidence": 0.95,
                    "pqc_status": oid.get("pqc_status", "UNKNOWN"),
                    "description": f"ASN.1 OID for {oid['name']} ({oid['oid']})",
                }
                patterns.append((meta, oid_bytes, "der-oid"))
            except ValueError:
                continue

        cls._cached_patterns = patterns
        return patterns

    @classmethod
    def match(
        cls,
        data: bytes,
        sections: Optional[List[SectionInfo]] = None,
        max_detections: int = 10000,
    ) -> List[SignatureMatch]:
        patterns = cls._initialize_patterns()
        matches: List[SignatureMatch] = []
        seen_offsets: Set[Tuple[str, int]] = set()

        for meta, pat_bytes, byte_order in patterns:
            start = 0
            while True:
                pos = data.find(pat_bytes, start)
                if pos < 0:
                    break

                key = (meta["id"], pos)
                if key not in seen_offsets:
                    seen_offsets.add(key)
                    # Find enclosing section
                    sec_name = None
                    if sections:
                        for s in sections:
                            if s.offset <= pos < s.offset + s.size:
                                sec_name = s.name
                                break

                    matches.append(
                        SignatureMatch(
                            rule_id=meta["id"],
                            name=meta["name"],
                            family=meta["family"],
                            algorithm=meta["algorithm"],
                            category=meta["category"],
                            offset=pos,
                            matched_length=len(pat_bytes),
                            byte_order=byte_order,
                            severity=meta.get("severity", "LOW"),
                            confidence=float(meta.get("confidence", 0.85)),
                            pqc_status=meta.get("pqc_status", "UNKNOWN"),
                            description=meta.get("description", "Cryptographic signature constant detected"),
                            section=sec_name,
                        )
                    )

                    if len(matches) >= max_detections:
                        return matches

                start = pos + max(1, len(pat_bytes))

        return matches
