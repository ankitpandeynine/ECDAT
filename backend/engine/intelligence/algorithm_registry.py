"""
ECDAT V4 P2.1 Algorithm Registry.

Loads algorithm_security.yaml and provides:
- Algorithm normalization (alias -> canonical entry)
- Crypto role resolution
- Quantum impact lookup
- Hybrid KEX detection and decomposition

AXIOM: ML-KEM != ML-DSA. Hybrid KEX detection never implies signature algorithms.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .models import CryptoRole, QuantumImpact


_KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"
_ALGO_YAML_PATH = _KNOWLEDGE_DIR / "algorithm_security.yaml"

_ROLE_MAP = {
    "KEY_ESTABLISHMENT": CryptoRole.KEY_ESTABLISHMENT,
    "SIGNATURE": CryptoRole.SIGNATURE,
    "PUBLIC_KEY_ENCRYPTION": CryptoRole.PUBLIC_KEY_ENCRYPTION,
    "SYMMETRIC_ENCRYPTION": CryptoRole.SYMMETRIC_ENCRYPTION,
    "HASH": CryptoRole.HASH,
    "MAC": CryptoRole.MAC,
    "KDF": CryptoRole.KDF,
    "AUTHENTICATION": CryptoRole.AUTHENTICATION,
    "CERTIFICATE_SIGNATURE": CryptoRole.CERTIFICATE_SIGNATURE,
    "AEAD": CryptoRole.AEAD,
}

_IMPACT_MAP = {
    "SHOR_BREAKS": QuantumImpact.SHOR_BREAKS,
    "GROVER_HALVING": QuantumImpact.GROVER_HALVING,
    "GROVER_HALVING_COLLISION": QuantumImpact.GROVER_HALVING_COLLISION,
    "HYBRID_PARTIAL": QuantumImpact.HYBRID_PARTIAL,
    "NONE_PQC_SECURE": QuantumImpact.NONE_PQC_SECURE,
    "BROKEN_CLASSICALLY": QuantumImpact.BROKEN_CLASSICALLY,
}


@dataclass
class AlgorithmEntry:
    canonical_name: str
    category: str
    roles: List[CryptoRole]
    status: str
    quantum_impact: QuantumImpact
    pqc_status: str
    deprecation_status: str
    aliases: List[str] = field(default_factory=list)
    classical_security_bits: Optional[Any] = None  # int or dict{str:int}
    quantum_security_bits: Optional[int] = None
    quantum_notes: str = ""
    security_level: Optional[int] = None
    default_parameter_status: str = "KNOWN"
    components: Optional[Dict[str, str]] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HybridConstruction:
    """Decomposed hybrid KEX construction."""
    canonical_name: str
    classical_component: str
    pqc_component: str
    role: CryptoRole = CryptoRole.KEY_ESTABLISHMENT
    note: str = ""

    @property
    def is_kem(self) -> bool:
        return True

    @property
    def is_signature(self) -> bool:
        """A hybrid KEX is NOT a signature. This is always False."""
        return False


class AlgorithmRegistry:
    """Singleton registry loaded from algorithm_security.yaml."""

    def __init__(self, yaml_path: Path = _ALGO_YAML_PATH) -> None:
        with open(yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self._version: str = data.get("version", "UNKNOWN")
        self._entries: Dict[str, AlgorithmEntry] = {}  # canonical -> entry
        self._alias_map: Dict[str, str] = {}           # lower alias -> canonical

        for raw in data.get("algorithms", []):
            entry = self._parse_entry(raw)
            self._entries[entry.canonical_name] = entry
            # Index by canonical (case-insensitive)
            self._alias_map[entry.canonical_name.lower()] = entry.canonical_name
            for alias in entry.aliases:
                self._alias_map[alias.lower()] = entry.canonical_name

    def _parse_entry(self, raw: Dict[str, Any]) -> AlgorithmEntry:
        roles = [_ROLE_MAP.get(r, CryptoRole.UNKNOWN) for r in raw.get("roles", [])]
        impact_str = raw.get("quantum_impact", "UNKNOWN")
        impact = _IMPACT_MAP.get(impact_str, QuantumImpact.UNKNOWN)
        return AlgorithmEntry(
            canonical_name=raw["canonical_name"],
            category=raw.get("category", "UNKNOWN"),
            roles=roles,
            status=raw.get("status", "UNKNOWN"),
            quantum_impact=impact,
            pqc_status=raw.get("pqc_status", "UNKNOWN"),
            deprecation_status=raw.get("deprecation_status", "UNKNOWN"),
            aliases=raw.get("aliases", []),
            classical_security_bits=raw.get("classical_security_bits") or raw.get("classical_security_bits_by_param"),
            quantum_security_bits=raw.get("quantum_security_bits"),
            quantum_notes=raw.get("quantum_notes", ""),
            security_level=raw.get("security_level"),
            default_parameter_status=raw.get("default_parameter_status", "KNOWN"),
            components=raw.get("components"),
            raw=raw,
        )

    def knowledge_base_version(self) -> str:
        return self._version

    def normalize(self, raw_name: str) -> Optional[AlgorithmEntry]:
        """Return the AlgorithmEntry for raw_name, or None if unrecognized."""
        if not raw_name:
            return None
        key = raw_name.strip().lower()
        canonical = self._alias_map.get(key)
        if canonical:
            return self._entries[canonical]
        # Fuzzy: try stripping trailing version/curve suffixes
        for suffix_pattern in [
            r"-\d{3,4}$", r"_\d{3,4}$", r"\s+\d{3,4}$",
            r"[\s\-_/]+p[\-_]?\d{3}$", r"[\s\-_/]+secp\w+$", r"[\s\-_/]+prime\w+$"
        ]:
            stripped = re.sub(suffix_pattern, "", key)
            if stripped != key:
                canonical = self._alias_map.get(stripped)
                if canonical:
                    return self._entries[canonical]
        return None

    def get_roles(self, canonical_or_raw: str) -> List[CryptoRole]:
        entry = self.normalize(canonical_or_raw)
        if entry is None:
            return [CryptoRole.UNKNOWN]
        return entry.roles or [CryptoRole.UNKNOWN]

    def get_quantum_impact(self, canonical_or_raw: str) -> QuantumImpact:
        entry = self.normalize(canonical_or_raw)
        if entry is None:
            return QuantumImpact.UNKNOWN
        return entry.quantum_impact

    def is_hybrid_kem(self, name: str) -> bool:
        entry = self.normalize(name)
        if entry is None:
            return False
        return entry.category == "HYBRID_KEM"

    def is_pqc_kem(self, name: str) -> bool:
        entry = self.normalize(name)
        if entry is None:
            return False
        return entry.category in ("PQC_KEM", "HYBRID_KEM")

    def is_pqc_signature(self, name: str) -> bool:
        entry = self.normalize(name)
        if entry is None:
            return False
        return entry.category == "PQC_SIGNATURE"

    def resolve_hybrid(self, name: str) -> Optional[HybridConstruction]:
        """
        Decompose a hybrid KEM name into its components.
        AXIOM: Hybrid KEX is NOT a signature. resolve_hybrid always returns is_signature=False.
        """
        entry = self.normalize(name)
        if entry is None or entry.category != "HYBRID_KEM":
            return None
        comps = entry.components or {}
        classical = comps.get("classical", "UNKNOWN")
        pqc = comps.get("pqc", "UNKNOWN")
        return HybridConstruction(
            canonical_name=entry.canonical_name,
            classical_component=classical,
            pqc_component=pqc,
            role=CryptoRole.KEY_ESTABLISHMENT,
            note=entry.quantum_notes or
                 "Hybrid KEX only. Does NOT provide PQC signature capability.",
        )

    def get_entry(self, name: str) -> Optional[AlgorithmEntry]:
        return self.normalize(name)

    def all_canonical_names(self) -> List[str]:
        return list(self._entries.keys())


@lru_cache(maxsize=1)
def _get_registry() -> AlgorithmRegistry:
    return AlgorithmRegistry()


def get_registry() -> AlgorithmRegistry:
    return _get_registry()


def normalize_algorithm(raw: str) -> Optional[AlgorithmEntry]:
    return get_registry().normalize(raw)

def lookup_algorithm(raw: str) -> Optional[AlgorithmEntry]:
    return get_registry().normalize(raw)

def decompose_hybrid(name: str) -> Optional[List[AlgorithmEntry]]:
    h = get_registry().resolve_hybrid(name)
    if not h:
        return None
    c_entry = get_registry().normalize(h.classical_component)
    p_entry = get_registry().normalize(h.pqc_component)
    res = []
    if c_entry:
        res.append(c_entry)
    if p_entry:
        res.append(p_entry)
    return res if res else None

def get_crypto_roles(name: str) -> List[CryptoRole]:
    return get_registry().get_roles(name)

def get_quantum_impact(name: str) -> QuantumImpact:
    return get_registry().get_quantum_impact(name)

def is_hybrid_kem(name: str) -> bool:
    return get_registry().is_hybrid_kem(name)

def is_pqc_kem(name: str) -> bool:
    return get_registry().is_pqc_kem(name)

def is_pqc_signature(name: str) -> bool:
    return get_registry().is_pqc_signature(name)

def resolve_hybrid(name: str) -> Optional[HybridConstruction]:
    return get_registry().resolve_hybrid(name)

def knowledge_base_version() -> str:
    return get_registry().knowledge_base_version()
