"""
ECDAT V4 P2.2 Agility Evidence Adapter.

Maps and normalizes P0/P1/P2.1 evidence into agility-relevant signals
without inventing facts or discarding provenance.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple
from .models import AgilityConfidence, AgilityDimension, AgilityState


# Canonical Agility Signal Vocabulary
SIGNAL_ABSTRACTION = "CRYPTO_ABSTRACTION"
SIGNAL_FACTORY = "CRYPTO_FACTORY"
SIGNAL_REGISTRY = "ALGORITHM_REGISTRY"
SIGNAL_PROVIDER = "PROVIDER_INTERFACE"
SIGNAL_HARDCODED_ALGORITHM = "HARDCODED_ALGORITHM"
SIGNAL_DIRECT_BINDING = "DIRECT_LIBRARY_BINDING"
SIGNAL_CONFIGURABLE = "CONFIGURABLE_ALGORITHM"
SIGNAL_RUNTIME_RELOAD = "RUNTIME_CONFIG_RELOAD"
SIGNAL_CONFIG_FILE = "CONFIG_FILE"
SIGNAL_ENV_VAR = "ENVIRONMENT_VARIABLE"
SIGNAL_HARDCODED_FALLBACK = "HARDCODED_FALLBACK"
SIGNAL_HARDCODED_KEY = "HARDCODED_KEY"
SIGNAL_HARDCODED_IV = "HARDCODED_IV"
SIGNAL_DEPENDENCY_DEC = "DEPENDENCY_DECLARATION"
SIGNAL_DEPENDENCY_LOCK = "DEPENDENCY_LOCK"
SIGNAL_VENDORED = "VENDORED_SOURCE"
SIGNAL_DYNAMIC_LIB = "DYNAMIC_LIBRARY"
SIGNAL_STATIC_BINDING = "STATIC_BINARY_BINDING"
SIGNAL_TLS_NEGOTIATION = "TLS_NEGOTIATION"
SIGNAL_PROTOCOL_CONFIG = "PROTOCOL_CONFIGURATION"
SIGNAL_HARDCODED_PROTOCOL = "HARDCODED_PROTOCOL"
SIGNAL_ACME = "ACME_INTEGRATION"
SIGNAL_ROTATION = "ROTATION_MECHANISM"
SIGNAL_CERT_EXTERNAL = "CERT_EXTERNALIZATION"
SIGNAL_KEY_EXTERNAL = "KEY_EXTERNALIZATION"
SIGNAL_STATIC_CERT = "STATIC_CERT_NO_AUTOMATION"
SIGNAL_CONTAINER = "CONTAINER_IMAGE"
SIGNAL_DEPLOYMENT_CONFIG = "DEPLOYMENT_CONFIGURATION"
SIGNAL_FIRMWARE = "FIRMWARE_CONTENT"
SIGNAL_CRYPTO_TEST = "CRYPTO_TEST"
SIGNAL_UNIT_TEST = "UNIT_TEST"
SIGNAL_INTEROP_TEST = "INTEROPERABILITY_TEST"
SIGNAL_NO_TESTS = "NO_TESTS_OBSERVED"


class AgilityEvidenceItem:
    """Wrapper around raw evidence dictionary or Evidence dataclass for agility analysis."""
    def __init__(self, raw: Any):
        self.raw = raw
        if isinstance(raw, AgilityEvidenceItem):
            self.data = dict(raw.data)
            self.raw = raw.raw
        elif hasattr(raw, "to_dict"):
            self.data = raw.to_dict()
        elif isinstance(raw, dict):
            self.data = raw
        else:
            self.data = {"description": str(raw)}


        self.id = self.data.get("id") or self.data.get("evidence_id", "")
        self.state = str(self.data.get("state", "UNMEASURED"))
        self.level = str(self.data.get("level", "E0"))
        self.confidence = float(self.data.get("confidence", 0.0))
        self.observation_type = str(self.data.get("observation_type", ""))
        self.description = str(self.data.get("description", ""))
        self.metadata = self.data.get("metadata", {})
        self.raw_details = self.data.get("raw_details", {})
        self.file_path = self.data.get("file_path") or self.metadata.get("file_path")
        self.line_start = self.data.get("line_start")
        self.symbol = self.data.get("symbol") or self.metadata.get("symbol")

    def has_text(self, *keywords: str) -> bool:
        full_text = f"{self.observation_type} {self.description} {str(self.metadata)} {str(self.raw_details)}".lower()
        normalized_text = full_text.replace("_", " ").replace("-", " ")
        for k in keywords:
            kl = k.lower()
            if kl in full_text:
                return True
            kl_spaced = kl.replace("_", " ").replace("-", " ")
            if kl_spaced in normalized_text:
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.data)




def extract_confidence(evidence_items: List[AgilityEvidenceItem]) -> AgilityConfidence:
    """Computes categorical confidence from evidence levels and fusion states."""
    if not evidence_items:
        return AgilityConfidence.UNKNOWN

    states = {e.state for e in evidence_items}
    levels = {e.level for e in evidence_items}

    if "CONTRADICTED" in states:
        return AgilityConfidence.CONTRADICTED
    if "CORROBORATED" in states:
        return AgilityConfidence.CORROBORATED
    if any(lvl in ("E3", "E4", "E5") for lvl in levels) or "MEASURED" in states:
        return AgilityConfidence.MEASURED
    if any(lvl in ("E1", "E2") for lvl in levels) or "INFERRED" in states:
        return AgilityConfidence.INFERRED
    if "DECLARED" in states or "ESTIMATED" in states:
        return AgilityConfidence.UNVERIFIED
    return AgilityConfidence.UNKNOWN


def is_dimension_scanner_unavailable(
    dimension: AgilityDimension,
    evidence_items: List[AgilityEvidenceItem],
    context: Optional[Dict[str, Any]] = None,
) -> bool:
    """Determines if the scanner for a specific agility dimension was unavailable."""
    context = context or {}
    if context.get("scanner_unavailable") or context.get(f"{dimension.value.lower()}_scanner_unavailable") or context.get(f"{dimension.name.lower()}_scanner_unavailable"):
        return True

    dim_patterns = {
        AgilityDimension.AGILITY_ALGORITHM: ("algorithm", "source", "binary", "ast"),
        AgilityDimension.AGILITY_CONFIGURATION: ("config", "env_var", "configuration"),
        AgilityDimension.AGILITY_DEPENDENCY: ("depend", "package", "lockfile", "vendor"),
        AgilityDimension.AGILITY_PROTOCOL: ("tls", "ssh", "quic", "protocol", "cipher_suite", "handshake"),
        AgilityDimension.AGILITY_CERTIFICATE: ("cert", "x509", "rotation", "acme", "keystore", "key"),
        AgilityDimension.AGILITY_DEPLOYMENT: ("deploy", "container", "docker", "k8s", "firmware", "reload"),
        AgilityDimension.AGILITY_VALIDATION: ("test", "wycheproof", "validation", "kat"),
    }

    keywords = dim_patterns.get(dimension, ())
    for e in evidence_items:
        if "SCANNER_UNAVAILABLE" in e.state:
            if any(k in e.observation_type.lower() or k in e.description.lower() for k in keywords):
                return True

    return False

