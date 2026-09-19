"""
ECDAT V4 Unified Evidence Model & Provenance Engine.

Core Principles:
1. WHAT WAS MEASURED != WHAT WAS INFERRED != WHAT WAS ESTIMATED != WHAT CANNOT BE INDEPENDENTLY VERIFIED.
2. Evidence level (E0..E5) is strictly distinct from statistical confidence (0.0..1.0).
3. Every finding links back to an immutable, reproducible provenance record.
4. Unified EvidenceRecord schema for cross-surface correlation, verification, and CBOM generation.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid



class EvidenceState(str, Enum):
    MEASURED = "MEASURED"
    INFERRED = "INFERRED"
    ESTIMATED = "ESTIMATED"
    DECLARED = "DECLARED"
    UNMEASURED = "UNMEASURED"
    EXTRAPOLATED = "EXTRAPOLATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_IN_OBSERVED_SCOPE = "NOT_IN_OBSERVED_SCOPE"


class EvidenceLevel(str, Enum):
    E0 = "E0"  # Unmeasured / no evidence collected
    E1 = "E1"  # Pattern or heuristic candidate detected
    E2 = "E2"  # Structured asset detected
    E3 = "E3"  # Actual reference / API use confirmed
    E4 = "E4"  # Reachability or execution path confirmed
    E5 = "E5"  # Live protocol / network behavior observed

    @property
    def rank(self) -> int:
        return int(self.value[1])

    @property
    def label(self) -> str:
        descriptions = {
            "E0": "Unmeasured / no evidence collected",
            "E1": "Pattern or heuristic candidate detected",
            "E2": "Structured asset detected",
            "E3": "Actual reference / API use confirmed",
            "E4": "Reachability or execution path confirmed",
            "E5": "Live protocol / network behavior observed",
        }
        return f"{self.value} — {descriptions[self.value]}"


LEVEL_RANK: Dict[EvidenceLevel, int] = {
    EvidenceLevel.E0: 0,
    EvidenceLevel.E1: 1,
    EvidenceLevel.E2: 2,
    EvidenceLevel.E3: 3,
    EvidenceLevel.E4: 4,
    EvidenceLevel.E5: 5,
}


class ArtifactType(str, Enum):
    SOURCE_FILE = "SOURCE_FILE"
    BINARY = "BINARY"
    FIRMWARE = "FIRMWARE"
    NETWORK_ENDPOINT = "NETWORK_ENDPOINT"
    CONFIG_FILE = "CONFIG_FILE"
    CERTIFICATE = "CERTIFICATE"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    SYSTEM_PACKAGE = "SYSTEM_PACKAGE"


class ObservationType(str, Enum):
    SOURCE_PATTERN = "SOURCE_PATTERN"
    SOURCE_API_USE = "SOURCE_API_USE"
    SOURCE_IMPORT = "SOURCE_IMPORT"
    SOURCE_DATAFLOW = "SOURCE_DATAFLOW"
    DEPENDENCY_DECLARATION = "DEPENDENCY_DECLARATION"
    DEPENDENCY_LOCKFILE = "DEPENDENCY_LOCKFILE"
    BINARY_SIGNATURE = "BINARY_SIGNATURE"
    BINARY_SYMBOL = "BINARY_SYMBOL"
    BINARY_FUNCTION = "BINARY_FUNCTION"
    BINARY_REFERENCE = "BINARY_REFERENCE"
    HARDCODED_KEY = "HARDCODED_KEY"
    FIRMWARE_CONTENT = "FIRMWARE_CONTENT"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    TLS_CONFIGURATION = "TLS_CONFIGURATION"
    X509_CERTIFICATE = "X509_CERTIFICATE"
    SSH_NEGOTIATION = "SSH_NEGOTIATION"
    PQC_NEGOTIATION = "PQC_NEGOTIATION"
    QUIC_NEGOTIATION = "QUIC_NEGOTIATION"
    PROTOCOL_OBSERVATION = "PROTOCOL_OBSERVATION"
    RUNTIME_CALL = "RUNTIME_CALL"
    HTTP_HEADER = "HTTP_HEADER"
    COOKIE = "COOKIE"
    THIRD_PARTY_RESOURCE = "THIRD_PARTY_RESOURCE"
    CONFIGURATION = "CONFIGURATION"
    MANIFEST = "MANIFEST"
    USER_SUPPLIED = "USER_SUPPLIED"
    SSH_CAPABILITY = "SSH_CAPABILITY"


@dataclass
class Provenance:
    input_hash: str = ""
    source_engine: str = ""
    engine_version: str = "4.0.0"
    scan_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scanner_version: str = "4.0.0"
    artifact_hash: Optional[str] = None
    rule_id: Optional[str] = None
    rule_version: Optional[str] = None
    location: Optional[str] = None
    environment: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def hash(self) -> str:
        serialized = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class Evidence:
    state: EvidenceState
    level: EvidenceLevel
    confidence: float
    source_engine: str
    observation_type: ObservationType
    artifact_type: str | ArtifactType
    description: str
    provenance: Provenance
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    engine_version: str = "4.0.0"
    rule_id: Optional[str] = None
    rule_version: Optional[str] = None
    artifact_id: Optional[str] = None
    location: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    byte_offset: Optional[str] = None
    function_name: Optional[str] = None
    symbol: Optional[str] = None
    limitations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    supporting: List[str] = field(default_factory=list)
    contradicting: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Validate confidence is strictly bound to [0.0, 1.0]
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if isinstance(self.state, str):
            self.state = EvidenceState(self.state)
        if isinstance(self.level, str):
            self.level = EvidenceLevel(self.level)
        if isinstance(self.observation_type, str):
            self.observation_type = ObservationType(self.observation_type)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["state"] = self.state.value
        res["level"] = self.level.value
        res["observation_type"] = self.observation_type.value
        res["level_label"] = self.level.label
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Evidence:
        d = dict(data)
        prov_data = d.pop("provenance")
        if isinstance(prov_data, dict):
            provenance = Provenance(**prov_data)
        else:
            provenance = prov_data
        d.pop("level_label", None)
        return cls(provenance=provenance, **d)


from pydantic import BaseModel, Field



def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetType(str, Enum):
    APPLICATION = "application"
    SERVICE = "service"
    LIBRARY = "library"
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    ENDPOINT = "endpoint"
    BINARY = "binary"
    DATA_FLOW = "data_flow"
    KEY_MATERIAL = "key_material"
    UNKNOWN = "unknown"


class CryptographicRole(str, Enum):
    KEY_EXCHANGE = "key_exchange"
    DIGITAL_SIGNATURE = "digital_signature"
    BULK_ENCRYPTION = "bulk_encryption"
    HASH_INTEGRITY = "hash_integrity"
    MAC = "mac"
    CERTIFICATE_PKI = "certificate_pki"
    KEY_DERIVATION = "key_derivation"
    UNKNOWN = "unknown"


class SourceSurface(str, Enum):
    SOURCE_CODE = "source_code"
    DEPENDENCIES = "dependencies"
    BINARY_FIRMWARE = "binary_firmware"
    NETWORK_TLS = "network_tls"
    CERTIFICATES = "certificates"
    RUNTIME_TRACE = "runtime_trace"
    PASSIVE_PCAP = "passive_pcap"
    UNKNOWN = "unknown"


class EvidenceType(str, Enum):
    STATIC_INFERRED = "static_inferred"
    RUNTIME_OBSERVED = "runtime_observed"
    NETWORK_OBSERVED = "network_observed"
    CORROBORATED = "corroborated"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "CONFIRMED"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class EvidenceProvenance(BaseModel):
    detector_engine: str
    rule_or_signature: Optional[str] = None
    raw_match: Optional[str] = None
    surrounding_context: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    detection_technique: Optional[str] = None  # e.g., "ast_analysis", "byte_signature", "tls_handshake"


class EvidenceRecord(BaseModel):
    asset_id: str
    asset_type: AssetType = AssetType.ALGORITHM
    algorithm: str
    cryptographic_role: CryptographicRole = CryptographicRole.UNKNOWN
    source_surface: SourceSurface = SourceSurface.UNKNOWN
    evidence_type: EvidenceType = EvidenceType.UNKNOWN
    location_endpoint: str  # e.g. "src/auth.py:42", "0x0004FA10", "192.168.1.50:443"
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    timestamp: str = Field(default_factory=utc_now_iso)
    input_hash: str = ""
    engine_version: str = "3.0.0"

    # Exploded metadata
    severity: str = "LOW"
    description: str = ""
    nist_status: Optional[str] = None
    quantum_vulnerable: Optional[bool] = None
    is_unknown: bool = False
    provenance: EvidenceProvenance = Field(default_factory=lambda: EvidenceProvenance(detector_engine="generic"))

    @staticmethod
    def generate_asset_id(surface: str, location: str, algorithm: str, extra: str = "") -> str:
        """Generates a stable, deterministic asset identity."""
        raw = f"{surface}|{location}|{algorithm.upper().strip()}|{extra}"
        return "asset_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def infer_crypto_role(algorithm_str: str, category: Optional[str] = None) -> CryptographicRole:
    upper = (algorithm_str or "").upper()
    cat = (category or "").upper()

    if any(k in upper for k in ("KEM", "ECDH", "DH", "KEY EXCHANGE", "X25519", "SECP", "FFDHE")):
        return CryptographicRole.KEY_EXCHANGE
    if any(k in upper for k in ("DSA", "DILITHIUM", "SPHINCS", "SIGNATURE", "ED25519", "PKCS#1")):
        return CryptographicRole.DIGITAL_SIGNATURE
    if any(k in upper for k in ("AES", "DES", "CHACHA", "3DES", "RC4", "CIPHER")):
        return CryptographicRole.BULK_ENCRYPTION
    if any(k in upper for k in ("MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA3", "SHAKE", "HASH")):
        return CryptographicRole.HASH_INTEGRITY
    if any(k in upper for k in ("HMAC", "CMAC", "POLY1305")):
        return CryptographicRole.MAC
    if any(k in upper for k in ("CERT", "X509", "PKI")):
        return CryptographicRole.CERTIFICATE_PKI
    if "RSA" in upper:
        if "SIGN" in cat:
            return CryptographicRole.DIGITAL_SIGNATURE
        return CryptographicRole.KEY_EXCHANGE
    return CryptographicRole.UNKNOWN


def is_quantum_vulnerable(algorithm_str: str) -> Optional[bool]:
    upper = (algorithm_str or "").upper()
    # Quantum vulnerable public-key mechanisms: RSA, ECC (ECDSA, ECDH), DSA, DH
    if any(k in upper for k in ("RSA", "ECDSA", "ECDH", "DIFFIE-HELLMAN", "ED25519", "SECP", "CURVE25519")):
        return True
    # Quantum-safe PQC standards
    if any(k in upper for k in ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS")):
        return False
    # Symmetric ciphers: Grover affects them by halving security bits
    if "DES" in upper or "RC4" in upper or "MD5" in upper or "SHA1" in upper or "SHA-1" in upper:
        return True
    if "AES-128" in upper:
        return True  # 64-bit quantum security level
    if "AES-256" in upper or "SHA-256" in upper or "SHA-384" in upper or "SHA-512" in upper:
        return False
    return None


def normalize_source_finding(finding: Dict[str, Any], input_hash: str = "") -> EvidenceRecord:
    primitive = finding.get("primitive", "Unknown")
    file_path = finding.get("file", "snippet")
    line = finding.get("line")
    location = f"{file_path}:{line}" if line is not None else file_path
    role = infer_crypto_role(primitive, finding.get("category"))
    asset_id = EvidenceRecord.generate_asset_id("source_code", location, primitive)
    
    conf_str = finding.get("confidence", "MEDIUM").upper()
    try:
        conf = ConfidenceLevel[conf_str]
    except KeyError:
        conf = ConfidenceLevel.MEDIUM

    return EvidenceRecord(
        asset_id=asset_id,
        asset_type=AssetType.ALGORITHM,
        algorithm=primitive,
        cryptographic_role=role,
        source_surface=SourceSurface.SOURCE_CODE,
        evidence_type=EvidenceType.STATIC_INFERRED,
        location_endpoint=location,
        confidence=conf,
        input_hash=input_hash or finding.get("source_hash", ""),
        severity=finding.get("severity", "LOW").upper(),
        description=finding.get("issue") or finding.get("description", ""),
        quantum_vulnerable=is_quantum_vulnerable(primitive),
        provenance=EvidenceProvenance(
            detector_engine=finding.get("engine", "source-scanner"),
            rule_or_signature=finding.get("issue"),
            raw_match=finding.get("code"),
            detection_technique="ast_or_polyglot_regex"
        )
    )


def normalize_binary_detection(detection: Dict[str, Any], file_name: str, input_hash: str = "") -> EvidenceRecord:
    primitive = detection.get("primitive", "Unknown")
    offset = detection.get("offset", "0x0")
    location = f"{file_name}@{offset}"
    role = infer_crypto_role(primitive, detection.get("type"))
    asset_id = EvidenceRecord.generate_asset_id("binary_firmware", location, primitive)

    conf_str = detection.get("confidence", "MEDIUM").upper()
    try:
        conf = ConfidenceLevel[conf_str]
    except KeyError:
        conf = ConfidenceLevel.MEDIUM

    asset_type = AssetType.ALGORITHM
    if "PRIVATE KEY" in primitive.upper() or "KEY" in detection.get("type", "").upper():
        asset_type = AssetType.KEY_MATERIAL
    elif "CERTIFICATE" in primitive.upper():
        asset_type = AssetType.CERTIFICATE

    return EvidenceRecord(
        asset_id=asset_id,
        asset_type=asset_type,
        algorithm=primitive,
        cryptographic_role=role,
        source_surface=SourceSurface.BINARY_FIRMWARE,
        evidence_type=EvidenceType.STATIC_INFERRED,
        location_endpoint=location,
        confidence=conf,
        input_hash=input_hash,
        severity=detection.get("severity", "LOW").upper(),
        description=detection.get("description", ""),
        quantum_vulnerable=is_quantum_vulnerable(primitive),
        provenance=EvidenceProvenance(
            detector_engine="binary_deep",
            rule_or_signature=detection.get("byte_order"),
            detection_technique=detection.get("type", "byte-signature"),
            parameters={"section": detection.get("section")}
        )
    )


def normalize_network_scan(network_result: Dict[str, Any], scan_id: str, input_hash: str = "") -> List[EvidenceRecord]:
    records: List[EvidenceRecord] = []
    target = network_result.get("target") or f"{network_result.get('host', 'unknown')}:{network_result.get('port', 443)}"
    cipher = network_result.get("cipher_name")
    
    if cipher and cipher != "Unknown":
        role = infer_crypto_role(cipher)
        rec = EvidenceRecord(
            asset_id=EvidenceRecord.generate_asset_id("network_tls", target, cipher),
            asset_type=AssetType.ALGORITHM,
            algorithm=cipher,
            cryptographic_role=role,
            source_surface=SourceSurface.NETWORK_TLS,
            evidence_type=EvidenceType.NETWORK_OBSERVED,
            location_endpoint=target,
            confidence=ConfidenceLevel.CONFIRMED,
            input_hash=input_hash,
            severity=network_result.get("hndl_risk", "LOW"),
            description=network_result.get("hndl_rationale", "Negotiated TLS cipher suite"),
            quantum_vulnerable=network_result.get("quantum_vulnerable"),
            provenance=EvidenceProvenance(
                detector_engine="network_prober",
                detection_technique="live_tls_handshake",
                parameters={
                    "protocol": network_result.get("protocol"),
                    "key_exchange": network_result.get("key_exchange"),
                    "secret_bits": network_result.get("secret_bits")
                }
            )
        )
        records.append(rec)

    # Post-quantum hybrid probe observations
    pqc = network_result.get("post_quantum") or {}
    for test in pqc.get("tests", []):
        if test.get("status") == "negotiated":
            group = test.get("negotiated_group") or test.get("group")
            rec = EvidenceRecord(
                asset_id=EvidenceRecord.generate_asset_id("network_tls", target, f"TLS_GROUP_{group}"),
                asset_type=AssetType.ALGORITHM,
                algorithm=f"TLS_GROUP_{group}",
                cryptographic_role=CryptographicRole.KEY_EXCHANGE,
                source_surface=SourceSurface.NETWORK_TLS,
                evidence_type=EvidenceType.NETWORK_OBSERVED,
                location_endpoint=target,
                confidence=ConfidenceLevel.CONFIRMED,
                input_hash=input_hash,
                severity="LOW",
                description=f"Negotiated post-quantum hybrid group: {group}",
                quantum_vulnerable=False,
                provenance=EvidenceProvenance(
                    detector_engine="pqc_probe",
                    detection_technique="tls13_group_negotiation",
                    parameters={"group": group, "evidence": test.get("evidence")}
                )
            )
            records.append(rec)

    # Certificate details
    cert = network_result.get("certificate") or {}
    if cert.get("public_key"):
        pk = cert["public_key"]
        subj = cert.get("subject", target)
        rec = EvidenceRecord(
            asset_id=EvidenceRecord.generate_asset_id("certificates", subj, pk),
            asset_type=AssetType.CERTIFICATE,
            algorithm=pk,
            cryptographic_role=CryptographicRole.CERTIFICATE_PKI,
            source_surface=SourceSurface.CERTIFICATES,
            evidence_type=EvidenceType.NETWORK_OBSERVED,
            location_endpoint=f"{target} (Cert: {subj})",
            confidence=ConfidenceLevel.CONFIRMED,
            input_hash=input_hash,
            severity="CRITICAL" if cert.get("expired") else ("HIGH" if is_quantum_vulnerable(pk) else "LOW"),
            description=f"Server X.509 certificate public key: {pk}. Expired: {cert.get('expired')}",
            quantum_vulnerable=is_quantum_vulnerable(pk),
            provenance=EvidenceProvenance(
                detector_engine="network_prober",
                detection_technique="x509_der_parse",
                parameters={
                    "issuer": cert.get("issuer"),
                    "sha256": cert.get("sha256"),
                    "valid_to": cert.get("valid_to")
                }
            )
        )
        records.append(rec)

    return records

