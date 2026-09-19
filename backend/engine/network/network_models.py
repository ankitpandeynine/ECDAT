"""
ECDAT V4 Network Intelligence Models.

Preserves the strict distinction between:
CAPABILITY != ADVERTISEMENT != NEGOTIATION
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


class MeasurementType(str, Enum):
    TLS_VERSION = "TLS_VERSION"
    TLS_CIPHER = "TLS_CIPHER"
    TLS_KEX = "TLS_KEX"
    TLS_AUTH = "TLS_AUTH"
    X509_CERTIFICATE = "X509_CERTIFICATE"
    SSH_ALGORITHM = "SSH_ALGORITHM"
    QUIC_SUPPORT = "QUIC_SUPPORT"
    PQC_HYBRID = "PQC_HYBRID"


class NetworkState(str, Enum):
    UNMEASURED = "UNMEASURED"
    CONFIGURED = "CONFIGURED"
    SUPPORTED = "SUPPORTED"
    ADVERTISED = "ADVERTISED"
    OFFERED = "OFFERED"
    NEGOTIATED = "NEGOTIATED"
    NOT_NEGOTIATED = "NOT_NEGOTIATED"
    INCONCLUSIVE = "INCONCLUSIVE"
    SCANNER_UNAVAILABLE = "SCANNER_UNAVAILABLE"
    FAILED = "FAILED"


@dataclass
class NetworkEndpoint:
    host: str
    ip: str
    port: int
    protocol: str
    
    def __str__(self) -> str:
        return f"{self.protocol}://{self.host}:{self.port} (ip:{self.ip})"


@dataclass
class NetworkObservation:
    endpoint: NetworkEndpoint
    measurement_type: MeasurementType
    state: NetworkState
    symbol: str
    description: str
    raw_details: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": str(self.endpoint),
            "host": self.endpoint.host,
            "ip": self.endpoint.ip,
            "port": self.endpoint.port,
            "measurement_type": self.measurement_type.value,
            "state": self.state.value,
            "symbol": self.symbol,
            "description": self.description,
            "raw_details": self.raw_details,
            "limitations": self.limitations,
            "timestamp": self.timestamp,
        }


@dataclass
class NetworkScanResult:
    target: str
    resolved_endpoints: List[NetworkEndpoint] = field(default_factory=list)
    observations: List[NetworkObservation] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "resolved_endpoints": [str(e) for e in self.resolved_endpoints],
            "observations": [obs.to_dict() for obs in self.observations],
            "errors": self.errors,
            "duration_ms": self.duration_ms,
        }
