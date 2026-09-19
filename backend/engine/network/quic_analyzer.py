"""QUIC & HTTP/3 Detection (Level 1: HTTP Alt-Svc headers)."""
from typing import List, Dict, Any
from .network_models import NetworkEndpoint, NetworkObservation, MeasurementType, NetworkState


def analyze_quic_headers(endpoint: NetworkEndpoint, headers: Dict[str, str]) -> List[NetworkObservation]:
    """Level 1 QUIC Detection: Checks Alt-Svc headers from an HTTP response."""
    observations = []
    alt_svc = headers.get("alt-svc", "")
    
    if "h3=" in alt_svc or 'h3-29=' in alt_svc:
        observations.append(NetworkObservation(
            endpoint=endpoint,
            measurement_type=MeasurementType.QUIC_SUPPORT,
            state=NetworkState.ADVERTISED,
            symbol="HTTP/3",
            description=f"Server advertised HTTP/3 via Alt-Svc header",
            raw_details={"alt-svc": alt_svc[:500]}
        ))
    
    # Level 2 Active Probe is unavailable locally without large third-party dependencies (aioquic/etc)
    # The requirement strictly says: "Do NOT build an incomplete custom QUIC protocol implementation"
    observations.append(NetworkObservation(
        endpoint=endpoint,
        measurement_type=MeasurementType.QUIC_SUPPORT,
        state=NetworkState.SCANNER_UNAVAILABLE,
        symbol="QUIC Handshake",
        description="Active UDP QUIC TLS 1.3 handshake scanner is unavailable.",
        limitations=["Only HTTP Alt-Svc advertisement is checked. Runtime capabilities unverified."]
    ))
        
    return observations
