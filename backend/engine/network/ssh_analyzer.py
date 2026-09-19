"""Safe SSH capability probing (no authentication)."""
import re
import socket
import time
from typing import List, Tuple
from .network_models import NetworkEndpoint, NetworkObservation, MeasurementType, NetworkState
from .resolver import create_connection


def _parse_namelist(payload: bytes, offset: int) -> Tuple[List[str], int]:
    if offset + 4 > len(payload):
        return [], offset
    length = int.from_bytes(payload[offset:offset+4], byteorder='big')
    offset += 4
    if offset + length > len(payload):
        return [], offset
    name_str = payload[offset:offset+length].decode('ascii', 'ignore')
    return name_str.split(',') if name_str else [], offset + length


def analyze_ssh(endpoint: NetworkEndpoint, address: Tuple, timeout: float = 2.0) -> List[NetworkObservation]:
    observations = []
    
    try:
        raw = create_connection(address, timeout)
        
        # 1. SSH Identification String (Banner)
        banner = b""
        with raw:
            raw.settimeout(timeout)
            # Read until \r\n (server identification)
            while not banner.endswith(b"\r\n") and len(banner) < 2048:
                chunk = raw.recv(1)
                if not chunk:
                    break
                banner += chunk
            
            if not banner.startswith(b"SSH-"):
                observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.SSH_ALGORITHM,
                    state=NetworkState.NOT_NEGOTIATED,
                    symbol="SSH",
                    description="Target did not present a valid SSH banner."
                ))
                return observations
                
            banner_str = banner.decode('ascii', 'ignore').strip()
            
            # Send our identification string
            raw.sendall(b"SSH-2.0-ECDAT_V4_SCANNER\r\n")
            
            # 2. Read Server KEXINIT (Message 20)
            # Packet format: uint32 packet_length, byte padding_length, byte[n] payload (type 20 is first byte)
            header = b""
            while len(header) < 5:
                chunk = raw.recv(5 - len(header))
                if not chunk: break
                header += chunk
            
            if len(header) == 5:
                packet_len = int.from_bytes(header[0:4], 'big')
                padding_len = header[4]
                
                payload_len = packet_len - padding_len - 1
                if 0 < payload_len < 32000:
                    payload = b""
                    while len(payload) < payload_len:
                        chunk = raw.recv(payload_len - len(payload))
                        if not chunk: break
                        payload += chunk
                        
                    if payload and payload[0] == 20: # SSH_MSG_KEXINIT
                        # Skip cookie (16 bytes)
                        offset = 17
                        kex_algs, offset = _parse_namelist(payload, offset)
                        host_key_algs, offset = _parse_namelist(payload, offset)
                        enc_client_to_server, offset = _parse_namelist(payload, offset)
                        enc_server_to_client, offset = _parse_namelist(payload, offset)
                        mac_client_to_server, offset = _parse_namelist(payload, offset)
                        mac_server_to_client, offset = _parse_namelist(payload, offset)
                        
                        all_algs = set(kex_algs + host_key_algs + enc_client_to_server + mac_client_to_server)
                        
                        for alg in all_algs:
                            if not alg: continue
                            observations.append(NetworkObservation(
                                endpoint=endpoint,
                                measurement_type=MeasurementType.SSH_ALGORITHM,
                                state=NetworkState.ADVERTISED,
                                symbol=alg,
                                description=f"SSH server advertised capability: {alg}",
                                raw_details={"banner": banner_str}
                            ))
                            
                        return observations

            # If we reached here, parsing KEX failed, but banner was read
            observations.append(NetworkObservation(
                endpoint=endpoint,
                measurement_type=MeasurementType.SSH_ALGORITHM,
                state=NetworkState.INCONCLUSIVE,
                symbol="SSH KEX",
                description=f"SSH banner received ({banner_str}) but KEXINIT parsing failed."
            ))

    except Exception as exc:
        observations.append(NetworkObservation(
            endpoint=endpoint,
            measurement_type=MeasurementType.SSH_ALGORITHM,
            state=NetworkState.FAILED,
            symbol="SSH",
            description="Failed to collect SSH capabilities",
            limitations=[str(exc)[:200]]
        ))
        
    return observations
