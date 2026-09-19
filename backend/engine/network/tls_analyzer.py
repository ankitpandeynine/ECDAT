"""TLS 1.0-1.3 Analyzer and bounded cipher enumerator."""
import ssl
import time
from typing import List, Tuple
from .network_models import NetworkEndpoint, NetworkObservation, MeasurementType, NetworkState
from .resolver import create_connection


COMMON_CIPHERS = [
    # Modern / TLS 1.3
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_GCM_SHA256",
    # TLS 1.2
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    # Legacy / Weak
    "AES256-GCM-SHA384",
    "AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA256",
    "AES256-SHA256",
    "AES128-SHA256",
    "AES256-SHA",
    "AES128-SHA",
    "DES-CBC3-SHA",
    "RC4-SHA",
]


def _tls_context(verify=False, version=None, cipher=None):
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
    if version is not None:
        ctx.minimum_version = ctx.maximum_version = version
    
    if cipher is not None:
        # TLS 1.3 ciphers are set differently in OpenSSL, but Python `set_ciphers` handles both.
        # However, to be strict, we offer ONLY the specified cipher (plus ALL:@SECLEVEL=0 for fallback parsing)
        # Actually, if we want to test a single cipher, we should just offer that cipher.
        try:
            ctx.set_ciphers(f"{cipher}:@SECLEVEL=0")
        except ssl.SSLError:
            pass # Invalid cipher string for this openssl version
    else:
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    return ctx


def analyze_tls(endpoint: NetworkEndpoint, address: Tuple, timeout: float = 2.0, deadline: float = 0.0) -> List[NetworkObservation]:
    observations = []
    
    # 1. Probe for generic TLS support and maximum negotiated protocol
    if time.monotonic() > deadline:
        return observations

    try:
        raw = create_connection(address, min(timeout, max(0.1, deadline - time.monotonic())))
        ctx = _tls_context()
        with ctx.wrap_socket(raw, server_hostname=endpoint.host) as conn:
            proto = conn.version()
            cipher, _proto, bits = conn.cipher()
            
            # Record general negotiation
            observations.append(NetworkObservation(
                endpoint=endpoint,
                measurement_type=MeasurementType.TLS_VERSION,
                state=NetworkState.NEGOTIATED,
                symbol=proto,
                description=f"Server negotiated {proto}",
            ))
            
            observations.append(NetworkObservation(
                endpoint=endpoint,
                measurement_type=MeasurementType.TLS_CIPHER,
                state=NetworkState.NEGOTIATED,
                symbol=cipher,
                description=f"Server negotiated cipher {cipher} over {proto}",
                raw_details={"secret_bits": bits}
            ))
            
    except Exception as exc:
        observations.append(NetworkObservation(
            endpoint=endpoint,
            measurement_type=MeasurementType.TLS_VERSION,
            state=NetworkState.FAILED,
            symbol="TLS",
            description="Initial generic TLS handshake failed",
            limitations=[str(exc)[:200]]
        ))
        return observations # Stop if generic handshake fails

    # 2. Enumerate TLS versions explicitly
    versions = [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
        ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ]
    for v_name, v_enum in versions:
        if time.monotonic() > deadline:
            break
        try:
            raw = create_connection(address, min(timeout, max(0.1, deadline - time.monotonic())))
            ctx = _tls_context(version=v_enum)
            with ctx.wrap_socket(raw, server_hostname=endpoint.host) as conn:
                observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.TLS_VERSION,
                    state=NetworkState.SUPPORTED,
                    symbol=v_name,
                    description=f"Server explicitly supported {v_name} when offered."
                ))
        except ssl.SSLError as exc:
            err_str = str(exc)
            if "VERSION" in err_str.upper() or "HANDSHAKE_FAILURE" in err_str.upper() or "PROTOCOL_VERSION" in err_str.upper():
                observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.TLS_VERSION,
                    state=NetworkState.NOT_NEGOTIATED,
                    symbol=v_name,
                    description=f"Server rejected {v_name}."
                ))
            else:
                observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.TLS_VERSION,
                    state=NetworkState.INCONCLUSIVE,
                    symbol=v_name,
                    description=f"Inconclusive test for {v_name}: {err_str[:100]}"
                ))
        except Exception as exc:
             observations.append(NetworkObservation(
                endpoint=endpoint,
                measurement_type=MeasurementType.TLS_VERSION,
                state=NetworkState.INCONCLUSIVE,
                symbol=v_name,
                description=f"Connection failure during {v_name} test."
            ))

    # 3. Enumerate bounded cipher list explicitly
    # To save time, we only probe a subset if deadline is tight, but we'll loop through COMMON_CIPHERS
    for cipher in COMMON_CIPHERS:
        if time.monotonic() > deadline:
            break
        try:
            # Note: We don't force a TLS version here because some ciphers are TLS 1.3 only, others 1.2
            # We let OpenSSL pick the version that fits the cipher
            raw = create_connection(address, min(timeout, max(0.1, deadline - time.monotonic())))
            ctx = _tls_context(cipher=cipher)
            with ctx.wrap_socket(raw, server_hostname=endpoint.host) as conn:
                neg_cipher = conn.cipher()[0]
                neg_proto = conn.version()
                # Ensure the negotiated cipher is what we offered
                if cipher.upper() in neg_cipher.upper() or neg_cipher.upper() in cipher.upper():
                    observations.append(NetworkObservation(
                        endpoint=endpoint,
                        measurement_type=MeasurementType.TLS_CIPHER,
                        state=NetworkState.SUPPORTED,
                        symbol=cipher,
                        description=f"Server supported explicit offer of {cipher} over {neg_proto}"
                    ))
                else:
                    observations.append(NetworkObservation(
                        endpoint=endpoint,
                        measurement_type=MeasurementType.TLS_CIPHER,
                        state=NetworkState.INCONCLUSIVE,
                        symbol=cipher,
                        description=f"Offered {cipher} but negotiated {neg_cipher} (unexpected fallback)."
                    ))
        except ssl.SSLError as exc:
            err_str = str(exc)
            if "HANDSHAKE_FAILURE" in err_str.upper() or "NO_SHARED_CIPHER" in err_str.upper() or "NO_CIPHERS_AVAILABLE" in err_str.upper():
                observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.TLS_CIPHER,
                    state=NetworkState.NOT_NEGOTIATED,
                    symbol=cipher,
                    description=f"Server rejected cipher {cipher}."
                ))
            else:
                 observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.TLS_CIPHER,
                    state=NetworkState.INCONCLUSIVE,
                    symbol=cipher,
                    description=f"SSLError during cipher test: {err_str[:100]}."
                ))
        except Exception:
            pass # Socket errors ignored to save space

    return observations
