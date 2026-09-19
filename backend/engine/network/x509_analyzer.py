"""X.509 Certificate Chain Analyzer."""
import ssl
import time
from typing import List, Tuple
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from datetime import datetime, timezone

from .network_models import NetworkEndpoint, NetworkObservation, MeasurementType, NetworkState
from .resolver import create_connection


def _extract_public_key_info(public_key) -> Tuple[str, int]:
    """Returns (canonical_algorithm_name, key_size_in_bits)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.curve.key_size
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    else:
        return type(public_key).__name__, 0


def analyze_x509_chain(endpoint: NetworkEndpoint, address: Tuple, timeout: float = 2.0) -> List[NetworkObservation]:
    observations = []
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        raw = create_connection(address, timeout)
        with ctx.wrap_socket(raw, server_hostname=endpoint.host) as conn:
            # Python 3.10+ provides the raw DER certificates of the unverified chain
            chain = conn.get_unverified_chain()
            if not chain:
                return []
                
            # Parse the chain
            parsed_chain = []
            for cert_der in chain:
                # In Python 3.10, get_unverified_chain returns OpenSSL Certificate objects
                # which have public_bytes(serialization.Encoding.DER)
                if not isinstance(cert_der, bytes):
                    import cryptography.hazmat.primitives.serialization as serial
                    der_bytes = cert_der.public_bytes(serial.Encoding.DER)
                else:
                    der_bytes = cert_der # If it's already bytes
                cert = x509.load_der_x509_certificate(der_bytes)
                parsed_chain.append(cert)
                
            for idx, cert in enumerate(parsed_chain):
                key = cert.public_key()
                pub_algo, pub_size = _extract_public_key_info(key)
                
                try:
                    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
                except x509.ExtensionNotFound:
                    sans = []
                
                # Build canonical primitive string e.g. RSA-2048 or Ed25519
                canonical_primitive = f"{pub_algo}-{pub_size}" if pub_size and pub_algo not in ("Ed25519", "Ed448") else pub_algo
                
                now = datetime.now(timezone.utc)
                expires = cert.not_valid_after_utc
                
                details = {
                    "subject": cert.subject.rfc4514_string(),
                    "issuer": cert.issuer.rfc4514_string(),
                    "serial_number": hex(cert.serial_number),
                    "valid_from": cert.not_valid_before_utc.isoformat(),
                    "valid_to": expires.isoformat(),
                    "days_remaining": (expires - now).days,
                    "expired": expires < now,
                    "sans": sans,
                    "public_key_algorithm": pub_algo,
                    "public_key_size": pub_size,
                    "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
                    "sha256": cert.fingerprint(hashes.SHA256()).hex(),
                    "chain_position": idx,
                    "is_leaf": (idx == 0)
                }
                
                if idx == 0:
                    # Perform trust validation check on the leaf
                    trust_ctx = ssl.create_default_context()
                    try:
                        raw_trust = create_connection(address, timeout)
                        with trust_ctx.wrap_socket(raw_trust, server_hostname=endpoint.host):
                            details["trust_validated"] = True
                    except Exception as exc:
                        details["trust_validated"] = False
                        details["verification_error"] = str(exc)
                        
                observations.append(NetworkObservation(
                    endpoint=endpoint,
                    measurement_type=MeasurementType.X509_CERTIFICATE,
                    state=NetworkState.ADVERTISED,
                    symbol=canonical_primitive,
                    description=f"{'Leaf' if idx == 0 else 'Intermediate'} Certificate ({canonical_primitive}) for {details['subject']}",
                    raw_details=details
                ))

    except Exception as exc:
        print(f"X509 ERROR: {exc}", flush=True)
        import traceback
        traceback.print_exc()
        observations.append(NetworkObservation(
            endpoint=endpoint,
            measurement_type=MeasurementType.X509_CERTIFICATE,
            state=NetworkState.FAILED,
            symbol="X509",
            description="Failed to collect certificate chain",
            limitations=[str(exc)[:200] + " REPR: " + repr(exc)]
        ))
        
    return observations
