"""
ECDAT V4 Binary String & Embedded Secret Extractor.

Extracts ASCII and UTF-16LE strings and identifies:
- Embedded PEM private keys and certificates
- Hardcoded crypto tokens and secrets
- Algorithm names, curve names, OIDs, and cipher suites

Research Axiom:
Finding an embedded string literal "AES-256-GCM" or "secp256r1" in .rodata
proves configuration or metadata presence, NOT that the cipher is actually used.

CRITICAL SECURITY MANDATE:
Raw private keys are NEVER emitted in scan outputs.
They are masked with 'SECRET_INDICATOR_DETECTED'.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, Generator, List, Optional, Tuple

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


@dataclass
class StringMatch:
    value: str
    offset: int
    encoding: str  # "ascii" or "utf-16le"
    section: Optional[str] = None
    category: Optional[str] = None
    algorithm: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "offset": f"0x{self.offset:08x}",
            "encoding": self.encoding,
            "section": self.section,
            "category": self.category,
            "algorithm": self.algorithm,
        }


@dataclass
class SecretCandidate:
    secret_type: str  # "PEM_PRIVATE_KEY", "PEM_CERTIFICATE", "API_KEY", "HARDCODED_SECRET"
    offset: int
    length: int
    is_valid_pem: bool
    is_encrypted: bool
    masked_indicator: str = "SECRET_INDICATOR_DETECTED"
    algorithm: Optional[str] = None
    key_size: Optional[int] = None
    section: Optional[str] = None
    severity: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_type": self.secret_type,
            "offset": f"0x{self.offset:08x}",
            "length": self.length,
            "is_valid_pem": self.is_valid_pem,
            "is_encrypted": self.is_encrypted,
            "masked_indicator": self.masked_indicator,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "section": self.section,
            "severity": self.severity,
        }


PEM_PRIVATE_KEY_REGEX = re.compile(
    rb"-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|OPENSSH PRIVATE KEY|ENCRYPTED PRIVATE KEY|PRIVATE KEY)-----"
)

PEM_CERT_REGEX = re.compile(
    rb"-----BEGIN (CERTIFICATE|TRUSTED CERTIFICATE|X509 CERTIFICATE)-----"
)

CRYPTO_STRING_KEYWORDS: List[Dict[str, Any]] = [
    {"pattern": r"(?i)\b(?:ml[-_]?kem[-_]?\d*|kyber\d*)\b", "category": "PQC", "algorithm": "ML-KEM"},
    {"pattern": r"(?i)\b(?:ml[-_]?dsa[-_]?\d*|dilithium\d*)\b", "category": "PQC", "algorithm": "ML-DSA"},
    {"pattern": r"(?i)\b(?:slh[-_]?dsa[-_]?\d*|sphincs\+?)\b", "category": "PQC", "algorithm": "SLH-DSA"},
    {"pattern": r"(?i)\b(?:falcon[-_]?\d*)\b", "category": "PQC", "algorithm": "Falcon"},
    {"pattern": r"(?i)\b(?:aes[-_]?(?:128|192|256)[-_]?(?:gcm|cbc|ctr|ecb)?)\b", "category": "SYMMETRIC", "algorithm": "AES"},
    {"pattern": r"(?i)\b(?:chacha20[-_]?poly1305)\b", "category": "SYMMETRIC", "algorithm": "ChaCha20"},
    {"pattern": r"(?i)\b(?:secp256r1|prime256v1|secp384r1|secp521r1|secp256k1)\b", "category": "ASYMMETRIC", "algorithm": "ECDSA"},
    {"pattern": r"(?i)\b(?:curve25519|x25519|ed25519)\b", "category": "ASYMMETRIC", "algorithm": "X25519"},
    {"pattern": r"(?i)\b(?:sha[-_]?256|sha[-_]?512|sha[-_]?384|sha[-_]?224)\b", "category": "HASH", "algorithm": "SHA-2"},
    {"pattern": r"(?i)\b(?:sha3[-_]?(?:256|384|512)|keccak)\b", "category": "HASH", "algorithm": "SHA-3"},
    {"pattern": r"(?i)\b(?:rsa[-_]?(?:1024|2048|3072|4096))\b", "category": "ASYMMETRIC", "algorithm": "RSA"},
    {"pattern": r"(?i)\b(?:md5|sha1|des|3des|rc4)\b", "category": "LEGACY", "algorithm": "LegacyCrypto"},
]


class BinaryStringExtractor:
    """Extracts strings and identifies embedded secret keys and crypto keywords."""

    @staticmethod
    def extract_secrets(data: bytes) -> List[SecretCandidate]:
        """Detects embedded private keys and certificates with strict masking."""
        secrets: List[SecretCandidate] = []

        # 1. PEM Private Keys
        for match in PEM_PRIVATE_KEY_REGEX.finditer(data):
            label = match.group(1)
            end_marker = b"-----END " + label + b"-----"
            start_off = match.start()
            end_pos = data.find(end_marker, match.end())

            is_valid = False
            is_enc = (label == b"ENCRYPTED PRIVATE KEY")
            algo = "RSA" if b"RSA" in label else ("ECDSA" if b"EC" in label else "GenericPrivate")
            key_size = None
            total_len = (end_pos + len(end_marker) - start_off) if end_pos != -1 else (len(match.group(0)))

            if end_pos != -1 and (end_pos - start_off) <= 65536 and HAS_CRYPTOGRAPHY:
                pem_bytes = data[start_off:end_pos + len(end_marker)]
                try:
                    loaded_key = load_pem_private_key(pem_bytes, password=None)
                    is_valid = True
                    if hasattr(loaded_key, "key_size"):
                        key_size = loaded_key.key_size
                except (ValueError, TypeError):
                    if is_enc or b"Proc-Type: 4,ENCRYPTED" in pem_bytes:
                        is_enc = True
                        is_valid = True

            secrets.append(
                SecretCandidate(
                    secret_type="PEM_PRIVATE_KEY",
                    offset=start_off,
                    length=total_len,
                    is_valid_pem=is_valid,
                    is_encrypted=is_enc,
                    masked_indicator="SECRET_INDICATOR_DETECTED",
                    algorithm=algo,
                    key_size=key_size,
                    severity="CRITICAL" if not is_enc else "HIGH",
                )
            )

        # 2. PEM Certificates
        for match in PEM_CERT_REGEX.finditer(data):
            label = match.group(1)
            end_marker = b"-----END " + label + b"-----"
            start_off = match.start()
            end_pos = data.find(end_marker, match.end())

            is_valid = False
            algo = "X509"
            key_size = None
            total_len = (end_pos + len(end_marker) - start_off) if end_pos != -1 else (len(match.group(0)))

            if end_pos != -1 and (end_pos - start_off) <= 65536 and HAS_CRYPTOGRAPHY:
                pem_bytes = data[start_off:end_pos + len(end_marker)]
                try:
                    cert = x509.load_pem_x509_certificate(pem_bytes)
                    is_valid = True
                    pub = cert.public_key()
                    if hasattr(pub, "key_size"):
                        key_size = pub.key_size
                except (ValueError, TypeError):
                    pass

            secrets.append(
                SecretCandidate(
                    secret_type="PEM_CERTIFICATE",
                    offset=start_off,
                    length=total_len,
                    is_valid_pem=is_valid,
                    is_encrypted=False,
                    masked_indicator="CERTIFICATE_OBSERVED",
                    algorithm=algo,
                    key_size=key_size,
                    severity="LOW",
                )
            )

        return secrets

    @staticmethod
    def extract_strings(
        data: bytes, min_length: int = 4, max_strings: int = 1000
    ) -> List[StringMatch]:
        """Extracts printable ASCII and UTF-16LE strings matching crypto concepts."""
        matches: List[StringMatch] = []

        # ASCII scan
        ascii_pattern = re.compile(rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}")
        for m in ascii_pattern.finditer(data):
            text = m.group(0).decode("ascii", "ignore")
            for rule in CRYPTO_STRING_KEYWORDS:
                for submatch in re.finditer(rule["pattern"], text):
                    matches.append(
                        StringMatch(
                            value=submatch.group(0)[:120],
                            offset=m.start() + submatch.start(),
                            encoding="ascii",
                            category=rule["category"],
                            algorithm=rule["algorithm"],
                        )
                    )
                    if len(matches) >= max_strings:
                        break
                if len(matches) >= max_strings:
                    break
            if len(matches) >= max_strings:
                break

        # UTF-16LE scan
        if len(matches) < max_strings:
            utf16_pattern = re.compile(rb"(?:[\x20-\x7E]\x00){" + str(min_length).encode() + rb",}")
            for m in utf16_pattern.finditer(data):
                try:
                    text = m.group(0).decode("utf-16le", "ignore")
                    for rule in CRYPTO_STRING_KEYWORDS:
                        for submatch in re.finditer(rule["pattern"], text):
                            matches.append(
                                StringMatch(
                                    value=submatch.group(0)[:120],
                                    offset=m.start() + (submatch.start() * 2),
                                    encoding="utf-16le",
                                    category=rule["category"],
                                    algorithm=rule["algorithm"],
                                )
                            )
                            if len(matches) >= max_strings:
                                break
                        if len(matches) >= max_strings:
                            break
                    if len(matches) >= max_strings:
                        break
                except UnicodeDecodeError:
                    pass

        return matches
