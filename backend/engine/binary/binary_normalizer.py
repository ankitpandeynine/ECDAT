"""
ECDAT V4 Binary Cryptographic Entity Normalizer.

Standardizes cryptographic algorithms, variants, key lengths, and PQC transition statuses
detected from symbols, byte constants, imports, and string markers.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple


ALGORITHM_CANONICAL_MAP: Dict[str, Tuple[str, str, str]] = {
    # Key: pattern/lowercase, Value: (Canonical Name, Category, PQC Status)
    "aes": ("AES", "SYMMETRIC", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "chacha20": ("ChaCha20", "SYMMETRIC", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "sm4": ("SM4", "SYMMETRIC", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "des": ("DES", "SYMMETRIC", "LEGACY_BROKEN"),
    "3des": ("3DES", "SYMMETRIC", "LEGACY_BROKEN"),
    "rc4": ("RC4", "SYMMETRIC", "LEGACY_BROKEN"),
    "blowfish": ("Blowfish", "SYMMETRIC", "LEGACY_DEPRECATED"),

    "rsa": ("RSA", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
    "ecdsa": ("ECDSA", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
    "ecdh": ("ECDH", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
    "x25519": ("X25519", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
    "ed25519": ("Ed25519", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
    "dsa": ("DSA", "ASYMMETRIC", "LEGACY_DEPRECATED"),

    "ml-kem": ("ML-KEM", "PQC", "PQC_STANDARDIZED"),
    "kyber": ("ML-KEM", "PQC", "PQC_STANDARDIZED"),
    "ml-dsa": ("ML-DSA", "PQC", "PQC_STANDARDIZED"),
    "dilithium": ("ML-DSA", "PQC", "PQC_STANDARDIZED"),
    "slh-dsa": ("SLH-DSA", "PQC", "PQC_STANDARDIZED"),
    "sphincs": ("SLH-DSA", "PQC", "PQC_STANDARDIZED"),
    "falcon": ("Falcon", "PQC", "PQC_STANDARDIZED"),

    "sha-256": ("SHA-256", "HASH", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "sha-384": ("SHA-384", "HASH", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "sha-512": ("SHA-512", "HASH", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "sha-224": ("SHA-224", "HASH", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "sha-3": ("SHA-3", "HASH", "PQC_STANDARDIZED"),
    "blake2": ("BLAKE2", "HASH", "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"),
    "sha-1": ("SHA-1", "HASH", "LEGACY_BROKEN"),
    "md5": ("MD5", "HASH", "LEGACY_BROKEN"),
}


class BinaryNormalizer:
    """Normalizes cryptographic names, key sizes, and PQC transition classifications."""

    @staticmethod
    def normalize_algorithm(raw_name: str, preserve_specificity: bool = False) -> Tuple[str, str, str]:
        """
        Returns (canonical_name, category, pqc_status).
        If preserve_specificity is True, incorporates known key sizes, parameter sets, or cipher modes.
        """
        lower = raw_name.lower().strip()
        matched_entry: Optional[Tuple[str, str, str]] = None
        for key, val in ALGORITHM_CANONICAL_MAP.items():
            if key in lower:
                matched_entry = val
                break

        if not matched_entry:
            return raw_name, "CRYPTOGRAPHIC_PRIMITIVE", "UNKNOWN"

        family, category, pqc_status = matched_entry

        if not preserve_specificity:
            return family, category, pqc_status

        # Build specific representation
        key_size = BinaryNormalizer.infer_key_size(raw_name)
        mode = BinaryNormalizer.infer_mode(raw_name)

        specific_name = family
        if family == "RSA" and key_size:
            specific_name = f"RSA-{key_size}"
        elif family == "ML-KEM" and key_size in (512, 768, 1024):
            specific_name = f"ML-KEM-{key_size}"
        elif family == "ML-DSA" and key_size in (44, 65, 87):
            specific_name = f"ML-DSA-{key_size}"
        elif family == "AES":
            parts = ["AES"]
            if key_size:
                parts.append(str(key_size))
            if mode:
                parts.append(mode)
            if len(parts) > 1:
                specific_name = "-".join(parts)
        elif key_size and family not in ("SHA-256", "SHA-384", "SHA-512", "SHA-224"):
            specific_name = f"{family}-{key_size}"

        return specific_name, category, pqc_status

    @staticmethod
    def normalize_canonical(raw_name: str, preserve_specificity: bool = True) -> Tuple[str, str, str]:
        """Convenience method defaulting to specificity preservation."""
        return BinaryNormalizer.normalize_algorithm(raw_name, preserve_specificity=preserve_specificity)

    @staticmethod
    def infer_key_size(name: str) -> Optional[int]:
        """Infers key size or security parameter in bits from string or symbol names."""
        m = re.search(r"(?:128|192|256|384|512|768|1024|2048|3072|4096|44|65|87)", name)
        if m:
            return int(m.group(0))
        return None

    @staticmethod
    def infer_mode(name: str) -> Optional[str]:
        """Infers block cipher or AEAD mode if present in identifier."""
        valid_modes = ("GCM", "CBC", "CTR", "ECB", "CFB", "OFB", "XTS", "CCM", "POLY1305")
        upper = name.upper()
        for mode in valid_modes:
            if re.search(rf"\b{mode}\b|[-_]{mode}[-_]?", upper):
                return mode
        return None

    @staticmethod
    def normalize_entity(raw_name: str, explicit_key_size: Optional[int] = None) -> Dict[str, Any]:
        """Returns comprehensive normalized dictionary representation with precision audit."""
        family, category, pqc_status = BinaryNormalizer.normalize_algorithm(raw_name, preserve_specificity=False)
        specific_name, _, _ = BinaryNormalizer.normalize_algorithm(raw_name, preserve_specificity=True)

        key_size = explicit_key_size or BinaryNormalizer.infer_key_size(raw_name)
        mode = BinaryNormalizer.infer_mode(raw_name)

        if explicit_key_size and family == "RSA":
            specific_name = f"RSA-{explicit_key_size}"
        elif explicit_key_size and family == "ML-KEM" and explicit_key_size in (512, 768, 1024):
            specific_name = f"ML-KEM-{explicit_key_size}"

        return {
            "raw_name": raw_name,
            "canonical_family": family,
            "canonical_name": specific_name,
            "category": category,
            "pqc_status": pqc_status,
            "key_size": key_size,
            "mode": mode,
            "specificity_preserved": specific_name != family,
        }
