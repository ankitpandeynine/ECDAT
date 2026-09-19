"""
ECDAT V4 P2.1 Intelligence Normalizer.

Normalizes raw algorithm strings from P1 scanners into canonical forms
before registry lookup.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple


# TLS 1.3 cipher suite -> components
_TLS13_CIPHER_MAP = {
    "TLS_AES_256_GCM_SHA384":       {"symmetric": "AES-256", "mode": "GCM", "mac": "SHA-384"},
    "TLS_AES_128_GCM_SHA256":       {"symmetric": "AES-128", "mode": "GCM", "mac": "SHA-256"},
    "TLS_CHACHA20_POLY1305_SHA256": {"symmetric": "ChaCha20-Poly1305", "mode": "AEAD", "mac": "SHA-256"},
}

# TLS 1.2 cipher suite -> components (partial)
_TLS12_CIPHER_MAP = {
    "ECDHE-RSA-AES256-GCM-SHA384":  {"kex": "ECDHE", "auth": "RSA", "symmetric": "AES-256", "mac": "SHA-384"},
    "ECDHE-ECDSA-AES256-GCM-SHA384":{"kex": "ECDHE", "auth": "ECDSA", "symmetric": "AES-256", "mac": "SHA-384"},
    "ECDHE-RSA-AES128-GCM-SHA256":  {"kex": "ECDHE", "auth": "RSA", "symmetric": "AES-128", "mac": "SHA-256"},
    "ECDHE-RSA-CHACHA20-POLY1305":  {"kex": "ECDHE", "auth": "RSA", "symmetric": "ChaCha20-Poly1305", "mac": "POLY1305"},
    "DHE-RSA-AES256-GCM-SHA384":    {"kex": "DHE", "auth": "RSA", "symmetric": "AES-256", "mac": "SHA-384"},
    "AES256-GCM-SHA384":            {"kex": "RSA", "auth": "RSA", "symmetric": "AES-256", "mac": "SHA-384"},
    "DES-CBC3-SHA":                 {"kex": "RSA", "auth": "RSA", "symmetric": "3DES", "mac": "SHA-1"},
    "RC4-SHA":                      {"kex": "RSA", "auth": "RSA", "symmetric": "RC4", "mac": "SHA-1"},
    "RC4-MD5":                      {"kex": "RSA", "auth": "RSA", "symmetric": "RC4", "mac": "MD5"},
}


def normalize_algorithm_from_evidence(
    raw: str,
    observation_type: str = "",
) -> str:
    """
    Best-effort normalization of a raw algorithm string to a canonical form
    suitable for AlgorithmRegistry.normalize().

    Does NOT invent information. Returns raw if no normalization applies.
    """
    if not raw:
        return raw
    stripped = raw.strip()
    # Handle common prefix patterns
    stripped = re.sub(r"^id-", "", stripped, flags=re.IGNORECASE)
    stripped = re.sub(r"^oid:", "", stripped, flags=re.IGNORECASE)
    # OID-only: leave as-is (registry will return None for unrecognized OIDs)
    if re.match(r"^\d+(\.\d+)+$", stripped):
        return stripped
    return stripped


def normalize_tls_cipher(cipher_str: Optional[str]) -> Dict[str, Optional[str]]:
    """
    Decompose a TLS cipher suite string into components.
    Returns: {kex, symmetric, mac, mode} -- any may be None if not parseable.

    AXIOM: Does NOT infer KEX type beyond what the cipher name encodes.
    """
    if not cipher_str:
        return {"kex": None, "symmetric": None, "mac": None, "mode": None}

    upper = cipher_str.upper().strip()

    # TLS 1.3 (no auth in name)
    if upper in _TLS13_CIPHER_MAP:
        r = dict(_TLS13_CIPHER_MAP[upper])
        r.setdefault("kex", None)
        r.setdefault("mode", None)
        return r

    # TLS 1.2
    if upper in _TLS12_CIPHER_MAP:
        return dict(_TLS12_CIPHER_MAP[upper])

    # Try pattern matching
    result: Dict[str, Optional[str]] = {"kex": None, "symmetric": None, "mac": None, "mode": None}

    if "ECDHE" in upper or "ECDH" in upper:
        result["kex"] = "ECDHE"
    elif "DHE" in upper or "EDH" in upper:
        result["kex"] = "DHE"
    elif upper.startswith("RSA") or upper.startswith("AES") or upper.startswith("DES"):
        result["kex"] = "RSA"

    if "CHACHA20" in upper:
        result["symmetric"] = "ChaCha20-Poly1305"
        result["mode"] = "AEAD"
    elif "AES256" in upper or "AES-256" in upper:
        result["symmetric"] = "AES-256"
    elif "AES128" in upper or "AES-128" in upper:
        result["symmetric"] = "AES-128"
    elif "3DES" in upper or "DES-CBC3" in upper or "DES3" in upper:
        result["symmetric"] = "3DES"
    elif "RC4" in upper:
        result["symmetric"] = "RC4"
    elif "DES" in upper:
        result["symmetric"] = "DES"

    if "GCM" in upper:
        result["mode"] = "GCM"
    elif "CBC" in upper:
        result["mode"] = "CBC"

    if "SHA384" in upper or "SHA-384" in upper:
        result["mac"] = "SHA-384"
    elif "SHA256" in upper or "SHA-256" in upper:
        result["mac"] = "SHA-256"
    elif "SHA1" in upper or "SHA-1" in upper or upper.endswith("-SHA"):
        result["mac"] = "SHA-1"
    elif "MD5" in upper:
        result["mac"] = "MD5"

    return result
