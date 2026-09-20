import math
import re
from typing import Dict, Any, List, Tuple

# Standard Cryptographic Constants (Byte signatures found in compiled binaries)

# AES Rijndael Substitution Box (First 32 bytes)
AES_SBOX_PREFIX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
])

# AES Inverse S-Box (First 16 bytes)
AES_INVSBOX_PREFIX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
])

# DES Initial Permutation Table (First 16 entries)
DES_IP_TABLE = bytes([
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4
])

# MD5 Initialization Constants (Little-endian words)
MD5_IV_LITTLE = bytes([
    0x01, 0x23, 0x45, 0x67, # A = 0x67452301
    0x89, 0xab, 0xcd, 0xef, # B = 0xefcdab89
    0xfe, 0xdc, 0xba, 0x98, # C = 0x98badcfe
    0x76, 0x54, 0x32, 0x10  # D = 0x10325476
])

# SHA-1 Initialization Constants (Big-endian words)
SHA1_IV_BIG = bytes([
    0x67, 0x45, 0x23, 0x01,
    0xef, 0xcd, 0xab, 0x89,
    0x98, 0xba, 0xdc, 0xfe,
    0x10, 0x32, 0x54, 0x76,
    0xc3, 0xd2, 0xe1, 0xf0
])

# SHA-256 Initialization Constants (Big-endian words)
SHA256_IV_BIG = bytes([
    0x6a, 0x09, 0xe6, 0x67,
    0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72,
    0xa5, 0x4f, 0xf5, 0x3a
])

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0 bits per byte)."""
    if not data:
        return 0.0
    from collections import Counter
    counts = Counter(data).values()
    total = len(data)
    entropy = 0.0
    for count in counts:
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def generate_sample_binary_blob() -> bytes:
    """
    Generates a realistic synthetic compiled binary (.elf/.so mock)
    containing embedded cryptographic S-boxes, hardcoded keys, and MD5 constants.
    """
    # 1. ELF Header mock
    header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x3e\x00"
    
    # 2. Executable code padding (low entropy)
    padding1 = b"\x90\x55\x48\x89\xe5\x48\x83\xec\x20" * 30
    
    # 3. Embedded AES S-box
    sbox_blob = AES_SBOX_PREFIX + bytes(range(32, 64))
    
    # 4. Embedded MD5 IV
    md5_blob = MD5_IV_LITTLE
    
    # 5. Embedded hardcoded private key token
    key_pem = b"-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKCAQEA0mockNTROcrypto...\n-----END RSA PRIVATE KEY-----\n"
    
    # 6. High entropy pseudo-encrypted block (random-like bytes)
    high_entropy = bytes([(x * 167 + 13) % 256 for x in range(256)])

    return header + padding1 + sbox_blob + padding1 + md5_blob + padding1 + key_pem + high_entropy

def scan_binary_data(data: bytes, file_name: str = "firmware_image.bin") -> Dict[str, Any]:
    """
    Scans a binary buffer for compiled cryptographic signatures, S-boxes,
    embedded private keys, and calculates Shannon entropy distributions.
    """
    file_size = len(data)
    detections: List[Dict[str, Any]] = []

    # 1. AES S-Box Search
    idx = 0
    while True:
        pos = data.find(AES_SBOX_PREFIX, idx)
        if pos == -1:
            break
        detections.append({
            "type": "Substitution Table (S-Box)",
            "primitive": "AES-128/256 S-Box (Rijndael)",
            "offset": f"0x{pos:08X}",
            "severity": "LOW",
            "confidence": "HIGH",
            "description": "Compiled AES Rijndael forward substitution box table located in binary .rodata section.",
            "quantum_impact": "AES-256 remains Grover-resistant; AES-128 drops to 64 bits of security."
        })
        idx = pos + 1

    # 2. AES Inverse S-Box
    pos = data.find(AES_INVSBOX_PREFIX)
    if pos != -1:
        detections.append({
            "type": "Inverse S-Box",
            "primitive": "AES InvSBox",
            "offset": f"0x{pos:08X}",
            "severity": "LOW",
            "confidence": "HIGH",
            "description": "AES inverse substitution box table for decryption operations.",
            "quantum_impact": "Symmetric primitives require 256-bit keying."
        })

    # 3. DES Initial Permutation Table
    pos = data.find(DES_IP_TABLE)
    if pos != -1:
        detections.append({
            "type": "Permutation Matrix",
            "primitive": "DES IP Table (Obsolete)",
            "offset": f"0x{pos:08X}",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "description": "Data Encryption Standard (DES) Initial Permutation (IP) table detected in binary memory.",
            "quantum_impact": "56-bit key length is broken classically and defenseless against quantum attacks."
        })

    # 4. MD5 Constants Search
    pos = data.find(MD5_IV_LITTLE)
    if pos != -1:
        detections.append({
            "type": "Initialization Vector Constants",
            "primitive": "MD5 State Constants",
            "offset": f"0x{pos:08X}",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "description": "Compiled MD5 message digest initialization words (0x67452301, 0xefcdab89...) located.",
            "quantum_impact": "MD5 suffers from proven classical collision attacks and Grover acceleration."
        })

    # 5. SHA-1 Constants Search
    pos = data.find(SHA1_IV_BIG)
    if pos != -1:
        detections.append({
            "type": "Initialization Vector Constants",
            "primitive": "SHA-1 Hash Constants",
            "offset": f"0x{pos:08X}",
            "severity": "HIGH",
            "confidence": "HIGH",
            "description": "SHA-1 initial state constants detected in executable image.",
            "quantum_impact": "Disallowed per NIST SP 800-131A."
        })

    # 6. Hardcoded PEM / Key Headers
    pem_patterns = [
        (b"-----BEGIN RSA PRIVATE KEY-----", "Hardcoded RSA Private Key", "CRITICAL"),
        (b"-----BEGIN EC PRIVATE KEY-----", "Hardcoded EC Private Key", "CRITICAL"),
        (b"-----BEGIN CERTIFICATE-----", "Hardcoded X.509 Certificate", "MEDIUM"),
        (b"-----BEGIN PRIVATE KEY-----", "Hardcoded PKCS#8 Private Key", "CRITICAL")
    ]
    for pattern, label, sev in pem_patterns:
        pos = data.find(pattern)
        if pos != -1:
            detections.append({
                "type": "Hardcoded Key Material",
                "primitive": label,
                "offset": f"0x{pos:08X}",
                "severity": sev,
                "confidence": "CONFIRMED",
                "description": f"Static private cryptographic key or certificate string embedded directly in compiled image.",
                "quantum_impact": "Static asymmetric private keys enable catastrophic retroactive decryption."
            })

    # 7. Entropy chunk analysis (Chunk size 256 bytes)
    chunk_size = 256
    entropy_map: List[Dict[str, Any]] = []
    high_entropy_blocks = 0

    for i in range(0, min(file_size, 4096), chunk_size):
        chunk = data[i:i + chunk_size]
        ent = calculate_shannon_entropy(chunk)
        if ent > 7.2:
            high_entropy_blocks += 1
        entropy_map.append({
            "offset": f"0x{i:04X}",
            "entropy": ent,
            "status": "Encrypted/Key Material" if ent > 7.2 else ("Code/Data" if ent > 4.5 else "Sparse/Padded")
        })

    overall_entropy = calculate_shannon_entropy(data)

    # Risk summary
    critical_count = sum(1 for d in detections if d["severity"] == "CRITICAL")
    high_count = sum(1 for d in detections if d["severity"] == "HIGH")

    return {
        "file_name": file_name,
        "file_size_bytes": file_size,
        "overall_entropy": overall_entropy,
        "entropy_category": "Encrypted/Packed" if overall_entropy > 7.0 else "Executable Image",
        "detections": detections,
        "total_detections": len(detections),
        "critical_count": critical_count,
        "high_count": high_count,
        "entropy_map": entropy_map,
        "hex_preview": data[:256].hex()
    }
