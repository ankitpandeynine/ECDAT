"""Standards and Regulatory Mapping for ECDAT.

Implements Section 21 of the specification:
Explicit, versioned mappings to:
  - NIST Post-Quantum Cryptography: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 197 (AES)
  - Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)
  - White House OMB M-23-02 (Post-Quantum Cryptography migration milestones)
  - ANSSI (French National Cybersecurity Agency) PQC recommendations
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RegulatoryControl(BaseModel):
    standard: str
    jurisdiction: str
    requirement: str
    deadline_or_milestone: Optional[str] = None
    applies_to: str
    status: str
    source_url: str


class StandardMapping(BaseModel):
    category: str
    legacy_primitive: str
    target_standard: str
    security_strength_bits: int
    controls: List[RegulatoryControl]
    guidance: str


STANDARDS_CATALOG: List[StandardMapping] = [
    StandardMapping(
        category="Key Encapsulation / Key Exchange",
        legacy_primitive="RSA (2048/4096), ECDH (P-256, P-384, X25519)",
        target_standard="NIST FIPS 203 (ML-KEM-768 / ML-KEM-1024)",
        security_strength_bits=192,
        guidance="Deploy hybrid ML-KEM with classical X25519 or SecP384r1 in TLS 1.3 key exchange immediately to defeat Harvest-Now-Decrypt-Later (HNDL) attacks.",
        controls=[
            RegulatoryControl(
                standard="NIST FIPS 203",
                jurisdiction="US Federal / Global",
                requirement="Module-Lattice-Based Key-Encapsulation Mechanism Standard",
                deadline_or_milestone="Published August 2024",
                applies_to="Federal information systems and commercial cryptographic products",
                status="MANDATORY_TARGET",
                source_url="https://csrc.nist.gov/pubs/fips/203/final"
            ),
            RegulatoryControl(
                standard="CNSA 2.0",
                jurisdiction="US National Security Systems (NSS)",
                requirement="Transition software/firmware and networking to ML-KEM",
                deadline_or_milestone="2025: Preferred / 2033: Exclusively required",
                applies_to="National Security Systems (NSS), defense contractors, critical infra",
                status="ACTIVE_TIMELINE",
                source_url="https://media.defense.gov/2022/Sep/07/2003071823/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
            ),
            RegulatoryControl(
                standard="OMB M-23-02",
                jurisdiction="US Executive Branch Agencies",
                requirement="Annual inventory of quantum-vulnerable cryptographic systems and prioritize high-value assets",
                deadline_or_milestone="Annual reporting requirement starting 2023",
                applies_to="All federal executive agencies",
                status="MANDATORY_ANNUAL_REPORT",
                source_url="https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf"
            )
        ]
    ),
    StandardMapping(
        category="Digital Signatures & Authentication",
        legacy_primitive="RSA PKCS#1 v1.5 / PSS, ECDSA, Ed25519",
        target_standard="NIST FIPS 204 (ML-DSA) & NIST FIPS 205 (SLH-DSA)",
        security_strength_bits=192,
        guidance="Adopt ML-DSA (Dilithium) for general digital signatures, code signing, and certificates. Use SLH-DSA (SPHINCS+) for conservative, hash-based fallback.",
        controls=[
            RegulatoryControl(
                standard="NIST FIPS 204",
                jurisdiction="US Federal / Global",
                requirement="Module-Lattice-Based Digital Signature Standard",
                deadline_or_milestone="Published August 2024",
                applies_to="Digital signatures, code signing, PKI authentication",
                status="MANDATORY_TARGET",
                source_url="https://csrc.nist.gov/pubs/fips/204/final"
            ),
            RegulatoryControl(
                standard="NIST FIPS 205",
                jurisdiction="US Federal / Global",
                requirement="Stateless Hash-Based Digital Signature Standard",
                deadline_or_milestone="Published August 2024",
                applies_to="Digital signatures requiring conservative hash assumptions",
                status="RECOMMENDED_ALTERNATIVE",
                source_url="https://csrc.nist.gov/pubs/fips/205/final"
            ),
            RegulatoryControl(
                standard="CNSA 2.0 Software Signing",
                jurisdiction="US Defense & NSS",
                requirement="Software and firmware signing must begin adopting ML-DSA/SLH-DSA by 2025; exclusive by 2030",
                deadline_or_milestone="2025: Transition begins / 2030: Mandatory cutoff",
                applies_to="Firmware updates, OS installers, application binaries",
                status="ACTIVE_TIMELINE",
                source_url="https://media.defense.gov/2022/Sep/07/2003071823/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
            )
        ]
    ),
    StandardMapping(
        category="Symmetric Ciphers & Hash Integrity",
        legacy_primitive="DES, 3DES, RC4, MD5, SHA-1, AES-128",
        target_standard="NIST FIPS 197 (AES-256) & FIPS 180-4 (SHA-256 / SHA-3)",
        security_strength_bits=256,
        guidance="Ensure 256-bit symmetric keys to resist Grover's quantum search speedup. Retire 64-bit block ciphers and collision-vulnerable hashes immediately.",
        controls=[
            RegulatoryControl(
                standard="NIST SP 800-131A Rev 2",
                jurisdiction="US Federal / Financial",
                requirement="Disallow MD5, SHA-1, and Triple-DES for security applications",
                deadline_or_milestone="Disallowed since 2023",
                applies_to="All federal systems and payment card networks (PCI DSS 4.0)",
                status="PROHIBITED",
                source_url="https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
            ),
            RegulatoryControl(
                standard="CNSA 2.0 Symmetric",
                jurisdiction="US NSS",
                requirement="AES-256 is required for all symmetric encryption; SHA-384 or SHA-512 for hashing",
                deadline_or_milestone="Current requirement",
                applies_to="All national security confidential data",
                status="MANDATORY",
                source_url="https://media.defense.gov/2022/Sep/07/2003071823/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"
            )
        ]
    )
]


def get_standards_mapping_for_primitive(primitive: str) -> Optional[StandardMapping]:
    upper = primitive.upper()
    if any(k in upper for k in ("RSA", "ECDH", "KEM", "DH", "KEY EXCHANGE")):
        return STANDARDS_CATALOG[0]
    if any(k in upper for k in ("DSA", "ECDSA", "ED25519", "SIGNATURE", "DILITHIUM", "SPHINCS")):
        return STANDARDS_CATALOG[1]
    if any(k in upper for k in ("DES", "RC4", "MD5", "SHA1", "SHA-1", "AES")):
        return STANDARDS_CATALOG[2]
    return None


def get_all_standards() -> Dict[str, Any]:
    return {
        "frameworks": [
            {"name": "NIST PQC Standards (FIPS 203, 204, 205)", "status": "Official Standards (August 2024)"},
            {"name": "NSA Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)", "status": "Active Policy"},
            {"name": "White House OMB Memorandum M-23-02", "status": "Active Federal Directive"},
            {"name": "ANSSI Scientific Advisory on Post-Quantum Cryptography", "status": "European Recommendation"}
        ],
        "mappings": [m.model_dump() for m in STANDARDS_CATALOG]
    }
