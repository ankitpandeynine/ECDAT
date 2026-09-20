from typing import Dict, Any, List

def calculate_mosca_risk(shelf_life: int, migration_time: int, crqc_horizon: int = 8) -> Dict[str, Any]:
    """
    Evaluates quantum exposure using Mosca's Theorem:
      X = Data Shelf-Life Requirement (years)
      Y = Migration / Re-engineering Duration (years)
      Z = Estimated arrival time of a Cryptanalytically Relevant Quantum Computer (CRQC) (years)

    Inequality:
      If (X + Y) > Z: CRITICAL EXPOSURE (Adversaries can record now and decrypt before shelf-life expires)
      If (X + Y) <= Z: SECURE MARGIN (Safe window exists if migration begins immediately)
    """
    x = max(0, int(shelf_life))
    y = max(0, int(migration_time))
    z = max(1, int(crqc_horizon))

    total_exposure_need = x + y
    deficit = total_exposure_need - z
    is_critical = deficit > 0

    if is_critical:
        posture_status = "CRITICAL QUANTUM EXPOSURE"
        posture_badge = "CRITICAL"
        posture_color = "red"
        explanation = (
            f"Under Mosca's Theorem (X + Y > Z), your data is currently exposed! "
            f"Required security timeline ({total_exposure_need} years: {x}y shelf-life + {y}y migration) "
            f"exceeds the estimated CRQC horizon ({z} years) by {deficit} year(s). "
            "Hostile adversaries capturing encrypted traffic today (Harvest Now, Decrypt Later) will be able "
            "to retroactively decrypt classified payloads before their required confidentiality expires."
        )
    else:
        posture_status = "MIGRATION WINDOW SECURE"
        posture_badge = "OPTIMAL"
        posture_color = "green"
        explanation = (
            f"Under Mosca's Theorem (X + Y <= Z), your migration timeline ({total_exposure_need} years) "
            f"falls within the estimated CRQC arrival window ({z} years) with a safety margin of {abs(deficit)} year(s). "
            "Immediate execution of PQC migration protocols is required to maintain this posture."
        )

    # NIST Post-Quantum Cryptography Roadmap & Mapping (FIPS 203, 204, 205)
    nist_standards_mapping = [
        {
            "category": "Asymmetric Key Encapsulation (KEM)",
            "legacy_primitive": "RSA (2048/4096), ECDH (P-256, P-384)",
            "quantum_threat": "Shor's Algorithm (Polynomial Time Factoring / Discrete Log)",
            "pqc_standard": "FIPS 203: ML-KEM (Module-Lattice-based KEM / Kyber)",
            "security_levels": "ML-KEM-512 (Cat 1), ML-KEM-768 (Cat 3), ML-KEM-1024 (Cat 5)",
            "urgency": "IMMEDIATE (High HNDL Vulnerability)"
        },
        {
            "category": "Primary Digital Signatures",
            "legacy_primitive": "RSA PKCS#1 v1.5 / PSS, ECDSA, Ed25519",
            "quantum_threat": "Shor's Algorithm (Signature Forgery)",
            "pqc_standard": "FIPS 204: ML-DSA (Module-Lattice-based DSA / Dilithium)",
            "security_levels": "ML-DSA-44 (Cat 2), ML-DSA-65 (Cat 3), ML-DSA-87 (Cat 5)",
            "urgency": "HIGH (Authentication & Software Signing Transition)"
        },
        {
            "category": "Stateful/Stateless Hash Signatures (Fallback)",
            "legacy_primitive": "Classic Digital Signatures (RSA/ECDSA)",
            "quantum_threat": "General Quantum Asymmetric Cryptanalysis",
            "pqc_standard": "FIPS 205: SLH-DSA (Stateless Hash-based DSA / SPHINCS+)",
            "security_levels": "SLH-DSA-SHA2 / SLH-DSA-SHAKE (Cat 1, 3, 5)",
            "urgency": "RECOMMENDED (Conservative Back-up Alternative)"
        },
        {
            "category": "Symmetric Ciphers (Grover Halving)",
            "legacy_primitive": "AES-128",
            "quantum_threat": "Grover's Algorithm (Quadratic Speedup reduces 128-bit key to 64-bit security)",
            "pqc_standard": "AES-256 (FIPS 197)",
            "security_levels": "AES-256 maintains >= 128 bits post-quantum security",
            "urgency": "MEDIUM (Upgrade key lengths from 128-bit to 256-bit)"
        },
        {
            "category": "Classically Broken Primitives (No Quantum Needed)",
            "legacy_primitive": "MD5, SHA-1, DES, 3DES, RC4",
            "quantum_threat": "Classically Broken (Wang & Yu 2004, Sweet32, EFF Deep Crack) - DISALLOWED (NIST SP 800-131A Rev 2)",
            "pqc_standard": "FIPS 180-4 (SHA-256 / SHA-512) & FIPS 197 (AES-256-GCM)",
            "security_levels": "NIST Approved Classical / Quantum-Resistant Minimum",
            "urgency": "FIX_NOW (Immediately Prohibited Under Classical Cryptanalysis)"
        }
    ]

    return {
        "x_shelf_life": x,
        "y_migration_time": y,
        "z_crqc_horizon": z,
        "total_time_needed": total_exposure_need,
        "deficit_years": deficit,
        "is_critical": is_critical,
        "posture_status": posture_status,
        "posture_badge": posture_badge,
        "posture_color": posture_color,
        "explanation": explanation,
        "nist_mapping": nist_standards_mapping
    }
