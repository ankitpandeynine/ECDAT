"""
ECDAT V4 P3 Role-Aware Migration Target Selector.

Determines concrete MigrationTarget based on cryptographic role, algorithm class,
and PQC migration knowledge. Prevents role conflation (e.g. ML-KEM != ML-DSA,
symmetric encryption != KEM, hybrid KEX != PQC certificate signature).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .migration_rules import MigrationRulesEngine
from .models import MigrationContext, MigrationTarget, TransitionMode


def select_migration_target(
    context: MigrationContext,
    rules_engine: Optional[MigrationRulesEngine] = None,
) -> Tuple[MigrationTarget, List[str]]:
    """
    Selects valid MigrationTarget grounded in knowledge base.
    Returns: (MigrationTarget, limitations)
    """
    rules_engine = rules_engine or MigrationRulesEngine()
    role = context.cryptographic_role
    algo = context.algorithm.strip().upper()
    limitations: List[str] = []

    # 1. Unknown or unsupported role
    if role == "UNKNOWN" or not role:
        limitations.append(f"Cryptographic role could not be definitively determined for algorithm '{context.algorithm}'.")
        return (
            MigrationTarget(
                current_algorithm=context.algorithm,
                current_role="UNKNOWN",
                target_algorithm="UNKNOWN",
                target_role="UNKNOWN",
                transition_mode=TransitionMode.UNKNOWN,
                rationale="Target algorithm cannot be determined without verified cryptographic role.",
                limitations=limitations,
            ),
            limitations,
        )

    # 2. Hashing — Not a public-key PQC migration concern unless collision-broken (MD5/SHA1)
    if role == "HASHING":
        if any(b in algo for b in ("MD5", "SHA1", "SHA-1")):
            return (
                MigrationTarget(
                    current_algorithm=context.algorithm,
                    current_role=role,
                    target_algorithm="SHA-256 / SHA-384 (FIPS 180-4)",
                    target_role="HASHING",
                    transition_mode=TransitionMode.DIRECT_REPLACEMENT,
                    rationale="Replace collision-compromised hash with secure classical hash; hashing is not broken by Shor's algorithm.",
                    limitations=limitations,
                ),
                limitations,
            )
        else:
            return (
                MigrationTarget(
                    current_algorithm=context.algorithm,
                    current_role=role,
                    target_algorithm=context.algorithm,
                    target_role=role,
                    transition_mode=TransitionMode.UNKNOWN,
                    rationale=f"Hash function {context.algorithm} is quantum-resistant against collision attacks; no PQC migration required.",
                    limitations=["Hashing algorithms do not require PQC replacement under NIST guidelines."],
                ),
                ["Hashing algorithms do not require PQC replacement under NIST guidelines."],
            )

    # 3. Symmetric Encryption — Grover halving, not public-key KEM
    if role == "SYMMETRIC_ENCRYPTION":
        mapping = rules_engine.get_target_for_role("SYMMETRIC_ENCRYPTION")
        target_algo = mapping.get("pqc_target", "AES-256-GCM") if mapping else "AES-256-GCM"
        if "256" in algo and ("GCM" in algo or "CTR" in algo):
            return (
                MigrationTarget(
                    current_algorithm=context.algorithm,
                    current_role=role,
                    target_algorithm=context.algorithm,
                    target_role=role,
                    transition_mode=TransitionMode.UNKNOWN,
                    rationale=f"{context.algorithm} retains ~128-bit post-quantum security after Grover's algorithm halving.",
                    limitations=["Symmetric 256-bit ciphers do not require PQC replacement."],
                ),
                ["Symmetric 256-bit ciphers do not require PQC replacement."],
            )
        return (
            MigrationTarget(
                current_algorithm=context.algorithm,
                current_role=role,
                target_algorithm=target_algo,
                target_role=role,
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
                rationale="Upgrade key size to 256-bit to preserve 128-bit quantum security against Grover search.",
                limitations=limitations,
            ),
            limitations,
        )

    # 4. Key Establishment / KEM (RSA-KEM, DH, ECDH, X25519)
    if role == "KEY_ESTABLISHMENT":
        mapping = rules_engine.get_target_for_role("KEY_ESTABLISHMENT")
        pqc_target = mapping.get("pqc_target", "ML-KEM-768 (FIPS 203)") if mapping else "ML-KEM-768 (FIPS 203)"
        hybrid_target = mapping.get("hybrid_target", "X25519MLKEM768") if mapping else "X25519MLKEM768"

        # Check if agility or TLS context indicates hybrid capability
        pqc_state = str(context.pqc_readiness.get("state", "")).upper()
        if "HYBRID" in pqc_state or context.parameters.get("prefer_hybrid", True):
            return (
                MigrationTarget(
                    current_algorithm=context.algorithm,
                    current_role=role,
                    target_algorithm=hybrid_target,
                    target_role=role,
                    transition_mode=TransitionMode.HYBRID_TRANSITION,
                    rationale="Enable dual classical+PQC hybrid key encapsulation (X25519MLKEM768) during transition.",
                    limitations=["Hybrid KEX protects session keys but does NOT authenticate server via PQC signature."],
                ),
                ["Hybrid KEX protects session keys but does NOT authenticate server via PQC signature."],
            )
        return (
            MigrationTarget(
                current_algorithm=context.algorithm,
                current_role=role,
                target_algorithm=pqc_target,
                target_role=role,
                transition_mode=TransitionMode.DIRECT_REPLACEMENT,
                rationale="Migrate to NIST FIPS 203 standardized ML-KEM lattice-based key encapsulation.",
                limitations=limitations,
            ),
            limitations,
        )

    # 5. Digital Signatures & Certificate Signatures
    if role in ("SIGNATURE", "CERTIFICATE_SIGNATURE"):
        mapping = rules_engine.get_target_for_role("SIGNATURE")
        pqc_target = mapping.get("pqc_target", "ML-DSA-65 (FIPS 204)") if mapping else "ML-DSA-65 (FIPS 204)"
        alt_target = mapping.get("alternative_target", "SLH-DSA (FIPS 205)") if mapping else "SLH-DSA (FIPS 205)"

        is_cert = (role == "CERTIFICATE_SIGNATURE") or ("CERT" in context.algorithm.upper())
        trans_mode = TransitionMode.CERTIFICATE_MIGRATION if is_cert else TransitionMode.DIRECT_REPLACEMENT

        return (
            MigrationTarget(
                current_algorithm=context.algorithm,
                current_role=role,
                target_algorithm=pqc_target,
                target_role=role,
                target_parameters={"alternative": alt_target},
                transition_mode=trans_mode,
                rationale="Migrate to NIST FIPS 204 ML-DSA primary signature scheme (or FIPS 205 SLH-DSA for stateful/stateless hash alternative).",
                limitations=["Note: ML-DSA signatures have significantly larger public key and signature byte sizes than classical ECDSA/RSA."],
            ),
            ["Note: ML-DSA signatures have significantly larger public key and signature byte sizes than classical ECDSA/RSA."],
        )

    # Default fallback
    limitations.append(f"No authoritative PQC migration target known for role '{role}'.")
    return (
        MigrationTarget(
            current_algorithm=context.algorithm,
            current_role=role,
            target_algorithm="UNKNOWN",
            target_role=role,
            transition_mode=TransitionMode.UNKNOWN,
            rationale="No standardized PQC replacement exists in current knowledge base.",
            limitations=limitations,
        ),
        limitations,
    )
