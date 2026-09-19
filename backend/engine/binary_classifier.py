"""Experimental G: Binary & Firmware ML Classifier / Deep Cryptographic Analysis.

Implements Section 18 of the specification:
Exposes deep binary analysis using opcode frequency distributions, rolling entropy profiles,
byte chi-square randomness statistics, and structural indicators.

Features:
  - Feature extraction from compiled binaries (ELF/PE/raw firmware)
  - ML scoring model calculating probability of cryptographic code
  - Detection technique and confidence metadata exposed explicitly
  - EvidenceRecord generation
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from .evidence_model import (
    AssetType,
    ConfidenceLevel,
    CryptographicRole,
    EvidenceProvenance,
    EvidenceRecord,
    EvidenceType,
    SourceSurface,
    infer_crypto_role,
    is_quantum_vulnerable,
)


class BinaryFeatureVector(BaseModel):
    total_bytes: int
    overall_entropy: float
    chi_square_stat: float
    xor_instruction_ratio: float
    bitshift_instruction_ratio: float
    arithmetic_ratio: float
    high_entropy_blocks_ratio: float
    constant_sbox_matches: int


class BinaryClassificationResult(BaseModel):
    file_name: str
    predicted_category: str  # "SYMMETRIC_CRYPTO", "HASH_PRIMITIVE", "ASYMMETRIC_PRIMITIVE", "HIGH_ENTROPY_PACKED", "NON_CRYPTO"
    crypto_probability: float  # 0.0 - 1.0
    confidence_level: str  # "HIGH", "MEDIUM", "LOW"
    detection_technique: str
    feature_vector: BinaryFeatureVector
    indicators: List[str]
    evidence_records: List[EvidenceRecord] = Field(default_factory=list)


class BinaryMLClassifier:
    """Classifies binary buffers and sections using statistical and opcode features."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def calculate_chi_square(data: bytes) -> float:
        if len(data) < 256:
            return 0.0
        expected = len(data) / 256.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        chi2 = sum(((f - expected) ** 2) / expected for f in freq)
        return round(chi2, 2)

    @classmethod
    def extract_features(cls, data: bytes) -> BinaryFeatureVector:
        total = len(data)
        if total == 0:
            return BinaryFeatureVector(
                total_bytes=0, overall_entropy=0.0, chi_square_stat=0.0,
                xor_instruction_ratio=0.0, bitshift_instruction_ratio=0.0,
                arithmetic_ratio=0.0, high_entropy_blocks_ratio=0.0, constant_sbox_matches=0
            )

        entropy = cls.calculate_entropy(data)
        chi2 = cls.calculate_chi_square(data)

        # Rolling entropy block analysis (256-byte chunks)
        chunk_size = 256
        high_entropy_chunks = 0
        total_chunks = max(1, total // chunk_size)
        for i in range(0, total - chunk_size + 1, chunk_size):
            c_ent = cls.calculate_entropy(data[i:i + chunk_size])
            if c_ent >= 7.2:
                high_entropy_chunks += 1
        high_ent_ratio = round(high_entropy_chunks / total_chunks, 4)

        # Opcode / instruction byte heuristics
        # x86 opcodes: XOR (0x30-0x35), ROL/ROR/SHL/SHR (0xC0, 0xC1, 0xD0-0xD3), ADD/SUB (0x00-0x05, 0x28-0x2D)
        xor_count = sum(1 for b in data if b in (0x30, 0x31, 0x32, 0x33, 0x34, 0x35))
        shift_count = sum(1 for b in data if b in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3))
        arith_count = sum(1 for b in data if b in (0x00, 0x01, 0x02, 0x03, 0x28, 0x29, 0x2A, 0x2B))

        # Check for known crypto constants / tables
        aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
        sbox_matches = 1 if aes_sbox in data else 0

        return BinaryFeatureVector(
            total_bytes=total,
            overall_entropy=entropy,
            chi_square_stat=chi2,
            xor_instruction_ratio=round(xor_count / total, 4),
            bitshift_instruction_ratio=round(shift_count / total, 4),
            arithmetic_ratio=round(arith_count / total, 4),
            high_entropy_blocks_ratio=high_ent_ratio,
            constant_sbox_matches=sbox_matches
        )

    @classmethod
    def classify_binary(cls, data: bytes, file_name: str = "binary.bin") -> BinaryClassificationResult:
        features = cls.extract_features(data)
        indicators: List[str] = []
        score = 0.1
        category = "NON_CRYPTO"

        # Evaluation rules mimicking ML decision forest
        if features.constant_sbox_matches > 0:
            score += 0.65
            indicators.append("Contains exact AES substitution table (S-Box) sequence.")
            category = "SYMMETRIC_CRYPTO"

        if 6.8 <= features.overall_entropy <= 7.9:
            score += 0.25
            indicators.append(f"Moderate-high Shannon entropy ({features.overall_entropy}) typical of compiled crypto code.")
        elif features.overall_entropy >= 7.92:
            indicators.append(f"Extremely high entropy ({features.overall_entropy}) indicates packed, compressed, or ciphertext payload.")
            if score < 0.5:
                category = "HIGH_ENTROPY_PACKED"

        if features.xor_instruction_ratio >= 0.02 and features.bitshift_instruction_ratio >= 0.015:
            score += 0.35
            indicators.append(f"Elevated bitwise XOR ({features.xor_instruction_ratio * 100:.1f}%) and shift instruction density.")
            if category == "NON_CRYPTO":
                category = "HASH_PRIMITIVE"

        # Check for embedded PEM strings
        if b"BEGIN RSA PRIVATE KEY" in data or b"BEGIN PRIVATE KEY" in data:
            score = max(score, 0.95)
            category = "ASYMMETRIC_PRIMITIVE"
            indicators.append("Embedded RSA / PKCS#8 private key header detected.")

        probability = round(min(max(score, 0.05), 0.99), 2)
        confidence = "HIGH" if probability > 0.8 else ("MEDIUM" if probability > 0.5 else "LOW")

        evidence_records: List[EvidenceRecord] = []
        if probability >= 0.5:
            rec = EvidenceRecord(
                asset_id=EvidenceRecord.generate_asset_id("binary_ml", file_name, category),
                asset_type=AssetType.ALGORITHM,
                algorithm=f"Binary_ML::{category}",
                cryptographic_role=CryptographicRole.BULK_ENCRYPTION if category == "SYMMETRIC_CRYPTO" else CryptographicRole.UNKNOWN,
                source_surface=SourceSurface.BINARY_FIRMWARE,
                evidence_type=EvidenceType.STATIC_INFERRED,
                location_endpoint=f"{file_name}@offset_range",
                confidence=ConfidenceLevel[confidence],
                severity="HIGH" if category in ("ASYMMETRIC_PRIMITIVE", "SYMMETRIC_CRYPTO") else "LOW",
                description=f"Deep binary ML analysis classified {file_name} as {category} (Prob: {probability})",
                quantum_vulnerable=True if category == "ASYMMETRIC_PRIMITIVE" else None,
                provenance=EvidenceProvenance(
                    detector_engine="binary_ml_classifier",
                    detection_technique="feature_vector_scoring",
                    parameters={"features": features.model_dump(), "indicators": indicators}
                )
            )
            evidence_records.append(rec)

        return BinaryClassificationResult(
            file_name=file_name,
            predicted_category=category,
            crypto_probability=probability,
            confidence_level=confidence,
            detection_technique="opcode_entropy_feature_vector",
            feature_vector=features,
            indicators=indicators,
            evidence_records=evidence_records
        )
