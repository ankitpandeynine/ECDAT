"""
ECDAT V4 Binary Evidence Generator.

Transforms binary analysis observations into P0 Evidence instances with:
- Formal Evidence Levels (E1, E2, E3)
- Explicit EvidenceState (MEASURED)
- Full Provenance records
- Epistemic limitations preventing false conflation of presence with execution.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..evidence_model import (
    ArtifactType,
    Evidence,
    EvidenceLevel,
    EvidenceState,
    ObservationType,
    Provenance,
)
from .binary_imports import ImportInfo
from .binary_signatures import SignatureMatch
from .binary_strings import SecretCandidate, StringMatch
from .binary_symbols import SymbolInfo


class BinaryEvidenceGenerator:
    """Generates immutable P0 Evidence items from binary analysis results."""

    @staticmethod
    def from_signature_match(
        match: SignatureMatch, file_path: str, file_hash: str, scan_id: str = ""
    ) -> Evidence:
        level = EvidenceLevel.E2 if match.section else EvidenceLevel.E1
        return Evidence(
            state=EvidenceState.MEASURED,
            level=level,
            confidence=match.confidence,
            source_engine="binary_discovery",
            engine_version="4.0.0",
            rule_id=match.rule_id,
            rule_version="4.0.0",
            observation_type=ObservationType.BINARY_SIGNATURE,
            artifact_type=ArtifactType.BINARY.value,
            symbol=match.algorithm,
            file_path=file_path,
            byte_offset=f"0x{match.offset:08x}",
            description=f"{match.name} observed at offset 0x{match.offset:08x} ({match.description})",
            limitations=[
                "Static observation of byte constant or S-box table.",
                "Presence in binary does not prove runtime invocation or specific key size.",
            ],
            raw_details={
                "section": match.section,
                "byte_order": match.byte_order,
                "severity": match.severity,
                "pqc_status": match.pqc_status,
            },
            provenance=Provenance(
                input_hash=file_hash,
                source_engine="binary_discovery",
                engine_version="4.0.0",
                scan_id=scan_id,
                location=f"{file_path}:0x{match.offset:08x}",
            ),
        )

    @staticmethod
    def from_symbol(
        sym: SymbolInfo, file_path: str, file_hash: str, scan_id: str = ""
    ) -> Evidence:
        # Defined functions compiled into the binary are E3; external undefined imports are E2
        level = EvidenceLevel.E3 if sym.is_defined else EvidenceLevel.E2
        status_label = "defined function" if sym.is_defined else "imported dynamic external symbol"

        return Evidence(
            state=EvidenceState.MEASURED,
            level=level,
            confidence=0.90 if sym.is_defined else 0.80,
            source_engine="binary_discovery",
            engine_version="4.0.0",
            rule_id=f"SYM-{sym.algorithm or 'CRYPTO'}",
            rule_version="4.0.0",
            observation_type=ObservationType.BINARY_SYMBOL,
            artifact_type=ArtifactType.BINARY.value,
            symbol=sym.name,
            file_path=file_path,
            byte_offset=f"0x{sym.value:08x}",
            description=f"Cryptographic symbol '{sym.name}' ({status_label})",
            limitations=[
                f"Symbol observed in binary symbol table as {status_label}.",
                "Dynamic reachability or runtime invocation path is not proven without dynamic tracing.",
            ],
            raw_details={
                "is_defined": sym.is_defined,
                "symbol_type": sym.symbol_type.value,
                "binding": sym.binding.value,
                "category": sym.crypto_category,
                "algorithm": sym.algorithm,
                "pqc_status": sym.pqc_status,
            },
            provenance=Provenance(
                input_hash=file_hash,
                source_engine="binary_discovery",
                engine_version="4.0.0",
                scan_id=scan_id,
                location=f"{file_path}:{sym.name}",
            ),
        )

    @staticmethod
    def from_import(
        imp: ImportInfo, file_path: str, file_hash: str, scan_id: str = ""
    ) -> Evidence:
        return Evidence(
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E2,
            confidence=0.85,
            source_engine="binary_discovery",
            engine_version="4.0.0",
            rule_id=f"LIB-{imp.crypto_family or 'SHARED'}",
            rule_version="4.0.0",
            observation_type=ObservationType.BINARY_REFERENCE,
            artifact_type=ArtifactType.BINARY.value,
            symbol=imp.library_name,
            file_path=file_path,
            description=f"Shared library dependency on '{imp.library_name}' ({imp.description or 'Cryptographic Library'})",
            limitations=[
                "Binary links against shared cryptographic library.",
                "Specific algorithms used at runtime cannot be confirmed from dependency declaration alone.",
            ],
            raw_details={
                "library_name": imp.library_name,
                "crypto_family": imp.crypto_family,
                "format": imp.format,
            },
            provenance=Provenance(
                input_hash=file_hash,
                source_engine="binary_discovery",
                engine_version="4.0.0",
                scan_id=scan_id,
                location=f"{file_path}:{imp.library_name}",
            ),
        )

    @staticmethod
    def from_secret(
        sec: SecretCandidate, file_path: str, file_hash: str, scan_id: str = ""
    ) -> Evidence:
        is_key = "PRIVATE_KEY" in sec.secret_type
        level = EvidenceLevel.E3
        obs_type = ObservationType.HARDCODED_KEY if is_key else ObservationType.X509_CERTIFICATE

        return Evidence(
            state=EvidenceState.MEASURED,
            level=level,
            confidence=1.0 if sec.is_valid_pem else 0.75,
            source_engine="binary_discovery",
            engine_version="4.0.0",
            rule_id=f"SEC-{sec.secret_type}",
            rule_version="4.0.0",
            observation_type=obs_type,
            artifact_type=ArtifactType.BINARY.value,
            symbol=sec.algorithm or "SECRET",
            file_path=file_path,
            byte_offset=f"0x{sec.offset:08x}",
            description=f"Embedded {sec.secret_type} observed (masked for confidentiality)",
            limitations=[
                "Static detection of embedded credential material.",
                "Raw private key material is masked as SECRET_INDICATOR_DETECTED.",
            ],
            raw_details={
                "secret_type": sec.secret_type,
                "is_encrypted": sec.is_encrypted,
                "is_valid_pem": sec.is_valid_pem,
                "key_size": sec.key_size,
                "severity": sec.severity,
            },
            provenance=Provenance(
                input_hash=file_hash,
                source_engine="binary_discovery",
                engine_version="4.0.0",
                scan_id=scan_id,
                location=f"{file_path}:0x{sec.offset:08x}",
            ),
        )

    @staticmethod
    def from_string(
        st: StringMatch, file_path: str, file_hash: str, scan_id: str = ""
    ) -> Evidence:
        return Evidence(
            state=EvidenceState.MEASURED,
            level=EvidenceLevel.E1,
            confidence=0.70,
            source_engine="binary_discovery",
            engine_version="4.0.0",
            rule_id=f"STR-{st.algorithm or 'CRYPTO'}",
            rule_version="4.0.0",
            observation_type=ObservationType.BINARY_REFERENCE,
            artifact_type=ArtifactType.BINARY.value,
            symbol=st.value,
            file_path=file_path,
            byte_offset=f"0x{st.offset:08x}",
            description=f"String literal '{st.value}' observed in binary",
            limitations=[
                "Pattern match on string literal in binary payload.",
                "String presence does not indicate active runtime usage.",
            ],
            raw_details={
                "encoding": st.encoding,
                "section": st.section,
                "category": st.category,
                "algorithm": st.algorithm,
            },
            provenance=Provenance(
                input_hash=file_hash,
                source_engine="binary_discovery",
                engine_version="4.0.0",
                scan_id=scan_id,
                location=f"{file_path}:0x{st.offset:08x}",
            ),
        )

    @staticmethod
    def from_deep_re_finding(
        engine_name: str,
        finding: Dict[str, Any],
        file_path: str,
        file_hash: str,
        scan_id: str = "",
    ) -> Evidence:
        """
        Transforms external deep reverse-engineering findings (Ghidra, angr, YARA) into E1..E4 evidence.
        Enforces epistemic separation: Static/symbolic analysis NEVER produces E5 (Live execution).
        """
        engine_lower = engine_name.lower()
        if "ghidra" in engine_lower:
            level = EvidenceLevel.E3
            obs_type = ObservationType.BINARY_FUNCTION
            confidence = finding.get("confidence", 0.85)
            engine_str = "ghidra_decompiler"
            limitations = [
                "Observation derived from Ghidra static decompilation / function recovery.",
                "Function presence does not prove runtime invocation path.",
            ]
        elif "angr" in engine_lower:
            level = EvidenceLevel.E4
            obs_type = ObservationType.BINARY_FUNCTION
            confidence = finding.get("confidence", 0.90)
            engine_str = "angr_symbolic"
            limitations = [
                "Observation derived from angr symbolic execution / control-flow reachability analysis.",
                "Symbolic path reachability does not constitute dynamic execution observation.",
            ]
        elif "yara" in engine_lower:
            level = EvidenceLevel.E1
            obs_type = ObservationType.BINARY_SIGNATURE
            confidence = finding.get("confidence", 0.70)
            engine_str = "yara_scanner"
            limitations = [
                "Observation derived from YARA binary pattern matching.",
                "Binary signature pattern match does not verify active execution or valid key material.",
            ]
        else:
            level = EvidenceLevel.E2
            obs_type = ObservationType.BINARY_REFERENCE
            confidence = finding.get("confidence", 0.75)
            engine_str = engine_name
            limitations = [
                f"Observation derived from external reverse engineering tool '{engine_name}'.",
                "Static observation; runtime execution not observed.",
            ]

        symbol = finding.get("symbol") or finding.get("algorithm") or finding.get("rule_name") or "DEEP_RE_ARTIFACT"
        offset = finding.get("offset", 0)
        offset_str = f"0x{offset:08x}" if isinstance(offset, int) else str(offset)

        return Evidence(
            state=EvidenceState.MEASURED,
            level=level,
            confidence=confidence,
            source_engine=engine_str,
            engine_version="4.0.0",
            rule_id=finding.get("rule_id", f"RE-{engine_name.upper()}"),
            rule_version="4.0.0",
            observation_type=obs_type,
            artifact_type=ArtifactType.BINARY.value,
            symbol=symbol,
            file_path=file_path,
            byte_offset=offset_str,
            description=finding.get("description", f"Finding from {engine_name}: {symbol}"),
            limitations=limitations,
            raw_details=finding.get("raw_details", {}),
            provenance=Provenance(
                input_hash=file_hash,
                source_engine=engine_str,
                engine_version="4.0.0",
                scan_id=scan_id,
                location=f"{file_path}:{offset_str}",
            ),
        )

