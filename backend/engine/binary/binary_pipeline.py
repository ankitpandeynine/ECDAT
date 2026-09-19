"""
ECDAT V4 Master Binary & Firmware Discovery Pipeline.

Orchestrates:
1. Format identification & triage
2. Bounded recursive firmware/archive extraction
3. Section header, stripped status, and build-id parsing
4. Static/dynamic symbol table analysis (defined vs undefined imports)
5. Shared library / DLL dependency extraction
6. Byte signature, IV, S-Box, and OID matching
7. Embedded private key masking & certificate parsing
8. Deep reverse engineering plugin health integration
9. Evidence generation & Asset Graph service population
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from typing import Any, Callable, Dict, List, Optional

from ..asset_graph import AssetGraphService, AssetType, CryptoAsset, RelationshipType
from ..evidence_model import Evidence
from .binary_evidence import BinaryEvidenceGenerator
from .binary_identifier import BinaryFormat, BinaryIdentifier, IdentificationResult
from .binary_imports import BinaryImportParser, ImportInfo
from .binary_metadata import BinaryMetadata, BinaryMetadataParser
from .binary_signatures import BinarySignatureMatcher, SignatureMatch
from .binary_strings import BinaryStringExtractor, SecretCandidate, StringMatch
from .binary_symbols import BinarySymbolParser, SymbolInfo
from .deep_re_plugins import get_engine_health_report
from .firmware_extractor import ExtractedMember, ExtractionResult, FirmwareExtractor


@dataclass
class SingleBinaryAnalysis:
    file_name: str
    sha256: str
    file_size: int
    identification: IdentificationResult
    metadata: BinaryMetadata
    symbols: List[SymbolInfo] = field(default_factory=list)
    imports: List[ImportInfo] = field(default_factory=list)
    signatures: List[SignatureMatch] = field(default_factory=list)
    strings: List[StringMatch] = field(default_factory=list)
    secrets: List[SecretCandidate] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    legacy_detections: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "sha256": self.sha256,
            "file_size_bytes": self.file_size,
            "format": self.identification.format.value,
            "architecture": self.identification.architecture,
            "bits": self.identification.bits,
            "endianness": self.identification.endianness,
            "is_stripped": self.metadata.is_stripped,
            "build_id": self.metadata.build_id,
            "sections": [s.to_dict() for s in self.metadata.sections],
            "symbols_count": len(self.symbols),
            "crypto_symbols": [s.to_dict() for s in self.symbols if s.is_crypto],
            "imports": [i.to_dict() for i in self.imports],
            "crypto_imports": [i.to_dict() for i in self.imports if i.is_crypto],
            "signatures": [sig.to_dict() for sig in self.signatures],
            "secrets": [sec.to_dict() for sec in self.secrets],
            "evidence": [ev.to_dict() for ev in self.evidence],
            "total_evidence": len(self.evidence),
        }


@dataclass
class BinaryScanResult:
    target_name: str
    target_format: BinaryFormat
    sha256: str
    file_size_bytes: int
    is_archive_or_firmware: bool
    total_members_analyzed: int
    members: List[SingleBinaryAnalysis] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    deep_re_engines: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "success"

    def to_dict(self) -> Dict[str, Any]:
        all_legacy_detections = []
        for m in self.members:
            all_legacy_detections.extend(m.legacy_detections)

        crit_count = sum(1 for d in all_legacy_detections if d.get("severity") == "CRITICAL")
        high_count = sum(1 for d in all_legacy_detections if d.get("severity") == "HIGH")

        primary = self.members[0] if self.members else None

        return {
            "file_name": self.target_name,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "format": self.target_format.value,
            "status": self.status,
            "total_members_analyzed": self.total_members_analyzed,
            "deep_re_engines": self.deep_re_engines,
            "critical_count": crit_count,
            "high_count": high_count,
            "total_detections": len(all_legacy_detections),
            "detections": all_legacy_detections,
            "members": [m.to_dict() for m in self.members],
            "evidence": [ev.to_dict() for ev in self.evidence],
            "entropy_category": "Archive" if self.is_archive_or_firmware else "Binary",
            "coverage": {
                "bytes_scanned": self.file_size_bytes,
                "members_count": self.total_members_analyzed,
            },
        }


class BinaryDiscoveryPipeline:
    """Master discovery orchestrator for binaries and firmware images."""

    def __init__(self, asset_graph: Optional[AssetGraphService] = None):
        self.asset_graph = asset_graph

    def scan(
        self,
        data: bytes,
        file_name: str = "target.bin",
        project: str = "default",
        scan_id: str = "",
    ) -> BinaryScanResult:
        if not data:
            raise ValueError("File must contain 1 byte to 8 MiB")

        root_id = BinaryIdentifier.identify(data, file_name)
        root_hash = hashlib.sha256(data).hexdigest()
        engine_health = get_engine_health_report()

        # Check if container / archive requiring extraction
        is_container = root_id.is_archive or root_id.is_firmware or root_id.format in (
            BinaryFormat.ZIP, BinaryFormat.TAR, BinaryFormat.GZIP,
            BinaryFormat.UIMAGE, BinaryFormat.CPIO
        )

        members_to_scan: List[Tuple[str, bytes]] = []

        if is_container:
            extract_res = FirmwareExtractor.extract(data, file_name)
            for m in extract_res.members:
                members_to_scan.append((m.virtual_path, m.data))
        else:
            members_to_scan.append((file_name, data))

        analyses: List[SingleBinaryAnalysis] = []
        all_evidence: List[Evidence] = []

        # Graph node for parent container if archive/firmware
        parent_asset_id = None
        if self.asset_graph and is_container:
            parent_asset_id = f"fw_{root_hash[:16]}"
            fw_type = AssetType.FIRMWARE if root_id.is_firmware else AssetType.APPLICATION
            self.asset_graph.upsert_asset(
                project=project,
                asset_type=fw_type,
                name=file_name,
                scan_id=scan_id,
                status="ACTIVE",
                highest_evidence_level="E2",
                confidence=1.0,
                explanation=f"Firmware/Archive container {root_id.description}",
                asset_id=parent_asset_id,
            )

        for mem_path, mem_bytes in members_to_scan:
            analysis = self._analyze_single(mem_bytes, mem_path, scan_id=scan_id)
            analyses.append(analysis)
            all_evidence.extend(analysis.evidence)

            # Connect to Asset Graph
            if self.asset_graph:
                self._populate_asset_graph(
                    analysis=analysis,
                    project=project,
                    scan_id=scan_id,
                    parent_asset_id=parent_asset_id,
                )

        return BinaryScanResult(
            target_name=file_name,
            target_format=root_id.format,
            sha256=root_hash,
            file_size_bytes=len(data),
            is_archive_or_firmware=is_container,
            total_members_analyzed=len(analyses),
            members=analyses,
            evidence=all_evidence,
            deep_re_engines=engine_health,
            status="success",
        )

    def _analyze_single(
        self, data: bytes, file_name: str, scan_id: str = ""
    ) -> SingleBinaryAnalysis:
        file_hash = hashlib.sha256(data).hexdigest()
        ident = BinaryIdentifier.identify(data, file_name)
        meta = BinaryMetadataParser.parse(data, file_name)
        symbols = BinarySymbolParser.parse(data, file_name)
        imports = BinaryImportParser.parse(data, file_name)
        signatures = BinarySignatureMatcher.match(data, meta.sections)
        strings = BinaryStringExtractor.extract_strings(data)
        secrets = BinaryStringExtractor.extract_secrets(data)

        evidence_list: List[Evidence] = []
        legacy_detections: List[Dict[str, Any]] = []

        # 1. Evidence from Signatures
        for sig in signatures:
            ev = BinaryEvidenceGenerator.from_signature_match(sig, file_name, file_hash, scan_id)
            evidence_list.append(ev)
            legacy_detections.append({
                "primitive": sig.name,
                "offset": f"0x{sig.offset:08X}",
                "severity": sig.severity,
                "confidence": "HIGH" if sig.confidence >= 0.9 else "MEDIUM",
                "type": "byte-signature",
                "byte_order": sig.byte_order,
                "description": sig.description,
                "section": sig.section,
                "file": file_name,
                "source_hash": file_hash,
            })

        # 2. Evidence from Symbols
        for sym in symbols:
            if sym.is_crypto:
                ev = BinaryEvidenceGenerator.from_symbol(sym, file_name, file_hash, scan_id)
                evidence_list.append(ev)
                legacy_detections.append({
                    "primitive": f"Symbol: {sym.name}",
                    "offset": f"0x{sym.value:08X}",
                    "severity": "LOW" if sym.is_defined else "INFO",
                    "confidence": "HIGH" if sym.is_defined else "MEDIUM",
                    "type": "symbol",
                    "description": f"Cryptographic symbol ({'defined' if sym.is_defined else 'imported'})",
                    "section": sym.section,
                    "file": file_name,
                    "source_hash": file_hash,
                })

        # 3. Evidence from Imports
        for imp in imports:
            if imp.is_crypto:
                ev = BinaryEvidenceGenerator.from_import(imp, file_name, file_hash, scan_id)
                evidence_list.append(ev)

        # 4. Evidence from Secrets
        for sec in secrets:
            ev = BinaryEvidenceGenerator.from_secret(sec, file_name, file_hash, scan_id)
            evidence_list.append(ev)
            legacy_detections.append({
                "primitive": sec.secret_type.replace("_", " "),
                "offset": f"0x{sec.offset:08X}",
                "severity": sec.severity,
                "confidence": "HIGH" if sec.is_valid_pem else "LOW",
                "type": "PEM marker",
                "description": f"Embedded {sec.secret_type} (masked as SECRET_INDICATOR_DETECTED)",
                "file": file_name,
                "source_hash": file_hash,
            })

        # 5. Evidence from Strings
        for st in strings[:20]:  # Limit noisy string literals
            ev = BinaryEvidenceGenerator.from_string(st, file_name, file_hash, scan_id)
            evidence_list.append(ev)

        return SingleBinaryAnalysis(
            file_name=file_name,
            sha256=file_hash,
            file_size=len(data),
            identification=ident,
            metadata=meta,
            symbols=symbols,
            imports=imports,
            signatures=signatures,
            strings=strings,
            secrets=secrets,
            evidence=evidence_list,
            legacy_detections=legacy_detections,
        )

    def _populate_asset_graph(
        self,
        analysis: SingleBinaryAnalysis,
        project: str,
        scan_id: str,
        parent_asset_id: Optional[str] = None,
    ) -> None:
        if not self.asset_graph:
            return

        bin_asset_id = f"bin_{analysis.sha256[:16]}"
        self.asset_graph.upsert_asset(
            project=project,
            asset_type=AssetType.BINARY,
            name=analysis.file_name,
            scan_id=scan_id,
            status="ACTIVE",
            highest_evidence_level="E2",
            confidence=1.0,
            explanation=f"{analysis.identification.description}",
            asset_id=bin_asset_id,
        )

        if parent_asset_id:
            self.asset_graph.add_relationship(
                project=project,
                source_id=parent_asset_id,
                source_type="FIRMWARE",
                relationship=RelationshipType.CONTAINS,
                target_id=bin_asset_id,
                target_type="BINARY",
                scan_id=scan_id,
                confidence=1.0,
            )

        # Connect Crypto Libraries
        for imp in analysis.imports:
            if imp.is_crypto:
                lib_id = f"lib_{imp.library_name}"
                self.asset_graph.upsert_asset(
                    project=project,
                    asset_type=AssetType.CRYPTO_LIBRARY,
                    name=imp.library_name,
                    scan_id=scan_id,
                    library=imp.crypto_family,
                    status="ACTIVE",
                    highest_evidence_level="E2",
                    confidence=0.85,
                    explanation=f"Dynamic link: {imp.description}",
                    asset_id=lib_id,
                )
                self.asset_graph.add_relationship(
                    project=project,
                    source_id=bin_asset_id,
                    source_type="BINARY",
                    relationship=RelationshipType.USES,
                    target_id=lib_id,
                    target_type="CRYPTO_LIBRARY",
                    scan_id=scan_id,
                    confidence=0.85,
                )

        # Connect Crypto Algorithms (from Signatures and Symbols)
        seen_algos = set()
        for sig in analysis.signatures:
            algo_key = sig.algorithm
            if algo_key and algo_key not in seen_algos:
                seen_algos.add(algo_key)
                algo_id = f"algo_{algo_key.lower()}"
                self.asset_graph.upsert_asset(
                    project=project,
                    asset_type=AssetType.ALGORITHM,
                    name=algo_key,
                    algorithm=algo_key,
                    scan_id=scan_id,
                    status="ACTIVE",
                    highest_evidence_level="E2",
                    confidence=sig.confidence,
                    explanation=f"Constant/S-box signature: {sig.name}",
                    asset_id=algo_id,
                )
                self.asset_graph.add_relationship(
                    project=project,
                    source_id=bin_asset_id,
                    source_type="BINARY",
                    relationship=RelationshipType.IMPLEMENTS,
                    target_id=algo_id,
                    target_type="ALGORITHM",
                    scan_id=scan_id,
                    confidence=sig.confidence,
                )

        for sym in analysis.symbols:
            if sym.is_crypto and sym.algorithm and sym.algorithm not in seen_algos:
                seen_algos.add(sym.algorithm)
                algo_id = f"algo_{sym.algorithm.lower()}"
                self.asset_graph.upsert_asset(
                    project=project,
                    asset_type=AssetType.ALGORITHM,
                    name=sym.algorithm,
                    algorithm=sym.algorithm,
                    scan_id=scan_id,
                    status="ACTIVE",
                    highest_evidence_level="E3" if sym.is_defined else "E2",
                    confidence=0.90 if sym.is_defined else 0.80,
                    explanation=f"Symbol {sym.name}",
                    asset_id=algo_id,
                )
                rel_type = RelationshipType.IMPLEMENTS if sym.is_defined else RelationshipType.CALLS
                self.asset_graph.add_relationship(
                    project=project,
                    source_id=bin_asset_id,
                    source_type="BINARY",
                    relationship=rel_type,
                    target_id=algo_id,
                    target_type="ALGORITHM",
                    scan_id=scan_id,
                    confidence=0.90 if sym.is_defined else 0.80,
                )
