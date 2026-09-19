"""
ECDAT V4 Binary & Firmware Discovery Package.
"""
from .binary_identifier import BinaryIdentifier, BinaryFormat, IdentificationResult
from .binary_metadata import BinaryMetadataParser, BinaryMetadata, SectionInfo
from .binary_symbols import BinarySymbolParser, SymbolInfo, SymbolType, SymbolBinding
from .binary_imports import BinaryImportParser, ImportInfo
from .binary_strings import BinaryStringExtractor, StringMatch, SecretCandidate
from .binary_signatures import BinarySignatureMatcher, SignatureMatch
from .firmware_extractor import FirmwareExtractor, ExtractedMember, ExtractionResult
from .deep_re_plugins import DiscoveryEngine, EngineHealth, GhidraEngine, AngrEngine, YaraEngine, get_available_engines, get_engine_health_report
from .binary_normalizer import BinaryNormalizer
from .binary_evidence import BinaryEvidenceGenerator
from .binary_pipeline import BinaryDiscoveryPipeline, BinaryScanResult

__all__ = [
    "BinaryIdentifier",
    "BinaryFormat",
    "IdentificationResult",
    "BinaryMetadataParser",
    "BinaryMetadata",
    "SectionInfo",
    "BinarySymbolParser",
    "SymbolInfo",
    "SymbolType",
    "SymbolBinding",
    "BinaryImportParser",
    "ImportInfo",
    "BinaryStringExtractor",
    "StringMatch",
    "SecretCandidate",
    "BinarySignatureMatcher",
    "SignatureMatch",
    "FirmwareExtractor",
    "ExtractedMember",
    "ExtractionResult",
    "DiscoveryEngine",
    "EngineHealth",
    "GhidraEngine",
    "AngrEngine",
    "YaraEngine",
    "get_available_engines",
    "BinaryNormalizer",
    "BinaryEvidenceGenerator",
    "BinaryDiscoveryPipeline",
    "BinaryScanResult",
]
