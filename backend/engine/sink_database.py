"""
ECDAT V4 Cryptographic Sink & Capability Knowledge Database.

Provides programmatic querying over versioned cryptographic sinks,
operations, and dependency capabilities defined in backend/knowledge/crypto_sinks.yaml.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


def normalize_lang(lang: str) -> str:
    l = lang.lower().strip()
    if l in ("go", "golang"):
        return "golang"
    if l in ("c", "cpp", "c++", "c_cpp", "h", "hpp"):
        return "c_cpp"
    if l in ("py", "python"):
        return "python"
    if l in ("js", "javascript", "jsx", "ts", "typescript", "tsx"):
        return "javascript"
    if l in ("rs", "rust"):

        return "rust"
    if l in ("java",):
        return "java"
    return l


class CryptoSinkDatabase:
    def __init__(self, yaml_path: Optional[Path | str] = None):
        if yaml_path is None:
            yaml_path = Path(__file__).parent.parent / "knowledge" / "crypto_sinks.yaml"
        self.yaml_path = Path(yaml_path)
        self.sinks: List[Dict[str, Any]] = []
        self.dependency_capabilities: Dict[str, Dict[str, Any]] = {}
        self._api_index: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self) -> None:
        if not self.yaml_path.exists():
            return
        with open(self.yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self.sinks = data.get("sinks", [])
        self.dependency_capabilities = data.get("dependency_capabilities", {})

        # Build lookup index: (language, api_token) -> sink
        self._api_index.clear()
        for sink in self.sinks:
            lang = normalize_lang(sink.get("language", ""))
            api = sink.get("api", "")
            if lang and api:
                self._api_index[f"{lang}::{api}"] = sink
                # Also index bare method/function name
                bare_api = api.split(".")[-1].split("::")[-1]
                if bare_api != api:
                    self._api_index[f"{lang}::{bare_api}"] = sink

    def find_sink(self, language: str, api: str) -> Optional[Dict[str, Any]]:
        """Exact or suffix match for API call."""
        lang = normalize_lang(language)
        key = f"{lang}::{api}"
        if key in self._api_index:
            return self._api_index[key]

        # Suffix matching for qualified calls (e.g., 'rsa.generate_private_key')
        for sink in self.sinks:
            if normalize_lang(sink.get("language", "")) == lang:
                sink_api = sink.get("api", "")
                if api == sink_api or api.endswith(f".{sink_api}") or sink_api.endswith(f".{api}"):
                    return sink
        return None

    def match_call(self, language: str, call_expression: str) -> Optional[Dict[str, Any]]:
        """Matches a call expression (e.g. 'hashlib.sha256', 'Cipher.getInstance') against known sinks."""
        lang = normalize_lang(language)
        clean_expr = call_expression.strip()

        # Check exact or normalized match
        match = self.find_sink(lang, clean_expr)
        if match:
            return match

        # Substring / token matching
        for sink in self.sinks:
            if normalize_lang(sink.get("language", "")) == lang:
                sink_api = sink.get("api", "")
                if sink_api in clean_expr:
                    return sink
        return None


    def is_crypto_dependency(self, package_name: str) -> bool:
        """Returns True if the package is a known cryptographic library."""
        norm_name = package_name.lower().replace("-", "_").replace(".", "_").replace(":", "_")
        for key in self.dependency_capabilities:
            norm_key = key.lower().replace("-", "_").replace(".", "_")
            if norm_name == norm_key or norm_key in norm_name or norm_name.startswith(norm_key):
                return True
        return False

    def get_dependency_capabilities(self, package_name: str) -> List[str]:
        """Returns list of cryptographic capabilities for the dependency without implying actual use."""
        norm_name = package_name.lower().replace("-", "_").replace(".", "_").replace(":", "_")
        for key, details in self.dependency_capabilities.items():
            norm_key = key.lower().replace("-", "_").replace(".", "_")
            if norm_name == norm_key or norm_key in norm_name or norm_name.startswith(norm_key):
                return details.get("capabilities", [])
        return []



# Global singleton instance
_GLOBAL_SINK_DB: Optional[CryptoSinkDatabase] = None


def get_sink_database() -> CryptoSinkDatabase:
    global _GLOBAL_SINK_DB
    if _GLOBAL_SINK_DB is None:
        _GLOBAL_SINK_DB = CryptoSinkDatabase()
    return _GLOBAL_SINK_DB
