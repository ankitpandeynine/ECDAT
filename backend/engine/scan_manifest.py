"""
ECDAT V4 Reproducibility Manifest & Configuration Engine.

A scan must be deterministic and fully reproducible.
Captures:
- Exact scanner, engine, and ruleset versions
- Configuration hash (sanitized of secrets)
- Execution environment & resource boundaries
- Deterministic result hash (SHA-256 of canonicalized result)
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional
import uuid


SECRET_KEY_SUBSTRINGS = (
    "token", "secret", "password", "key", "auth", "credential", "cookie", "session"
)


def sanitize_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively scrub secrets and sensitive tokens from configuration records."""
    sanitized: Dict[str, Any] = {}
    for k, v in sorted(config.items()):
        lower_k = k.lower()
        if any(sub in lower_k for sub in SECRET_KEY_SUBSTRINGS):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = sanitize_config(v)
        elif isinstance(v, (list, tuple)):
            sanitized[k] = [
                sanitize_config(x) if isinstance(x, dict) else x for x in v
            ]
        else:
            sanitized[k] = v
    return sanitized


def sanitize_secrets(config: Dict[str, Any]) -> Dict[str, Any]:
    return sanitize_config(config)


def canonical_json(data: Any) -> str:
    """Produces deterministic canonicalized JSON string with sorted keys and tight separators."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def compute_sha256(data: str | bytes) -> str:
    """Computes SHA-256 hex digest of string or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json_hash(data: Any) -> str:
    """Produces deterministic SHA-256 hash of arbitrarily nested JSON-compatible data."""
    return compute_sha256(canonical_json(data))


def get_git_commit() -> Optional[str]:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return None


def get_openssl_version() -> Optional[str]:
    binary = os.getenv("ECDAT_OPENSSL_BIN") or shutil.which("openssl")
    if not binary:
        return None
    try:
        res = subprocess.run(
            [binary, "version"],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return None


@dataclass
class EnvironmentInfo:
    platform: str = field(default_factory=lambda: platform.platform())
    os_name: str = field(default_factory=lambda: platform.system())
    python_version: str = field(default_factory=lambda: sys.version)
    openssl_version: Optional[str] = field(default_factory=get_openssl_version)
    git_commit: Optional[str] = field(default_factory=get_git_commit)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanManifest:
    scan_id: str
    input_hash: str
    scanner_version: str = "4.0.0"
    manifest_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_kind: str = "general"
    engine_versions: Dict[str, str] = field(default_factory=lambda: {
        "source_scan": "4.0.0",
        "ast_scanner": "4.0.0",
        "polyglot_scanner": "4.0.0",
        "binary_deep": "4.0.0",
        "network_prober": "4.0.0",
        "pqc_probe": "4.0.0",
        "asset_graph": "4.0.0",
        "evidence_fusion": "4.0.0",
        "cbom_generator": "4.0.0",
        "crypto_risk_intelligence": "4.0.0",
    })
    ruleset_versions: Dict[str, str] = field(default_factory=lambda: {
        "python_ast_rules": "4.0.0",
        "polyglot_rules": "4.0.0",
        "binary_signatures": "4.0.0",
        "pqc_hybrid_groups": "4.0.0",
        "crypto_risk_rules": "2024.1",
        "algorithm_security": "2024.1",
    })
    configuration: Dict[str, Any] = field(default_factory=dict)
    configuration_hash: str = ""
    enabled_engines: List[str] = field(default_factory=lambda: [
        "source_scan", "binary_deep", "network_prober", "pqc_probe", "asset_graph", "evidence_fusion"
    ])
    disabled_engines: List[str] = field(default_factory=list)
    environment: EnvironmentInfo = field(default_factory=EnvironmentInfo)
    resource_limits: Dict[str, Any] = field(default_factory=lambda: {
        "max_bytes": 8 * 1024 * 1024,
        "max_files": 100,
        "max_archive_depth": 1,
        "max_execution_seconds": 25,
    })
    result_hash: str = ""

    def __post_init__(self):
        sanitized = sanitize_config(self.configuration)
        self.configuration = sanitized
        if not self.configuration_hash:
            self.configuration_hash = "sha256:" + canonical_json_hash(sanitized)
        if self.input_hash and not self.input_hash.startswith("sha256:"):
            self.input_hash = "sha256:" + self.input_hash
        if isinstance(self.environment, dict):
            self.environment = EnvironmentInfo(**self.environment)

    def finalize_result(self, result_data: Any) -> str:
        """Computes and assigns the deterministic result hash."""
        self.result_hash = "sha256:" + canonical_json_hash(result_data)
        return self.result_hash

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(self.environment, EnvironmentInfo):
            d["environment"] = self.environment.to_dict()
        return d

    @classmethod
    def create(
        cls,
        scan_id: str,
        scan_kind: str,
        input_data: Any,
        config: Optional[Dict[str, Any]] = None,
        toolchain: Optional[Dict[str, Any]] = None,
    ) -> ScanManifest:
        input_h = "sha256:" + canonical_json_hash(input_data)
        config_dict = config or {}
        return cls(
            scan_id=scan_id,
            input_hash=input_h,
            scan_kind=scan_kind,
            configuration=config_dict,
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanManifest:
        d = dict(data)
        if "environment" in d and isinstance(d["environment"], dict):
            d["environment"] = EnvironmentInfo(**d["environment"])
        return cls(**d)
