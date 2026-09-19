"""Centralized, environment-configurable upload and payload size limits.

All size ceilings in ECDAT derive from this module so the backend, the
frontend proxy and user-facing error messages always agree.

Environment variables:
    ECDAT_MAX_DIRECT_MB   - Max size (MiB) of a single direct upload
                            (multipart file or JSON API body). Default 64.
    ECDAT_MAX_CHUNKED_MB  - Max size (MiB) of a chunked-upload assembly.
                            Default 1024 (1 GiB).
    ECDAT_MAX_SOURCE_CHARS- Max characters of source text accepted per file
                            in JSON scan payloads. Default 5,000,000 (~5 MB).
"""
from __future__ import annotations

import os


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, value)


# Direct (single-request) uploads: multipart /scan/binary/upload, /archive/upload,
# hex JSON bodies and pasted source code bundles.
MAX_DIRECT_UPLOAD_MB = _env_int("ECDAT_MAX_DIRECT_MB", 64)
MAX_DIRECT_UPLOAD_BYTES = MAX_DIRECT_UPLOAD_MB * 1024 * 1024

# Chunked uploads assemble on disk; they may be much larger than direct uploads.
MAX_CHUNKED_UPLOAD_MB = _env_int("ECDAT_MAX_CHUNKED_MB", 1024)
MAX_CHUNKED_UPLOAD_BYTES = MAX_CHUNKED_UPLOAD_MB * 1024 * 1024

# Source text per file inside JSON scan/patch payloads (UTF-8 characters).
MAX_SOURCE_FILE_CHARS = _env_int("ECDAT_MAX_SOURCE_CHARS", 5_000_000)

# Files at or above this threshold are uploaded via the chunked endpoint.
CHUNK_THRESHOLD_BYTES = 10 * 1024 * 1024

# Middleware ceiling for buffered JSON/OCTET-STREAM request bodies. Hex-encoded
# endpoints double their payload size, hence the 2x headroom over direct uploads.
MAX_JSON_BODY_BYTES = MAX_DIRECT_UPLOAD_BYTES * 2


def human_mb(num_bytes: int) -> str:
    """Render a byte count as a human-readable MiB/GiB string."""
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.0f} GB"
    return f"{num_bytes / (1024 * 1024):.0f} MiB"
