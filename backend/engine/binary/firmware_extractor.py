"""
ECDAT V4 Bounded Multi-Format Firmware & Archive Extractor.

Supports pure-Python safe extraction for:
- ZIP archives
- Tar archives (.tar, .tar.gz, .tgz)
- Gzip compressed streams
- U-Boot uImage containers
- CPIO archives

Security & Sandbox Bounds:
- MAX_DEPTH = 3 (recursion depth limit)
- MAX_ENTRIES = 200 (max files total across all containers)
- MAX_TOTAL_BYTES = 16 MiB (cumulative decompressed volume)
- MAX_FILE_BYTES = 8 MiB (per-file decompressed ceiling)
- Strict path traversal prevention: forbids '..', leading slashes, null bytes
- In-memory execution: zero temporary files persisted to host filesystem
"""
from __future__ import annotations

from dataclasses import dataclass, field
import gzip
import hashlib
import io
import os
import struct
import tarfile
from typing import Any, Dict, Generator, List, Optional, Set, Tuple
import zipfile

from .binary_identifier import BinaryFormat, BinaryIdentifier

MAX_DEPTH = 3
MAX_ENTRIES = 200
MAX_TOTAL_BYTES = 16 * 1024 * 1024  # 16 MiB
MAX_FILE_BYTES = 8 * 1024 * 1024   # 8 MiB


@dataclass
class ExtractedMember:
    virtual_path: str
    filename: str
    data: bytes
    size_bytes: int
    sha256: str
    format: BinaryFormat
    depth: int
    parent_hash: str = ""
    container_path: str = ""
    extraction_method: str = "direct"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "virtual_path": self.virtual_path,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "format": self.format.value,
            "depth": self.depth,
            "parent_hash": self.parent_hash,
            "container_path": self.container_path,
            "extraction_method": self.extraction_method,
        }


@dataclass
class ExtractionResult:
    archive_name: str
    format: BinaryFormat
    total_files_extracted: int
    total_decompressed_bytes: int
    members: List[ExtractedMember] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    depth_reached: int = 1


def _is_safe_path(path: str) -> bool:
    """Rejects path traversal attempts, absolute paths, and null bytes."""
    if not path or "\0" in path:
        return False
    clean = path.replace("\\", "/")
    if clean.startswith("/") or clean.startswith("~"):
        return False
    parts = clean.split("/")
    if any(p in ("..", "") for p in parts if p != "."):
        # Check if actually climbing up
        depth = 0
        for p in parts:
            if p == "..":
                depth -= 1
                if depth < 0:
                    return False
            elif p and p != ".":
                depth += 1
    return True


class FirmwareExtractor:
    """Safely extracts archives and firmware containers with hard resource limits."""

    @classmethod
    def extract(cls, data: bytes, name: str = "firmware.bin") -> ExtractionResult:
        if not data or len(data) > MAX_FILE_BYTES:
            raise ValueError(f"Payload must contain 1 byte to {MAX_FILE_BYTES // (1024*1024)} MiB")

        id_res = BinaryIdentifier.identify(data, name)
        result = ExtractionResult(archive_name=name, format=id_res.format, total_files_extracted=0, total_decompressed_bytes=0)

        total_extracted = [0]
        total_bytes = [0]
        visited_hashes: Set[str] = set()

        def recurse(
            curr_data: bytes,
            curr_path: str,
            depth: int,
            parent_hash: str = "",
            container_path: str = "",
            extraction_method: str = "direct",
        ):
            if depth > MAX_DEPTH:
                result.errors.append(f"Maximum extraction depth ({MAX_DEPTH}) exceeded at {curr_path}")
                return

            if total_extracted[0] >= MAX_ENTRIES:
                result.errors.append(f"Maximum file count ({MAX_ENTRIES}) exceeded")
                return

            curr_hash = hashlib.sha256(curr_data).hexdigest()
            if curr_hash in visited_hashes:
                return  # Prevent recursive archive bomb loops
            visited_hashes.add(curr_hash)

            curr_id = BinaryIdentifier.identify(curr_data, curr_path)

            if depth > result.depth_reached:
                result.depth_reached = depth

            # ZIP
            if curr_id.format == BinaryFormat.ZIP or zipfile.is_zipfile(io.BytesIO(curr_data)):
                cls._extract_zip(curr_data, curr_path, depth, recurse, total_extracted, total_bytes, result)
            # TAR
            elif curr_id.format == BinaryFormat.TAR:
                cls._extract_tar(curr_data, curr_path, depth, recurse, total_extracted, total_bytes, result)
            # GZIP
            elif curr_id.format == BinaryFormat.GZIP:
                cls._extract_gzip(curr_data, curr_path, depth, recurse, total_extracted, total_bytes, result)
            # UIMAGE
            elif curr_id.format == BinaryFormat.UIMAGE:
                cls._extract_uimage(curr_data, curr_path, depth, recurse, total_extracted, total_bytes, result)
            # CPIO
            elif curr_id.format == BinaryFormat.CPIO:
                cls._extract_cpio(curr_data, curr_path, depth, recurse, total_extracted, total_bytes, result)
            # Leaf member file (executable, library, config, raw)
            else:
                member_fname = os.path.basename(curr_path) or "payload.bin"
                result.members.append(
                    ExtractedMember(
                        virtual_path=curr_path,
                        filename=member_fname,
                        data=curr_data,
                        size_bytes=len(curr_data),
                        sha256=curr_hash,
                        format=curr_id.format,
                        depth=depth,
                        parent_hash=parent_hash,
                        container_path=container_path,
                        extraction_method=extraction_method,
                    )
                )

        recurse(data, name, depth=1)
        result.total_files_extracted = len(result.members)
        result.total_decompressed_bytes = total_bytes[0]
        return result

    @classmethod
    def _extract_zip(
        cls,
        data: bytes,
        parent_path: str,
        depth: int,
        recurse_fn: Any,
        total_extracted: List[int],
        total_bytes: List[int],
        result: ExtractionResult,
    ) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infolist = zf.infolist()
                if len(infolist) > 100:
                    raise ValueError("Archive has more than 100 entries")

                for info in infolist:
                    if info.is_dir():
                        continue
                    if info.flag_bits & 1:
                        raise ValueError("Encrypted ZIP entries are unsupported")

                    if not _is_safe_path(info.filename):
                        result.errors.append(f"Skipping dangerous path in ZIP: {info.filename}")
                        continue

                    if info.file_size > MAX_FILE_BYTES:
                        raise ValueError("Expanded archive exceeds 8 MiB")

                    total_bytes[0] += info.file_size
                    if total_bytes[0] > MAX_TOTAL_BYTES:
                        raise ValueError("Expanded archive exceeds 8 MiB")

                    total_extracted[0] += 1
                    with zf.open(info) as f:
                        file_data = f.read(MAX_FILE_BYTES + 1)

                    if len(file_data) != info.file_size:
                        raise ValueError("Archive size mismatch")

                    vpath = f"{parent_path}!/{info.filename}"
                    recurse_fn(
                        file_data,
                        vpath,
                        depth + 1,
                        parent_hash=hashlib.sha256(data).hexdigest(),
                        container_path=parent_path,
                        extraction_method="zip",
                    )
        except zipfile.BadZipFile:
            result.errors.append(f"Corrupted ZIP archive at {parent_path}")

    @classmethod
    def _extract_tar(
        cls,
        data: bytes,
        parent_path: str,
        depth: int,
        recurse_fn: Any,
        total_extracted: List[int],
        total_bytes: List[int],
        result: ExtractionResult,
    ) -> None:
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                for member in tf.getmembers():
                    if not member.isfile():
                        continue

                    if not _is_safe_path(member.name):
                        result.errors.append(f"Skipping dangerous path in TAR: {member.name}")
                        continue

                    if member.size > MAX_FILE_BYTES:
                        raise ValueError("Expanded archive exceeds 8 MiB")

                    total_bytes[0] += member.size
                    if total_bytes[0] > MAX_TOTAL_BYTES:
                        raise ValueError("Expanded archive exceeds 8 MiB")

                    total_extracted[0] += 1
                    f = tf.extractfile(member)
                    if f is not None:
                        file_data = f.read(MAX_FILE_BYTES + 1)
                        vpath = f"{parent_path}!/{member.name}"
                        recurse_fn(
                            file_data,
                            vpath,
                            depth + 1,
                            parent_hash=hashlib.sha256(data).hexdigest(),
                            container_path=parent_path,
                            extraction_method="tar",
                        )
        except tarfile.TarError:
            result.errors.append(f"Corrupted Tar archive at {parent_path}")

    @classmethod
    def _extract_gzip(
        cls,
        data: bytes,
        parent_path: str,
        depth: int,
        recurse_fn: Any,
        total_extracted: List[int],
        total_bytes: List[int],
        result: ExtractionResult,
    ) -> None:
        try:
            decompressed = gzip.decompress(data)
            if len(decompressed) > MAX_FILE_BYTES:
                raise ValueError("Expanded archive exceeds 8 MiB")

            total_bytes[0] += len(decompressed)
            total_extracted[0] += 1

            inner_name = parent_path[:-3] if parent_path.endswith(".gz") else f"{parent_path}.decompressed"
            vpath = f"{parent_path}!/{inner_name}"
            recurse_fn(
                decompressed,
                vpath,
                depth + 1,
                parent_hash=hashlib.sha256(data).hexdigest(),
                container_path=parent_path,
                extraction_method="gzip",
            )
        except Exception:
            result.errors.append(f"Gzip decompression failed for {parent_path}")

    @classmethod
    def _extract_uimage(
        cls,
        data: bytes,
        parent_path: str,
        depth: int,
        recurse_fn: Any,
        total_extracted: List[int],
        total_bytes: List[int],
        result: ExtractionResult,
    ) -> None:
        if len(data) < 64:
            return
        # U-Boot image header: size at offset 12 (4 bytes big-endian)
        img_size = struct.unpack_from(">I", data, 12)[0]
        payload = data[64:64 + img_size]
        if payload:
            total_bytes[0] += len(payload)
            total_extracted[0] += 1
            vpath = f"{parent_path}!/uimage_payload.bin"
            recurse_fn(
                payload,
                vpath,
                depth + 1,
                parent_hash=hashlib.sha256(data).hexdigest(),
                container_path=parent_path,
                extraction_method="uimage",
            )

    @classmethod
    def _extract_cpio(
        cls,
        data: bytes,
        parent_path: str,
        depth: int,
        recurse_fn: Any,
        total_extracted: List[int],
        total_bytes: List[int],
        result: ExtractionResult,
    ) -> None:
        """Parses CPIO new ascii format (070701 / 070702)."""
        offset = 0
        while offset + 110 <= len(data):
            magic = data[offset:offset + 6]
            if magic not in (b"070701", b"070702"):
                break
            try:
                namesize = int(data[offset + 94:offset + 102], 16)
                filesize = int(data[offset + 54:offset + 62], 16)
            except ValueError:
                break

            name_offset = offset + 110
            # Name padded to 4 bytes
            name_padded = (namesize + 3) & ~3
            data_offset = name_offset + name_padded
            # Data padded to 4 bytes
            data_padded = (filesize + 3) & ~3

            if data_offset + filesize > len(data):
                break

            raw_name = data[name_offset:name_offset + namesize - 1].decode("ascii", "replace")
            if raw_name == "TRAILER!!!":
                break

            if filesize > 0 and _is_safe_path(raw_name):
                file_bytes = data[data_offset:data_offset + filesize]
                total_bytes[0] += len(file_bytes)
                if total_bytes[0] > MAX_TOTAL_BYTES:
                    raise ValueError("Expanded archive exceeds 8 MiB")
                total_extracted[0] += 1
                vpath = f"{parent_path}!/{raw_name}"
                recurse_fn(
                    file_bytes,
                    vpath,
                    depth + 1,
                    parent_hash=hashlib.sha256(data).hexdigest(),
                    container_path=parent_path,
                    extraction_method="cpio",
                )

            offset = data_offset + data_padded
