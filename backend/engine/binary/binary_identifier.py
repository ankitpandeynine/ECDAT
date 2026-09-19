"""
ECDAT V4 Binary & Firmware Format Identifier.

Pure Python format detection for:
- Executables: ELF (32/64-bit, LE/BE), PE/COFF, Mach-O
- Firmware Containers: U-Boot uImage, FIT, SquashFS, cpio
- Archives: ZIP, Tar, Gzip
- Raw / Unknown binaries
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import io
import math
import struct
import tarfile
from typing import Dict, Optional, Tuple
import zipfile


class BinaryFormat(str, Enum):
    ELF = "ELF"
    PE = "PE"
    MACHO = "MACHO"
    ZIP = "ZIP"
    TAR = "TAR"
    GZIP = "GZIP"
    CPIO = "CPIO"
    SQUASHFS = "SQUASHFS"
    UIMAGE = "UIMAGE"
    FIT = "FIT"
    RAW = "RAW"
    UNKNOWN = "UNKNOWN"


@dataclass
class IdentificationResult:
    format: BinaryFormat
    description: str
    architecture: str
    bits: int
    endianness: str  # "little", "big", "unknown"
    is_archive: bool
    is_firmware: bool
    file_size: int
    sha256: str
    entropy: float
    mime_type: str


ELF_MACHINE_MAP: Dict[int, str] = {
    0x03: "x86 (i386)",
    0x3E: "x86_64",
    0x28: "ARM",
    0xB7: "AArch64 (ARM64)",
    0x08: "MIPS",
    0xF3: "RISC-V",
    0x14: "PowerPC",
    0x15: "PowerPC64",
    0x02: "SPARC",
}

PE_MACHINE_MAP: Dict[int, str] = {
    0x014C: "x86 (i386)",
    0x8664: "x86_64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "AArch64 (ARM64)",
    0x0200: "IA64",
}

MACHO_CPUTYPE_MAP: Dict[int, str] = {
    7: "x86",
    0x01000007: "x86_64",
    12: "ARM",
    0x0100000C: "ARM64",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy (0.0 to 8.0 bits per byte)."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class BinaryIdentifier:
    """Identifies executable, firmware, and archive formats from bytes."""

    @staticmethod
    def identify(data: bytes, filename: str = "") -> IdentificationResult:
        file_size = len(data)
        sha256 = hashlib.sha256(data).hexdigest() if data else ""
        entropy = calculate_entropy(data)

        if not data:
            return IdentificationResult(
                format=BinaryFormat.UNKNOWN,
                description="Empty buffer",
                architecture="unknown",
                bits=0,
                endianness="unknown",
                is_archive=False,
                is_firmware=False,
                file_size=0,
                sha256=sha256,
                entropy=0.0,
                mime_type="application/octet-stream",
            )

        # 1. ELF
        if data.startswith(b"\x7fELF"):
            return BinaryIdentifier._identify_elf(data, sha256, entropy)

        # 2. PE (Portable Executable / COFF)
        if data.startswith(b"MZ"):
            res = BinaryIdentifier._identify_pe(data, sha256, entropy)
            if res is not None:
                return res

        # 3. Mach-O
        macho_res = BinaryIdentifier._identify_macho(data, sha256, entropy)
        if macho_res is not None:
            return macho_res

        # 4. U-Boot uImage (Magic 0x27051956)
        if len(data) >= 64 and data[:4] == b"\x27\x05\x19\x56":
            arch_code = data[29] if len(data) > 29 else 0
            uimage_arch = {2: "ARM", 3: "x86", 5: "MIPS", 7: "PowerPC", 22: "ARM64", 26: "RISC-V"}.get(arch_code, "unknown")
            return IdentificationResult(
                format=BinaryFormat.UIMAGE,
                description="U-Boot Legacy uImage firmware container",
                architecture=uimage_arch,
                bits=32 if arch_code != 22 else 64,
                endianness="big",
                is_archive=True,
                is_firmware=True,
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-u-boot-image",
            )

        # 5. FIT (Device Tree Blob / Flattened Image Tree 0xd00dfeed)
        if len(data) >= 8 and data[:4] == b"\xd0\x0d\xfe\xed":
            return IdentificationResult(
                format=BinaryFormat.FIT,
                description="Flattened Image Tree (FIT) Device Tree Blob firmware",
                architecture="embedded",
                bits=32,
                endianness="big",
                is_archive=True,
                is_firmware=True,
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-dtb",
            )

        # 6. SquashFS (hsqs, sqsh, qshs, shsq)
        if len(data) >= 4 and data[:4] in (b"hsqs", b"sqsh", b"qshs", b"shsq"):
            endianness = "little" if data[:4] in (b"hsqs", b"qshs") else "big"
            return IdentificationResult(
                format=BinaryFormat.SQUASHFS,
                description=f"SquashFS compressed filesystem image ({data[:4].decode('ascii', 'replace')})",
                architecture="filesystem",
                bits=0,
                endianness=endianness,
                is_archive=True,
                is_firmware=True,
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-squashfs-image",
            )

        # 7. CPIO (070701, 070702, 070707 or binary \xc7\x71, \x71\xc7)
        if len(data) >= 6 and (
            data.startswith(b"070701")
            or data.startswith(b"070702")
            or data.startswith(b"070707")
            or data.startswith(b"\xc7\x71")
            or data.startswith(b"\x71\xc7")
        ):
            return IdentificationResult(
                format=BinaryFormat.CPIO,
                description="CPIO archive filesystem",
                architecture="archive",
                bits=0,
                endianness="little" if data.startswith(b"070701") or data.startswith(b"\x71\xc7") else "big",
                is_archive=True,
                is_firmware=True,
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-cpio",
            )

        # 8. ZIP
        if data.startswith(b"PK\x03\x04") or zipfile.is_zipfile(io.BytesIO(data)):
            return IdentificationResult(
                format=BinaryFormat.ZIP,
                description="ZIP Archive container",
                architecture="archive",
                bits=0,
                endianness="little",
                is_archive=True,
                is_firmware=filename.lower().endswith((".bin", ".fw", ".img", ".rom")),
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/zip",
            )

        # 9. GZIP
        if data.startswith(b"\x1f\x8b"):
            return IdentificationResult(
                format=BinaryFormat.GZIP,
                description="Gzip compressed data",
                architecture="compressed",
                bits=0,
                endianness="little",
                is_archive=True,
                is_firmware=filename.lower().endswith((".bin", ".fw", ".img", ".rom")),
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/gzip",
            )

        # 10. TAR
        if len(data) >= 512 and data[257:262] == b"ustar":
            return IdentificationResult(
                format=BinaryFormat.TAR,
                description="POSIX tar archive",
                architecture="archive",
                bits=0,
                endianness="unknown",
                is_archive=True,
                is_firmware=filename.lower().endswith((".bin", ".fw", ".img", ".rom")),
                file_size=file_size,
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-tar",
            )

        # Fallback: RAW binary blob
        is_fw = filename.lower().endswith((".bin", ".fw", ".img", ".rom", ".hex"))
        return IdentificationResult(
            format=BinaryFormat.RAW,
            description="Raw binary payload / unformatted blob",
            architecture="unknown",
            bits=0,
            endianness="unknown",
            is_archive=False,
            is_firmware=is_fw,
            file_size=file_size,
            sha256=sha256,
            entropy=entropy,
            mime_type="application/octet-stream",
        )

    @staticmethod
    def _identify_elf(data: bytes, sha256: str, entropy: float) -> IdentificationResult:
        if len(data) < 52:
            return IdentificationResult(
                format=BinaryFormat.ELF,
                description="Truncated ELF binary",
                architecture="unknown",
                bits=0,
                endianness="unknown",
                is_archive=False,
                is_firmware=False,
                file_size=len(data),
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-executable",
            )

        bit_flag = data[4]  # 1 = 32-bit, 2 = 64-bit
        endian_flag = data[5]  # 1 = Little Endian, 2 = Big Endian
        bits = 64 if bit_flag == 2 else 32
        endianness = "little" if endian_flag == 1 else "big"
        endian_char = "<" if endian_flag == 1 else ">"

        machine_code = 0
        try:
            machine_code = struct.unpack_from(endian_char + "H", data, 18)[0]
        except struct.error:
            pass

        arch = ELF_MACHINE_MAP.get(machine_code, f"unknown (0x{machine_code:04x})")
        desc = f"ELF {bits}-bit {endianness}-endian ({arch})"

        return IdentificationResult(
            format=BinaryFormat.ELF,
            description=desc,
            architecture=arch,
            bits=bits,
            endianness=endianness,
            is_archive=False,
            is_firmware=False,
            file_size=len(data),
            sha256=sha256,
            entropy=entropy,
            mime_type="application/x-executable",
        )

    @staticmethod
    def _identify_pe(data: bytes, sha256: str, entropy: float) -> Optional[IdentificationResult]:
        if len(data) < 64:
            return None
        try:
            pe_offset = struct.unpack_from("<I", data, 60)[0]
            if pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
                return None
            machine_code = struct.unpack_from("<H", data, pe_offset + 4)[0]
            magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
            bits = 64 if magic == 0x20B else 32
            arch = PE_MACHINE_MAP.get(machine_code, f"unknown (0x{machine_code:04x})")
            return IdentificationResult(
                format=BinaryFormat.PE,
                description=f"PE/COFF {bits}-bit ({arch})",
                architecture=arch,
                bits=bits,
                endianness="little",
                is_archive=False,
                is_firmware=False,
                file_size=len(data),
                sha256=sha256,
                entropy=entropy,
                mime_type="application/vnd.microsoft.portable-executable",
            )
        except (struct.error, IndexError):
            return None

    @staticmethod
    def _identify_macho(data: bytes, sha256: str, entropy: float) -> Optional[IdentificationResult]:
        if len(data) < 12:
            return None
        magic = data[:4]
        # Thin Mach-O
        # 0xfeedface = 32-bit big, 0xcefaedfe = 32-bit little
        # 0xfeedfacf = 64-bit big, 0xcffaedfe = 64-bit little
        if magic in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            is_64 = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
            is_le = magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
            endian_char = "<" if is_le else ">"
            cputype = struct.unpack_from(endian_char + "I", data, 4)[0]
            arch = MACHO_CPUTYPE_MAP.get(cputype, f"unknown (0x{cputype:x})")
            return IdentificationResult(
                format=BinaryFormat.MACHO,
                description=f"Mach-O {'64-bit' if is_64 else '32-bit'} ({arch})",
                architecture=arch,
                bits=64 if is_64 else 32,
                endianness="little" if is_le else "big",
                is_archive=False,
                is_firmware=False,
                file_size=len(data),
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-mach-binary",
            )
        # Universal Fat Mach-O
        if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            return IdentificationResult(
                format=BinaryFormat.MACHO,
                description="Mach-O Universal Fat Binary",
                architecture="universal",
                bits=64,
                endianness="big" if magic == b"\xca\xfe\xba\xbe" else "little",
                is_archive=False,
                is_firmware=False,
                file_size=len(data),
                sha256=sha256,
                entropy=entropy,
                mime_type="application/x-mach-binary",
            )
        return None
