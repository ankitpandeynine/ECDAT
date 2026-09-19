"""
ECDAT V4 Binary Shared Library & Import Dependency Parser.

Extracts dynamic shared library dependencies:
- ELF DT_NEEDED entries from .dynamic
- PE Import Directory DLL names
- Mach-O LC_LOAD_DYLIB commands

Research Axiom:
A binary dependency on libcrypto.so or bcrypt.dll confirms the application links
against a cryptographic provider, but DOES NOT prove specific algorithms are invoked.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct
from typing import Any, Dict, List, Optional, Set

from .binary_identifier import BinaryFormat, BinaryIdentifier


@dataclass
class ImportInfo:
    library_name: str
    is_crypto: bool
    crypto_family: Optional[str] = None
    description: Optional[str] = None
    format: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "library_name": self.library_name,
            "is_crypto": self.is_crypto,
            "crypto_family": self.crypto_family,
            "description": self.description,
            "format": self.format,
        }


KNOWN_CRYPTO_LIBS: List[Dict[str, Any]] = [
    {"pattern": r"(?i).*libcrypto.*", "family": "OpenSSL", "desc": "OpenSSL Cryptographic Primitives Library"},
    {"pattern": r"(?i).*libssl.*", "family": "OpenSSL", "desc": "OpenSSL SSL/TLS Transport Library"},
    {"pattern": r"(?i).*bcrypt(?:\.dll)?$", "family": "Windows CNG", "desc": "Windows Best Cryptography Next Generation Library"},
    {"pattern": r"(?i).*crypt32(?:\.dll)?$", "family": "Windows CryptoAPI", "desc": "Windows CryptoAPI 32-bit Service Provider"},
    {"pattern": r"(?i).*ncrypt(?:\.dll)?$", "family": "Windows CNG", "desc": "Windows CNG Key Storage Provider"},
    {"pattern": r"(?i).*libsodium.*", "family": "Sodium", "desc": "libsodium Modern Cryptographic Library"},
    {"pattern": r"(?i).*libgnutls.*", "family": "GnuTLS", "desc": "GNU Transport Layer Security Library"},
    {"pattern": r"(?i).*libwolfssl.*", "family": "wolfSSL", "desc": "wolfSSL Embedded TLS / Crypto Engine"},
    {"pattern": r"(?i).*libmbed(?:crypto|tls).*", "family": "mbedTLS", "desc": "ARM mbed TLS Embedded Cryptographic Library"},
    {"pattern": r"(?i).*liboqs.*", "family": "Open Quantum Safe", "desc": "Open Quantum Safe Post-Quantum Cryptographic Library"},
    {"pattern": r"(?i).*libbotan.*", "family": "Botan", "desc": "Botan Cryptographic Library"},
    {"pattern": r"(?i).*libtomcrypt.*", "family": "LibTomCrypt", "desc": "LibTomCrypt Modular Toolkit"},
]


def classify_crypto_library(name: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Checks if an imported library name belongs to a cryptographic suite."""
    for rule in KNOWN_CRYPTO_LIBS:
        if re.match(rule["pattern"], name):
            return True, rule["family"], rule["desc"]
    return False, None, None


class BinaryImportParser:
    """Extracts shared libraries and detects cryptographic external linkages."""

    @staticmethod
    def parse(data: bytes, filename: str = "") -> List[ImportInfo]:
        id_res = BinaryIdentifier.identify(data, filename)
        if id_res.format == BinaryFormat.ELF:
            return BinaryImportParser._parse_elf_imports(data, id_res)
        elif id_res.format == BinaryFormat.PE:
            return BinaryImportParser._parse_pe_imports(data)
        elif id_res.format == BinaryFormat.MACHO:
            return BinaryImportParser._parse_macho_imports(data, id_res)
        return []

    @staticmethod
    def _parse_elf_imports(data: bytes, id_res: Any) -> List[ImportInfo]:
        if len(data) < 52:
            return []

        endian_char = "<" if id_res.endianness == "little" else ">"
        is_64 = id_res.bits == 64

        try:
            if is_64:
                sh_offset = struct.unpack_from(endian_char + "Q", data, 40)[0]
                sh_entsize, sh_num = struct.unpack_from(endian_char + "HH", data, 58)
            else:
                sh_offset = struct.unpack_from(endian_char + "I", data, 32)[0]
                sh_entsize, sh_num = struct.unpack_from(endian_char + "HH", data, 46)
        except struct.error:
            return []

        if sh_num == 0 or sh_entsize == 0 or sh_offset + (sh_entsize * sh_num) > len(data):
            return []

        raw_sections = []
        for i in range(min(sh_num, 512)):
            base = sh_offset + i * sh_entsize
            try:
                if is_64:
                    sh_name, sh_type, sh_flags = struct.unpack_from(endian_char + "IIQ", data, base)
                    sh_addr, sh_off, sh_size, sh_link = struct.unpack_from(endian_char + "QQQI", data, base + 16)
                else:
                    sh_name, sh_type, sh_flags = struct.unpack_from(endian_char + "III", data, base)
                    sh_addr, sh_off, sh_size, sh_link = struct.unpack_from(endian_char + "IIII", data, base + 12)
                raw_sections.append((sh_type, sh_off, sh_size, sh_link))
            except struct.error:
                break

        imports: List[ImportInfo] = []
        seen: Set[str] = set()

        # Find .dynamic section (sh_type == 6: SHT_DYNAMIC)
        for sh_type, sh_off, sh_size, sh_link in raw_sections:
            if sh_type == 6:  # SHT_DYNAMIC
                # Associated dynamic string table index in sh_link
                dynstr = b""
                if 0 <= sh_link < len(raw_sections):
                    _, str_off, str_size, _ = raw_sections[sh_link]
                    if str_off + str_size <= len(data):
                        dynstr = data[str_off:str_off + str_size]

                ent_size = 16 if is_64 else 8
                count = min(sh_size // ent_size, 1024)
                for d in range(count):
                    dbase = sh_off + d * ent_size
                    try:
                        if is_64:
                            d_tag, d_val = struct.unpack_from(endian_char + "QQ", data, dbase)
                        else:
                            d_tag, d_val = struct.unpack_from(endian_char + "II", data, dbase)
                    except struct.error:
                        break

                    # DT_NEEDED = 1
                    if d_tag == 1 and dynstr and d_val < len(dynstr):
                        lib_name = dynstr[d_val:].split(b"\0", 1)[0].decode("latin-1", "replace").strip()
                        if lib_name and lib_name not in seen:
                            seen.add(lib_name)
                            is_c, fam, desc = classify_crypto_library(lib_name)
                            imports.append(
                                ImportInfo(
                                    library_name=lib_name,
                                    is_crypto=is_c,
                                    crypto_family=fam,
                                    description=desc,
                                    format="ELF",
                                )
                            )

        return imports

    @staticmethod
    def _parse_pe_imports(data: bytes) -> List[ImportInfo]:
        if len(data) < 64:
            return []

        imports: List[ImportInfo] = []
        seen: Set[str] = set()

        try:
            pe_offset = struct.unpack_from("<I", data, 60)[0]
            opt_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
            is_64 = magic == 0x20B

            dd_offset = pe_offset + 24 + (112 if is_64 else 96)
            if dd_offset + 16 > len(data):
                return []

            import_rva, import_size = struct.unpack_from("<II", data, dd_offset + 8)
            if import_rva == 0 or import_size == 0:
                return []

            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            sec_table = pe_offset + 24 + opt_hdr_size

            sections_map = []
            for i in range(min(num_sections, 128)):
                base = sec_table + i * 40
                if base + 40 > len(data):
                    break
                vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", data, base + 8)
                sections_map.append((vaddr, vsize, raw_offset, raw_size))

            def rva_to_offset(rva: int) -> Optional[int]:
                for vaddr, vsize, raw_offset, raw_size in sections_map:
                    if vaddr <= rva < vaddr + max(vsize, raw_size):
                        return raw_offset + (rva - vaddr)
                return None

            imp_off = rva_to_offset(import_rva)
            if imp_off is not None:
                for desc_idx in range(64):
                    desc_base = imp_off + desc_idx * 20
                    if desc_base + 20 > len(data):
                        break
                    ilt_rva, _, _, name_rva, iat_rva = struct.unpack_from("<IIIII", data, desc_base)
                    if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                        break

                    name_off = rva_to_offset(name_rva)
                    if name_off is not None and name_off < len(data):
                        dll_name = data[name_off:].split(b"\0", 1)[0].decode("latin-1", "replace").strip()
                        if dll_name and dll_name.lower() not in seen:
                            seen.add(dll_name.lower())
                            is_c, fam, desc = classify_crypto_library(dll_name)
                            imports.append(
                                ImportInfo(
                                    library_name=dll_name,
                                    is_crypto=is_c,
                                    crypto_family=fam,
                                    description=desc,
                                    format="PE",
                                )
                            )

        except (struct.error, IndexError):
            pass

        return imports

    @staticmethod
    def _parse_macho_imports(data: bytes, id_res: Any) -> List[ImportInfo]:
        if len(data) < 28:
            return []

        endian_char = "<" if id_res.endianness == "little" else ">"
        is_64 = id_res.bits == 64
        hdr_size = 32 if is_64 else 28

        imports: List[ImportInfo] = []
        seen: Set[str] = set()

        try:
            ncmds = struct.unpack_from(endian_char + "I", data, 16)[0]
            offset = hdr_size

            for _ in range(min(ncmds, 128)):
                if offset + 8 > len(data):
                    break
                cmd, cmdsize = struct.unpack_from(endian_char + "II", data, offset)
                # LC_LOAD_DYLIB = 0xC, LC_LOAD_WEAK_DYLIB = 0x80000018
                if cmd in (0xC, 0x80000018) and cmdsize > 24:
                    stroff = struct.unpack_from(endian_char + "I", data, offset + 8)[0]
                    if offset + stroff < len(data):
                        raw_name = data[offset + stroff:offset + cmdsize].split(b"\0", 1)[0]
                        lib_name = raw_name.decode("utf-8", "replace").split("/")[-1]
                        if lib_name and lib_name not in seen:
                            seen.add(lib_name)
                            is_c, fam, desc = classify_crypto_library(lib_name)
                            imports.append(
                                ImportInfo(
                                    library_name=lib_name,
                                    is_crypto=is_c,
                                    crypto_family=fam,
                                    description=desc,
                                    format="Mach-O",
                                )
                            )
                offset += cmdsize
                if cmdsize <= 0:
                    break
        except (struct.error, IndexError):
            pass

        return imports
