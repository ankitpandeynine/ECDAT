"""
ECDAT V4 Binary Metadata & Section Header Parser.

Pure Python parser for:
- ELF 32/64-bit section headers, entrypoint, stripped status, build-id
- PE/COFF section table, entrypoint, machine, compilation timestamp
- Mach-O load commands and segment/section headers
"""
from __future__ import annotations

from dataclasses import dataclass, field
import struct
from typing import Any, Dict, List, Optional, Tuple

from .binary_identifier import BinaryFormat, BinaryIdentifier, calculate_entropy


@dataclass
class SectionInfo:
    name: str
    offset: int
    size: int
    virtual_address: int = 0
    entropy: float = 0.0
    flags: int = 0
    is_executable: bool = False
    is_writable: bool = False
    is_readable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "offset": f"0x{self.offset:08x}",
            "size": self.size,
            "virtual_address": f"0x{self.virtual_address:08x}",
            "entropy": self.entropy,
            "is_executable": self.is_executable,
            "is_writable": self.is_writable,
        }


@dataclass
class BinaryMetadata:
    format: BinaryFormat
    architecture: str
    bits: int
    endianness: str
    entrypoint: int
    is_stripped: bool
    build_id: Optional[str] = None
    sections: List[SectionInfo] = field(default_factory=list)
    compile_time: Optional[int] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def find_section_for_offset(self, byte_offset: int) -> Optional[SectionInfo]:
        """Finds the section containing a specific raw byte offset."""
        for sec in self.sections:
            if sec.offset <= byte_offset < sec.offset + sec.size:
                return sec
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format.value,
            "architecture": self.architecture,
            "bits": self.bits,
            "endianness": self.endianness,
            "entrypoint": f"0x{self.entrypoint:08x}",
            "is_stripped": self.is_stripped,
            "build_id": self.build_id,
            "sections": [s.to_dict() for s in self.sections],
            "compile_time": self.compile_time,
            "extra": self.extra,
        }


class BinaryMetadataParser:
    """Parses structural headers and section tables from executable binaries."""

    @staticmethod
    def parse(data: bytes, filename: str = "") -> BinaryMetadata:
        id_res = BinaryIdentifier.identify(data, filename)

        if id_res.format == BinaryFormat.ELF:
            return BinaryMetadataParser._parse_elf(data, id_res)
        elif id_res.format == BinaryFormat.PE:
            return BinaryMetadataParser._parse_pe(data, id_res)
        elif id_res.format == BinaryFormat.MACHO:
            return BinaryMetadataParser._parse_macho(data, id_res)
        else:
            return BinaryMetadata(
                format=id_res.format,
                architecture=id_res.architecture,
                bits=id_res.bits,
                endianness=id_res.endianness,
                entrypoint=0,
                is_stripped=True,
                build_id=None,
                sections=[],
            )

    @staticmethod
    def _parse_elf(data: bytes, id_res: Any) -> BinaryMetadata:
        if len(data) < 52:
            return BinaryMetadata(
                format=BinaryFormat.ELF, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=0,
                is_stripped=True, sections=[]
            )

        endian_char = "<" if id_res.endianness == "little" else ">"
        is_64 = id_res.bits == 64

        entrypoint = 0
        sh_offset = 0
        sh_entsize = 0
        sh_num = 0
        sh_strndx = 0

        try:
            if is_64:
                # 64-bit ELF header
                entrypoint = struct.unpack_from(endian_char + "Q", data, 24)[0]
                sh_offset = struct.unpack_from(endian_char + "Q", data, 40)[0]
                sh_entsize, sh_num, sh_strndx = struct.unpack_from(endian_char + "HHH", data, 58)
            else:
                # 32-bit ELF header
                entrypoint = struct.unpack_from(endian_char + "I", data, 24)[0]
                sh_offset = struct.unpack_from(endian_char + "I", data, 32)[0]
                sh_entsize, sh_num, sh_strndx = struct.unpack_from(endian_char + "HHH", data, 46)
        except struct.error:
            return BinaryMetadata(
                format=BinaryFormat.ELF, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=0,
                is_stripped=True, sections=[]
            )

        if sh_num == 0 or sh_entsize == 0 or sh_offset + (sh_entsize * sh_num) > len(data):
            return BinaryMetadata(
                format=BinaryFormat.ELF, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=entrypoint,
                is_stripped=True, sections=[]
            )

        # Parse string table for section names
        sections: List[SectionInfo] = []
        raw_entries = []
        for i in range(min(sh_num, 512)):
            base = sh_offset + i * sh_entsize
            try:
                if is_64:
                    sh_name, sh_type, sh_flags = struct.unpack_from(endian_char + "IIQ", data, base)
                    sh_addr, sh_off, sh_size = struct.unpack_from(endian_char + "QQQ", data, base + 16)
                else:
                    sh_name, sh_type, sh_flags = struct.unpack_from(endian_char + "III", data, base)
                    sh_addr, sh_off, sh_size = struct.unpack_from(endian_char + "III", data, base + 12)
                raw_entries.append((sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size))
            except struct.error:
                break

        # Resolve section names via sh_strndx
        strtab = b""
        if 0 <= sh_strndx < len(raw_entries):
            _, _, _, _, str_off, str_size = raw_entries[sh_strndx]
            if str_off + str_size <= len(data):
                strtab = data[str_off:str_off + str_size]

        has_symtab = False
        build_id = None

        for sh_name_off, sh_type, sh_flags, sh_addr, sh_off, sh_size in raw_entries:
            name = ""
            if strtab and sh_name_off < len(strtab):
                name = strtab[sh_name_off:].split(b"\0", 1)[0].decode("utf-8", "replace")

            if name == ".symtab":
                has_symtab = True

            # Check for GNU build-id in .note.gnu.build-id
            if name in (".note.gnu.build-id", ".note.gnu.property") and sh_off + sh_size <= len(data):
                note_bytes = data[sh_off:sh_off + sh_size]
                if len(note_bytes) >= 16:
                    # Note format: namesz (4), descsz (4), type (4), name, desc
                    namesz, descsz, ntype = struct.unpack_from(endian_char + "III", note_bytes, 0)
                    if ntype == 3 and namesz == 4 and note_bytes[12:16] == b"GNU\0":
                        desc_off = 16
                        if desc_off + descsz <= len(note_bytes):
                            build_id = note_bytes[desc_off:desc_off + descsz].hex()

            # Skip SHT_NOBITS (type 8)
            if sh_type != 8 and sh_off + sh_size <= len(data) and sh_size > 0:
                sec_bytes = data[sh_off:sh_off + sh_size]
                sec_entropy = calculate_entropy(sec_bytes[:1024])
                is_exec = bool(sh_flags & 0x4)  # SHF_EXECINSTR
                is_write = bool(sh_flags & 0x1)  # SHF_WRITE
                is_alloc = bool(sh_flags & 0x2)  # SHF_ALLOC
                sections.append(
                    SectionInfo(
                        name=name,
                        offset=sh_off,
                        size=sh_size,
                        virtual_address=sh_addr,
                        entropy=sec_entropy,
                        flags=sh_flags,
                        is_executable=is_exec,
                        is_writable=is_write,
                        is_readable=is_alloc,
                    )
                )

        return BinaryMetadata(
            format=BinaryFormat.ELF,
            architecture=id_res.architecture,
            bits=id_res.bits,
            endianness=id_res.endianness,
            entrypoint=entrypoint,
            is_stripped=not has_symtab,
            build_id=build_id,
            sections=sections,
        )

    @staticmethod
    def _parse_pe(data: bytes, id_res: Any) -> BinaryMetadata:
        if len(data) < 64:
            return BinaryMetadata(
                format=BinaryFormat.PE, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=0,
                is_stripped=True, sections=[]
            )

        try:
            pe_offset = struct.unpack_from("<I", data, 60)[0]
            num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
            time_date_stamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
            opt_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]

            entrypoint = 0
            if opt_hdr_size >= 28:
                entrypoint = struct.unpack_from("<I", data, pe_offset + 40)[0]

            section_table_offset = pe_offset + 24 + opt_hdr_size
            sections: List[SectionInfo] = []

            for i in range(min(num_sections, 256)):
                base = section_table_offset + i * 40
                if base + 40 > len(data):
                    break
                sec_name = data[base:base + 8].rstrip(b"\0").decode("latin-1", "replace")
                vsize, vaddr, raw_size, raw_offset = struct.unpack_from("<IIII", data, base + 8)
                characteristics = struct.unpack_from("<I", data, base + 36)[0]

                if raw_offset + raw_size <= len(data) and raw_size > 0:
                    sec_bytes = data[raw_offset:raw_offset + raw_size]
                    sec_entropy = calculate_entropy(sec_bytes[:1024])
                    is_exec = bool(characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
                    is_read = bool(characteristics & 0x40000000)  # IMAGE_SCN_MEM_READ
                    is_write = bool(characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE

                    sections.append(
                        SectionInfo(
                            name=sec_name,
                            offset=raw_offset,
                            size=raw_size,
                            virtual_address=vaddr,
                            entropy=sec_entropy,
                            flags=characteristics,
                            is_executable=is_exec,
                            is_writable=is_write,
                            is_readable=is_read,
                        )
                    )

            return BinaryMetadata(
                format=BinaryFormat.PE,
                architecture=id_res.architecture,
                bits=id_res.bits,
                endianness="little",
                entrypoint=entrypoint,
                is_stripped=True,  # PE standard releases typically strip debug syms
                build_id=None,
                sections=sections,
                compile_time=time_date_stamp,
            )
        except (struct.error, IndexError):
            return BinaryMetadata(
                format=BinaryFormat.PE, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=0,
                is_stripped=True, sections=[]
            )

    @staticmethod
    def _parse_macho(data: bytes, id_res: Any) -> BinaryMetadata:
        if len(data) < 28:
            return BinaryMetadata(
                format=BinaryFormat.MACHO, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=0,
                is_stripped=True, sections=[]
            )

        endian_char = "<" if id_res.endianness == "little" else ">"
        is_64 = id_res.bits == 64
        hdr_size = 32 if is_64 else 28

        try:
            ncmds = struct.unpack_from(endian_char + "I", data, 16)[0]
            sections: List[SectionInfo] = []
            offset = hdr_size

            for _ in range(min(ncmds, 128)):
                if offset + 8 > len(data):
                    break
                cmd, cmdsize = struct.unpack_from(endian_char + "II", data, offset)
                # LC_SEGMENT (0x1) or LC_SEGMENT_64 (0x19)
                if cmd in (0x1, 0x19):
                    segname = data[offset + 8:offset + 24].rstrip(b"\0").decode("latin-1", "replace")
                    if is_64:
                        vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian_char + "QQQQ", data, offset + 24)
                        nsects = struct.unpack_from(endian_char + "I", data, offset + 64)[0]
                        sect_base = offset + 72
                        sect_size = 80
                    else:
                        vmaddr, vmsize, fileoff, filesize = struct.unpack_from(endian_char + "IIII", data, offset + 24)
                        nsects = struct.unpack_from(endian_char + "I", data, offset + 48)[0]
                        sect_base = offset + 56
                        sect_size = 68

                    for s in range(min(nsects, 64)):
                        sb = sect_base + s * sect_size
                        if sb + sect_size > len(data):
                            break
                        sectname = data[sb:sb + 16].rstrip(b"\0").decode("latin-1", "replace")
                        if is_64:
                            s_addr, s_size, s_off = struct.unpack_from(endian_char + "QQI", data, sb + 32)
                        else:
                            s_addr, s_size, s_off = struct.unpack_from(endian_char + "III", data, sb + 32)

                        if s_off + s_size <= len(data) and s_size > 0:
                            sections.append(
                                SectionInfo(
                                    name=f"{segname},{sectname}",
                                    offset=s_off,
                                    size=s_size,
                                    virtual_address=s_addr,
                                    entropy=calculate_entropy(data[s_off:s_off + min(s_size, 1024)]),
                                    is_executable="text" in sectname.lower(),
                                )
                            )
                offset += cmdsize
                if cmdsize <= 0:
                    break

            return BinaryMetadata(
                format=BinaryFormat.MACHO,
                architecture=id_res.architecture,
                bits=id_res.bits,
                endianness=id_res.endianness,
                entrypoint=0,
                is_stripped=True,
                sections=sections,
            )
        except (struct.error, IndexError):
            return BinaryMetadata(
                format=BinaryFormat.MACHO, architecture=id_res.architecture,
                bits=id_res.bits, endianness=id_res.endianness, entrypoint=0,
                is_stripped=True, sections=[]
            )
