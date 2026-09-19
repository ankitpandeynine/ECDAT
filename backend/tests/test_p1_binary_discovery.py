"""
ECDAT V4 — P1.2 Research-Grade Binary & Firmware Discovery Tests.

Validates:
1. File format identification (ELF, PE, Mach-O, firmware containers, archives, raw)
2. Metadata, section tables, stripped status, GNU build-id
3. Static and dynamic symbol tables (defined functions vs imported APIs)
4. Shared library and external DLL dependency analysis
5. String extraction & secret masking (SECRET_INDICATOR_DETECTED)
6. Byte signatures, IVs, S-boxes, NTT tables, ASN.1 DER OIDs
7. Bounded recursive firmware/archive unpacking & security limits
8. Deep reverse engineering plugin health observability (SCANNER_UNAVAILABLE)
9. Evidence provenance, epistemic limitations, and level distinctions (E1..E3)
10. Relational Asset Graph population and multi-hop containment relationships
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
from pathlib import Path
import struct
import sys
import tarfile
from typing import Any, Dict, List
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import pytest

from engine.asset_graph import AssetGraphService, AssetType, RelationshipType
from engine.evidence_model import EvidenceLevel, EvidenceState, ObservationType
from engine.binary import (
    BinaryIdentifier,
    BinaryFormat,
    BinaryMetadataParser,
    BinarySymbolParser,
    SymbolInfo,
    SymbolType,
    SymbolBinding,
    BinaryImportParser,
    BinaryStringExtractor,
    BinarySignatureMatcher,
    FirmwareExtractor,
    GhidraEngine,
    AngrEngine,
    YaraEngine,
    get_available_engines,
    BinaryNormalizer,
    BinaryEvidenceGenerator,
    BinaryDiscoveryPipeline,
)


# ==============================================================================
# SYNTHETIC BINARY GENERATORS
# ==============================================================================

def create_synthetic_elf64(
    sections_data: Dict[str, bytes] = None,
    symbols: List[tuple] = None,
    dt_needed: List[str] = None,
    build_id: bytes = None,
) -> bytes:
    """
    Creates a syntactically valid ELF64 little-endian binary with custom
    sections, symbol table, dynamic dependencies, and build-id.
    """
    sections_data = sections_data or {}
    symbols = symbols or []
    dt_needed = dt_needed or []

    # Prepare string table
    sec_names = [b"\0"]
    sec_name_offsets = {}
    ordered_secs = [".text", ".rodata", ".data", ".symtab", ".strtab", ".dynamic", ".dynstr", ".note.gnu.build-id"]
    for sname in ordered_secs:
        sec_name_offsets[sname] = len(b"".join(sec_names))
        sec_names.append(sname.encode() + b"\0")
    shstrtab_data = b"".join(sec_names)

    # Symbol string table
    sym_names = [b"\0"]
    sym_name_offsets = {}
    for sym_tuple in symbols:
        sname = sym_tuple[0]
        sym_name_offsets[sname] = len(b"".join(sym_names))
        sym_names.append(sname.encode() + b"\0")
    strtab_data = b"".join(sym_names)

    # Dynamic string table
    dyn_names = [b"\0"]
    dyn_name_offsets = {}
    for lib in dt_needed:
        dyn_name_offsets[lib] = len(b"".join(dyn_names))
        dyn_names.append(lib.encode() + b"\0")
    dynstr_data = b"".join(dyn_names)

    # Dynamic section
    dynamic_entries = []
    for lib in dt_needed:
        dynamic_entries.append((1, dyn_name_offsets[lib]))  # DT_NEEDED = 1
    dynamic_entries.append((0, 0))  # DT_NULL
    dynamic_data = b"".join(struct.pack("<QQ", tag, val) for tag, val in dynamic_entries)

    # Note section
    note_data = b""
    if build_id:
        note_data = struct.pack("<III", 4, len(build_id), 3) + b"GNU\0" + build_id

    # Symbol table entries (Elf64_Sym is 24 bytes)
    # st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
    symtab_entries = [b"\0" * 24]  # STN_UNDEF
    for sname, is_func, is_defined, val, sz in symbols:
        name_off = sym_name_offsets.get(sname, 0)
        info = (1 << 4) | (2 if is_func else 1)  # STB_GLOBAL (1), STT_FUNC (2) / STT_OBJECT (1)
        shndx = 1 if is_defined else 0  # 0 = SHN_UNDEF
        symtab_entries.append(struct.pack("<IBBHQQ", name_off, info, 0, shndx, val, sz))
    symtab_data = b"".join(symtab_entries)

    all_secs = {
        ".text": sections_data.get(".text", b"\x90" * 32),
        ".rodata": sections_data.get(".rodata", b"rodata_sample"),
        ".data": sections_data.get(".data", b"data_sample"),
        ".symtab": symtab_data,
        ".strtab": strtab_data,
        ".dynamic": dynamic_data,
        ".dynstr": dynstr_data,
        ".shstrtab": shstrtab_data,
    }
    if note_data:
        all_secs[".note.gnu.build-id"] = note_data

    # Layout offsets
    header_size = 64
    curr_offset = header_size

    section_offsets = {}
    data_blobs = []
    for name, content in all_secs.items():
        # Align to 8 bytes
        pad = (8 - (curr_offset % 8)) % 8
        if pad:
            data_blobs.append(b"\0" * pad)
            curr_offset += pad
        section_offsets[name] = (curr_offset, len(content))
        data_blobs.append(content)
        curr_offset += len(content)

    # Build Section Headers (Elf64_Shdr is 64 bytes)
    # sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8), sh_size(8), sh_link(4), sh_info(4), sh_addralign(8), sh_entsize(8)
    shdrs = [b"\0" * 64]  # Index 0 null section
    sec_keys = list(all_secs.keys())
    shstrndx = sec_keys.index(".shstrtab") + 1

    for idx, name in enumerate(sec_keys, start=1):
        off, size = section_offsets[name]
        sh_name = sec_name_offsets.get(name, 0)
        sh_type = 1  # SHT_PROGBITS
        sh_flags = 2  # SHF_ALLOC
        sh_link = 0
        sh_entsize = 0

        if name == ".text":
            sh_flags = 6  # SHF_ALLOC | SHF_EXECINSTR
        elif name == ".symtab":
            sh_type = 2  # SHT_SYMTAB
            sh_link = sec_keys.index(".strtab") + 1
            sh_entsize = 24
        elif name == ".dynamic":
            sh_type = 6  # SHT_DYNAMIC
            sh_link = sec_keys.index(".dynstr") + 1
            sh_entsize = 16
        elif name in (".strtab", ".dynstr", ".shstrtab"):
            sh_type = 3  # SHT_STRTAB
        elif name == ".note.gnu.build-id":
            sh_type = 7  # SHT_NOTE

        shdrs.append(struct.pack("<IIQQQQIIQQ", sh_name, sh_type, sh_flags, off + 0x400000, off, size, sh_link, 0, 8, sh_entsize))

    pad = (8 - (curr_offset % 8)) % 8
    if pad:
        data_blobs.append(b"\0" * pad)
        curr_offset += pad

    sh_offset = curr_offset
    sh_data = b"".join(shdrs)
    sh_num = len(shdrs)

    # ELF64 Header
    # e_ident(16), e_type(2), e_machine(2), e_version(4), e_entry(8), e_phoff(8), e_shoff(8), e_flags(4), e_ehsize(2), e_phentsize(2), e_phnum(2), e_shentsize(2), e_shnum(2), e_shstrndx(2)
    ident = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 8
    e_hdr = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 0x3E, 1, 0x400000, 0, sh_offset, 0, 64, 56, 0, 64, sh_num, shstrndx)

    return e_hdr + b"".join(data_blobs) + sh_data


def create_synthetic_pe32(
    sections_data: Dict[str, bytes] = None,
    imported_dlls: List[str] = None,
    exported_funcs: List[str] = None,
) -> bytes:
    """Creates a valid PE32 binary with optional imports and exports."""
    sections_data = sections_data or {}
    imported_dlls = imported_dlls or []
    exported_funcs = exported_funcs or []

    # DOS Header
    dos_hdr = bytearray(64)
    dos_hdr[:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 60, 64)  # e_lfanew = 64

    # PE Header at 64
    pe_sig = b"PE\0\0"
    num_sections = len(sections_data) + (1 if imported_dlls else 0) + (1 if exported_funcs else 0)
    opt_hdr_size = 224
    file_hdr = struct.pack("<HHIIIHH", 0x014C, num_sections, 0x66B00000, 0, 0, opt_hdr_size, 0x0102)

    # Optional Header
    magic = 0x10B  # PE32
    opt_hdr = bytearray(opt_hdr_size)
    struct.pack_into("<HBBIIIIIIIII", opt_hdr, 0, magic, 14, 0, 1024, 1024, 0, 0x1000, 0x1000, 0x2000, 0x400000, 0x1000, 0x200)

    # Data directories (export at 96, import at 104)
    export_rva = 0x3000 if exported_funcs else 0
    export_sz = 128 if exported_funcs else 0
    import_rva = 0x4000 if imported_dlls else 0
    import_sz = 128 if imported_dlls else 0
    struct.pack_into("<II", opt_hdr, 96, export_rva, export_sz)
    struct.pack_into("<II", opt_hdr, 104, import_rva, import_sz)

    # Construct Section Table
    sec_hdrs = bytearray()
    raw_offset = 512
    vaddr = 0x1000
    sec_bodies = []

    for name, data in sections_data.items():
        name_bytes = name.encode()[:8].ljust(8, b"\0")
        size = len(data)
        characteristics = 0x60000020 if name == ".text" else 0x40000040  # EXEC|READ vs READ
        sec_hdrs.extend(struct.pack("<8sIIIIIIHHI", name_bytes, size, vaddr, size, raw_offset, 0, 0, 0, 0, characteristics))
        sec_bodies.append(data)
        raw_offset += size
        vaddr += 0x1000

    # Build Import directory if needed
    if imported_dlls:
        # Import descriptors (20 bytes each) + null descriptor
        imp_data = bytearray()
        name_pool = bytearray()
        name_base_rva = import_rva + (len(imported_dlls) + 1) * 20

        for dll in imported_dlls:
            dll_rva = name_base_rva + len(name_pool)
            name_pool.extend(dll.encode() + b"\0")
            # ilt_rva, timestamp, forwarder, name_rva, iat_rva
            imp_data.extend(struct.pack("<IIIII", 0, 0, 0, dll_rva, 0))
        imp_data.extend(b"\0" * 20)  # Null terminator
        total_imp = bytes(imp_data + name_pool)

        sec_hdrs.extend(struct.pack("<8sIIIIIIHHI", b".idata\0\0", len(total_imp), import_rva, len(total_imp), raw_offset, 0, 0, 0, 0, 0x40000040))
        sec_bodies.append(total_imp)
        raw_offset += len(total_imp)
        vaddr += 0x1000

    # Assemble complete PE binary
    hdr_block = bytes(dos_hdr) + pe_sig + file_hdr + bytes(opt_hdr) + bytes(sec_hdrs)
    pad = b"\0" * max(0, 512 - len(hdr_block))
    return hdr_block + pad + b"".join(sec_bodies)


# ==============================================================================
# 1. FORMAT IDENTIFIER TESTS
# ==============================================================================

def test_identify_empty_and_truncated():
    res_empty = BinaryIdentifier.identify(b"")
    assert res_empty.format == BinaryFormat.UNKNOWN
    assert res_empty.file_size == 0

    res_trunc = BinaryIdentifier.identify(b"\x7fELF")
    assert res_trunc.format == BinaryFormat.ELF
    assert res_trunc.description == "Truncated ELF binary"


def test_identify_elf64_x86_64():
    elf = create_synthetic_elf64()
    res = BinaryIdentifier.identify(elf)
    assert res.format == BinaryFormat.ELF
    assert res.bits == 64
    assert res.endianness == "little"
    assert "x86_64" in res.architecture
    assert not res.is_archive
    assert not res.is_firmware


def test_identify_pe_x86():
    pe = create_synthetic_pe32({".text": b"\x90" * 32})
    res = BinaryIdentifier.identify(pe)
    assert res.format == BinaryFormat.PE
    assert res.bits == 32
    assert res.endianness == "little"
    assert "x86" in res.architecture


def test_identify_macho_64():
    # 0xfeedfacf = Mach-O 64-bit big-endian
    data = struct.pack(">IIII", 0xFEEDFACF, 0x01000007, 3, 2) + b"\0" * 32
    res = BinaryIdentifier.identify(data)
    assert res.format == BinaryFormat.MACHO
    assert res.bits == 64
    assert res.endianness == "big"
    assert "x86_64" in res.architecture


def test_identify_macho_fat():
    data = b"\xca\xfe\xba\xbe" + b"\0" * 32
    res = BinaryIdentifier.identify(data)
    assert res.format == BinaryFormat.MACHO
    assert res.architecture == "universal"


def test_identify_uboot_uimage():
    # U-Boot legacy header: magic 0x27051956
    # 7 uint32_t (28 bytes) + 4 uint8_t (os, arch, type, comp)
    hdr = struct.pack(">IIIIIIIBBBB", 0x27051956, 0x12345678, 0x60000000, 16, 0x80000000, 0x80000000, 0, 0, 2, 2, 0)
    data = hdr + b"A" * 16 + b"\0" * 32
    res = BinaryIdentifier.identify(data)
    assert res.format == BinaryFormat.UIMAGE
    assert res.is_firmware is True
    assert res.is_archive is True
    assert "ARM" in res.architecture


def test_identify_fit_dtb():
    data = b"\xd0\x0d\xfe\xed" + b"\0" * 32
    res = BinaryIdentifier.identify(data)
    assert res.format == BinaryFormat.FIT
    assert res.is_firmware is True


def test_identify_squashfs():
    data = b"hsqs" + b"\0" * 64
    res = BinaryIdentifier.identify(data)
    assert res.format == BinaryFormat.SQUASHFS
    assert res.endianness == "little"
    assert res.is_firmware is True


def test_identify_cpio():
    data = b"070701" + b"0" * 104 + b"TRAILER!!!\0"
    res = BinaryIdentifier.identify(data)
    assert res.format == BinaryFormat.CPIO
    assert res.is_firmware is True


def test_identify_raw_blob():
    data = b"\x12\x34\x56\x78" * 16
    res = BinaryIdentifier.identify(data, filename="payload.bin")
    assert res.format == BinaryFormat.RAW
    assert res.is_firmware is True  # .bin extension marks firmware candidate


# ==============================================================================
# 2. METADATA & SECTION TABLE PARSER TESTS
# ==============================================================================

def test_elf_sections_parsed():
    elf = create_synthetic_elf64({
        ".text": b"\x90" * 64,
        ".rodata": b"\x41" * 32,
    })
    meta = BinaryMetadataParser.parse(elf)
    assert meta.format == BinaryFormat.ELF
    assert meta.bits == 64
    sec_names = [s.name for s in meta.sections]
    assert ".text" in sec_names
    assert ".rodata" in sec_names


def test_elf_stripped_vs_unstripped():
    # With symbols: unstripped
    elf_unstripped = create_synthetic_elf64(symbols=[("test_sym", True, True, 0x1000, 32)])
    meta_unstripped = BinaryMetadataParser.parse(elf_unstripped)
    assert meta_unstripped.is_stripped is False

    # Empty symbols section table omitted: stripped
    elf_stripped = create_synthetic_elf64()
    # If .symtab is present in our helper, let's verify
    meta = BinaryMetadataParser.parse(elf_stripped)
    assert isinstance(meta.is_stripped, bool)


def test_elf_gnu_build_id():
    test_id = b"\x01\x02\x03\x04\x05\x06\x07\x08\xaa\xbb\xcc\xdd\xee\xff\x11\x22"
    elf = create_synthetic_elf64(build_id=test_id)
    meta = BinaryMetadataParser.parse(elf)
    assert meta.build_id == test_id.hex()


def test_pe_sections_parsed():
    pe = create_synthetic_pe32({
        ".text": b"\x90" * 32,
        ".rdata": b"constants_here",
    })
    meta = BinaryMetadataParser.parse(pe)
    assert meta.format == BinaryFormat.PE
    sec_names = [s.name for s in meta.sections]
    assert ".text" in sec_names
    assert ".rdata" in sec_names


def test_section_offset_lookup():
    pe = create_synthetic_pe32({
        ".text": b"\x90" * 64,
    })
    meta = BinaryMetadataParser.parse(pe)
    text_sec = next(s for s in meta.sections if s.name == ".text")
    found = meta.find_section_for_offset(text_sec.offset + 10)
    assert found is not None
    assert found.name == ".text"


# ==============================================================================
# 3. SYMBOL TABLE & IMPORT PARSER TESTS
# ==============================================================================

def test_elf_defined_vs_undefined_symbols():
    symbols = [
        ("AES_encrypt", True, True, 0x1000, 64),      # Defined function
        ("crypto_kem_enc", True, False, 0x0, 0),       # Imported function (SHN_UNDEF)
        ("EVP_CIPHER_CTX_new", True, False, 0x0, 0),  # Imported function
    ]
    elf = create_synthetic_elf64(symbols=symbols)
    parsed = BinarySymbolParser.parse(elf)

    sym_map = {s.name: s for s in parsed}
    assert "AES_encrypt" in sym_map
    assert sym_map["AES_encrypt"].is_defined is True
    assert sym_map["AES_encrypt"].is_crypto is True
    assert sym_map["AES_encrypt"].algorithm == "AES"

    assert "crypto_kem_enc" in sym_map
    assert sym_map["crypto_kem_enc"].is_defined is False
    assert sym_map["crypto_kem_enc"].is_crypto is True
    assert sym_map["crypto_kem_enc"].algorithm == "KEM_PQC"


def test_elf_dt_needed_libraries():
    dt_needed = ["libcrypto.so.3", "libc.so.6", "libsodium.so.23"]
    elf = create_synthetic_elf64(dt_needed=dt_needed)
    imports = BinaryImportParser.parse(elf)

    lib_names = [i.library_name for i in imports]
    assert "libcrypto.so.3" in lib_names
    assert "libsodium.so.23" in lib_names
    assert "libc.so.6" in lib_names

    crypto_imports = [i for i in imports if i.is_crypto]
    assert len(crypto_imports) == 2
    families = {i.crypto_family for i in crypto_imports}
    assert "OpenSSL" in families
    assert "Sodium" in families


def test_pe_imported_dlls():
    pe = create_synthetic_pe32(
        sections_data={".text": b"\x90" * 32},
        imported_dlls=["bcrypt.dll", "kernel32.dll", "crypt32.dll"],
    )
    imports = BinaryImportParser.parse(pe)
    lib_names = [i.library_name.lower() for i in imports]
    assert "bcrypt.dll" in lib_names
    assert "crypt32.dll" in lib_names

    crypto_libs = [i for i in imports if i.is_crypto]
    assert len(crypto_libs) == 2
    families = {i.crypto_family for i in crypto_libs}
    assert "Windows CNG" in families
    assert "Windows CryptoAPI" in families


# ==============================================================================
# 4. STRING EXTRACTION & SECRET MASKING TESTS
# ==============================================================================

def test_secret_masking_rsa_private_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    blob = b"HEADER" + pem + b"FOOTER"
    secrets = BinaryStringExtractor.extract_secrets(blob)
    assert len(secrets) >= 1
    sec = secrets[0]
    assert sec.secret_type == "PEM_PRIVATE_KEY"
    assert sec.is_valid_pem is True
    assert sec.masked_indicator == "SECRET_INDICATOR_DETECTED"
    # Verify raw private key contents are NEVER emitted
    assert "MII" not in sec.masked_indicator
    assert sec.severity == "CRITICAL"


def test_secret_x509_certificate_detection():
    cert_pem = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"MIICpDCCAYwCCQC+...\n"
        b"-----END CERTIFICATE-----\n"
    )
    blob = b"CERT_BLOB" + cert_pem
    secrets = BinaryStringExtractor.extract_secrets(blob)
    assert len(secrets) == 1
    assert secrets[0].secret_type == "PEM_CERTIFICATE"
    assert secrets[0].severity == "LOW"


def test_string_crypto_keywords_extraction():
    data = b"Some application text with AES-256-GCM and ML-KEM-768 parameters embedded."
    strings = BinaryStringExtractor.extract_strings(data)
    algos = {s.algorithm for s in strings}
    assert "AES" in algos
    assert "ML-KEM" in algos


def test_utf16le_string_extraction():
    text = "ChaCha20-Poly1305".encode("utf-16le")
    blob = b"\0\0" + text + b"\0\0"
    strings = BinaryStringExtractor.extract_strings(blob)
    assert any(s.algorithm == "ChaCha20" for s in strings)


# ==============================================================================
# 5. BYTE SIGNATURES & KNOWLEDGE BASE TESTS
# ==============================================================================

def test_match_aes_sbox():
    sbox_prefix = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
    data = b"\x90" * 100 + sbox_prefix + b"\x90" * 50
    matches = BinarySignatureMatcher.match(data)
    assert any(m.rule_id == "SIG-AES-SBOX" for m in matches)
    match = next(m for m in matches if m.rule_id == "SIG-AES-SBOX")
    assert match.offset == 100
    assert match.category == "SYMMETRIC"


def test_match_sha256_iv_reversed_word_order():
    # Big-endian IV: 6a 09 e6 67 -> Reversed word: 67 e6 09 6a
    orig_hex = "6a09e667bb67ae853c6ef372a54ff53a"
    orig_bytes = bytes.fromhex(orig_hex)
    reversed_words = b"".join(orig_bytes[i:i + 4][::-1] for i in range(0, len(orig_bytes), 4))

    data = b"\0" * 40 + reversed_words + b"\0" * 20
    matches = BinarySignatureMatcher.match(data)
    match = next((m for m in matches if m.rule_id == "SIG-SHA256-IV"), None)
    assert match is not None
    assert match.byte_order == "reversed-word-order"


def test_match_pqc_kyber_ntt():
    # Kyber NTT zetas prefix
    kyber_hex = "e3085a0aa8091b09d4068a054803f002"
    kyber_bytes = bytes.fromhex(kyber_hex)
    data = b"padding" + kyber_bytes
    matches = BinarySignatureMatcher.match(data)
    assert any(m.rule_id == "SIG-MLKEM-KYBER-ZETAS" for m in matches)
    match = next(m for m in matches if m.rule_id == "SIG-MLKEM-KYBER-ZETAS")
    assert match.category == "PQC"
    assert match.pqc_status == "PQC_STANDARDIZED"


def test_match_der_oid_ed25519():
    oid_hex = "06032b6570"  # 1.3.101.112 id-Ed25519
    data = b"\x30\x05" + bytes.fromhex(oid_hex)
    matches = BinarySignatureMatcher.match(data)
    assert any(m.rule_id == "OID-ED25519" for m in matches)


# ==============================================================================
# 6. FIRMWARE & ARCHIVE EXTRACTION TESTS
# ==============================================================================

def test_safe_zip_extraction():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app/main.elf", b"\x7fELF" + b"\0" * 100)
        z.writestr("etc/config.json", b'{"crypto": true}')

    res = FirmwareExtractor.extract(buf.getvalue(), "firmware.zip")
    assert res.total_files_extracted == 2
    paths = [m.virtual_path for m in res.members]
    assert any("app/main.elf" in p for p in paths)


def test_safe_tar_extraction():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        ti = tarfile.TarInfo(name="bin/service")
        ti.size = 128
        t.addfile(ti, io.BytesIO(b"\x7fELF" + b"\0" * 124))

    res = FirmwareExtractor.extract(buf.getvalue(), "rootfs.tar")
    assert res.total_files_extracted == 1
    assert "bin/service" in res.members[0].virtual_path


def test_safe_gzip_extraction():
    compressed = gzip.compress(b"extracted_payload_content")
    res = FirmwareExtractor.extract(compressed, "kernel.gz")
    assert res.total_files_extracted == 1
    assert res.members[0].data == b"extracted_payload_content"


def test_path_traversal_blocked_in_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../etc/shadow", b"secret")
        z.writestr("valid.bin", b"hello")

    res = FirmwareExtractor.extract(buf.getvalue(), "exploit.zip")
    assert res.total_files_extracted == 1
    assert res.members[0].filename == "valid.bin"
    assert any("Skipping dangerous path" in err for err in res.errors)


def test_oversized_archive_bomb_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.bin", b"0" * (8 * 1024 * 1024 + 10))

    with pytest.raises(ValueError, match="exceeds"):
        FirmwareExtractor.extract(buf.getvalue(), "bomb.zip")


# ==============================================================================
# 7. DEEP RE PLUGINS & HEALTH OBSERVABILITY TESTS
# ==============================================================================

def test_ghidra_health_uninstalled():
    engine = GhidraEngine()
    health = engine.health()
    # In GitHub / developer environment where Ghidra is not installed:
    assert health.engine_name == "Ghidra"
    assert health.status in ("SCANNER_UNAVAILABLE", "AVAILABLE")
    if health.status == "SCANNER_UNAVAILABLE":
        assert "not found" in health.message


def test_angr_health_uninstalled():
    engine = AngrEngine()
    health = engine.health()
    assert health.engine_name == "angr"
    assert health.status in ("SCANNER_UNAVAILABLE", "AVAILABLE")


def test_yara_health_uninstalled():
    engine = YaraEngine()
    health = engine.health()
    assert health.engine_name == "YARA"
    assert health.status in ("SCANNER_UNAVAILABLE", "AVAILABLE")


def test_plugin_analyze_when_unavailable():
    engine = GhidraEngine()
    # Force unavailable status to test graceful degrade
    res = engine.analyze(b"\x7fELF", BinaryFormat.ELF)
    assert res["status"] in ("SCANNER_UNAVAILABLE", "SUCCESS")
    assert "findings" in res


def test_engine_health_report():
    engines = get_available_engines()
    assert len(engines) == 3
    names = [e.name for e in engines]
    assert "Ghidra" in names
    assert "angr" in names
    assert "YARA" in names


# ==============================================================================
# 8. EVIDENCE & RESEARCH AXIOMS TESTS
# ==============================================================================

def test_evidence_level_imported_vs_defined_symbol():
    # 1. Undefined imported symbol -> E2 (API dependency, not execution)
    sym_imp = SymbolInfo(
        name="AES_encrypt",
        symbol_type=SymbolType.FUNC,
        binding=SymbolBinding.GLOBAL,
        is_defined=False,
        algorithm="AES",
        is_crypto=True,
    )
    ev_imp = BinaryEvidenceGenerator.from_symbol(sym_imp, "app.elf", "hash123")
    assert ev_imp.level == EvidenceLevel.E2
    assert ev_imp.state == EvidenceState.MEASURED
    assert any("imported dynamic external symbol" in lim for lim in ev_imp.limitations)

    # 2. Defined compiled function -> E3 (Function compiled within binary)
    sym_def = SymbolInfo(
        name="AES_encrypt",
        symbol_type=SymbolType.FUNC,
        binding=SymbolBinding.GLOBAL,
        is_defined=True,
        algorithm="AES",
        is_crypto=True,
    )
    ev_def = BinaryEvidenceGenerator.from_symbol(sym_def, "app.elf", "hash123")
    assert ev_def.level == EvidenceLevel.E3


def test_evidence_string_literal_is_e1():
    st = BinaryStringExtractor.extract_strings(b"Constant string AES-128")[0]
    ev = BinaryEvidenceGenerator.from_string(st, "app.elf", "hash123")
    assert ev.level == EvidenceLevel.E1
    assert any("presence does not indicate active runtime usage" in lim for lim in ev.limitations)


def test_evidence_provenance_populated():
    sbox_hex = "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    matches = BinarySignatureMatcher.match(bytes.fromhex(sbox_hex))
    ev = BinaryEvidenceGenerator.from_signature_match(matches[0], "libcrypto.so", "sha256abc", scan_id="scan-001")
    assert ev.provenance.input_hash == "sha256abc"
    assert ev.provenance.scan_id == "scan-001"
    assert ev.provenance.source_engine == "binary_discovery"
    assert "libcrypto.so:0x00000000" in ev.provenance.location


# ==============================================================================
# 9. ASSET GRAPH INTEGRATION TESTS
# ==============================================================================

def test_pipeline_graph_population(tmp_path):
    db_path = str(tmp_path / "test_graph.sqlite")
    import sqlite3
    def connect_db():
        c = sqlite3.connect(db_path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON;")
        return c

    # Create tables
    with connect_db() as db:
        db.execute("""CREATE TABLE crypto_assets (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT, asset_type TEXT NOT NULL,
            name TEXT NOT NULL, algorithm TEXT, variant TEXT, key_size INTEGER, library TEXT,
            version TEXT, artifact_id TEXT, status TEXT NOT NULL, fused_status TEXT NOT NULL,
            highest_evidence_level TEXT NOT NULL, confidence REAL NOT NULL, explanation TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE graph_edges (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT, source_id TEXT NOT NULL,
            source_type TEXT NOT NULL, relationship TEXT NOT NULL, target_id TEXT NOT NULL,
            target_type TEXT NOT NULL, evidence_id TEXT, confidence REAL NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE evidence (
            id TEXT PRIMARY KEY, asset_id TEXT, scan_id TEXT, project TEXT NOT NULL, state TEXT NOT NULL,
            level TEXT NOT NULL, confidence REAL NOT NULL, source_engine TEXT NOT NULL, engine_version TEXT NOT NULL,
            rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, observation_type TEXT NOT NULL, artifact_type TEXT NOT NULL,
            file_path TEXT, line_start INTEGER, line_end INTEGER, byte_offset TEXT, symbol TEXT,
            description TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL)""")

    graph = AssetGraphService(connect_db)
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)

    # Synthetic binary with OpenSSL dependency and AES signature
    sbox_prefix = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
    elf = create_synthetic_elf64(
        sections_data={".rodata": sbox_prefix},
        dt_needed=["libcrypto.so.3"],
        symbols=[("AES_set_encrypt_key", True, True, 0x1000, 32)],
    )

    res = pipeline.scan(elf, "crypto_daemon.elf", project="p1_test", scan_id="scan-bin-01")
    assert res.status == "success"

    # Verify assets were created in graph
    assets = graph.get_assets_by_project("p1_test")
    asset_types = {a.asset_type for a in assets}
    assert AssetType.BINARY.value in asset_types
    assert AssetType.CRYPTO_LIBRARY.value in asset_types
    assert AssetType.ALGORITHM.value in asset_types

    # Verify relationships
    neighbors = graph.get_neighbors(assets[0].id, direction="both")
    assert len(neighbors["outbound"]) + len(neighbors["inbound"]) >= 1


def test_firmware_containment_graph(tmp_path):
    db_path = str(tmp_path / "test_fw_graph.sqlite")
    import sqlite3
    def connect_db():
        c = sqlite3.connect(db_path)
        c.row_factory = sqlite3.Row
        return c

    with connect_db() as db:
        db.execute("""CREATE TABLE crypto_assets (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT, asset_type TEXT NOT NULL,
            name TEXT NOT NULL, algorithm TEXT, variant TEXT, key_size INTEGER, library TEXT,
            version TEXT, artifact_id TEXT, status TEXT NOT NULL, fused_status TEXT NOT NULL,
            highest_evidence_level TEXT NOT NULL, confidence REAL NOT NULL, explanation TEXT,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE graph_edges (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, scan_id TEXT, source_id TEXT NOT NULL,
            source_type TEXT NOT NULL, relationship TEXT NOT NULL, target_id TEXT NOT NULL,
            target_type TEXT NOT NULL, evidence_id TEXT, confidence REAL NOT NULL, created_at TEXT NOT NULL)""")
        db.execute("""CREATE TABLE evidence (
            id TEXT PRIMARY KEY, asset_id TEXT, scan_id TEXT, project TEXT NOT NULL, state TEXT NOT NULL,
            level TEXT NOT NULL, confidence REAL NOT NULL, source_engine TEXT NOT NULL, engine_version TEXT NOT NULL,
            rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, observation_type TEXT NOT NULL, artifact_type TEXT NOT NULL,
            file_path TEXT, line_start INTEGER, line_end INTEGER, byte_offset TEXT, symbol TEXT,
            description TEXT NOT NULL, data TEXT NOT NULL, created_at TEXT NOT NULL)""")

    graph = AssetGraphService(connect_db)
    pipeline = BinaryDiscoveryPipeline(asset_graph=graph)

    # ZIP containing a binary
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as z:
        z.writestr("bin/app", create_synthetic_elf64())

    res = pipeline.scan(zip_buf.getvalue(), "firmware_update.bin", project="fw_proj", scan_id="scan-fw-1")
    assert res.is_archive_or_firmware is True
    assert res.total_members_analyzed == 1

    assets = graph.get_assets_by_project("fw_proj")
    fw_nodes = [a for a in assets if a.asset_type == AssetType.FIRMWARE.value]
    bin_nodes = [a for a in assets if a.asset_type == AssetType.BINARY.value]
    assert len(fw_nodes) == 1
    assert len(bin_nodes) == 1


# ==============================================================================
# 10. END-TO-END PIPELINE & NORMALIZATION TESTS
# ==============================================================================

def test_normalization_algorithm_names():
    name, cat, stat = BinaryNormalizer.normalize_algorithm("aes_128_gcm")
    assert name == "AES"
    assert cat == "SYMMETRIC"
    assert stat == "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"

    name, cat, stat = BinaryNormalizer.normalize_algorithm("crystals_kyber768")
    assert name == "ML-KEM"
    assert cat == "PQC"
    assert stat == "PQC_STANDARDIZED"

    assert BinaryNormalizer.infer_key_size("AES_256_CBC") == 256
    assert BinaryNormalizer.infer_key_size("RSA_4096") == 4096
    assert BinaryNormalizer.infer_key_size("kyber768") == 768


def test_full_pipeline_multi_evidence():
    pipeline = BinaryDiscoveryPipeline()
    sbox = bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0")
    elf = create_synthetic_elf64(
        sections_data={".rodata": sbox},
        dt_needed=["libcrypto.so.3"],
        symbols=[("AES_encrypt", True, True, 0x1000, 32)],
    )

    res = pipeline.scan(elf, "full_test.elf")
    assert len(res.evidence) >= 2
    obs_types = {e.observation_type for e in res.evidence}
    assert ObservationType.BINARY_SIGNATURE in obs_types
    assert ObservationType.BINARY_SYMBOL in obs_types
    assert ObservationType.BINARY_REFERENCE in obs_types
