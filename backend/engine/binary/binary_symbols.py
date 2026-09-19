"""
ECDAT V4 Binary Symbol Table Parser.

Pure Python symbol discovery for:
- ELF .symtab (static symbols) and .dynsym (dynamic symbols)
- PE Export and Import Address Tables (names & ordinals)
- Mach-O LC_SYMTAB symbol tables

Research Axiom:
A defined symbol (is_defined=True) shows the function is compiled within the artifact.
An undefined symbol (is_defined=False) shows an imported external API dependency.
NEITHER proves dynamic execution path or runtime invocation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple

from .binary_identifier import BinaryFormat, BinaryIdentifier


class SymbolType(str, Enum):
    FUNC = "FUNC"
    OBJECT = "OBJECT"
    FILE = "FILE"
    SECTION = "SECTION"
    UNKNOWN = "UNKNOWN"


class SymbolBinding(str, Enum):
    GLOBAL = "GLOBAL"
    LOCAL = "LOCAL"
    WEAK = "WEAK"
    UNKNOWN = "UNKNOWN"


@dataclass
class SymbolInfo:
    name: str
    symbol_type: SymbolType
    binding: SymbolBinding
    is_defined: bool  # False means imported (SHN_UNDEF / IAT)
    value: int = 0
    size: int = 0
    section: Optional[str] = None
    is_crypto: bool = False
    crypto_category: Optional[str] = None
    algorithm: Optional[str] = None
    pqc_status: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "symbol_type": self.symbol_type.value,
            "binding": self.binding.value,
            "is_defined": self.is_defined,
            "value": f"0x{self.value:08x}",
            "size": self.size,
            "section": self.section,
            "is_crypto": self.is_crypto,
            "crypto_category": self.crypto_category,
            "algorithm": self.algorithm,
            "pqc_status": self.pqc_status,
        }


# Cryptographic Symbol Knowledge Database
CRYPTO_SYMBOL_PATTERNS: List[Dict[str, Any]] = [
    # Post-Quantum Cryptography (PQC)
    {"pattern": r"(?i).*(?:ml_kem|kyber|crystals_kyber|oqs_kem_kyber).*", "algorithm": "ML-KEM", "category": "PQC", "pqc_status": "PQC_STANDARDIZED"},
    {"pattern": r"(?i).*(?:ml_dsa|dilithium|crystals_dilithium|oqs_sig_dilithium).*", "algorithm": "ML-DSA", "category": "PQC", "pqc_status": "PQC_STANDARDIZED"},
    {"pattern": r"(?i).*(?:slh_dsa|sphincs|sphincsplus).*", "algorithm": "SLH-DSA", "category": "PQC", "pqc_status": "PQC_STANDARDIZED"},
    {"pattern": r"(?i).*(?:falcon|oqs_sig_falcon).*", "algorithm": "Falcon", "category": "PQC", "pqc_status": "PQC_STANDARDIZED"},
    {"pattern": r"(?i).*(?:crypto_kem_(?:keypair|enc|dec)).*", "algorithm": "KEM_PQC", "category": "PQC", "pqc_status": "PQC_STANDARDIZED"},

    # Classic Asymmetric & Signatures
    {"pattern": r"(?i).*(?:rsa_generate|rsa_public|rsa_private|rsa_sign|rsa_verify|bcryptexportkey.*rsa|crypto_sign_ed25519).*", "algorithm": "RSA", "category": "ASYMMETRIC", "pqc_status": "QUANTUM_VULNERABLE"},
    {"pattern": r"(?i).*(?:ecdsa_do_sign|ecdsa_do_verify|ec_key_new|secp256k1_ecdsa).*", "algorithm": "ECDSA", "category": "ASYMMETRIC", "pqc_status": "QUANTUM_VULNERABLE"},
    {"pattern": r"(?i).*(?:ecdh_compute_key|x25519|crypto_scalarmult_curve25519).*", "algorithm": "ECDH", "category": "ASYMMETRIC", "pqc_status": "QUANTUM_VULNERABLE"},
    {"pattern": r"(?i).*(?:dsa_do_sign|dsa_do_verify).*", "algorithm": "DSA", "category": "ASYMMETRIC", "pqc_status": "LEGACY_DEPRECATED"},

    # Symmetric Ciphers
    {"pattern": r"(?i).*(?:aes_set_encrypt_key|aes_encrypt|aes_decrypt|aes_gcm|evp_aes_\d+|bcryptencrypt.*aes).*", "algorithm": "AES", "category": "SYMMETRIC", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},
    {"pattern": r"(?i).*(?:des_ecb_encrypt|des_ede3|des_set_key|des3).*", "algorithm": "3DES", "category": "SYMMETRIC", "pqc_status": "LEGACY_BROKEN"},
    {"pattern": r"(?i).*(?:chacha20_poly1305|chacha20_init|crypto_stream_chacha20).*", "algorithm": "ChaCha20", "category": "SYMMETRIC", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},
    {"pattern": r"(?i).*(?:sm4_setkey|sm4_crypt_ecb|sm4_crypt_cbc).*", "algorithm": "SM4", "category": "SYMMETRIC", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},
    {"pattern": r"(?i).*(?:rc4_set_key|rc4_crypt).*", "algorithm": "RC4", "category": "SYMMETRIC", "pqc_status": "LEGACY_BROKEN"},

    # Cryptographic Hashes
    {"pattern": r"(?i).*(?:md5_init|md5_update|md5_final|md5_transform).*", "algorithm": "MD5", "category": "HASH", "pqc_status": "LEGACY_BROKEN"},
    {"pattern": r"(?i).*(?:sha1_init|sha1_update|sha1_final|sha1_transform).*", "algorithm": "SHA-1", "category": "HASH", "pqc_status": "LEGACY_BROKEN"},
    {"pattern": r"(?i).*(?:sha256_init|sha256_update|sha256_final|sha224_init).*", "algorithm": "SHA-256", "category": "HASH", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},
    {"pattern": r"(?i).*(?:sha512_init|sha512_update|sha512_final|sha384_init).*", "algorithm": "SHA-512", "category": "HASH", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},
    {"pattern": r"(?i).*(?:sha3_256_init|sha3_512_init|keccak_f1600).*", "algorithm": "SHA-3", "category": "HASH", "pqc_status": "PQC_STANDARDIZED"},
    {"pattern": r"(?i).*(?:blake2b_init|blake2s_init).*", "algorithm": "BLAKE2", "category": "HASH", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},

    # Key Derivation & Management
    {"pattern": r"(?i).*(?:pkcs5_pbkdf2|hkdf_extract|hkdf_expand|scrypt|argon2).*", "algorithm": "KDF", "category": "KDF", "pqc_status": "QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED"},
    {"pattern": r"(?i).*(?:evp_pkey_encrypt|evp_pkey_decrypt|evp_pkey_sign|evp_cipher_ctx).*", "algorithm": "GenericCrypto", "category": "KEY_MANAGEMENT", "pqc_status": "UNKNOWN"},
]


def classify_crypto_symbol(name: str) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
    """Checks whether a symbol name represents cryptographic functionality."""
    clean_name = re.sub(r"^[_]+", "", name)
    for rule in CRYPTO_SYMBOL_PATTERNS:
        if re.search(rule["pattern"], clean_name):
            return True, rule["category"], rule["algorithm"], rule["pqc_status"]
    return False, None, None, None


class BinarySymbolParser:
    """Extracts and classifies static and dynamic symbols from executables."""

    @staticmethod
    def parse(data: bytes, filename: str = "") -> List[SymbolInfo]:
        id_res = BinaryIdentifier.identify(data, filename)
        if id_res.format == BinaryFormat.ELF:
            return BinarySymbolParser._parse_elf_symbols(data, id_res)
        elif id_res.format == BinaryFormat.PE:
            return BinarySymbolParser._parse_pe_symbols(data)
        return []

    @staticmethod
    def _parse_elf_symbols(data: bytes, id_res: Any) -> List[SymbolInfo]:
        if len(data) < 52:
            return []

        endian_char = "<" if id_res.endianness == "little" else ">"
        is_64 = id_res.bits == 64

        try:
            if is_64:
                sh_offset = struct.unpack_from(endian_char + "Q", data, 40)[0]
                sh_entsize, sh_num, sh_strndx = struct.unpack_from(endian_char + "HHH", data, 58)
            else:
                sh_offset = struct.unpack_from(endian_char + "I", data, 32)[0]
                sh_entsize, sh_num, sh_strndx = struct.unpack_from(endian_char + "HHH", data, 46)
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
                    sh_addr, sh_off, sh_size, sh_link, sh_info, sh_addralign, sh_entsize_sec = struct.unpack_from(
                        endian_char + "QQQIIQQ", data, base + 16
                    )
                else:
                    sh_name, sh_type, sh_flags = struct.unpack_from(endian_char + "III", data, base)
                    sh_addr, sh_off, sh_size, sh_link, sh_info, sh_addralign, sh_entsize_sec = struct.unpack_from(
                        endian_char + "IIIIIII", data, base + 12
                    )
                raw_sections.append((sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, sh_link, sh_entsize_sec))
            except struct.error:
                break

        # Find .strtab string table for section names
        strtab = b""
        if 0 <= sh_strndx < len(raw_sections):
            _, _, _, _, s_off, s_size, _, _ = raw_sections[sh_strndx]
            if s_off + s_size <= len(data):
                strtab = data[s_off:s_off + s_size]

        symbols: List[SymbolInfo] = []
        seen_names: Set[str] = set()

        # Iterate over sections looking for SHT_SYMTAB (2) and SHT_DYNSYM (11)
        for idx, (sh_name, sh_type, _, _, sh_off, sh_size, sh_link, ent_size) in enumerate(raw_sections):
            if sh_type in (2, 11):  # SHT_SYMTAB or SHT_DYNSYM
                # Associated string table section index is in sh_link
                sym_strtab = b""
                if 0 <= sh_link < len(raw_sections):
                    _, _, _, _, str_off, str_size, _, _ = raw_sections[sh_link]
                    if str_off + str_size <= len(data):
                        sym_strtab = data[str_off:str_off + str_size]

                sym_ent_size = ent_size if ent_size > 0 else (24 if is_64 else 16)
                if sh_off + sh_size > len(data) or sym_ent_size == 0:
                    continue

                count = min(sh_size // sym_ent_size, 4096)
                for s in range(count):
                    s_base = sh_off + s * sym_ent_size
                    try:
                        if is_64:
                            st_name, st_info, st_other, st_shndx = struct.unpack_from(endian_char + "IBBH", data, s_base)
                            st_value, st_size = struct.unpack_from(endian_char + "QQ", data, s_base + 8)
                        else:
                            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                                endian_char + "IIIBBH", data, s_base
                            )
                    except struct.error:
                        break

                    name = ""
                    if sym_strtab and st_name < len(sym_strtab):
                        name = sym_strtab[st_name:].split(b"\0", 1)[0].decode("latin-1", "replace").strip()

                    if not name or name in seen_names:
                        continue
                    seen_names.add(name)

                    st_type_val = st_info & 0xF
                    st_bind_val = st_info >> 4

                    sym_type = {
                        1: SymbolType.OBJECT,
                        2: SymbolType.FUNC,
                        3: SymbolType.SECTION,
                        4: SymbolType.FILE,
                    }.get(st_type_val, SymbolType.UNKNOWN)

                    sym_bind = {
                        0: SymbolBinding.LOCAL,
                        1: SymbolBinding.GLOBAL,
                        2: SymbolBinding.WEAK,
                    }.get(st_bind_val, SymbolBinding.UNKNOWN)

                    # st_shndx == 0 (SHN_UNDEF) means it is imported externally!
                    is_defined = (st_shndx != 0)

                    is_crypto, category, algorithm, pqc_stat = classify_crypto_symbol(name)

                    symbols.append(
                        SymbolInfo(
                            name=name,
                            symbol_type=sym_type,
                            binding=sym_bind,
                            is_defined=is_defined,
                            value=st_value,
                            size=st_size,
                            section=f"sec_{st_shndx}" if is_defined else None,
                            is_crypto=is_crypto,
                            crypto_category=category,
                            algorithm=algorithm,
                            pqc_status=pqc_stat,
                        )
                    )

        return symbols

    @staticmethod
    def _parse_pe_symbols(data: bytes) -> List[SymbolInfo]:
        """Parses Export and Import directories from PE binaries."""
        if len(data) < 64:
            return []

        symbols: List[SymbolInfo] = []
        try:
            pe_offset = struct.unpack_from("<I", data, 60)[0]
            opt_hdr_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
            is_64 = magic == 0x20B

            # Data directories offset:
            # 32-bit: pe_offset + 24 + 96
            # 64-bit: pe_offset + 24 + 112
            dd_offset = pe_offset + 24 + (112 if is_64 else 96)
            if dd_offset + 16 > len(data):
                return []

            # Directory 0: Export Table, Directory 1: Import Table
            export_rva, export_size = struct.unpack_from("<II", data, dd_offset)
            import_rva, import_size = struct.unpack_from("<II", data, dd_offset + 8)

            # Build RVA to FileOffset translator using section table
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

            # Parse Exports
            if export_rva > 0 and export_size > 0:
                exp_off = rva_to_offset(export_rva)
                if exp_off is not None and exp_off + 40 <= len(data):
                    num_funcs, num_names = struct.unpack_from("<II", data, exp_off + 20)
                    names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
                    names_off = rva_to_offset(names_rva)
                    if names_off is not None:
                        for n in range(min(num_names, 1024)):
                            if names_off + n * 4 + 4 > len(data):
                                break
                            name_rva = struct.unpack_from("<I", data, names_off + n * 4)[0]
                            str_off = rva_to_offset(name_rva)
                            if str_off is not None and str_off < len(data):
                                name = data[str_off:].split(b"\0", 1)[0].decode("ascii", "replace").strip()
                                if name:
                                    is_crypto, category, algorithm, pqc_stat = classify_crypto_symbol(name)
                                    symbols.append(
                                        SymbolInfo(
                                            name=name,
                                            symbol_type=SymbolType.FUNC,
                                            binding=SymbolBinding.GLOBAL,
                                            is_defined=True,  # Exported functions are defined within the PE
                                            is_crypto=is_crypto,
                                            crypto_category=category,
                                            algorithm=algorithm,
                                            pqc_status=pqc_stat,
                                        )
                                    )

            # Parse Imports
            if import_rva > 0 and import_size > 0:
                imp_off = rva_to_offset(import_rva)
                if imp_off is not None:
                    # Iterate IMAGE_IMPORT_DESCRIPTOR (20 bytes each, ends with null struct)
                    for desc_idx in range(64):
                        desc_base = imp_off + desc_idx * 20
                        if desc_base + 20 > len(data):
                            break
                        ilt_rva, time_stamp, forwarder, name_rva, iat_rva = struct.unpack_from("<IIIII", data, desc_base)
                        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
                            break

                        thunk_rva = ilt_rva if ilt_rva != 0 else iat_rva
                        thunk_off = rva_to_offset(thunk_rva)
                        if thunk_off is None:
                            continue

                        # Iterate thunk table
                        step = 8 if is_64 else 4
                        for t in range(512):
                            tb = thunk_off + t * step
                            if tb + step > len(data):
                                break
                            val = struct.unpack_from("<Q" if is_64 else "<I", data, tb)[0]
                            if val == 0:
                                break
                            # Check ordinal bit (MSB)
                            ordinal_bit = 0x8000000000000000 if is_64 else 0x80000000
                            if not (val & ordinal_bit):
                                hint_name_off = rva_to_offset(val)
                                if hint_name_off is not None and hint_name_off + 2 < len(data):
                                    fname = data[hint_name_off + 2:].split(b"\0", 1)[0].decode("ascii", "replace").strip()
                                    if fname:
                                        is_crypto, category, algorithm, pqc_stat = classify_crypto_symbol(fname)
                                        symbols.append(
                                            SymbolInfo(
                                                name=fname,
                                                symbol_type=SymbolType.FUNC,
                                                binding=SymbolBinding.GLOBAL,
                                                is_defined=False,  # Imported symbols are external
                                                is_crypto=is_crypto,
                                                crypto_category=category,
                                                algorithm=algorithm,
                                                pqc_status=pqc_stat,
                                            )
                                        )

        except (struct.error, IndexError):
            pass

        return symbols
