"""
ECDAT V4 Ground-Truth Benchmark Dataset Generator.

Generates >=700 deterministically labeled synthetic benchmark cases
across 7 modalities (SOURCE, DEPENDENCY, BINARY, FIRMWARE, NETWORK, X509, PQC)
including 20 mandatory hard negative categories and multi-modal cases.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Dict, List, Optional
from .models import BenchmarkCase, BenchmarkDataset, GroundTruthLabel, ModalityType, UseState
from .dataset import compute_dataset_hash


def generate_benchmark_cases() -> List[BenchmarkCase]:
    cases: List[BenchmarkCase] = []

    def add_case(
        case_id: str,
        modality: str,
        platform: str,
        artifact: Dict[str, Any],
        label: str,
        algorithm: Optional[str] = None,
        role: Optional[str] = None,
        evidence_state: str = "MEASURED",
        use_state: str = "ACTUAL_USE",
        confidence: str = "HIGH",
        pqc_state: Optional[str] = None,
        risk_cat: Optional[str] = None,
        agility_cat: Optional[str] = None,
        blast_rel: Optional[str] = None,
        desc: Optional[str] = None,
        hard_neg: Optional[str] = None,
        mm_comp: Optional[List[Dict[str, Any]]] = None,
    ):
        cases.append(BenchmarkCase(
            case_id=case_id,
            modality=modality,
            language_platform=platform,
            input_artifact=artifact,
            ground_truth_label=label,
            cryptographic_algorithm=algorithm,
            cryptographic_role=role,
            expected_evidence_state=evidence_state,
            expected_use_state=use_state,
            expected_confidence_class=confidence,
            expected_pqc_state=pqc_state,
            expected_risk_category=risk_cat,
            expected_agility_category=agility_cat,
            expected_blast_radius_relation=blast_rel,
            dataset_version="1.0.0",
            dataset_type="SYNTHETIC",
            description=desc,
            hard_negative_category=hard_neg,
            multi_modal_components=mm_comp,
        ))

    # =========================================================================
    # 1. SOURCE MODALITY (~140 cases: Positive, Negative, Hard Negatives)
    # =========================================================================
    languages = [
        ("python", "py"),
        ("java", "java"),
        ("c_cpp", "c"),
        ("golang", "go"),
        ("rust", "rs"),
        ("javascript", "js"),
    ]

    # Positive API Uses across languages
    algos_source = [
        ("AES-256-GCM", "SYMMETRIC_ENCRYPTION", "SYMMETRIC", "PQC_SAFE_SYMMETRIC"),
        ("AES-128-CBC", "SYMMETRIC_ENCRYPTION", "SYMMETRIC", "CLASSICAL_SYMMETRIC"),
        ("RSA-2048", "SIGNATURE", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
        ("RSA-4096", "KEY_ESTABLISHMENT", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
        ("ECDSA-P256", "SIGNATURE", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
        ("ECDSA-P384", "SIGNATURE", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
        ("Ed25519", "SIGNATURE", "ASYMMETRIC", "QUANTUM_VULNERABLE"),
        ("ChaCha20-Poly1305", "SYMMETRIC_ENCRYPTION", "AEAD", "PQC_SAFE_SYMMETRIC"),
        ("3DES", "SYMMETRIC_ENCRYPTION", "SYMMETRIC", "BROKEN"),
        ("DES", "SYMMETRIC_ENCRYPTION", "SYMMETRIC", "BROKEN"),
        ("RC4", "SYMMETRIC_ENCRYPTION", "SYMMETRIC", "BROKEN"),
        ("MD5", "HASHING", "HASH", "BROKEN"),
        ("SHA-1", "HASHING", "HASH", "DEPRECATED"),
        ("SHA-256", "HASHING", "HASH", "CLASSICAL_SECURE"),
    ]

    c_idx = 1
    for lang, ext in languages:
        for algo, role, cat, pqc in algos_source:
            cid = f"SRC_POS_{lang.upper()}_{c_idx:03d}"
            if lang == "python":
                code = f"from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\nimport os\nkey = os.urandom(32)\ncipher = Cipher(algorithms.AES(key), modes.GCM(os.urandom(12)))\nencryptor = cipher.encryptor()\n" if "AES" in algo else f"from cryptography.hazmat.primitives.asymmetric import rsa\nprivate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
            elif lang == "java":
                code = f'import javax.crypto.Cipher;\npublic class Sec {{\n  public void run() throws Exception {{\n    Cipher c = Cipher.getInstance("{algo}");\n  }}\n}}'
            elif lang == "c_cpp":
                code = f'#include <openssl/evp.h>\nvoid test() {{\n  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();\n  EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);\n}}'
            elif lang == "golang":
                code = f'package main\nimport "crypto/aes"\nfunc main() {{\n  c, _ := aes.NewCipher([]byte("12345678901234567890123456789012"))\n}}'
            elif lang == "rust":
                code = f'use aes_gcm::{{Aes256Gcm, KeyInit}};\nfn main() {{\n  let key = [0u8; 32];\n  let cipher = Aes256Gcm::new(&key.into());\n}}'
            else: # javascript
                code = f'const crypto = require("crypto");\nfunction enc() {{\n  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);\n}}'

            add_case(
                case_id=cid,
                modality="SOURCE",
                platform=lang,
                artifact={"path": f"src/crypto_{c_idx}.{ext}", "content": code, "language": lang},
                label="POSITIVE",
                algorithm=algo,
                role=role,
                evidence_state="MEASURED",
                use_state="ACTUAL_USE",
                confidence="HIGH",
                pqc_state=pqc,
                desc=f"Active invocation of {algo} in {lang}",
            )
            c_idx += 1

    # Source Hard Negatives (HN 1, 2, 5, 6, 7, 8)
    # HN 1: crypto import but no call
    for lang, ext in languages:
        cid = f"SRC_HN_IMPORT_NOCALL_{lang.upper()}_{c_idx:03d}"
        if lang == "python":
            code = "import cryptography\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n# No API calls made\ndef hello():\n    return 'world'\n"
        elif lang == "java":
            code = "import javax.crypto.Cipher;\nimport java.security.KeyPairGenerator;\npublic class Unused {\n  public int add(int a, int b) { return a + b; }\n}\n"
        elif lang == "golang":
            code = 'package main\nimport _ "crypto/sha256"\nfunc main() {}\n'
        elif lang == "rust":
            code = 'use ring::signature;\nfn compute() -> i32 { 42 }\n'
        elif lang == "c_cpp":
            code = '#include <openssl/rsa.h>\n#include <openssl/evp.h>\nint add(int a, int b) { return a + b; }\n'
        else:
            code = 'const crypto = require("crypto");\nfunction doWork() { return 123; }\n'

        add_case(
            case_id=cid,
            modality="SOURCE",
            platform=lang,
            artifact={"path": f"src/unused_{c_idx}.{ext}", "content": code, "language": lang},
            label="NEGATIVE",
            algorithm="RSA" if lang in ("python", "java", "c_cpp") else "GENERIC_CRYPTO",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="IMPORT_ONLY",
            confidence="MEDIUM",
            desc="Cryptographic library imported but zero APIs invoked",
            hard_neg="HN1_IMPORT_NO_CALL",
        )
        c_idx += 1

    # HN 2: crypto string only
    for algo_str in ["AES_KEY_DEBUG", "DES_EDE3_OLD_KEY", "MD5_CHECKSUM_FIELD"]:
        cid = f"SRC_HN_STRING_ONLY_{c_idx:03d}"
        code = f'# Debugging identifier\nlog_message = "Found constant identifier: {algo_str}"\n'
        add_case(
            case_id=cid,
            modality="SOURCE",
            platform="python",
            artifact={"path": f"src/strings_{c_idx}.py", "content": code, "language": "python"},
            label="NEGATIVE",
            algorithm=algo_str.split("_")[0],
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="STRING_ONLY",
            confidence="LOW",
            desc=f"String literal containing {algo_str} without crypto invocation",
            hard_neg="HN2_STRING_NO_USE",
        )
        c_idx += 1

    # HN 8: Algorithm name in variable name only
    for algo_str in ["rsa_key_name_var", "aes_gcm_mode_flag", "chacha20_config_option"]:
        cid = f"SRC_HN_VARNAME_ONLY_{c_idx:03d}"
        code = f'# Variable identifier only\n{algo_str} = "setting_value"\nstatus = len({algo_str})\n'
        add_case(
            case_id=cid,
            modality="SOURCE",
            platform="python",
            artifact={"path": f"src/vars_{c_idx}.py", "content": code, "language": "python"},
            label="NEGATIVE",
            algorithm=algo_str.split("_")[0].upper(),
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="STRING_ONLY",
            confidence="ZERO",
            desc=f"Algorithm name in variable name {algo_str} without cryptographic use",
            hard_neg="HN8_ALGO_IN_VARIABLE_NAME",
        )
        c_idx += 1

    # HN 5: Commented crypto API
    for lang, ext in [("python", "py"), ("java", "java"), ("c_cpp", "c"), ("golang", "go")]:
        cid = f"SRC_HN_COMMENTED_API_{c_idx:03d}"
        if lang == "python":
            code = "# rsa.generate_private_key(public_exponent=65537, key_size=2048)\n# cipher = Cipher(algorithms.AES(key))\ndef run(): pass\n"
        elif lang == "java":
            code = "// Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");\n/* KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); */\npublic class App {}\n"
        elif lang == "c_cpp":
            code = "/* EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL); */\n// DES_ede3_cbc_encrypt();\nint main() { return 0; }\n"
        else:
            code = "// c, _ := aes.NewCipher(key)\npackage main\nfunc main() {}\n"

        add_case(
            case_id=cid,
            modality="SOURCE",
            platform=lang,
            artifact={"path": f"src/commented_{c_idx}.{ext}", "content": code, "language": lang},
            label="NEGATIVE",
            algorithm="AES",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="UNUSED",
            confidence="ZERO",
            desc="Cryptographic invocation is commented out in source",
            hard_neg="HN5_COMMENTED_CRYPTO_API",
        )
        c_idx += 1

    # HN 6: Dead code crypto API
    for i in range(5):
        cid = f"SRC_HN_DEADCODE_{c_idx:03d}"
        code = f"""
def production_workflow():
    return "active service"

def deprecated_dormant():
    if False:
        # Dead branch never reachable
        from cryptography.hazmat.primitives.asymmetric import rsa
        return rsa.generate_private_key(65537, 2048)
"""
        add_case(
            case_id=cid,
            modality="SOURCE",
            platform="python",
            artifact={"path": f"src/deadcode_{c_idx}.py", "content": code, "language": "python"},
            label="NEGATIVE",
            algorithm="RSA-2048",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="UNUSED",
            confidence="LOW",
            desc="Cryptographic API call in dead code branch (if False:)",
            hard_neg="HN6_DEAD_CODE_CRYPTO_API",
        )
        c_idx += 1

    # HN 7: Algorithm name in docstring / documentation
    for i in range(5):
        cid = f"SRC_HN_DOCSTRING_{c_idx:03d}"
        code = '''
"""
Module Security Architecture Documentation
------------------------------------------
We previously evaluated RSA-2048 and 3DES before choosing our
standard transport layer. This module does simple string math.
"""
def add(a, b):
    return a + b
'''
        add_case(
            case_id=cid,
            modality="SOURCE",
            platform="python",
            artifact={"path": f"src/docs_{c_idx}.py", "content": code, "language": "python"},
            label="NEGATIVE",
            algorithm="RSA-2048",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="STRING_ONLY",
            confidence="ZERO",
            desc="Algorithm mentioned only in documentation comments",
            hard_neg="HN7_ALGO_IN_DOCUMENTATION",
        )
        c_idx += 1

    # =========================================================================
    # 2. DEPENDENCY MODALITY (~130 cases)
    # =========================================================================
    dep_manifests = [
        ("requirements.txt", "cryptography>=42.0.0\npycryptodome==3.20.0\nrequests==2.31.0", "python"),
        ("requirements.txt", "requests==2.31.0\nflask==3.0.0\npydantic==2.6.0", "python"), # Negative (no crypto)
        ("package.json", '{"dependencies": {"@noble/ciphers": "^0.4.0", "crypto-js": "^4.2.0"}}', "javascript"),
        ("package.json", '{"dependencies": {"lodash": "^4.17.21", "express": "^4.18.2"}}', "javascript"), # Negative
        ("pom.xml", '<project><dependencies><dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency></dependencies></project>', "java"),
        ("pom.xml", '<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-lang3</artifactId><version>3.14.0</version></dependency></dependencies></project>', "java"), # Negative
        ("go.mod", "module example.com/app\ngo 1.21\nrequire (\n\tgolang.org/x/crypto v0.21.0\n)", "golang"),
        ("go.mod", "module example.com/app\ngo 1.21\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)", "golang"), # Negative
        ("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nring = "0.17"\naes-gcm = "0.10"', "rust"),
        ("Cargo.toml", '[package]\nname = "app"\nversion = "0.1.0"\n[dependencies]\nserde = "1.0"\ntokio = "1.0"', "rust"), # Negative
    ]

    d_idx = 1
    for i in range(12):
        for fname, content, plat in dep_manifests:
            cid = f"DEP_{plat.upper()}_{d_idx:03d}"
            has_crypto = any(k in content for k in ("crypto", "bouncycastle", "ring", "aes"))
            add_case(
                case_id=cid,
                modality="DEPENDENCY",
                platform=plat,
                artifact={"file_path": f"manifests/{fname}_{d_idx}", "content": content},
                label="POSITIVE" if has_crypto else "NEGATIVE",
                algorithm="GENERIC_CRYPTO_LIB" if has_crypto else None,
                role="CAPABILITY",
                evidence_state="MEASURED",
                use_state="DEPENDENCY_DECLARED" if has_crypto else "UNUSED",
                confidence="HIGH" if has_crypto else "ZERO",
                desc=f"Manifest {fname} for {plat} {'with' if has_crypto else 'without'} crypto packages",
            )
            d_idx += 1

    # HN 4: Dependency declared but unused in code
    for i in range(5):
        cid = f"DEP_HN_UNUSED_PKG_{d_idx:03d}"
        add_case(
            case_id=cid,
            modality="DEPENDENCY",
            platform="python",
            artifact={
                "file_path": f"deps/requirements_unused_{d_idx}.txt",
                "content": "cryptography==42.0.0\npytest==8.0.0\n",
                "associated_source_files": [{"path": "main.py", "content": "print('hello world')"}],
            },
            label="NEGATIVE",
            algorithm="cryptography",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="DEPENDENCY_DECLARED",
            confidence="LOW",
            desc="cryptography package declared in requirements.txt but no imports or calls in codebase",
            hard_neg="HN4_DEPENDENCY_DECLARED_UNUSED",
        )
        d_idx += 1

    # HN 16: Library / Provider capability without runtime use
    for i in range(5):
        cid = f"DEP_HN_PROVIDER_UNUSED_{d_idx:03d}"
        add_case(
            case_id=cid,
            modality="DEPENDENCY",
            platform="java",
            artifact={
                "file_path": f"deps/pom_bouncycastle_{d_idx}.xml",
                "content": "<dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId><version>1.78</version></dependency>",
                "security_provider": "BC",
                "runtime_use_observed": False,
            },
            label="NEGATIVE",
            algorithm="BouncyCastleProvider",
            role="CAPABILITY",
            evidence_state="MEASURED",
            use_state="CAPABILITY_ONLY",
            confidence="LOW",
            desc="BouncyCastle provider included in build manifest but never registered or invoked in runtime",
            hard_neg="HN16_PROVIDER_CAPABILITY_NO_RUNTIME_USE",
        )
        d_idx += 1

    # =========================================================================
    # 3. BINARY MODALITY (~130 cases)
    # =========================================================================
    # Hex byte signatures for AES S-box, DES IP, SHA-256 K constants
    b_idx = 1
    binary_sigs = [
        ("AES_SBOX", "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0", "AES", "SYMMETRIC_ENCRYPTION"),
        ("AES_INVSBOX", "52096ad53036a538bf40a39e81f3d7fb", "AES", "SYMMETRIC_ENCRYPTION"),
        ("DES_IP", "3a322a221a120a023c342c241c140c04", "DES", "SYMMETRIC_ENCRYPTION"),
        ("SHA256_K", "982f8a4291443771b0fb1385a367d4ab5cb0a9e9", "SHA-256", "HASHING"),
        ("MD5_PAD", "80000000000000000000000000000000", "MD5", "HASHING"),
    ]

    for i in range(20):
        for name, hex_str, algo, role in binary_sigs:
            cid = f"BIN_SIG_{b_idx:03d}"
            # Construct a dummy binary payload with the signature embedded
            prefix = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00" # ELF header
            sig_bytes = bytes.fromhex(hex_str)
            payload = prefix + b"\x90" * 32 + sig_bytes + b"\x90" * 32
            add_case(
                case_id=cid,
                modality="BINARY",
                platform="x86_64_elf",
                artifact={"file_name": f"binary_{b_idx}.bin", "bytes_hex": payload.hex()},
                label="POSITIVE",
                algorithm=algo,
                role=role,
                evidence_state="MEASURED",
                use_state="SYMBOL_ONLY",
                confidence="HIGH",
                desc=f"Binary containing byte signature for {name}",
            )
            b_idx += 1

    # Negative binary cases (no crypto signatures)
    for i in range(20):
        cid = f"BIN_NEG_PLAIN_{b_idx:03d}"
        payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 128 + b"Hello World Plaintext Non-Crypto Executable"
        add_case(
            case_id=cid,
            modality="BINARY",
            platform="x86_64_elf",
            artifact={"file_name": f"plain_{b_idx}.bin", "bytes_hex": payload.hex()},
            label="NEGATIVE",
            algorithm=None,
            role=None,
            evidence_state="MEASURED",
            use_state="UNUSED",
            confidence="ZERO",
            desc="ELF binary with no cryptographic signatures or symbols",
        )
        b_idx += 1

    # HN 3 & 17: Binary string/symbol present without execution evidence
    for i in range(10):
        cid = f"BIN_HN_STRING_NO_EXEC_{b_idx:03d}"
        payload = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32 + b"libcrypto.so.3\x00EVP_aes_256_gcm\x00" + b"\x00" * 64
        add_case(
            case_id=cid,
            modality="BINARY",
            platform="x86_64_elf",
            artifact={"file_name": f"dormant_symbols_{b_idx}.bin", "bytes_hex": payload.hex()},
            label="NEGATIVE",
            algorithm="AES-256-GCM",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="STRING_ONLY",
            confidence="LOW",
            desc="Binary rodata contains symbol strings but no instruction invokes them",
            hard_neg="HN3_BINARY_SYMBOL_NO_EXECUTION",
        )
        b_idx += 1

    # =========================================================================
    # 4. FIRMWARE MODALITY (~50 cases)
    # =========================================================================
    f_idx = 1
    for i in range(35):
        cid = f"FW_POS_ARCHIVE_{f_idx:03d}"
        # Dummy archive with embedded crypto keys
        fw_payload = b"PK\x03\x04" + b"\x00" * 26 + b"cert.pem" + b"-----BEGIN CERTIFICATE-----\nMIIB...RSA-2048\n-----END CERTIFICATE-----"
        add_case(
            case_id=cid,
            modality="FIRMWARE",
            platform="uimage_embedded",
            artifact={"file_name": f"router_fw_{f_idx}.bin", "bytes_hex": fw_payload.hex()},
            label="POSITIVE",
            algorithm="RSA-2048",
            role="CERTIFICATE_SIGNATURE",
            evidence_state="MEASURED",
            use_state="CAPABILITY_ONLY",
            confidence="MEDIUM",
            desc="Firmware archive containing embedded RSA certificate",
        )
        f_idx += 1

    # Firmware Hard Negatives (HN 17: Signature without execution)
    for i in range(15):
        cid = f"FW_HN_STATIC_NO_EXEC_{f_idx:03d}"
        payload = b"uImage\x00\x00" + b"\x00" * 64 + b"STATIC_IMAGE_WITH_UNREFERENCED_SIGNATURE_AES"
        add_case(
            case_id=cid,
            modality="FIRMWARE",
            platform="uimage_embedded",
            artifact={"file_name": f"fw_blob_{f_idx}.bin", "bytes_hex": payload.hex()},
            label="NEGATIVE",
            algorithm="AES",
            role="UNKNOWN",
            evidence_state="MEASURED",
            use_state="STRING_ONLY",
            confidence="LOW",
            desc="Firmware blob has static signature string with no execution code",
            hard_neg="HN17_FIRMWARE_SIGNATURE_NO_EXECUTION",
        )
        f_idx += 1

    # =========================================================================
    # 5. NETWORK MODALITY (~130 cases)
    # =========================================================================
    n_idx = 1
    tls_negotiations = [
        ("TLS_AES_256_GCM_SHA384", "TLSv1.3", "AES-256-GCM", "NEGOTIATED", "POSITIVE"),
        ("TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", "ChaCha20-Poly1305", "NEGOTIATED", "POSITIVE"),
        ("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2", "AES-128-GCM", "NEGOTIATED", "POSITIVE"),
        ("ECDHE-ECDSA-AES256-GCM-SHA384", "TLSv1.2", "AES-256-GCM", "NEGOTIATED", "POSITIVE"),
        ("DES-CBC3-SHA", "TLSv1.0", "3DES", "NEGOTIATED", "POSITIVE"),
        ("RC4-MD5", "TLSv1.0", "RC4", "NEGOTIATED", "POSITIVE"),
    ]

    for i in range(15):
        for cipher, ver, algo, state, lbl in tls_negotiations:
            cid = f"NET_TLS_{n_idx:03d}"
            add_case(
                case_id=cid,
                modality="NETWORK",
                platform="tls_probe",
                artifact={
                    "target": f"api-{n_idx}.internal.service",
                    "port": 443,
                    "negotiated_version": ver,
                    "negotiated_cipher": cipher,
                    "state": state,
                },
                label=lbl,
                algorithm=algo,
                role="KEY_ESTABLISHMENT" if "ECDHE" in cipher else "SYMMETRIC_ENCRYPTION",
                evidence_state="MEASURED",
                use_state=state,
                confidence="HIGH",
                desc=f"Active TLS negotiation of {cipher} over {ver}",
            )
            n_idx += 1

    # Network Hard Negatives (HN 9, 10, 11, 12)
    # HN 9: TLS cipher string advertised but NOT negotiated
    for i in range(6):
        cid = f"NET_HN_CIPHER_ADVERTISED_{n_idx:03d}"
        add_case(
            case_id=cid,
            modality="NETWORK",
            platform="tls_probe",
            artifact={
                "target": f"legacy-{n_idx}.corp",
                "port": 443,
                "client_advertised_ciphers": ["DES-CBC3-SHA", "RC4-SHA", "AES128-SHA"],
                "server_chosen_cipher": "TLS_AES_256_GCM_SHA384",
                "negotiated_version": "TLSv1.3",
            },
            label="NEGATIVE",
            algorithm="3DES",
            role="SYMMETRIC_ENCRYPTION",
            evidence_state="MEASURED",
            use_state="ADVERTISED_ONLY",
            confidence="MEDIUM",
            desc="3DES advertised in ClientHello cipher list but server selected AES-256-GCM",
            hard_neg="HN9_TLS_CIPHER_NO_NEGOTIATION",
        )
        n_idx += 1

    # HN 10: Supported TLS version without negotiated use
    for i in range(6):
        cid = f"NET_HN_TLSVER_SUPPORT_NO_NEG_{n_idx:03d}"
        add_case(
            case_id=cid,
            modality="NETWORK",
            platform="tls_probe",
            artifact={
                "target": f"dual-stack-{n_idx}.corp",
                "port": 443,
                "server_supported_tls_versions": ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"],
                "negotiated_version": "TLSv1.3",
                "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
            },
            label="NEGATIVE",
            algorithm="TLSv1.0",
            role="PROTOCOL",
            evidence_state="MEASURED",
            use_state="ADVERTISED_ONLY",
            confidence="MEDIUM",
            desc="Server supports legacy TLSv1.0 capability, but active connection negotiated TLSv1.3",
            hard_neg="HN10_TLS_SUPPORT_NO_NEGOTIATION",
        )
        n_idx += 1

    # HN 11: SSH advertisement without negotiated KEX
    for i in range(10):
        cid = f"NET_HN_SSH_ADVERTISED_{n_idx:03d}"
        add_case(
            case_id=cid,
            modality="NETWORK",
            platform="ssh_probe",
            artifact={
                "target": f"ssh-{n_idx}.internal",
                "port": 22,
                "banner": "SSH-2.0-OpenSSH_8.9p1",
                "kex_algorithms_advertised": ["diffie-hellman-group1-sha1", "curve25519-sha256"],
                "kex_chosen": "curve25519-sha256",
            },
            label="NEGATIVE",
            algorithm="diffie-hellman-group1-sha1",
            role="KEY_ESTABLISHMENT",
            evidence_state="MEASURED",
            use_state="ADVERTISED_ONLY",
            confidence="MEDIUM",
            desc="DH-group1-sha1 advertised in SSH KEX capabilities but curve25519 was negotiated",
            hard_neg="HN11_SSH_ADVERTISEMENT_NO_NEGOTIATION",
        )
        n_idx += 1

    # HN 12: QUIC Alt-Svc advertised without active UDP connection
    for i in range(10):
        cid = f"NET_HN_QUIC_ALTSVC_{n_idx:03d}"
        add_case(
            case_id=cid,
            modality="NETWORK",
            platform="quic_probe",
            artifact={
                "target": f"web-{n_idx}.edge",
                "port": 443,
                "http_header_alt_svc": 'h3=":443"; ma=86400',
                "udp_handshake_observed": False,
                "actual_protocol": "TCP_TLSv1.3",
            },
            label="NEGATIVE",
            algorithm="QUIC_H3",
            role="PROTOCOL",
            evidence_state="MEASURED",
            use_state="ADVERTISED_ONLY",
            confidence="LOW",
            desc="Alt-Svc header advertises HTTP/3 QUIC, but active UDP handshake was not observed",
            hard_neg="HN12_QUIC_ALTSVC_NO_HANDSHAKE",
        )
        n_idx += 1

    # =========================================================================
    # 6. X509 MODALITY (~75 cases)
    # =========================================================================
    x_idx = 1
    x509_fixtures = [
        ("RSA-2048", "sha256WithRSAEncryption", 2048, "POSITIVE"),
        ("RSA-4096", "sha384WithRSAEncryption", 4096, "POSITIVE"),
        ("ECDSA-P256", "ecdsa-with-SHA256", 256, "POSITIVE"),
        ("ECDSA-P384", "ecdsa-with-SHA384", 384, "POSITIVE"),
        ("Ed25519", "Ed25519", 256, "POSITIVE"),
    ]

    for i in range(10):
        for algo, sig_algo, k_size, lbl in x509_fixtures:
            cid = f"X509_CERT_{x_idx:03d}"
            add_case(
                case_id=cid,
                modality="X509",
                platform="x509_parser",
                artifact={
                    "subject": f"CN=service-{x_idx}.internal.domain",
                    "issuer": "CN=Internal Root CA 2024",
                    "public_key_algorithm": algo,
                    "key_size_bits": k_size,
                    "signature_algorithm": sig_algo,
                    "validity": "VALID",
                    "trusted": True,
                },
                label=lbl,
                algorithm=algo,
                role="CERTIFICATE_SIGNATURE",
                evidence_state="MEASURED",
                use_state="ACTUAL_USE",
                confidence="HIGH",
                desc=f"Valid trusted X.509 certificate with {algo} key",
            )
            x_idx += 1

    # X509 Hard Negatives (HN 13, 14)
    # HN 13: Certificate presence without trust validation
    for i in range(12):
        cid = f"X509_HN_UNTRUSTED_{x_idx:03d}"
        add_case(
            case_id=cid,
            modality="X509",
            platform="x509_parser",
            artifact={
                "subject": f"CN=self-signed-expired-{x_idx}.local",
                "issuer": f"CN=self-signed-expired-{x_idx}.local",
                "public_key_algorithm": "RSA-2048",
                "validity": "EXPIRED",
                "trusted": False,
                "chain_verified": False,
            },
            label="NEGATIVE",
            algorithm="RSA-2048",
            role="CERTIFICATE_SIGNATURE",
            evidence_state="MEASURED",
            use_state="UNUSED",
            confidence="ZERO",
            desc="Expired self-signed certificate presented without trust validation",
            hard_neg="HN13_CERTIFICATE_UNTRUSTED",
        )
        x_idx += 1

    # HN 14: OCSP extension present without revocation check
    for i in range(13):
        cid = f"X509_HN_OCSP_NO_CHECK_{x_idx:03d}"
        add_case(
            case_id=cid,
            modality="X509",
            platform="x509_parser",
            artifact={
                "subject": f"CN=gateway-{x_idx}.cloud",
                "public_key_algorithm": "ECDSA-P256",
                "ocsp_url": "http://ocsp.example.com",
                "ocsp_checked": False,
                "stapling_observed": False,
            },
            label="NEGATIVE",
            algorithm="ECDSA-P256",
            role="CERTIFICATE_SIGNATURE",
            evidence_state="MEASURED",
            use_state="CAPABILITY_ONLY",
            confidence="LOW",
            desc="Certificate has AIA OCSP extension but revocation check was never performed",
            hard_neg="HN14_OCSP_EXTENSION_NO_REVOCATION_CHECK",
        )
        x_idx += 1

    # =========================================================================
    # 7. PQC MODALITY (~75 cases)
    # =========================================================================
    p_idx = 1
    pqc_fixtures = [
        ("ML-KEM-768", "KEY_ESTABLISHMENT", "PQC_STANDARDIZED", "POSITIVE"),
        ("ML-KEM-1024", "KEY_ESTABLISHMENT", "PQC_STANDARDIZED", "POSITIVE"),
        ("ML-DSA-65", "SIGNATURE", "PQC_STANDARDIZED", "POSITIVE"),
        ("ML-DSA-87", "SIGNATURE", "PQC_STANDARDIZED", "POSITIVE"),
        ("SLH-DSA", "SIGNATURE", "PQC_STANDARDIZED", "POSITIVE"),
        ("X25519MLKEM768", "KEY_ESTABLISHMENT", "HYBRID_PQC_TRANSITION", "POSITIVE"),
        ("SecP256r1MLKEM768", "KEY_ESTABLISHMENT", "HYBRID_PQC_TRANSITION", "POSITIVE"),
    ]

    for i in range(8):
        for algo, role, status, lbl in pqc_fixtures:
            cid = f"PQC_STANDARDIZED_{p_idx:03d}"
            add_case(
                case_id=cid,
                modality="PQC",
                platform="pqc_analyzer",
                artifact={
                    "algorithm_identifier": algo,
                    "role": role,
                    "standard": "NIST_FIPS_203_204_205",
                    "is_active": True,
                },
                label=lbl,
                algorithm=algo,
                role=role,
                evidence_state="MEASURED",
                use_state="ACTUAL_USE",
                confidence="HIGH",
                pqc_state=status,
                desc=f"Standardized PQC algorithm {algo}",
            )
            p_idx += 1

    # PQC Hard Negatives (HN 15: Hybrid KEX claimed as signature)
    for i in range(10):
        cid = f"PQC_HN_HYBRID_KEX_NOT_SIG_{p_idx:03d}"
        add_case(
            case_id=cid,
            modality="PQC",
            platform="pqc_analyzer",
            artifact={
                "algorithm_identifier": "X25519MLKEM768",
                "claimed_capability": "DIGITAL_SIGNATURE",
                "certificate_signature": "RSA-2048",
            },
            label="NEGATIVE",
            algorithm="X25519MLKEM768",
            role="SIGNATURE",
            evidence_state="MEASURED",
            use_state="CAPABILITY_ONLY",
            confidence="ZERO",
            pqc_state="CLASSICAL_VULNERABLE",
            desc="Hybrid KEX (X25519MLKEM768) incorrectly claimed to provide PQC signature",
            hard_neg="HN15_HYBRID_KEX_NOT_PQC_SIGNATURE",
        )
        p_idx += 1

    # Classical algorithms in PQC context (quantum vulnerable)
    classical_vulnerable = ["RSA-2048", "ECDSA-P256", "DH-2048", "DSA-1024"]
    for i in range(2):
        for calgo in classical_vulnerable:
            cid = f"PQC_CLASSICAL_VULN_{p_idx:03d}"
            add_case(
                case_id=cid,
                modality="PQC",
                platform="pqc_analyzer",
                artifact={"algorithm_identifier": calgo, "is_classical": True},
                label="NEGATIVE",
                algorithm=calgo,
                role="ASYMMETRIC",
                evidence_state="MEASURED",
                use_state="ACTUAL_USE",
                confidence="HIGH",
                pqc_state="QUANTUM_VULNERABLE",
                desc=f"Classical algorithm {calgo} evaluated under quantum threat",
            )
            p_idx += 1

    # =========================================================================
    # 8. MULTI-MODAL CASES (~40 cases: Corroborated & Contradicted)
    # =========================================================================
    m_idx = 1
    # Corroborated cases: SOURCE + DEPENDENCY + BINARY + NETWORK all point to AES-256-GCM
    for i in range(15):
        cid = f"MM_CORROBORATED_{m_idx:03d}"
        components = [
            {"modality": "SOURCE", "finding": "EVP_aes_256_gcm() invocation", "algo": "AES-256-GCM"},
            {"modality": "DEPENDENCY", "finding": "OpenSSL 3.2.0 declared", "algo": "AES-256-GCM"},
            {"modality": "BINARY", "finding": "AES S-box and AES-NI symbols found", "algo": "AES-256-GCM"},
            {"modality": "NETWORK", "finding": "TLS_AES_256_GCM_SHA384 negotiated", "algo": "AES-256-GCM"},
        ]
        add_case(
            case_id=cid,
            modality="SOURCE",
            platform="multi_modal_fusion",
            artifact={"target_service": f"secure-node-{m_idx}", "observations": components},
            label="CORROBORATED",
            algorithm="AES-256-GCM",
            role="SYMMETRIC_ENCRYPTION",
            evidence_state="MEASURED",
            use_state="ACTUAL_USE",
            confidence="HIGH",
            pqc_state="PQC_SAFE_SYMMETRIC",
            desc="Multi-modal consensus: Source, dependency, binary, and network all agree on AES-256-GCM",
            mm_comp=components,
        )
        m_idx += 1

    # Contradicted cases: SOURCE says Algorithm A, NETWORK observes Algorithm B
    contradiction_pairs = [
        ("AES-256-GCM", "3DES"),
        ("RSA-4096", "Ed25519"),
        ("ChaCha20-Poly1305", "RC4"),
        ("ECDSA-P384", "RSA-1024"),
        ("ML-KEM-768", "RSA-2048"),
    ]
    for i in range(3):
        for algo_a, algo_b in contradiction_pairs:
            cid = f"MM_CONTRADICTED_{m_idx:03d}"
            components = [
                {"modality": "SOURCE", "finding": f"Source code calls {algo_a}", "algo": algo_a},
                {"modality": "NETWORK", "finding": f"Live wire negotiated {algo_b}", "algo": algo_b},
            ]
            add_case(
                case_id=cid,
                modality="NETWORK",
                platform="multi_modal_fusion",
                artifact={
                    "target_service": f"mismatch-node-{m_idx}",
                    "source_claim": algo_a,
                    "network_observation": algo_b,
                    "observations": components,
                },
                label="CONTRADICTED",
                algorithm=f"{algo_a}_VS_{algo_b}",
                role="CONFLICT",
                evidence_state="INCONCLUSIVE",
                use_state="CONFLICT",
                confidence="LOW",
                desc=f"Contradictory evidence: Source indicates {algo_a} but network observed {algo_b}",
                mm_comp=components,
            )
            m_idx += 1

    # =========================================================================
    # 9. REMAINING HARD NEGATIVES (HN 18, 19, 20)
    # =========================================================================
    # HN 18: Configuration value without runtime reload
    for i in range(5):
        cid = f"CFG_HN_NO_RELOAD_{c_idx:03d}"
        add_case(
            case_id=cid,
            modality="SOURCE",
            platform="config_inspector",
            artifact={
                "config_file": f"config_{c_idx}.env",
                "content": "SSL_CIPHER_SUITE=TLS_AES_256_GCM_SHA384",
                "process_reload_supported": False,
                "runtime_active_cipher": "UNKNOWN",
            },
            label="NEGATIVE",
            algorithm="AES-256-GCM",
            role="CONFIGURATION",
            evidence_state="MEASURED",
            use_state="CONFIGURATION_ONLY",
            confidence="LOW",
            desc="Configuration specifies cipher but server does not reload configuration dynamically",
            hard_neg="HN18_CONFIG_WITHOUT_RUNTIME_RELOAD",
        )
        c_idx += 1

    # HN 19: Scanner unavailable must NOT become "not supported"
    for i in range(5):
        cid = f"SYS_HN_SCANNER_UNAVAIL_{c_idx:03d}"
        add_case(
            case_id=cid,
            modality="NETWORK",
            platform="network_prober",
            artifact={
                "target": f"blocked-host-{c_idx}.internal",
                "error": "Connection timed out / EDR driver blocked raw probe socket",
                "scanner_status": "SCANNER_UNAVAILABLE",
            },
            label="INCONCLUSIVE",
            algorithm=None,
            role="UNKNOWN",
            evidence_state="NOT_IN_OBSERVED_SCOPE",
            use_state="SCANNER_UNAVAILABLE",
            confidence="ZERO",
            desc="Network probe blocked by environment; must be SCANNER_UNAVAILABLE, not NOT_SUPPORTED",
            hard_neg="HN19_SCANNER_UNAVAILABLE_DISTINCTION",
        )
        c_idx += 1

    # HN 20: Unknown evidence must NOT become safe/low risk automatically
    for i in range(5):
        cid = f"SYS_HN_UNKNOWN_EVIDENCE_{c_idx:03d}"
        add_case(
            case_id=cid,
            modality="BINARY",
            platform="binary_pipeline",
            artifact={
                "file_name": f"obfuscated_{c_idx}.bin",
                "status": "PACKED_OR_ENCRYPTED_SECTION",
                "entropy": 7.98,
                "symbols_stripped": True,
            },
            label="UNKNOWN",
            algorithm=None,
            role="UNKNOWN",
            evidence_state="UNMEASURED",
            use_state="UNKNOWN",
            confidence="ZERO",
            risk_cat="UNKNOWN_HIGH_RISK",
            desc="High entropy packed binary with stripped symbols; unmeasured must NOT default to safe",
            hard_neg="HN20_UNKNOWN_EVIDENCE_NOT_SAFE",
        )
        c_idx += 1

    return cases


def generate_and_save_dataset(output_path: Optional[str] = None) -> BenchmarkDataset:
    """Generates the full benchmark dataset and writes it to YAML."""
    cases = generate_benchmark_cases()
    modality_counts: Dict[str, int] = {}
    for c in cases:
        modality_counts[c.modality] = modality_counts.get(c.modality, 0) + 1

    d_hash = compute_dataset_hash(cases)
    dataset = BenchmarkDataset(
        dataset_id="ecdat-v4-ground-truth-benchmark",
        dataset_version="1.0.0",
        dataset_type="SYNTHETIC",
        dataset_hash=d_hash,
        cases=cases,
        total_cases=len(cases),
        modality_counts=modality_counts,
        metadata={
            "description": "ECDAT V4 Ground-Truth Benchmark Dataset",
            "disclaimer": "These benchmark results are based on deterministic synthetic controlled fixtures and are not a substitute for validation on real-world production scan data.",
            "generator": "deterministic_fixture_generator",
            "total_cases_generated": len(cases),
        },
    )

    if output_path:
        from .dataset import save_dataset
        save_dataset(dataset, output_path)

    return dataset
