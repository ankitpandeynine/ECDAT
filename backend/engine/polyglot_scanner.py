import re
from typing import List, Dict, Any

# Language-specific sample vulnerable code presets for demo and testing
POLYGLOT_SAMPLES = {
    "python": """# Enterprise Python Service (Payment & Auth)
import hashlib
from cryptography.hazmat.primitives.ciphers import algorithms
import rsa

def verify_transaction(pin: str, account_key: bytes):
    # CWE-327: Obsolete MD5 hash
    token = hashlib.md5(pin.encode()).hexdigest()
    
    # CWE-326: 56-bit DES symmetric cipher
    cipher = algorithms.DES(account_key)
    
    # Quantum-vulnerable 1024-bit RSA keypair
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return token, cipher, key
""",
    "java": """// Enterprise Java Spring / Banking Module
package gov.ntro.crypto.service;

import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class PaymentSecurityProvider {
    public byte[] encryptPayload(byte[] keyBytes, byte[] plaintext) throws Exception {
        // CWE-327: Broken MD5 hashing
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(plaintext);

        // CWE-326: Obsolete DES cipher in ECB mode
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        // Quantum-vulnerable RSA 1024-bit key generation
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);

        return cipher.doFinal(plaintext);
    }
}
""",
    "c_cpp": """// Defense Embedded Telemetry (C / OpenSSL)
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rsa.h>

int secure_transmit(const unsigned char *data, size_t len) {
    // CWE-327: Deprecated OpenSSL MD5
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(data, len, digest);

    // CWE-326: Insecure DES key setup
    DES_cblock key;
    DES_key_schedule schedule;
    DES_set_key_unchecked(&key, &schedule);

    // Quantum-vulnerable RSA key generation (1024-bit)
    BIGNUM *bne = BN_new();
    BN_set_word(bne, RSA_F4);
    RSA *rsa = RSA_new();
    RSA_generate_key_ex(rsa, 1024, bne, NULL);

    return 0;
}
""",
    "golang": """// Cloud Gateway Service (Go)
package gateway

import (
	"crypto/md5"
	"crypto/des"
	"crypto/rsa"
	"crypto/rand"
)

func ProcessSecret(payload []byte) error {
	// CWE-327: Insecure hash
	h := md5.New()
	h.Write(payload)

	// CWE-326: 64-bit block DES cipher
	_, err := des.NewCipher([]byte("12345678"))
	if err != nil {
		return err
	}

	// Quantum-vulnerable RSA 1024 key size
	_, err = rsa.GenerateKey(rand.Reader, 1024)
	return err
}
""",
    "javascript": """// Node.js Microservice (Auth Gateway)
const crypto = require('crypto');

function processCredentials(password, secretKey) {
    // CWE-327: Deprecated MD5 digest
    const hash = crypto.createHash('md5').update(password).digest('hex');

    // CWE-326: Deprecated DES-ECB cipher
    const cipher = crypto.createCipheriv('des-ecb', secretKey, null);

    // Quantum-vulnerable RSA key generation
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024,
    });

    return { hash, cipher, publicKey };
}
"""
}

# Remediation snippets per language for quantum-safe drop-in replacement
POLYGLOT_REMEDIATIONS = {
    "python": """# ==============================================================================
# ECDAT REMEDIATED CODE (Python): NIST Post-Quantum Ready Baseline
# Upgrades: MD5 -> SHA-256 (FIPS 180-4) | DES -> AES-256-GCM (NIST SP 800-38D)
#           RSA-1024 -> Hybrid ML-KEM-768 / RSA-3072 Minimum
# ==============================================================================
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa

def secure_transaction(pin: str, account_key: bytes):
    # REMEDIATED: Collision-resistant SHA-256
    token = hashlib.sha256(pin.encode()).hexdigest()
    
    # REMEDIATED: 256-bit AEAD authenticated encryption (Grover resistant)
    key_256 = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key_256)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, pin.encode(), associated_data=b"NTRO-ECDAT")
    
    # REMEDIATED: Minimum 3072-bit classical RSA / ML-KEM ready key
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return token, ciphertext, key
""",
    "java": """// ==============================================================================
// ECDAT REMEDIATED CODE (Java): NIST FIPS 203 / AES-256-GCM Baseline
// Upgrades: MD5 -> SHA-256 | DES -> AES/GCM/NoPadding | RSA-1024 -> RSA-3072 / ML-KEM
// ==============================================================================
package gov.ntro.crypto.service;

import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class SecurePaymentProvider {
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;

    public byte[] secureEncrypt(byte[] plaintext) throws Exception {
        // REMEDIATED: SHA-256 Digest (FIPS 180-4)
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(plaintext);

        // REMEDIATED: AES-256-GCM Authenticated Encryption
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();

        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        // REMEDIATED: RSA-3072 (128-bit security) or ML-KEM (FIPS 203)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(3072);

        return cipher.doFinal(plaintext);
    }
}
""",
    "c_cpp": """// ==============================================================================
// ECDAT REMEDIATED CODE (C/C++ OpenSSL): NIST SP 800-38D & FIPS 203 Transition
// Upgrades: MD5 -> SHA-256 | DES -> EVP_aes_256_gcm() | RSA-1024 -> RSA >= 3072
// ==============================================================================
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

int secure_transmit_pqc(const unsigned char *data, size_t len) {
    // REMEDIATED: SHA-256
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);

    // REMEDIATED: AES-256-GCM through EVP API (Crypto-Agile)
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32], iv[12];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    // Ciphertext and Tag processing...
    EVP_CIPHER_CTX_free(ctx);

    // REMEDIATED: Minimum 3072-bit RSA or PQC KEM (ML-KEM-768)
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072);

    return 0;
}
""",
    "golang": """// ==============================================================================
// ECDAT REMEDIATED CODE (Go): Post-Quantum Ready AEAD & SHA-256
// ==============================================================================
package gateway

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
)

func ProcessSecretSecure(payload []byte) ([]byte, error) {
	// REMEDIATED: SHA-256
	h := sha256.Sum256(payload)
	_ = h

	// REMEDIATED: AES-256-GCM AEAD
	key := make([]byte, 32) // 256-bit key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, payload, []byte("NTRO-ECDAT"))

	// REMEDIATED: Minimum 3072-bit RSA key
	_, err = rsa.GenerateKey(rand.Reader, 3072)
	return ciphertext, err
}
""",
    "javascript": """// ==============================================================================
// ECDAT REMEDIATED CODE (Node.js): AES-256-GCM & SHA-256 Baseline
// ==============================================================================
const crypto = require('crypto');

function processCredentialsSecure(password, plaintext) {
    // REMEDIATED: SHA-256
    const hash = crypto.createHash('sha256').update(password).digest('hex');

    // REMEDIATED: AES-256-GCM with 96-bit IV
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    // REMEDIATED: Minimum 3072-bit RSA or Ed25519
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 3072,
    });

    return { hash, encrypted, authTag, iv: iv.toString('hex'), publicKey };
}
"""
}

# Rule dictionaries per language targeting common cryptographic vulnerabilities
LANGUAGE_RULES = {
    "python": [
        (r"hashlib\.md5\(|Crypto\.Hash\.MD5|\bmd5\(", "MD5", "Hash Function", "CRITICAL",
         "MD5 collision vulnerabilities (CVE-2004-2761). Cryptographically broken.",
         "Upgrade to SHA-256 (FIPS 180-4) or SHA-3 (FIPS 202).",
         "Vulnerable to Grover search; broken classically."),
        (r"hashlib\.sha1\(|Crypto\.Hash\.SHA1|\bsha1\(", "SHA-1", "Hash Function", "HIGH",
         "SHA-1 is susceptible to collision attacks (SHAttered, 2017). Disallowed by NIST SP 800-131A.",
         "Migrate to SHA-256, SHA-512, or SHA-3.",
         "Broken classically; insufficient collision margin."),
        (r"algorithms\.DES\(|Crypto\.Cipher\.DES|\bDES\.new\(", "DES", "Symmetric Cipher", "CRITICAL",
         "DES has an obsolete 56-bit key length vulnerable to brute force within hours.",
         "Replace with AES-256 (FIPS 197).",
         "Trivially breakable classically; zero quantum defense."),
        (r"algorithms\.TripleDES\(|Crypto\.Cipher\.DES3|\bDES3\.new\(", "3DES", "Symmetric Cipher", "HIGH",
         "Triple-DES (Sweet32 vulnerability) has a 64-bit block size susceptible to collision attacks. Deprecated by NIST.",
         "Replace with AES-256-GCM.",
         "Vulnerable to Sweet32 attacks and Grover's search."),
        (r"algorithms\.ARC4\(|Crypto\.Cipher\.ARC4|\bRC4\(|\bARC4\(", "RC4 / ARC4", "Stream Cipher", "CRITICAL",
         "RC4 stream cipher suffers from severe statistical keystream biases (RFC 7465 prohibitions).",
         "Replace with AES-256-GCM or ChaCha20-Poly1305.",
         "Broken classically."),
        (r"modes\.ECB\(|Crypto\.Cipher\..*\.MODE_ECB|\bMODE_ECB\b", "ECB Mode", "Cipher Mode", "CRITICAL",
         "Electronic Codebook (ECB) leaks plaintext patterns because identical blocks produce identical ciphertexts.",
         "Use Authenticated Encryption (AEAD) such as AES-256-GCM (NIST SP 800-38D).",
         "Insecure cipher mode."),
        (r"key_size\s*=\s*(?:512|1024)\b|RSA\.generate\((?:512|1024)\)", "RSA-1024", "Asymmetric Key", "CRITICAL",
         "RSA key size < 2048 bits is cryptographically broken and disallowed by NIST.",
         "Immediate upgrade: RSA >= 3072 bits. Long term: ML-KEM (FIPS 203) / ML-DSA (FIPS 204).",
         "Shor's algorithm factors RSA keys in polynomial time."),
        (r"key_size\s*=\s*2048\b|RSA\.generate\(2048\)", "RSA-2048", "Asymmetric Key", "HIGH",
         "RSA-2048 offers ~112 bits of classical security and zero resistance to Shor's algorithm.",
         "Transition to NIST Post-Quantum Cryptography standards: ML-KEM (FIPS 203).",
         "Shor's algorithm compromises RSA once CRQC is available.")
    ],
    "java": [
        (r'MessageDigest\.getInstance\(\s*["\']MD5["\']\s*\)', "MD5", "Hash Function", "CRITICAL",
         "MessageDigest MD5 has proven collision vulnerabilities (CWE-327).",
         "Migrate to MessageDigest.getInstance(\"SHA-256\") or SHA-3.",
         "Broken classically; Grover speedup applies."),
        (r'MessageDigest\.getInstance\(\s*["\']SHA-?1["\']\s*\)', "SHA-1", "Hash Function", "HIGH",
         "SHA-1 disallowed for digital signatures and integrity verification per NIST SP 800-131A.",
         "Migrate to SHA-256 or SHA-512.",
         "Vulnerable to collision attacks."),
        (r'Cipher\.getInstance\(\s*["\']DES(?:\/|\b)', "DES", "Symmetric Cipher", "CRITICAL",
         "DES key space (56-bit) is easily cracked via modern brute-force hardware.",
         "Use Cipher.getInstance(\"AES/GCM/NoPadding\") with a 256-bit key.",
         "Trivially breakable classically."),
        (r'Cipher\.getInstance\(\s*["\']DESede(?:\/|\b)', "3DES (Triple-DES)", "Symmetric Cipher", "HIGH",
         "DESede 64-bit block size suffers from Sweet32 collision vulnerabilities.",
         "Migrate to AES-256-GCM.",
         "Grover search weakens effective key strength to ~56 bits."),
        (r'Cipher\.getInstance\(\s*["\'](?:ARCFOUR|RC4)(?:\/|\b)', "RC4", "Stream Cipher", "CRITICAL",
         "RC4 prohibited by RFC 7465 due to keystream statistical biases.",
         "Replace with AES-256-GCM.",
         "Broken classically."),
        (r'Cipher\.getInstance\([^)]*\/ECB\/[^)]*\)', "ECB Mode", "Cipher Mode", "CRITICAL",
         "ECB cipher mode does not provide pattern confidentiality (Tux penguin leakage).",
         "Switch to GCM or CCM authenticated modes.",
         "Insecure cipher mode."),
        (r'kpg\.initialize\(\s*(?:512|1024)\s*\)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "KeyPairGenerator initialized with 1024-bit RSA key. Prohibited by NIST SP 800-131A.",
         "Initialize with at least 3072 bits or adopt BouncyCastle PQC ML-KEM.",
         "Shor's algorithm breaks this in polynomial time.")
    ],
    "c_cpp": [
        (r'\bMD5(?:_Init|_Update|_Final)?\s*\(|#include\s*<openssl/md5\.h>', "MD5", "Hash Function", "CRITICAL",
         "OpenSSL legacy MD5 function call detected (CWE-327).",
         "Upgrade to EVP_DigestInit_ex() with EVP_sha256().",
         "Broken classically."),
        (r'\bSHA1(?:_Init|_Update|_Final)?\s*\(|#include\s*<openssl/sha1\.h>', "SHA-1", "Hash Function", "HIGH",
         "OpenSSL legacy SHA1 call detected. Prohibited per NIST SP 800-131A.",
         "Upgrade to EVP_sha256() or EVP_sha512().",
         "Collision attacks."),
        (r'\bDES_(?:set_key|ecb_encrypt|ncbc_encrypt)\s*\(|EVP_des_ecb\(|EVP_des_cbc\(|#include\s*<openssl/des\.h>', "DES", "Symmetric Cipher", "CRITICAL",
         "DES functions in OpenSSL use 56-bit keys and lack authenticated integrity.",
         "Migrate to EVP_aes_256_gcm().",
         "Trivially broken classically."),
        (r'\bDES_ede3|EVP_des_ede3', "3DES", "Symmetric Cipher", "HIGH",
         "Triple-DES functions in OpenSSL vulnerable to Sweet32 attacks.",
         "Upgrade to EVP_aes_256_gcm().",
         "Sweet32 collision vulnerability."),
        (r'\bRC4\s*\(|EVP_rc4\(|#include\s*<openssl/rc4\.h>', "RC4", "Stream Cipher", "CRITICAL",
         "OpenSSL RC4 call detected (prohibited by RFC 7465).",
         "Use EVP_aes_256_gcm() or EVP_chacha20_poly1305().",
         "Broken classically."),
        (r'RSA_generate_key_ex\([^,]+,\s*(?:512|1024)\b|EVP_PKEY_CTX_set_rsa_keygen_bits\([^,]+,\s*(?:512|1024)\)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "RSA key generated with 1024-bit modulus. Inadequate security margin.",
         "Generate at least 3072-bit keys or implement FIPS 203 ML-KEM.",
         "Vulnerable to Shor's algorithm."),
        (r'RSA_generate_key_ex\([^,]+,\s*2048\b|EVP_PKEY_CTX_set_rsa_keygen_bits\([^,]+,\s*2048\)', "RSA-2048", "Asymmetric Key", "HIGH",
         "RSA-2048 offers ~112-bit classical margin and zero post-quantum resistance.",
         "Transition to NIST PQC standards: ML-KEM (FIPS 203).",
         "Vulnerable to Shor's algorithm once CRQC is available."),
        (r'EVP_aes_256_gcm\(\)', "AES-256-GCM", "Symmetric Cipher", "LOW",
         "NIST SP 800-38D compliant Authenticated Encryption with Associated Data (AEAD).",
         "Current standard compliant. Retain 256-bit key length.",
         "Maintains 128-bit security against Grover's algorithm."),
        (r'EVP_KEM_fetch\([^)]*ML-KEM|EVP_PKEY_ML_KEM|OQS_KEM_new\([^)]*ML-KEM', "ML-KEM", "Asymmetric Key", "LOW",
         "Post-quantum lattice-based Key Encapsulation Mechanism (NIST FIPS 203).",
         "Quantum-resistant standard. Ready for production deployment.",
         "Quantum-secure against Shor's algorithm."),
        (r'EVP_SIGNATURE_fetch\([^)]*ML-DSA|EVP_PKEY_ML_DSA|OQS_SIG_new\([^)]*ML-DSA', "ML-DSA", "Digital Signature", "LOW",
         "Post-quantum lattice-based Digital Signature Algorithm (NIST FIPS 204).",
         "Quantum-resistant signature standard.",
         "Quantum-secure against Shor's algorithm."),
        (r'BCryptCreateHash\([^,]+,\s*BCRYPT_MD5_ALGORITHM|CryptCreateHash\([^,]+,\s*CALG_MD5', "MD5 (CNG)", "Hash Function", "CRITICAL",
         "Windows CryptoAPI / CNG MD5 algorithm instantiation.",
         "Switch to BCRYPT_SHA256_ALGORITHM.",
         "Broken classically."),
        (r'BCryptGenerateSymmetricKey\([^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*BCRYPT_DES_ALGORITHM', "DES (CNG)", "Symmetric Cipher", "CRITICAL",
         "Windows CNG DES algorithm instantiation.",
         "Upgrade to BCRYPT_AES_ALGORITHM with BCRYPT_CHAIN_MODE_GCM.",
         "Broken classically.")
    ],
    "golang": [
        (r'"crypto/md5"|md5\.New\(|md5\.Sum\(', "MD5", "Hash Function", "CRITICAL",
         "Go crypto/md5 import or call detected.",
         "Use crypto/sha256.New() or crypto/sha512.",
         "Broken classically."),
        (r'"crypto/des"|des\.NewCipher\(', "DES", "Symmetric Cipher", "CRITICAL",
         "Go crypto/des call detected. 56-bit key length is deprecated.",
         "Use crypto/aes with NewGCM().",
         "Broken classically."),
        (r'"crypto/rc4"|rc4\.NewCipher\(', "RC4", "Stream Cipher", "CRITICAL",
         "Go crypto/rc4 call detected (RFC 7465 violation).",
         "Use crypto/cipher NewGCM() or golang.org/x/crypto/chacha20poly1305.",
         "Broken classically."),
        (r'rsa\.GenerateKey\([^,]+,\s*(?:512|1024)\b', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "rsa.GenerateKey called with < 2048 bit size.",
         "Upgrade key size to 3072 bits or adopt Post-Quantum hybrid key encapsulation.",
         "Vulnerable to Shor's algorithm.")
    ],
    "javascript": [
        (r"createHash\(\s*['\"]md5['\"]\s*\)", "MD5", "Hash Function", "CRITICAL",
         "Node.js crypto.createHash('md5') detected.",
         "Migrate to crypto.createHash('sha256') or 'sha512'.",
         "Broken classically."),
        (r"createHash\(\s*['\"]sha1['\"]\s*\)", "SHA-1", "Hash Function", "HIGH",
         "Node.js crypto.createHash('sha1') detected.",
         "Migrate to crypto.createHash('sha256').",
         "Collision attacks."),
        (r"createCipher(?:iv)?\(\s*['\"]des", "DES", "Symmetric Cipher", "CRITICAL",
         "Node.js DES cipher creation detected.",
         "Upgrade to crypto.createCipheriv('aes-256-gcm', key, iv).",
         "Broken classically."),
        (r"createCipher(?:iv)?\(\s*['\"]rc4", "RC4", "Stream Cipher", "CRITICAL",
         "Node.js RC4 cipher creation detected.",
         "Upgrade to aes-256-gcm or chacha20-poly1305.",
         "Broken classically."),
        (r"modulusLength\s*:\s*(?:512|1024)\b", "RSA-1024", "Asymmetric Key", "CRITICAL",
         "RSA key pair generated with modulusLength < 2048.",
         "Set modulusLength to at least 3072 or use Ed25519.",
         "Vulnerable to Shor's algorithm.")
    ]
}

def mask_comments(source):
    """Replace comments with whitespace while preserving strings and source lines."""
    pattern = r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)|(//[^\n]*|/\*.*?\*/)'
    def replace(match):
        if match.group(1):
            return match.group(1)
        return ''.join('\n' if c == '\n' else ' ' for c in match.group(0))
    return re.sub(pattern, replace, source, flags=re.DOTALL)


def scan_polyglot_code(source_code: str, language: str = 'python') -> Dict[str, Any]:
    lang = language.lower().strip()
    if lang not in LANGUAGE_RULES:
        raise ValueError('Unsupported language')
    cleaned = mask_comments(source_code) if lang != 'python' else source_code
    lines = source_code.splitlines()
    findings = []
    for pattern, primitive, category, severity, issue, recommendation, quantum_risk in LANGUAGE_RULES[lang]:
        for match in re.finditer(pattern, cleaned, re.IGNORECASE):
            line = cleaned.count('\n', 0, match.start()) + 1
            findings.append({'line': line, 'code': lines[line - 1].strip(), 'primitive': primitive,
                'category': category, 'severity': severity, 'issue': issue,
                'nist_recommendation': recommendation, 'quantum_risk': quantum_risk, 'language': lang})
    findings.sort(key=lambda f: f['line'])
    return {'language': lang, 'findings': findings, 'total_findings': len(findings),
            'critical_count': sum(f['severity'] == 'CRITICAL' for f in findings),
            'high_count': sum(f['severity'] == 'HIGH' for f in findings), 'remediation': ''}
