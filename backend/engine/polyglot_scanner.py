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
""",
    "rust": """// Rust Embedded IoT Firmware
use md5;
use des::Des;
use rsa::{RsaPrivateKey, pkcs1v15};
use sha1::Sha1;

fn process_telemetry(data: &[u8]) -> Vec<u8> {
    // CWE-327: Broken MD5 hash
    let digest = md5::compute(data);

    // CWE-327: Deprecated SHA-1
    let mut hasher = Sha1::new();

    // CWE-326: Obsolete DES cipher
    let cipher = Des::new_from_slice(b"12345678").unwrap();

    // Quantum-vulnerable RSA-1024
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 1024).unwrap();

    digest.to_vec()
}
""",
    "csharp": """// C# .NET Banking API
using System.Security.Cryptography;

public class PaymentProcessor {
    public byte[] ProcessTransaction(byte[] payload) {
        // CWE-327: Broken MD5 hash
        using var md5 = MD5.Create();
        byte[] hash = md5.ComputeHash(payload);

        // CWE-327: Deprecated SHA-1
        using var sha1 = SHA1.Create();
        byte[] sigHash = sha1.ComputeHash(payload);

        // CWE-326: Obsolete DES cipher
        using var des = DESCryptoServiceProvider.Create();

        // CWE-326: Weak 3DES
        using var tdes = TripleDESCryptoServiceProvider.Create();

        // Quantum-vulnerable RSA-1024
        using var rsa = new RSACryptoServiceProvider(1024);

        return hash;
    }
}
""",
    "php": """<?php
// PHP E-Commerce Payment Module
function processPayment($cardNumber, $amount) {
    // CWE-327: Broken MD5 hash
    $token = md5($cardNumber . $amount);

    // CWE-327: Deprecated SHA-1
    $signature = sha1($cardNumber);

    // CWE-326: Obsolete DES cipher
    $encrypted = openssl_encrypt($cardNumber, 'des-ecb', 'secretkey');

    // CWE-326: Weak RC4 stream cipher
    $rc4_data = openssl_encrypt($cardNumber, 'rc4', 'secretkey');

    // Quantum-vulnerable RSA-1024
    $config = array("private_key_bits" => 1024, "private_key_type" => OPENSSL_KEYTYPE_RSA);
    $key = openssl_pkey_new($config);

    return $token;
}
""",
    "ruby": """# Ruby on Rails Banking Controller
require 'openssl'
require 'digest'

class PaymentController < ApplicationController
  def process_transaction
    # CWE-327: Broken MD5 hash
    token = Digest::MD5.hexdigest(params[:card_number])

    # CWE-327: Deprecated SHA-1
    sig = Digest::SHA1.hexdigest(params[:payload])

    # CWE-326: Obsolete DES cipher
    cipher = OpenSSL::Cipher::DES.new('CBC')

    # CWE-326: Weak RC4
    rc4 = OpenSSL::Cipher::RC4.new

    # Quantum-vulnerable RSA-1024
    key = OpenSSL::PKey::RSA.generate(1024)

    render json: { token: token }
  end
end
""",
    "swift": """// Swift iOS Banking App
import CommonCrypto
import Security

func processTransaction(data: Data) -> Data? {
    // CWE-327: Broken MD5 hash
    var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
    CC_MD5((data as NSData).bytes, CC_LONG(data.count), &digest)

    // CWE-327: Deprecated SHA-1
    var sha1Digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    CC_SHA1((data as NSData).bytes, CC_LONG(data.count), &sha1Digest)

    // Quantum-vulnerable RSA-1024
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: 1024
    ]
    var error: Unmanaged<CFError>?
    let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)

    return Data(digest)
}
""",
    "kotlin": """// Kotlin Android Banking App
import java.security.MessageDigest
import java.security.KeyPairGenerator
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class PaymentService {
    fun processPayment(payload: ByteArray): ByteArray {
        // CWE-327: Broken MD5 hash
        val md = MessageDigest.getInstance("MD5")
        val hash = md.digest(payload)

        // CWE-327: Deprecated SHA-1
        val sha1 = MessageDigest.getInstance("SHA-1")

        // CWE-326: Obsolete DES cipher
        val cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
        val key = SecretKeySpec(ByteArray(8), "DES")

        // Quantum-vulnerable RSA-1024
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(1024)

        return hash
    }
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
""",
    "rust": """// ==============================================================================
// ECDAT REMEDIATED CODE (Rust): Post-Quantum Ready AEAD & SHA-256
// ==============================================================================
use sha2::{Sha256, Digest};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rsa::{RsaPrivateKey, pkcs1v15};

pub fn process_telemetry_secure(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // REMEDIATED: SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let _hash = hasher.finalize();

    // REMEDIATED: AES-256-GCM AEAD
    let key = Aes256Gcm::generate_key(&mut rand::thread_rng());
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(b"unique_nonce_12b");
    let ciphertext = cipher.encrypt(nonce, data)?;

    // REMEDIATED: 3072-bit RSA or ML-KEM-768
    let mut rng = rand::thread_rng();
    let _priv_key = RsaPrivateKey::new(&mut rng, 3072)?;

    Ok(ciphertext)
}
""",
    "csharp": """// ==============================================================================
// ECDAT REMEDIATED CODE (C# .NET): AES-256-GCM & SHA-256 Baseline
// ==============================================================================
using System;
using System.Security.Cryptography;

public class SecurePaymentProcessor {
    public byte[] ProcessTransactionSecure(byte[] payload) {
        // REMEDIATED: SHA-256
        using var sha256 = SHA256.Create();
        byte[] hash = sha256.ComputeHash(payload);

        // REMEDIATED: AES-256-GCM
        byte[] key = new byte[32];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[12];
        RandomNumberGenerator.Fill(nonce);
        byte[] tag = new byte[16];
        byte[] ciphertext = new byte[payload.Length];
        using var aesGcm = new AesGcm(key, 16);
        aesGcm.Encrypt(nonce, payload, ciphertext, tag);

        // REMEDIATED: Minimum 3072-bit RSA
        using var rsa = new RSACryptoServiceProvider(3072);

        return ciphertext;
    }
}
""",
    "php": """<?php
// ==============================================================================
// ECDAT REMEDIATED CODE (PHP): AES-256-GCM & SHA-256
// ==============================================================================
function processPaymentSecure($cardNumber, $amount) {
    // REMEDIATED: SHA-256
    $token = hash('sha256', $cardNumber . $amount);

    // REMEDIATED: AES-256-GCM
    $key = openssl_random_pseudo_bytes(32);
    $iv = openssl_random_pseudo_bytes(12);
    $tag = "";
    $encrypted = openssl_encrypt($cardNumber, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);

    // REMEDIATED: 3072-bit RSA
    $config = array("private_key_bits" => 3072, "private_key_type" => OPENSSL_KEYTYPE_RSA);
    $keyPair = openssl_pkey_new($config);

    return ['token' => $token, 'encrypted' => base64_encode($encrypted), 'tag' => base64_encode($tag)];
}
""",
    "ruby": """# ==============================================================================
# ECDAT REMEDIATED CODE (Ruby): AES-256-GCM & SHA-256
# ==============================================================================
require 'openssl'
require 'digest'

class SecurePaymentController
  def process_transaction_secure(payload)
    # REMEDIATED: SHA-256
    digest = Digest::SHA256.hexdigest(payload)

    # REMEDIATED: AES-256-GCM
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    key = cipher.random_key
    iv = cipher.random_iv
    cipher.auth_data = 'ECDAT-AUTH'
    encrypted = cipher.update(payload) + cipher.final
    tag = cipher.auth_tag

    # REMEDIATED: Minimum 3072-bit RSA
    rsa_key = OpenSSL::PKey::RSA.generate(3072)

    { digest: digest, encrypted: encrypted, tag: tag }
  end
end
""",
    "swift": """// ==============================================================================
// ECDAT REMEDIATED CODE (Swift / CryptoKit): Modern AEAD & SHA-256
// ==============================================================================
import CryptoKit
import Foundation

func processTransactionSecure(data: Data) throws -> Data {
    // REMEDIATED: SHA-256
    let hash = SHA256.hash(data: data)
    _ = hash

    // REMEDIATED: AES-GCM 256-bit
    let symmetricKey = SymmetricKey(size: .bits256)
    let sealedBox = try AES.GCM.seal(data, using: symmetricKey)

    // REMEDIATED: Curve25519 or 3072-bit RSA
    let privateKey = Curve25519.Signing.PrivateKey()
    _ = privateKey

    return sealedBox.combined ?? Data()
}
""",
    "kotlin": """// ==============================================================================
// ECDAT REMEDIATED CODE (Kotlin): AES-256-GCM & SHA-256 Baseline
// ==============================================================================
import java.security.MessageDigest
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SecurePaymentService {
    fun processPaymentSecure(payload: ByteArray): ByteArray {
        // REMEDIATED: SHA-256
        val md = MessageDigest.getInstance("SHA-256")
        val hash = md.digest(payload)

        // REMEDIATED: AES-256-GCM
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val key = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(payload)

        // REMEDIATED: Minimum 3072-bit RSA or Post-Quantum BouncyCastle
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(3072)

        return ciphertext
    }
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
         "Electronic Codebook (ECB) mode lacks cryptographic diffusion and reveals plaintext patterns.",
         "Switch to Authenticated Encryption: AES-256-GCM or ChaCha20-Poly1305.",
         "Exposes structured data under quantum side-channel and chosen-ciphertext attacks."),
        (r"rsa\.generate_private_key\([^)]*key_size\s*=\s*(?:512|1024)\b|RSA\.generate\(\s*(?:512|1024)\b", "RSA-1024", "Asymmetric Key", "CRITICAL",
         "RSA-1024 is vulnerable to classical factorisation attacks and broken in minutes by Shor's algorithm.",
         "Deploy Post-Quantum ML-KEM (FIPS 203) or upgrade to RSA-3072 as a transitional baseline.",
         "Critical vulnerability: factored in polynomial time via Shor's algorithm (O((log N)^3))."),
        (r"rsa\.generate_private_key\([^)]*key_size\s*=\s*2048\b|RSA\.generate\(\s*2048\b", "RSA-2048", "Asymmetric Key", "HIGH",
         "RSA-2048 has ~112 bits of classical security margin. Deprecated for use beyond 2030 by NIST SP 800-131A.",
         "Adopt ML-KEM (FIPS 203) Key Encapsulation or minimum RSA-3072 transitional baseline.",
         "Subject to Harvest Now, Decrypt Later (HNDL). Vulnerable to Shor's algorithm."),
        (r"ec\.generate_private_key\([^)]*(?:SECP256R1|SECP384R1|SECP521R1|SECP256K1)\(\)|ECC\.generate\([^)]*curve=['\"](?:p-256|p-384|p-521)['\"]\)", "ECC", "Asymmetric Key", "HIGH",
         "Elliptic Curve Cryptography (ECDSA/ECDH) will be broken by Shor's algorithm on a Cryptanalytically Relevant Quantum Computer.",
         "Migrate to ML-DSA (FIPS 204) for digital signatures and ML-KEM (FIPS 203) for key agreement.",
         "Shor's algorithm computes discrete logarithms on elliptic curves in O((log N)^3) operations."),
        (r"algorithms\.AES\(.*modes\.GCM\(", "AES-256-GCM", "Symmetric Cipher", "LOW",
         "AES-256-GCM is the gold standard for symmetric authenticated encryption (NIST SP 800-38D).",
         "Compliant with current NIST guidance. Maintain 256-bit key sizes.",
         "Grover's algorithm halves effective symmetric key length; 256-bit keys maintain 128-bit quantum security."),
        (r"hashes\.SHA256\(\)|hashes\.SHA384\(\)|hashes\.SHA512\(\)|hashes\.SHA3_256\(\)", "SHA-256 / SHA-3", "Hash Function", "LOW",
         "NIST FIPS 180-4 and FIPS 202 approved secure cryptographic hash functions.",
         "Standard compliant for collision resistance.",
         "Grover's algorithm reduces collision security margin to N/3; SHA-256 retains >= 128-bit collision resistance."),
        (r"oqs\.KeyEncapsulation\(['\"](?:ML-KEM|Kyber)['\"]\)|pqc\.MLKEM\b|fips203\.MLKEM\b", "ML-KEM", "Asymmetric Key", "LOW",
         "NIST FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism.",
         "Production post-quantum standard. Retain and monitor NIST guidance.",
         "Quantum-secure: based on hardness of Learning With Errors (MLWE).")
    ],
    "java": [
        (r'MessageDigest\.getInstance\(\s*["\']MD5["\']\s*\)', "MD5", "Hash Function", "CRITICAL",
         "Java MessageDigest MD5 algorithm detected (CWE-327). Broken collision resistance.",
         "Upgrade to MessageDigest.getInstance(\"SHA-256\").",
         "Broken classically; vulnerable to Grover search."),
        (r'MessageDigest\.getInstance\(\s*["\']SHA-?1["\']\s*\)', "SHA-1", "Hash Function", "HIGH",
         "Java MessageDigest SHA-1 algorithm detected. Deprecated per NIST SP 800-131A.",
         "Upgrade to MessageDigest.getInstance(\"SHA-256\") or SHA-512.",
         "Broken classically; vulnerable to collision attacks."),
        (r'Cipher\.getInstance\(\s*["\']DES(?:\b|/)', "DES", "Symmetric Cipher", "CRITICAL",
         "Java Cipher DES instantiation detected. Obsolete 56-bit key length.",
         "Upgrade to Cipher.getInstance(\"AES/GCM/NoPadding\") with 256-bit keys.",
         "Trivially broken classically; zero quantum resistance."),
        (r'Cipher\.getInstance\(\s*["\']DESede(?:\b|/)', "3DES", "Symmetric Cipher", "HIGH",
         "Triple-DES instantiation detected in Java (Sweet32 vulnerability).",
         "Upgrade to Cipher.getInstance(\"AES/GCM/NoPadding\").",
         "Vulnerable to Sweet32 collision attacks."),
        (r'Cipher\.getInstance\(\s*["\'](?:ARCFOUR|RC4)(?:\b|/)', "RC4", "Stream Cipher", "CRITICAL",
         "Java RC4/ARCFOUR Cipher detected (RFC 7465 violation).",
         "Replace with AES-GCM or ChaCha20-Poly1305.",
         "Broken classically."),
        (r'Cipher\.getInstance\(\s*["\'][^"\']+/ECB/[^"\']*["\']\)', "ECB Mode", "Cipher Mode", "CRITICAL",
         "Java Cipher with ECB mode detected. Lacks cryptographic diffusion.",
         "Migrate to AES/GCM/NoPadding.",
         "Exposes ciphertext block patterns."),
        (r'KeyPairGenerator\.getInstance\(\s*["\']RSA["\']\s*\).*(?:initialize\(\s*(?:512|1024)|1024)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "Java RSA KeyPairGenerator initialized with < 2048 bits.",
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
    ],
    "rust": [
        (r'\bmd5::compute\(|use\s+md5\b', "MD5", "Hash Function", "CRITICAL",
         "Rust md5 crate usage detected (CWE-327). Broken collision resistance.",
         "Migrate to sha2::Sha256 or sha3::Sha3_256.",
         "Broken classically."),
        (r'\bsha1::Sha1\b|use\s+sha1\b', "SHA-1", "Hash Function", "HIGH",
         "Rust sha1 crate usage detected. Disallowed by NIST SP 800-131A.",
         "Migrate to sha2::Sha256 or sha3::Sha3_256.",
         "Collision attacks."),
        (r'\bdes::Des\b|use\s+des\b', "DES", "Symmetric Cipher", "CRITICAL",
         "Rust des crate usage detected. Obsolete 56-bit key length.",
         "Replace with aes_gcm::Aes256Gcm.",
         "Trivially broken classically."),
        (r'\brc4::Rc4\b|use\s+rc4\b', "RC4", "Stream Cipher", "CRITICAL",
         "Rust rc4 crate usage detected (prohibited by RFC 7465).",
         "Migrate to aes_gcm or chacha20poly1305.",
         "Broken classically."),
        (r'RsaPrivateKey::new\([^,]+,\s*(?:512|1024)\b|Rsa::generate\((?:512|1024)\)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "Rust RSA key generated with < 2048 bit size.",
         "Upgrade key size to 3072 bits or adopt Post-Quantum hybrid KEM (ML-KEM-768).",
         "Vulnerable to Shor's algorithm.")
    ],
    "csharp": [
        (r'MD5\.Create\(\)|MD5CryptoServiceProvider\b', "MD5", "Hash Function", "CRITICAL",
         "C# .NET MD5 algorithm detected (CWE-327).",
         "Upgrade to SHA256.Create() or SHA512.Create().",
         "Broken classically."),
        (r'SHA1\.Create\(\)|SHA1CryptoServiceProvider\b', "SHA-1", "Hash Function", "HIGH",
         "C# .NET SHA-1 algorithm detected (NIST SP 800-131A disallowed).",
         "Migrate to SHA256.Create().",
         "Collision attacks."),
        (r'DESCryptoServiceProvider\b|DES\.Create\(\)', "DES", "Symmetric Cipher", "CRITICAL",
         "C# .NET DES cipher detected. 56-bit key size is insecure.",
         "Migrate to Aes.Create() with GCM mode.",
         "Broken classically."),
        (r'TripleDESCryptoServiceProvider\b|TripleDES\.Create\(\)', "3DES", "Symmetric Cipher", "HIGH",
         "C# .NET 3DES cipher detected (Sweet32 vulnerability).",
         "Migrate to Aes.Create() with GCM mode.",
         "Vulnerable to Sweet32 and Grover's algorithm."),
        (r'RC4CryptoServiceProvider\b|\bRC4\b', "RC4", "Stream Cipher", "CRITICAL",
         "C# .NET RC4 stream cipher detected (RFC 7465).",
         "Migrate to AES-GCM or ChaCha20-Poly1305.",
         "Broken classically."),
        (r'new\s+RSACryptoServiceProvider\(\s*(?:512|1024)\s*\)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "C# .NET RSA key created with < 2048 bit length.",
         "Use minimum 3072 bits: new RSACryptoServiceProvider(3072).",
         "Vulnerable to Shor's algorithm.")
    ],
    "php": [
        (r'\bmd5\s*\(', "MD5", "Hash Function", "CRITICAL",
         "PHP md5() call detected (CWE-327).",
         "Upgrade to hash('sha256', ...) or password_hash().",
         "Broken classically."),
        (r'\bsha1\s*\(', "SHA-1", "Hash Function", "HIGH",
         "PHP sha1() call detected.",
         "Migrate to hash('sha256', ...).",
         "Collision attacks."),
        (r'openssl_encrypt\([^,]+,\s*[\'"](?:des|des-ecb|des-cbc|3des)[\'"]', "DES", "Symmetric Cipher", "CRITICAL",
         "PHP OpenSSL DES/3DES cipher detected.",
         "Upgrade to openssl_encrypt(..., 'aes-256-gcm', ...).",
         "Broken classically."),
        (r'openssl_encrypt\([^,]+,\s*[\'"]rc4[\'"]', "RC4", "Stream Cipher", "CRITICAL",
         "PHP OpenSSL RC4 cipher detected.",
         "Migrate to aes-256-gcm or chacha20-poly1305.",
         "Broken classically."),
        (r'[\'"]private_key_bits[\'"]\s*=>\s*(?:512|1024)\b', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "PHP RSA key configuration with < 2048 bit size.",
         "Set 'private_key_bits' => 3072.",
         "Vulnerable to Shor's algorithm.")
    ],
    "ruby": [
        (r'Digest::MD5\b', "MD5", "Hash Function", "CRITICAL",
         "Ruby Digest::MD5 detected (CWE-327).",
         "Upgrade to Digest::SHA256.",
         "Broken classically."),
        (r'Digest::SHA1\b', "SHA-1", "Hash Function", "HIGH",
         "Ruby Digest::SHA1 detected.",
         "Migrate to Digest::SHA256.",
         "Collision attacks."),
        (r'OpenSSL::Cipher::DES\b|OpenSSL::Cipher(?:\.new)?\(\s*[\'"]des', "DES", "Symmetric Cipher", "CRITICAL",
         "Ruby OpenSSL DES cipher detected.",
         "Upgrade to OpenSSL::Cipher.new('aes-256-gcm').",
         "Broken classically."),
        (r'OpenSSL::Cipher::RC4\b|OpenSSL::Cipher(?:\.new)?\(\s*[\'"]rc4', "RC4", "Stream Cipher", "CRITICAL",
         "Ruby OpenSSL RC4 cipher detected.",
         "Upgrade to aes-256-gcm.",
         "Broken classically."),
        (r'OpenSSL::PKey::RSA(?:\.new|\.generate)\(\s*(?:512|1024)\s*\)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "Ruby OpenSSL RSA key generated with < 2048 bits.",
         "Generate at least 3072 bits: OpenSSL::PKey::RSA.generate(3072).",
         "Vulnerable to Shor's algorithm.")
    ],
    "swift": [
        (r'CC_MD5\b', "MD5", "Hash Function", "CRITICAL",
         "Apple CommonCrypto CC_MD5 detected (CWE-327).",
         "Migrate to CryptoKit SHA256.hash(data:).",
         "Broken classically."),
        (r'CC_SHA1\b', "SHA-1", "Hash Function", "HIGH",
         "Apple CommonCrypto CC_SHA1 detected.",
         "Migrate to CryptoKit SHA256.hash(data:).",
         "Collision attacks."),
        (r'kCCAlgorithmDES\b|kCCAlgorithm3DES\b', "DES", "Symmetric Cipher", "CRITICAL",
         "Apple CommonCrypto DES/3DES cipher detected.",
         "Migrate to CryptoKit AES.GCM.",
         "Broken classically."),
        (r'kCCAlgorithmRC4\b', "RC4", "Stream Cipher", "CRITICAL",
         "Apple CommonCrypto RC4 cipher detected.",
         "Migrate to CryptoKit ChaChaPoly or AES.GCM.",
         "Broken classically."),
        (r'kSecAttrKeyTypeRSA\b.*?(?:512|1024)|kSecAttrKeySizeInBits\s*as\s*String:\s*(?:512|1024)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "Apple Security framework RSA key generated with < 2048 bits.",
         "Set kSecAttrKeySizeInBits to 3072 or use Curve25519.",
         "Vulnerable to Shor's algorithm.")
    ],
    "kotlin": [
        (r'MessageDigest\.getInstance\(\s*["\']MD5["\']\s*\)', "MD5", "Hash Function", "CRITICAL",
         "Kotlin/Java MessageDigest MD5 detected (CWE-327).",
         "Upgrade to MessageDigest.getInstance(\"SHA-256\").",
         "Broken classically."),
        (r'MessageDigest\.getInstance\(\s*["\']SHA-?1["\']\s*\)', "SHA-1", "Hash Function", "HIGH",
         "Kotlin/Java MessageDigest SHA-1 detected.",
         "Upgrade to MessageDigest.getInstance(\"SHA-256\").",
         "Collision attacks."),
        (r'Cipher\.getInstance\(\s*["\']DES(?:\b|/)', "DES", "Symmetric Cipher", "CRITICAL",
         "Kotlin/Java DES Cipher detected.",
         "Upgrade to Cipher.getInstance(\"AES/GCM/NoPadding\").",
         "Broken classically."),
        (r'Cipher\.getInstance\(\s*["\']DESede(?:\b|/)', "3DES", "Symmetric Cipher", "HIGH",
         "Kotlin/Java Triple-DES Cipher detected.",
         "Upgrade to AES/GCM/NoPadding.",
         "Sweet32 collision vulnerability."),
        (r'Cipher\.getInstance\(\s*["\']RC4(?:\b|/)|\bARC4\b', "RC4", "Stream Cipher", "CRITICAL",
         "Kotlin/Java RC4 Cipher detected.",
         "Upgrade to AES-GCM or ChaCha20-Poly1305.",
         "Broken classically."),
        (r'kpg\.initialize\(\s*(?:512|1024)\s*\)|KeyPairGenerator\.getInstance\(\s*["\']RSA["\']\s*\).*(?:512|1024)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "Kotlin/Java RSA key initialized with < 2048 bits.",
         "Initialize with at least 3072 bits or adopt BouncyCastle PQC ML-KEM.",
         "Vulnerable to Shor's algorithm.")
    ],
    "universal": [
        (r'\bmd5\b', "MD5", "Hash Function", "CRITICAL",
         "MD5 algorithm reference detected (CWE-327).",
         "Upgrade to SHA-256 or SHA-3.",
         "Broken classically."),
        (r'\bsha-?1\b', "SHA-1", "Hash Function", "HIGH",
         "SHA-1 algorithm reference detected.",
         "Migrate to SHA-256 or SHA-512.",
         "Collision attacks."),
        (r'\bdes\b|\bdes3\b|\btriple-?des\b', "DES", "Symmetric Cipher", "CRITICAL",
         "DES/3DES legacy cipher detected.",
         "Upgrade to AES-256-GCM.",
         "Broken classically."),
        (r'\brc4\b|\barcfour\b', "RC4", "Stream Cipher", "CRITICAL",
         "RC4 stream cipher detected.",
         "Upgrade to AES-256-GCM or ChaCha20-Poly1305.",
         "Broken classically."),
        (r'\brsa[-_ ]?(?:512|1024)\b|\brsa\b.*?(?:512|1024)', "RSA-1024", "Asymmetric Key", "CRITICAL",
         "Legacy RSA key configuration with < 2048 bit size.",
         "Upgrade key size to 3072 bits or adopt Post-Quantum ML-KEM.",
         "Vulnerable to Shor's algorithm."),
        (r'\b(?:mode_)?ecb\b', "ECB Mode", "Cipher Mode", "CRITICAL",
         "Electronic Codebook (ECB) mode lacks cryptographic diffusion.",
         "Adopt Authenticated Encryption (AEAD) such as AES-GCM.",
         "Vulnerable to pattern leakage.")
    ]
}

LANGUAGE_ALIASES = {
    'c': 'c_cpp',
    'cpp': 'c_cpp',
    'c++': 'c_cpp',
    'c_cpp': 'c_cpp',
    'py': 'python',
    'python': 'python',
    'java': 'java',
    'golang': 'golang',
    'go': 'golang',
    'javascript': 'javascript',
    'js': 'javascript',
    'ts': 'javascript',
    'typescript': 'javascript',
    'node': 'javascript',
    'rust': 'rust',
    'rs': 'rust',
    'csharp': 'csharp',
    'cs': 'csharp',
    'c#': 'csharp',
    'dotnet': 'csharp',
    'php': 'php',
    'ruby': 'ruby',
    'rb': 'ruby',
    'swift': 'swift',
    'kotlin': 'kotlin',
    'kt': 'kotlin',
    'universal': 'universal',
    'generic': 'universal',
    'unknown': 'universal',
}

_COMMENT_MASK_RE = re.compile(
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)|(//[^\n]*|/\*.*?\*/)',
    flags=re.DOTALL
)

# Precompile language rule regexes once at module load
_COMPILED_LANGUAGE_RULES = {
    lang: [
        (re.compile(pattern, re.IGNORECASE), primitive, category, severity, issue, recommendation, quantum_risk)
        for pattern, primitive, category, severity, issue, recommendation, quantum_risk in rules
    ]
    for lang, rules in LANGUAGE_RULES.items()
}


def mask_comments(source):
    """Replace comments with whitespace while preserving strings and source lines."""
    def replace(match):
        if match.group(1):
            return match.group(1)
        return ''.join('\n' if c == '\n' else ' ' for c in match.group(0))
    return _COMMENT_MASK_RE.sub(replace, source)


def scan_polyglot_code(source_code: str, language: str = 'python', fallback_to_universal: bool = True) -> Dict[str, Any]:
    raw_lang = language.lower().strip()
    lang = LANGUAGE_ALIASES.get(raw_lang, raw_lang)
    if lang not in _COMPILED_LANGUAGE_RULES:
        if fallback_to_universal:
            lang = 'universal'
        else:
            raise ValueError('Unsupported language')
    cleaned = mask_comments(source_code) if lang != 'python' else source_code
    lines = source_code.splitlines()

    # Precalculate newline offsets for fast O(log L) line number lookup via bisect
    import bisect
    newline_offsets = [0]
    for idx, char in enumerate(cleaned):
        if char == '\n':
            newline_offsets.append(idx + 1)

    findings = []
    for compiled_re, primitive, category, severity, issue, recommendation, quantum_risk in _COMPILED_LANGUAGE_RULES[lang]:
        for match in compiled_re.finditer(cleaned):
            line = bisect.bisect_right(newline_offsets, match.start())
            findings.append({
                'line': line,
                'code': lines[line - 1].strip() if 0 < line <= len(lines) else '',
                'primitive': primitive,
                'category': category,
                'severity': severity,
                'issue': issue,
                'nist_recommendation': recommendation,
                'quantum_risk': quantum_risk,
                'language': lang
            })
    findings.sort(key=lambda f: f['line'])
    return {'language': lang, 'findings': findings, 'total_findings': len(findings),
            'critical_count': sum(f['severity'] == 'CRITICAL' for f in findings),
            'high_count': sum(f['severity'] == 'HIGH' for f in findings),
            'samples': POLYGLOT_SAMPLES.get(lang, ''),
            'remediated_samples': POLYGLOT_REMEDIATIONS.get(lang, '')}
