"use client";

import { useState, useEffect, useMemo, useCallback } from "react";
import {
  Cpu,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Hourglass,
  Clock,
  ArrowRight,
  Terminal,
  Zap,
  Flame,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  Code2,
  Network,
  Binary,
  FileCode,
  Lock,
  Layers,
  Sparkles,
  ExternalLink,
  Info,
} from "lucide-react";

interface QuantumRiskProps {
  projectId: string;
  project?: any;
  onNavigateTab?: (tab: string, filter?: string) => void;
}

// ─── CLIENT-SIDE INSTANT CODE SCANNER PATTERNS (<100ms) ─────────────
interface ScanRule {
  id: string;
  name: string;
  regex: RegExp;
  algorithm: string;
  tier: "FIX_NOW" | "URGENT" | "PLAN" | "SAFE";
  vulnerability: string;
  replacement: string;
  standard: string;
  category: "CLASSICAL" | "SHOR" | "GROVER" | "PQC_SAFE";
}

const CODE_SCAN_RULES: ScanRule[] = [
  // 1. hashlib.md5
  {
    id: "py-md5",
    name: "hashlib.md5",
    regex: /\bhashlib\.md5\s*\(/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004 (Wang & Yu)",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 (Disallowed) / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 2. hashlib.sha1 / sha
  {
    id: "py-sha1",
    name: "hashlib.sha1",
    regex: /\bhashlib\.(sha1|sha)\s*\(/i,
    algorithm: "SHA-1",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks (SHAttered 2017)",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 (Disallowed) / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 3. RSA.generate(1024)
  {
    id: "py-rsa-1024",
    name: "RSA.generate(1024)",
    regex: /\bRSA\.generate\s*\(\s*1024\b/i,
    algorithm: "RSA-1024",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor, ~2028 threat horizon) & Weak Classical Key",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 4. RSA.generate(2048)
  {
    id: "py-rsa-2048",
    name: "RSA.generate(2048)",
    regex: /\bRSA\.generate\s*\(\s*2048\b/i,
    algorithm: "RSA-2048",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor, ~2033 threat horizon — Gidney & Ekerå 2021)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 5. rsa.generate_private_key
  {
    id: "py-rsa-gen",
    name: "rsa.generate_private_key",
    regex: /\brsa\.generate_private_key\s*\(/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 6. PKCS1_OAEP
  {
    id: "py-pkcs1",
    name: "PKCS1_OAEP",
    regex: /\bPKCS1_OAEP\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm polynomial break)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 7. AES.MODE_ECB / AES.new(key, AES.MODE_ECB)
  {
    id: "py-aes-ecb",
    name: "AES.MODE_ECB",
    regex: /\bAES\.(MODE_ECB|new\s*\([^)]*MODE_ECB[^)]*\))/i,
    algorithm: "AES-ECB",
    tier: "FIX_NOW",
    vulnerability: "WEAK MODE (patterns leak, no IV/nonce diffusion)",
    replacement: "AES-256-GCM",
    standard: "NIST SP 800-38D (Authenticated Encryption)",
    category: "CLASSICAL",
  },
  // 8. rc4 / arcfour
  {
    id: "algo-rc4",
    name: "rc4 / arcfour",
    regex: /\b(rc4|arcfour)\b/i,
    algorithm: "RC4",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Keystream biases (RFC 7465 prohibited)",
    replacement: "ChaCha20-Poly1305",
    standard: "RFC 8439 / NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 9. DES.new
  {
    id: "py-des",
    name: "DES.new",
    regex: /\bDES\.new\s*\(/i,
    algorithm: "DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — 56-bit key trivially exhaustible (EFF Deep Crack)",
    replacement: "AES-256-GCM",
    standard: "NIST SP 800-131A Rev 2 (Disallowed)",
    category: "CLASSICAL",
  },
  // 10. TripleDES / 3DES
  {
    id: "algo-3des",
    name: "TripleDES / 3DES",
    regex: /\b(TripleDES|3DES|DES-EDE|DES3)\b/i,
    algorithm: "3DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — SWEET32 64-bit block collision (CVE-2016-2183)",
    replacement: "AES-256-GCM",
    standard: "NIST SP 800-131A Rev 2 (Disallowed after 2023)",
    category: "CLASSICAL",
  },
  // 11. ECDSA
  {
    id: "algo-ecdsa",
    name: "ECDSA",
    regex: /\b(ECDSA|ec\.generate_private_key|SECP256R1|SECP384R1)\b/i,
    algorithm: "ECDSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm solves ECDLP in ~2330 logical qubits)",
    replacement: "ML-DSA-65",
    standard: "NIST FIPS 204 (ML-DSA)",
    category: "SHOR",
  },
  // 12. Java MessageDigest MD5
  {
    id: "java-md5",
    name: 'MessageDigest.getInstance("MD5")',
    regex: /MessageDigest\.getInstance\s*\(\s*["']MD5["']\s*\)/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 13. Java MessageDigest SHA-1
  {
    id: "java-sha1",
    name: 'MessageDigest.getInstance("SHA-1")',
    regex: /MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']\s*\)/i,
    algorithm: "SHA-1",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision resistance broken",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 14. Java KeyPairGenerator RSA
  {
    id: "java-rsa",
    name: 'KeyPairGenerator.getInstance("RSA")',
    regex: /KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']\s*\)/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 15. Java Cipher DES
  {
    id: "java-cipher-des",
    name: 'Cipher.getInstance("DES")',
    regex: /Cipher\.getInstance\s*\(\s*["']DES(\/[^"']*)?["']\s*\)/i,
    algorithm: "DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — 56-bit key exhaustible",
    replacement: "AES-256-GCM",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 16. Java Cipher AES/ECB
  {
    id: "java-cipher-ecb",
    name: 'Cipher.getInstance("AES/ECB...")',
    regex: /Cipher\.getInstance\s*\(\s*["']AES\/ECB[^"']*["']\s*\)/i,
    algorithm: "AES-ECB",
    tier: "FIX_NOW",
    vulnerability: "WEAK MODE (No IV, identical plaintext blocks leak ciphertext patterns)",
    replacement: "AES-256-GCM",
    standard: "NIST SP 800-38D",
    category: "CLASSICAL",
  },
  // 17. Node.js crypto.createHash('md5')
  {
    id: "node-md5",
    name: "crypto.createHash('md5')",
    regex: /crypto\.createHash\s*\(\s*['"]md5['"]\s*\)/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 18. Node.js crypto.createHash('sha1')
  {
    id: "node-sha1",
    name: "crypto.createHash('sha1')",
    regex: /crypto\.createHash\s*\(\s*['"]sha1['"]\s*\)/i,
    algorithm: "SHA-1",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision resistance broken",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 19. OpenSSL C RSA_generate_key
  {
    id: "c-rsa-gen",
    name: "RSA_generate_key",
    regex: /\b(RSA_generate_key|RSA_generate_key_ex)\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 20. OpenSSL C MD5_Init / EVP_md5
  {
    id: "c-md5",
    name: "MD5_Init / EVP_md5",
    regex: /\b(MD5_Init|EVP_md5|MD5_Update|MD5_Final)\b/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 21. OpenSSL C SHA1_Init / EVP_sha1
  {
    id: "c-sha1",
    name: "SHA1_Init / EVP_sha1",
    regex: /\b(SHA1_Init|EVP_sha1|SHA1_Update)\b/i,
    algorithm: "SHA-1",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 22. OpenSSL C DES_set_key
  {
    id: "c-des",
    name: "DES_set_key",
    regex: /\b(DES_set_key|DES_ecb_encrypt|DES_cbc_encrypt)\b/i,
    algorithm: "DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — 56-bit key exhaustible",
    replacement: "AES-256-GCM",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 23. hashlib.sha256 / SHA256 (Safe)
  {
    id: "safe-sha256",
    name: "hashlib.sha256 / SHA256",
    regex: /\b(hashlib\.sha256|SHA256|SHA-256|EVP_sha256)\b/i,
    algorithm: "SHA-256",
    tier: "SAFE",
    vulnerability: "SAFE — Grover search leaves 128-bit collision security",
    replacement: "Retain Current Deployment",
    standard: "NIST FIPS 180-4 Approved",
    category: "PQC_SAFE",
  },
  // 24. AES.MODE_GCM (Safe)
  {
    id: "safe-aes-gcm",
    name: "AES.new(key, AES.MODE_GCM)",
    regex: /\b(AES\.MODE_GCM|AES-256-GCM|AES\/GCM)\b/i,
    algorithm: "AES-GCM",
    tier: "SAFE",
    vulnerability: "SAFE — Authenticated Encryption AEAD standard",
    replacement: "Retain Current Deployment",
    standard: "NIST SP 800-38D / FIPS 197",
    category: "PQC_SAFE",
  },
  // 25. ChaCha20 (Safe)
  {
    id: "safe-chacha20",
    name: "chacha20 / ChaCha20",
    regex: /\b(chacha20|ChaCha20-Poly1305)\b/i,
    algorithm: "ChaCha20",
    tier: "SAFE",
    vulnerability: "SAFE — 256-bit key stream cipher resistant to Grover",
    replacement: "Retain Current Deployment",
    standard: "RFC 8439 Approved",
    category: "PQC_SAFE",
  },
  // 26. bcrypt / argon2 (Safe)
  {
    id: "safe-kdf",
    name: "bcrypt / argon2",
    regex: /\b(bcrypt|argon2|Argon2id)\b/i,
    algorithm: "bcrypt/Argon2",
    tier: "SAFE",
    vulnerability: "SAFE — Memory-hard password hashing function",
    replacement: "Retain Current Deployment",
    standard: "RFC 9106 / OWASP Recommended KDF",
    category: "PQC_SAFE",
  },
  // 27. ML-KEM / ML-DSA / Kyber (Quantum Safe)
  {
    id: "safe-pqc",
    name: "ML_KEM / mlkem / kyber",
    regex: /\b(ML_?KEM|mlkem|kyber|ML_?DSA|mldsa|dilithium|SLH_?DSA|sphincs)\b/i,
    algorithm: "ML-KEM / ML-DSA",
    tier: "SAFE",
    vulnerability: "QUANTUM SAFE — Primary NIST PQC Standard",
    replacement: "Retain Current Deployment",
    standard: "NIST FIPS 203 & FIPS 204 Standardized",
    category: "PQC_SAFE",
  },
  // 28. Rust MD5
  {
    id: "rust-md5",
    name: "use md5 / md5::compute",
    regex: /\b(use\s+md5|md5::compute)\b/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "sha2::Sha256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 29. Rust DES
  {
    id: "rust-des",
    name: "use des / des::Des",
    regex: /\b(use\s+des|des::Des)\b/i,
    algorithm: "DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — 56-bit key exhaustible",
    replacement: "aes_gcm::Aes256Gcm",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 30. Rust RSA
  {
    id: "rust-rsa",
    name: "RsaPrivateKey::new",
    regex: /\bRsaPrivateKey::new\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 31. C# MD5
  {
    id: "cs-md5",
    name: "MD5.Create() / MD5CryptoServiceProvider",
    regex: /\b(MD5\.Create|MD5CryptoServiceProvider)\b/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "SHA256.Create()",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 32. C# DES / 3DES
  {
    id: "cs-des",
    name: "DESCryptoServiceProvider / TripleDES",
    regex: /\b(DESCryptoServiceProvider|TripleDESCryptoServiceProvider|DES\.Create|TripleDES\.Create)\b/i,
    algorithm: "DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Obsolete 56-bit key or Sweet32 collision",
    replacement: "Aes.Create() with GCM",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 33. C# RSA
  {
    id: "cs-rsa",
    name: "RSACryptoServiceProvider",
    regex: /\bRSACryptoServiceProvider\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 34. PHP md5()
  {
    id: "php-md5",
    name: "md5()",
    regex: /\bmd5\s*\(/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "hash('sha256', ...)",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 35. PHP openssl des/rc4
  {
    id: "php-ciphers",
    name: "openssl_encrypt('des' / 'rc4')",
    regex: /openssl_encrypt\s*\([^,]+,\s*['"](?:des|rc4)[^'"]*['"]/i,
    algorithm: "DES",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Deprecated symmetric cipher",
    replacement: "openssl_encrypt(..., 'aes-256-gcm', ...)",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 36. Ruby Digest::MD5
  {
    id: "ruby-md5",
    name: "Digest::MD5",
    regex: /Digest::MD5\b/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "Digest::SHA256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 37. Ruby OpenSSL RSA
  {
    id: "ruby-rsa",
    name: "OpenSSL::PKey::RSA",
    regex: /OpenSSL::PKey::RSA\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 38. Swift CC_MD5
  {
    id: "swift-md5",
    name: "CC_MD5",
    regex: /\bCC_MD5\b/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks since 2004",
    replacement: "CryptoKit SHA256.hash",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 39. Swift SecKeyCreateRandomKey RSA
  {
    id: "swift-rsa",
    name: "SecKeyCreateRandomKey (RSA)",
    regex: /\b(SecKeyCreateRandomKey|kSecAttrKeyTypeRSA)\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768 / Curve25519",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
  // 40. Universal / Catch-All MD5
  {
    id: "univ-md5",
    name: "Generic MD5 pattern",
    regex: /\bmd5\b/i,
    algorithm: "MD5",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Cryptographically broken collision resistance",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2 / FIPS 180-4",
    category: "CLASSICAL",
  },
  // 41. Universal / Catch-All SHA-1
  {
    id: "univ-sha1",
    name: "Generic SHA-1 pattern",
    regex: /\bsha-?1\b/i,
    algorithm: "SHA-1",
    tier: "FIX_NOW",
    vulnerability: "CLASSICALLY BROKEN — Collision attacks (SHAttered)",
    replacement: "SHA-256",
    standard: "NIST SP 800-131A Rev 2",
    category: "CLASSICAL",
  },
  // 42. Universal / Catch-All RSA
  {
    id: "univ-rsa",
    name: "Generic RSA pattern",
    regex: /\brsa\b/i,
    algorithm: "RSA",
    tier: "URGENT",
    vulnerability: "CRITICAL (Shor's Algorithm factoring vulnerable)",
    replacement: "ML-KEM-768",
    standard: "NIST FIPS 203 (ML-KEM)",
    category: "SHOR",
  },
];

// ─── LOOKUP TABLE FOR 2D SCATTER PLOT ─────────────────────────────
interface AlgoSecurityProfile {
  classical: number;
  quantumYears: number;
  status: string;
  category: "CLASSICAL_BROKEN" | "SHOR_CRITICAL" | "GROVER_WEAKENED" | "QUANTUM_SAFE";
  threatMechanism: string;
}

const ALGO_SECURITY_SCORES: Record<string, AlgoSecurityProfile> = {
  "MD5": { classical: 0, quantumYears: 0, status: "Broken Classically (Wang & Yu 2004)", category: "CLASSICAL_BROKEN", threatMechanism: "Collision attacks (no QC needed)" },
  "SHA-1": { classical: 20, quantumYears: 0, status: "Broken Classically (SHAttered 2017)", category: "CLASSICAL_BROKEN", threatMechanism: "Collision attacks (no QC needed)" },
  "RC4": { classical: 0, quantumYears: 0, status: "Broken Classically (Keystream Biases)", category: "CLASSICAL_BROKEN", threatMechanism: "Statistical correlation (no QC needed)" },
  "DES": { classical: 0, quantumYears: 0, status: "Broken Classically (56-bit Key Exhaust)", category: "CLASSICAL_BROKEN", threatMechanism: "Exhaustive key search (no QC needed)" },
  "3DES": { classical: 30, quantumYears: 0, status: "Weak / Sweet32 Collision Attacks", category: "CLASSICAL_BROKEN", threatMechanism: "64-bit block collision (no QC needed)" },
  "RSA-512": { classical: 40, quantumYears: 0, status: "Factorable Classically", category: "CLASSICAL_BROKEN", threatMechanism: "General Number Field Sieve" },
  "RSA-1024": { classical: 70, quantumYears: 3, status: "Near-Term Shor Target (~2028)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm (Polynomial Time Break)" },
  "RSA-2048": { classical: 85, quantumYears: 9, status: "Shor Polynomial Break (~2033)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm (Gidney & Ekerå 2021)" },
  "RSA-4096": { classical: 95, quantumYears: 14, status: "Shor Vulnerable Extended (~2038)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm (High parameter lattice)" },
  "ECC-256": { classical: 80, quantumYears: 9, status: "Shor Discrete Log (~2330 logical qubits)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm (Roetteler et al. 2017)" },
  "ECDSA-256": { classical: 80, quantumYears: 9, status: "Shor Discrete Log (~2330 logical qubits)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm (Roetteler et al. 2017)" },
  "ECDSA": { classical: 80, quantumYears: 9, status: "Shor Discrete Log (~2330 logical qubits)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm (Roetteler et al. 2017)" },
  "ECC-384": { classical: 90, quantumYears: 11, status: "Shor Vulnerable (~2035)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm" },
  "ECDSA-384": { classical: 90, quantumYears: 11, status: "Shor Vulnerable (~2035)", category: "SHOR_CRITICAL", threatMechanism: "Shor's Algorithm" },
  "AES-128": { classical: 90, quantumYears: 30, status: "Grover Quadratic Halving (64-bit security)", category: "GROVER_WEAKENED", threatMechanism: "Grover's Algorithm (Quadratic Speedup)" },
  "AES-192": { classical: 95, quantumYears: 80, status: "Grover Weakened (96-bit security)", category: "GROVER_WEAKENED", threatMechanism: "Grover's Algorithm" },
  "AES-256": { classical: 100, quantumYears: 999, status: "Grover Resistant (128-bit quantum security)", category: "QUANTUM_SAFE", threatMechanism: "Quantum Safe (NIST Approved)" },
  "SHA-256": { classical: 100, quantumYears: 50, status: "Grover Collision Resistant", category: "QUANTUM_SAFE", threatMechanism: "Quantum Safe (NIST FIPS 180-4)" },
  "SHA-3": { classical: 100, quantumYears: 50, status: "Grover Collision Resistant", category: "QUANTUM_SAFE", threatMechanism: "Quantum Safe (NIST FIPS 202)" },
  "ML-KEM-768": { classical: 100, quantumYears: 999, status: "NIST FIPS 203 PQC Standard", category: "QUANTUM_SAFE", threatMechanism: "Post-Quantum Cryptography" },
  "ML-DSA-65": { classical: 100, quantumYears: 999, status: "NIST FIPS 204 PQC Standard", category: "QUANTUM_SAFE", threatMechanism: "Post-Quantum Cryptography" },
};

// ─── NOISE FILTERING HELPER (Bug 2) ───────────────────────────────
const NPM_NOISE_NAMES = [
  "zod", "colors", "spinner", "eslint", "prettier", "lodash",
  "axios", "react", "next", "webpack", "babel", "typescript",
  "tailwind", "postcss", "lucide", "jest", "vite", "rollup", "turbo"
];

const KNOWN_CRYPTO_NAMES = [
  "RSA", "AES", "ECDSA", "ECDH", "ED25519", "X25519", "SHA", "MD5",
  "RC4", "DES", "3DES", "TRIPLE-DES", "DSA", "DIFFIE", "CHACHA",
  "ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS",
  "BLAKE", "HMAC", "PBKDF2", "BCRYPT", "ARGON2", "SCRYPT"
];

function isNoiseAsset(algoName: string, primaryRole: string = ""): boolean {
  const lower = (algoName || "").toLowerCase();
  const upper = (algoName || "").toUpperCase();
  const roleUpper = (primaryRole || "").toUpperCase();

  if (NPM_NOISE_NAMES.some((n) => lower.includes(n))) {
    return true;
  }

  if (["DEPENDENCY", "PACKAGE", "LIBRARY", "NPM"].includes(roleUpper)) {
    if (!KNOWN_CRYPTO_NAMES.some((c) => upper.includes(c))) {
      return true;
    }
  }

  return false;
}

export function QuantumRisk({ projectId, project, onNavigateTab }: QuantumRiskProps) {
  // ─── Section 1 State: Instant Code Risk Assessment
  const [codeSnippet, setCodeSnippet] = useState<string>("");
  const [scanFindings, setScanFindings] = useState<any[] | null>(null);
  const [scanTimeMs, setScanTimeMs] = useState<number>(0);

  // ─── Section 2 State: 4 Metric Cards
  const [riskMetrics, setRiskMetrics] = useState({
    broken_now: 0,
    quantum_critical: 0,
    mosca_at_risk: 0,
    quantum_safe: 0,
  });
  const [loadingMetrics, setLoadingMetrics] = useState<boolean>(true);

  // ─── Section 3 State: 2D Scatter Plot & Remediation Queue
  const [hoveredBubble, setHoveredBubble] = useState<any | null>(null);
  const [expandedRemediation, setExpandedRemediation] = useState<string | null>(null);

  // ─── Section 4 State: Mosca Timeline
  const defaultSens = typeof project?.data_sensitivity_years === "number" ? project.data_sensitivity_years : 10;
  const [dataSensitivityX, setDataSensitivityX] = useState<number>(defaultSens);
  const migrationTimeY = 3.0; // Fixed at 3 years per prompt
  const [timelineItems, setTimelineItems] = useState<any[]>([]);

  // ─── Section 5 State: Attack Surface Assets
  const [surfaceAssets, setSurfaceAssets] = useState<{
    network: any[];
    source: any[];
    binary: any[];
    certificate: any[];
  }>({
    network: [],
    source: [],
    binary: [],
    certificate: [],
  });

  // ─── SAMPLE CODE SNIPPETS FOR JUDGES ─────────────────────────────
  const sampleSnippets = {
    pythonLegacy: `# Legacy Python Banking Service
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

def process_transaction(user_id, amount):
    # Broken hash for transaction checksum
    tx_hash = hashlib.md5(f"{user_id}:{amount}".encode()).hexdigest()
    
    # Shor-vulnerable RSA key generation
    signing_key = RSA.generate(1024)
    
    # Insecure ECB block mode (leaks plaintext block patterns)
    cipher = AES.new(b"0123456789abcdef", AES.MODE_ECB)
    return tx_hash`,
    javaLegacy: `// Java Payment Gateway Cryptography
import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

public class PaymentAuth {
    public void authenticate(byte[] token) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        Cipher desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}`,
    cOpenSSL: `/* OpenSSL C Native Service */
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rsa.h>

void crypto_init() {
    MD5_Init(&ctx);
    DES_set_key((C_Block *)key, &ks);
    RSA *r = RSA_generate_key(2048, RSA_F4, NULL, NULL);
}`,
    pqcModern: `# Modern Quantum-Safe Deployment
import oqs
from Crypto.Cipher import AES

def modern_pqc_channel():
    # Primary NIST PQC FIPS 203 KEM
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    
    # 256-bit AEAD Grover Resistant
    cipher = AES.new(aes_key_256, AES.MODE_GCM)
    return kem, cipher`,
  };

  // ─── EXECUTE INSTANT CODE SCAN (<100ms) ──────────────────────────
  const runInstantScan = useCallback((codeToScan?: string) => {
    const text = codeToScan !== undefined ? codeToScan : codeSnippet;
    if (!text.trim()) {
      setScanFindings(null);
      return;
    }

    const start = performance.now();
    const findings: any[] = [];
    const seenPatterns = new Set<string>();

    for (const rule of CODE_SCAN_RULES) {
      if (rule.regex.test(text)) {
        if (!seenPatterns.has(rule.id)) {
          seenPatterns.add(rule.id);
          findings.push({
            id: rule.id,
            pattern: rule.name,
            algorithm: rule.algorithm,
            tier: rule.tier,
            vulnerability: rule.vulnerability,
            replacement: rule.replacement,
            standard: rule.standard,
            category: rule.category,
          });
        }
      }
    }

    // Sort: FIX_NOW first, then URGENT, then PLAN, then SAFE
    const tierOrder: Record<string, number> = {
      FIX_NOW: 0,
      URGENT: 1,
      PLAN: 2,
      SAFE: 3,
    };
    findings.sort((a, b) => (tierOrder[a.tier] ?? 99) - (tierOrder[b.tier] ?? 99));

    const elapsed = performance.now() - start;
    setScanFindings(findings);
    setScanTimeMs(Math.round(elapsed * 10) / 10);
  }, [codeSnippet]);

  // Handle Ctrl+Enter / Cmd+Enter shortcut
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runInstantScan();
    }
  };

  // ─── FETCH BACKEND DATA ──────────────────────────────────────────
  useEffect(() => {
    let isMounted = true;
    async function loadData() {
      try {
        setLoadingMetrics(true);

        // 1. Fetch Risk Summary (Section 2)
        const resMetrics = await fetch(`/api/quantum/risk-summary?project=${encodeURIComponent(projectId)}`);
        if (resMetrics.ok) {
          const data = await resMetrics.json();
          if (isMounted) {
            setRiskMetrics({
              broken_now: data.broken_now ?? data.broken_now_count ?? 0,
              quantum_critical: data.quantum_critical ?? data.quantum_critical_count ?? 0,
              mosca_at_risk: data.mosca_at_risk ?? data.mosca_at_risk_count ?? 0,
              quantum_safe: data.quantum_safe ?? data.quantum_safe_count ?? 0,
            });
          }
        }

        // 2. Fetch Timeline Summary (Section 4)
        const resTimeline = await fetch(`/api/quantum/timeline-summary?project=${encodeURIComponent(projectId)}`);
        if (resTimeline.ok) {
          const tData = await resTimeline.json();
          if (isMounted && Array.isArray(tData)) {
            // Filter out npm dependencies
            const clean = tData.filter((item) => !isNoiseAsset(item.algorithm, ""));
            setTimelineItems(clean);
          }
        }

        // 3. Fetch Assets for Attack Surface Map (Section 5) & 2D Graph
        const resAssets = await fetch(`/api/assets?project=${encodeURIComponent(projectId)}&per_page=100`);
        if (resAssets.ok) {
          const rawAssets = await resAssets.json();
          if (isMounted && Array.isArray(rawAssets)) {
            // Filter out non-crypto npm dependency noise
            const cleanAssets = rawAssets.filter(
              (a) => !isNoiseAsset(a.algorithm || a.name || "", a.asset_type || a.primary_role || "")
            );

            const net: any[] = [];
            const src: any[] = [];
            const bin: any[] = [];
            const cert: any[] = [];

            for (const a of cleanAssets) {
              const surf = (a.surface || a.asset_type || "").toLowerCase();
              if (surf.includes("network") || surf.includes("tls") || surf.includes("pcap") || surf.includes("endpoint")) {
                net.push(a);
              } else if (surf.includes("binary") || surf.includes("firmware")) {
                bin.push(a);
              } else if (surf.includes("cert")) {
                cert.push(a);
              } else {
                src.push(a);
              }
            }

            setSurfaceAssets({ network: net, source: src, binary: bin, certificate: cert });
          }
        }
      } catch (err) {
        console.error("Failed to load quantum risk page data:", err);
      } finally {
        if (isMounted) setLoadingMetrics(false);
      }
    }

    loadData();
    return () => {
      isMounted = false;
    };
  }, [projectId]);

  // ─── SECTION 3: 2D SCATTER PLOT POINTS ───────────────────────────
  // Map discovered algorithms into bubble plot data points
  const scatterPlotPoints = useMemo(() => {
    // Unique discovered algorithms across timeline & surfaces
    const discoveredAlgos = new Set<string>();
    for (const t of timelineItems) {
      if (t.algorithm) discoveredAlgos.add(t.algorithm);
    }
    for (const list of Object.values(surfaceAssets)) {
      for (const a of list) {
        const name = a.algorithm || a.name;
        if (name && !isNoiseAsset(name, "")) {
          discoveredAlgos.add(name);
        }
      }
    }

    // Default representative set if project has no scans yet
    const sourceKeys = discoveredAlgos.size > 0 ? Array.from(discoveredAlgos) : Object.keys(ALGO_SECURITY_SCORES);

    return sourceKeys.map((rawName) => {
      const cleanUpper = rawName.toUpperCase().trim();
      let matchedKey = Object.keys(ALGO_SECURITY_SCORES).find((k) => cleanUpper.includes(k) || k.includes(cleanUpper));
      if (!matchedKey) {
        if (cleanUpper.includes("RSA")) matchedKey = "RSA-2048";
        else if (cleanUpper.includes("AES")) matchedKey = "AES-128";
        else if (cleanUpper.includes("ECDSA") || cleanUpper.includes("EC")) matchedKey = "ECDSA";
        else if (cleanUpper.includes("MD5")) matchedKey = "MD5";
        else if (cleanUpper.includes("SHA1") || cleanUpper.includes("SHA-1")) matchedKey = "SHA-1";
        else if (cleanUpper.includes("DES")) matchedKey = "DES";
        else if (cleanUpper.includes("ML-KEM") || cleanUpper.includes("KYBER")) matchedKey = "ML-KEM-768";
        else matchedKey = "RSA-2048";
      }

      const profile = ALGO_SECURITY_SCORES[matchedKey] || {
        classical: 50,
        quantumYears: 8,
        status: "Standard algorithm",
        category: "SHOR_CRITICAL" as const,
        threatMechanism: "Shor's Algorithm",
      };

      return {
        id: rawName,
        displayName: rawName,
        matchedStandard: matchedKey,
        classicalScore: profile.classical,
        quantumYears: profile.quantumYears,
        statusText: profile.status,
        category: profile.category,
        threatMechanism: profile.threatMechanism,
      };
    });
  }, [timelineItems, surfaceAssets]);

  // ─── REMEDIATION QUEUE GROUPING ──────────────────────────────────
  const remediationQueue = useMemo(() => {
    const fixNow: any[] = [];
    const urgent: any[] = [];
    const plan: any[] = [];
    const safe: any[] = [];

    const seen = new Set<string>();

    for (const pt of scatterPlotPoints) {
      if (seen.has(pt.displayName)) continue;
      seen.add(pt.displayName);

      if (pt.category === "CLASSICAL_BROKEN") {
        fixNow.push({
          algo: pt.displayName,
          brokenBy: pt.statusText,
          oneLineFix: "Retire immediately and replace with NIST FIPS 180-4 (SHA-256) or FIPS 197 (AES-256-GCM).",
          patchSnippet: pt.displayName.includes("MD5")
            ? `# MD5 -> SHA-256 Remediation:\n- import hashlib\n- tx_hash = hashlib.md5(payload).hexdigest()\n+ tx_hash = hashlib.sha256(payload).hexdigest()`
            : `# Legacy Cipher Remediation:\n- cipher = DES.new(key, DES.MODE_ECB)\n+ cipher = AES.new(key_256, AES.MODE_GCM)`,
        });
      } else if (pt.category === "SHOR_CRITICAL") {
        urgent.push({
          algo: pt.displayName,
          horizon: `~${pt.quantumYears} years threat horizon (CRQC arrival)`,
          hndlExposure: "Adversaries actively recording traffic (HNDL). Retroactive decrypt when CRQC realized.",
          targetStandard: "NIST FIPS 203 (ML-KEM-768) or FIPS 204 (ML-DSA-65)",
        });
      } else if (pt.category === "GROVER_WEAKENED") {
        plan.push({
          algo: pt.displayName,
          effectiveBits: "Effective security halved by Grover quadratic speedup (e.g. 128-bit -> 64-bit).",
          upgradePath: "Enforce 256-bit symmetric keys (AES-256-GCM) to preserve >=128-bit post-quantum security.",
        });
      } else {
        safe.push({
          algo: pt.displayName,
          standardNote: pt.statusText,
        });
      }
    }

    return { fixNow, urgent, plan, safe };
  }, [scatterPlotPoints]);

  return (
    <div className="space-y-8 pb-16 font-sans">
      {/* ─── Page Header ────────────────────────────────────────── */}
      <div className="border-b border-subtle pb-4 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="h-9 w-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Cpu className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
                Quantum Risk &amp; Cryptanalytic Relevance Hub
              </h1>
              <p className="text-xs text-quiet mt-0.5">
                Deterministic post-quantum evaluation under Shor &amp; Grover models • Mosca&apos;s Theorem $X+Y&gt;Z$ • HNDL attack surface
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 1 — Instant Code Risk Assessment (Top of Page)
          ════════════════════════════════════════════════════════════════ */}
      <div className="rounded-xl border border-cyan-500/30 bg-surface/90 shadow-xl overflow-hidden">
        <div className="p-4 bg-gradient-to-r from-cyan-950/40 via-surface to-surface border-b border-subtle flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <Terminal className="h-5 w-5 text-cyan-400" />
            <span className="font-bold text-sm tracking-tight text-foreground">Instant Code Risk Assessment</span>
            <span className="px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 animate-pulse">
              LIVE DEMO — paste any code
            </span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-quiet hidden sm:inline">Try samples:</span>
            <button
              onClick={() => {
                setCodeSnippet(sampleSnippets.pythonLegacy);
                runInstantScan(sampleSnippets.pythonLegacy);
              }}
              className="text-[10px] px-2 py-1 rounded bg-canvas hover:bg-subtle text-cyan-400 border border-subtle cursor-pointer transition-colors"
            >
              Python Legacy
            </button>
            <button
              onClick={() => {
                setCodeSnippet(sampleSnippets.javaLegacy);
                runInstantScan(sampleSnippets.javaLegacy);
              }}
              className="text-[10px] px-2 py-1 rounded bg-canvas hover:bg-subtle text-cyan-400 border border-subtle cursor-pointer transition-colors"
            >
              Java Crypto
            </button>
            <button
              onClick={() => {
                setCodeSnippet(sampleSnippets.cOpenSSL);
                runInstantScan(sampleSnippets.cOpenSSL);
              }}
              className="text-[10px] px-2 py-1 rounded bg-canvas hover:bg-subtle text-cyan-400 border border-subtle cursor-pointer transition-colors"
            >
              C / OpenSSL
            </button>
            <button
              onClick={() => {
                setCodeSnippet(sampleSnippets.pqcModern);
                runInstantScan(sampleSnippets.pqcModern);
              }}
              className="text-[10px] px-2 py-1 rounded bg-canvas hover:bg-subtle text-emerald-400 border border-subtle cursor-pointer transition-colors"
            >
              PQC Modern
            </button>
          </div>
        </div>

        <div className="p-4 space-y-3">
          <div className="relative">
            <textarea
              id="instant-code-input"
              rows={5}
              value={codeSnippet}
              onChange={(e) => setCodeSnippet(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Paste any source code here — Python, Java, C, Go, JavaScript..."
              className="w-full font-mono text-xs p-3 rounded-lg bg-canvas text-foreground border border-subtle focus:border-cyan-500 focus:outline-none resize-y placeholder:text-quiet/60"
            />
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="text-[11px] text-quiet flex items-center gap-1.5">
              <span>Shortcuts:</span>
              <kbd className="px-1.5 py-0.5 rounded bg-canvas border border-subtle text-[10px] font-mono text-foreground">
                Ctrl
              </kbd>
              <span>+</span>
              <kbd className="px-1.5 py-0.5 rounded bg-canvas border border-subtle text-[10px] font-mono text-foreground">
                Enter
              </kbd>
              <span className="text-quiet/70 pl-2">• 100% Client-side instant evaluation (sub-100ms)</span>
            </div>

            <div className="flex items-center gap-2">
              {codeSnippet && (
                <button
                  onClick={() => {
                    setCodeSnippet("");
                    setScanFindings(null);
                  }}
                  className="px-3 py-1.5 rounded-lg text-xs text-quiet hover:text-foreground border border-subtle bg-canvas cursor-pointer"
                >
                  Clear
                </button>
              )}
              <button
                id="instant-scan-btn"
                onClick={() => runInstantScan()}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-500/20 flex items-center gap-1.5 cursor-pointer transition-all active:scale-95"
              >
                <span>Scan &amp; Assess</span>
                <span className="text-[10px]">▶</span>
              </button>
            </div>
          </div>

          {/* Inline Findings Display (<100ms response) */}
          {scanFindings !== null && (
            <div className="mt-4 pt-3 border-t border-subtle space-y-3 animate-in fade-in duration-150">
              {scanFindings.length > 0 ? (
                <div>
                  <div className="flex items-center justify-between pb-2">
                    <div className="flex items-center gap-2 text-rose-400 font-bold text-xs">
                      <AlertTriangle className="h-4 w-4" />
                      <span>⚠ {scanFindings.length} issue{scanFindings.length > 1 ? "s" : ""} found — immediate action required</span>
                    </div>
                    <span className="text-[10px] font-mono text-quiet">Scanned in {scanTimeMs}ms</span>
                  </div>

                  <div className="divide-y divide-subtle border border-subtle rounded-lg overflow-hidden bg-canvas/40">
                    {scanFindings.map((f, idx) => {
                      const isFixNow = f.tier === "FIX_NOW";
                      const isUrgent = f.tier === "URGENT";
                      const isPlan = f.tier === "PLAN";
                      const isSafe = f.tier === "SAFE";

                      return (
                        <div key={idx} className="p-3 flex flex-col md:flex-row md:items-center justify-between gap-3 hover:bg-canvas/80 transition-colors">
                          <div className="flex items-start md:items-center gap-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[11px] font-bold font-mono shrink-0 ${
                                isFixNow
                                  ? "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                                  : isUrgent
                                  ? "bg-orange-500/20 text-orange-300 border border-orange-500/30"
                                  : isPlan
                                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                                  : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                              }`}
                            >
                              {f.algorithm}
                            </span>
                            <div>
                              <div className="text-xs font-semibold text-foreground flex items-center gap-2">
                                <span className="font-mono text-cyan-400 text-[11px]">{f.pattern}</span>
                                <span className="text-quiet">•</span>
                                <span className={isFixNow ? "text-rose-400" : isUrgent ? "text-orange-400" : "text-foreground"}>
                                  {f.vulnerability}
                                </span>
                              </div>
                              <div className="text-[10px] text-quiet mt-0.5">
                                Citing: <span className="font-medium text-foreground/80">{f.standard}</span>
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 shrink-0 self-end md:self-center">
                            <span className="text-[11px] text-quiet">→</span>
                            <span
                              className={`px-2 py-1 rounded text-xs font-semibold font-mono ${
                                isSafe
                                  ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30"
                                  : "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30"
                              }`}
                            >
                              {f.replacement}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="flex items-center justify-between p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs">
                  <div className="flex items-center gap-2 font-medium">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>✓ No recognized weak crypto patterns detected in submitted snippet.</span>
                  </div>
                  <span className="text-[10px] font-mono text-quiet">Scanned in {scanTimeMs}ms</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 2 — Four Metric Cards (GET /api/quantum/risk-summary)
          ════════════════════════════════════════════════════════════════ */}
      <div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Card 1: Broken NOW (red) */}
          <div className="rounded-xl border border-rose-500/30 bg-rose-500/5 p-4 space-y-2 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-rose-400 uppercase tracking-wider">Broken NOW</span>
              <div className="h-7 w-7 rounded-lg bg-rose-500/20 text-rose-400 flex items-center justify-center">
                <Flame className="h-4 w-4" />
              </div>
            </div>
            <div className="text-3xl font-extrabold font-mono text-rose-300">
              {loadingMetrics ? "..." : riskMetrics.broken_now}
            </div>
            <p className="text-[11px] text-quiet">
              Classically broken primitives (MD5, SHA-1, DES, RC4). No quantum computer needed.
            </p>
          </div>

          {/* Card 2: Quantum Critical (amber/orange) */}
          <div className="rounded-xl border border-orange-500/30 bg-orange-500/5 p-4 space-y-2 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-orange-400 uppercase tracking-wider">Quantum Critical</span>
              <div className="h-7 w-7 rounded-lg bg-orange-500/20 text-orange-400 flex items-center justify-center">
                <Zap className="h-4 w-4" />
              </div>
            </div>
            <div className="text-3xl font-extrabold font-mono text-orange-300">
              {loadingMetrics ? "..." : riskMetrics.quantum_critical}
            </div>
            <p className="text-[11px] text-quiet">
              Shor-vulnerable public keys (RSA, ECC, DSA). Factored in polynomial time by CRQC.
            </p>
          </div>

          {/* Card 3: Mosca At Risk (blue) */}
          <div className="rounded-xl border border-cyan-500/30 bg-cyan-500/5 p-4 space-y-2 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider">Mosca At Risk</span>
              <div className="h-7 w-7 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center">
                <Hourglass className="h-4 w-4" />
              </div>
            </div>
            <div className="text-3xl font-extrabold font-mono text-cyan-300">
              {loadingMetrics ? "..." : riskMetrics.mosca_at_risk}
            </div>
            <p className="text-[11px] text-quiet">
              Assets where $X + Y &gt; Z$ is true. Shelf-life + migration exceeds CRQC arrival.
            </p>
          </div>

          {/* Card 4: Quantum Safe (green) */}
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-2 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Quantum Safe</span>
              <div className="h-7 w-7 rounded-lg bg-emerald-500/20 text-emerald-400 flex items-center justify-center">
                <ShieldCheck className="h-4 w-4" />
              </div>
            </div>
            <div className="text-3xl font-extrabold font-mono text-emerald-300">
              {loadingMetrics ? "..." : riskMetrics.quantum_safe}
            </div>
            <p className="text-[11px] text-quiet">
              Meets NIST PQC minimum (ML-KEM, ML-DSA, SLH-DSA, AES-256 Grover-resistant).
            </p>
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 3 — Two-Column: 2D Risk Scatter Plot & Remediation Queue
          ════════════════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Classical vs Quantum 2D Risk Scatter Plot (6 cols) */}
        <div className="lg:col-span-6 rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold tracking-tight text-foreground flex items-center gap-2">
                <span>Classical vs Quantum 2D Risk Map</span>
              </h2>
              <p className="text-[11px] text-quiet mt-0.5">
                Quadrant matrix: Classical strength (0-100) vs Years until quantum threat (0-40+y)
              </p>
            </div>
          </div>

          {/* Interactive SVG Scatter Plot */}
          <div className="relative border border-subtle rounded-lg bg-canvas/60 p-2 overflow-hidden">
            <svg viewBox="0 0 500 320" className="w-full h-72 select-none">
              <defs>
                {/* Quadrant gradient fills */}
                <rect id="bg-canvas" width="500" height="320" fill="transparent" />
              </defs>

              {/* Quadrant backgrounds */}
              {/* Bottom-Left: Broken NOW (red tint) */}
              <rect x="50" y="160" width="200" height="120" fill="rgba(244, 63, 94, 0.05)" />
              {/* Bottom-Right: Classically OK, Quantum Vulnerable (orange tint) */}
              <rect x="250" y="160" width="220" height="120" fill="rgba(249, 115, 22, 0.05)" />
              {/* Upper-Right: Safe from both (green tint) */}
              <rect x="250" y="20" width="220" height="140" fill="rgba(16, 185, 129, 0.05)" />

              {/* Quadrant labels */}
              <text x="60" y="270" fill="rgba(244, 63, 94, 0.5)" fontSize="10" fontWeight="bold">
                BROKEN NOW (Classical)
              </text>
              <text x="260" y="270" fill="rgba(249, 115, 22, 0.5)" fontSize="10" fontWeight="bold">
                QUANTUM VULNERABLE (Shor)
              </text>
              <text x="260" y="35" fill="rgba(16, 185, 129, 0.6)" fontSize="10" fontWeight="bold">
                QUANTUM SAFE (PQC)
              </text>

              {/* Axes lines */}
              <line x1="50" y1="280" x2="470" y2="280" stroke="currentColor" strokeOpacity="0.2" strokeWidth="1" />
              <line x1="50" y1="20" x2="50" y2="280" stroke="currentColor" strokeOpacity="0.2" strokeWidth="1" />

              {/* Midpoint dividers */}
              <line x1="250" y1="20" x2="250" y2="280" stroke="currentColor" strokeOpacity="0.1" strokeDasharray="3 3" />
              <line x1="50" y1="160" x2="470" y2="160" stroke="currentColor" strokeOpacity="0.1" strokeDasharray="3 3" />

              {/* Y Axis Ticks & Labels (Years until quantum threat) */}
              <text x="42" y="280" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="end">0y</text>
              <text x="42" y="220" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="end">10y</text>
              <text x="42" y="160" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="end">20y</text>
              <text x="42" y="100" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="end">30y</text>
              <text x="42" y="40" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="end">40+y</text>
              <text x="20" y="150" fill="currentColor" fillOpacity="0.7" fontSize="9" fontWeight="bold" transform="rotate(-90 20 150)" textAnchor="middle">
                Years until Quantum Threat →
              </text>

              {/* X Axis Ticks & Labels (Classical security strength 0-100) */}
              <text x="50" y="295" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="middle">0</text>
              <text x="150" y="295" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="middle">25</text>
              <text x="250" y="295" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="middle">50</text>
              <text x="350" y="295" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="middle">75</text>
              <text x="460" y="295" fill="currentColor" fillOpacity="0.5" fontSize="9" textAnchor="middle">100</text>
              <text x="260" y="312" fill="currentColor" fillOpacity="0.7" fontSize="9" fontWeight="bold" textAnchor="middle">
                Classical Security Strength (0=broken, 100=strong) →
              </text>

              {/* Plot Data Bubbles (always size=7px radius) */}
              {scatterPlotPoints.map((pt, idx) => {
                // Map X: 0 -> 50, 100 -> 460
                const cx = 50 + (pt.classicalScore / 100) * 410;
                // Map Y: 0y -> 280, 40+y -> 40 (clamped)
                const clampedYears = Math.min(40, pt.quantumYears);
                const cy = 280 - (clampedYears / 40) * 240;

                // Color by category
                let fillColor = "#10b981"; // green
                let strokeColor = "#34d399";
                if (pt.category === "CLASSICAL_BROKEN") {
                  fillColor = "#f43f5e"; // red
                  strokeColor = "#fb7185";
                } else if (pt.category === "SHOR_CRITICAL") {
                  fillColor = "#f97316"; // orange
                  strokeColor = "#fb923c";
                } else if (pt.category === "GROVER_WEAKENED") {
                  fillColor = "#f59e0b"; // amber
                  strokeColor = "#fbbf24";
                }

                const isHovered = hoveredBubble?.displayName === pt.displayName;

                return (
                  <g key={idx} className="cursor-pointer" onMouseEnter={() => setHoveredBubble(pt)} onMouseLeave={() => setHoveredBubble(null)}>
                    {isHovered && (
                      <circle cx={cx} cy={cy} r="12" fill={fillColor} fillOpacity="0.3" className="animate-ping" />
                    )}
                    <circle
                      cx={cx}
                      cy={cy}
                      r="7"
                      fill={fillColor}
                      stroke={strokeColor}
                      strokeWidth="2"
                      className="transition-all duration-150 hover:r-9"
                    />
                    <text
                      x={cx}
                      y={cy - 10}
                      fill="currentColor"
                      fontSize="9"
                      fontWeight="bold"
                      textAnchor="middle"
                      className="pointer-events-none drop-shadow"
                    >
                      {pt.displayName}
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* Hover Tooltip Overlay */}
            {hoveredBubble && (
              <div className="absolute top-3 right-3 p-3 rounded-lg bg-surface/95 border border-cyan-500/30 text-xs shadow-xl max-w-xs space-y-1 backdrop-blur pointer-events-none">
                <div className="flex items-center justify-between gap-2 font-bold text-foreground">
                  <span>{hoveredBubble.displayName}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] ${
                      hoveredBubble.category === "CLASSICAL_BROKEN"
                        ? "bg-rose-500/20 text-rose-300"
                        : hoveredBubble.category === "SHOR_CRITICAL"
                        ? "bg-orange-500/20 text-orange-300"
                        : hoveredBubble.category === "GROVER_WEAKENED"
                        ? "bg-amber-500/20 text-amber-300"
                        : "bg-emerald-500/20 text-emerald-300"
                    }`}
                  >
                    {hoveredBubble.category.replace("_", " ")}
                  </span>
                </div>
                <div className="text-[11px] text-quiet">
                  Classical Score: <strong className="text-foreground">{hoveredBubble.classicalScore}/100</strong>
                </div>
                <div className="text-[11px] text-quiet">
                  Quantum Horizon: <strong className="text-foreground">{hoveredBubble.quantumYears >= 500 ? "Quantum Safe (999y)" : `~${hoveredBubble.quantumYears} years`}</strong>
                </div>
                <div className="text-[10px] text-quiet pt-0.5 border-t border-subtle">
                  {hoveredBubble.statusText}
                </div>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center justify-between text-[11px] text-quiet pt-1">
            <div className="flex items-center gap-3">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-rose-500" /> Broken now</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-orange-500" /> Shor critical</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500" /> Grover weakened</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-500" /> Quantum safe</span>
            </div>
            <span className="text-quiet/70">Hover bubbles for details</span>
          </div>
        </div>

        {/* Right: Prioritized Remediation Queue (6 cols) */}
        <div className="lg:col-span-6 rounded-xl border border-subtle bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold tracking-tight text-foreground flex items-center gap-2">
                <span>Prioritized Remediation Queue</span>
              </h2>
              <p className="text-[11px] text-quiet mt-0.5">
                Deterministic tiering: FIX NOW → URGENT → PLAN → SAFE
              </p>
            </div>
          </div>

          <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
            {/* TIER 1: FIX NOW (red) */}
            {remediationQueue.fixNow.map((item, idx) => {
              const isExpanded = expandedRemediation === `fix-${idx}`;
              return (
                <div key={idx} className="rounded-lg border border-rose-500/30 bg-rose-500/5 p-3 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-rose-500 text-white uppercase tracking-wider">
                        FIX NOW
                      </span>
                      <span className="font-bold text-xs text-foreground font-mono">{item.algo}</span>
                    </div>
                    <button
                      onClick={() => onNavigateTab?.("assets", item.algo)}
                      className="text-[11px] text-rose-400 hover:text-rose-300 font-medium flex items-center gap-1 cursor-pointer"
                    >
                      → View Assets
                    </button>
                  </div>
                  <p className="text-xs text-rose-300 font-medium">{item.brokenBy}</p>
                  <p className="text-[11px] text-quiet">{item.oneLineFix}</p>

                  <div>
                    <button
                      onClick={() => setExpandedRemediation(isExpanded ? null : `fix-${idx}`)}
                      className="text-[10px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer font-semibold pt-1"
                    >
                      {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                      <span>{isExpanded ? "Hide Code Change" : "Show Required Code Change"}</span>
                    </button>
                    {isExpanded && (
                      <pre className="mt-2 p-2 rounded bg-canvas font-mono text-[10px] text-foreground border border-subtle overflow-x-auto">
                        {item.patchSnippet}
                      </pre>
                    )}
                  </div>
                </div>
              );
            })}

            {/* TIER 2: URGENT (orange) */}
            {remediationQueue.urgent.map((item, idx) => (
              <div key={idx} className="rounded-lg border border-orange-500/30 bg-orange-500/5 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-orange-500 text-white uppercase tracking-wider">
                      URGENT
                    </span>
                    <span className="font-bold text-xs text-foreground font-mono">{item.algo}</span>
                  </div>
                  <button
                    onClick={() => onNavigateTab?.("assets", item.algo)}
                    className="text-[11px] text-orange-400 hover:text-orange-300 font-medium flex items-center gap-1 cursor-pointer"
                  >
                    → View Assets
                  </button>
                </div>
                <div className="text-xs text-orange-300 font-medium">{item.horizon}</div>
                <p className="text-[11px] text-quiet">{item.hndlExposure}</p>
                <div className="text-[11px] text-cyan-300 font-mono">Target: {item.targetStandard}</div>
              </div>
            ))}

            {/* TIER 3: PLAN (amber) */}
            {remediationQueue.plan.map((item, idx) => (
              <div key={idx} className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-amber-500 text-black uppercase tracking-wider">
                      PLAN
                    </span>
                    <span className="font-bold text-xs text-foreground font-mono">{item.algo}</span>
                  </div>
                  <button
                    onClick={() => onNavigateTab?.("assets", item.algo)}
                    className="text-[11px] text-amber-400 hover:text-amber-300 font-medium flex items-center gap-1 cursor-pointer"
                  >
                    → View Assets
                  </button>
                </div>
                <p className="text-[11px] text-foreground/90">{item.effectiveBits}</p>
                <p className="text-[11px] text-quiet">{item.upgradePath}</p>
              </div>
            ))}

            {/* TIER 4: SAFE (green) */}
            {remediationQueue.safe.map((item, idx) => (
              <div key={idx} className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-extrabold bg-emerald-500 text-black uppercase tracking-wider">
                    SAFE
                  </span>
                  <span className="font-bold text-xs text-emerald-300 font-mono">{item.algo}</span>
                  <span className="text-[11px] text-quiet">• {item.standardNote}</span>
                </div>
                <button
                  onClick={() => onNavigateTab?.("assets", item.algo)}
                  className="text-[11px] text-emerald-400 hover:text-emerald-300 font-medium cursor-pointer"
                >
                  → View Assets
                </button>
              </div>
            ))}

            {remediationQueue.fixNow.length === 0 &&
              remediationQueue.urgent.length === 0 &&
              remediationQueue.plan.length === 0 &&
              remediationQueue.safe.length === 0 && (
                <div className="p-8 text-center text-xs text-quiet">
                  No cryptographic assets discovered yet. Run a source or binary scan to populate the queue.
                </div>
              )}
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 4 — Mosca X+Y>Z Interactive Timeline
          ════════════════════════════════════════════════════════════════ */}
      <div className="rounded-xl border border-subtle bg-surface p-5 space-y-5">
        <div className="border-b border-subtle pb-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold tracking-tight text-foreground flex items-center gap-2">
              <Hourglass className="h-4 w-4 text-cyan-400" />
              <span>Mosca&apos;s Theorem Interactive Timeline $(X + Y &gt; Z)$</span>
            </h2>
            <p className="text-xs text-quiet mt-0.5">
              If your data must stay secret for <strong className="text-foreground">X years</strong> and migration takes{" "}
              <strong className="text-foreground">Y years</strong>, then <strong className="text-foreground">X + Y</strong> must be less than{" "}
              <strong className="text-foreground">Z</strong> (when the quantum computer can break this algorithm).
            </p>
          </div>
        </div>

        {/* Sliders & Formula Controls */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 p-4 rounded-lg bg-canvas/60 border border-subtle">
          <div className="md:col-span-6 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-foreground">Data Sensitivity (X years):</span>
              <span className="font-mono font-bold text-cyan-400 text-sm">{dataSensitivityX} years</span>
            </div>
            <input
              type="range"
              min={1}
              max={50}
              step={1}
              value={dataSensitivityX}
              onChange={(e) => setDataSensitivityX(Number(e.target.value))}
              className="w-full h-1.5 bg-subtle rounded-lg appearance-none cursor-pointer accent-cyan-500"
            />
            <div className="flex justify-between text-[10px] text-quiet font-mono">
              <span>1 yr</span>
              <span>10 yrs (default)</span>
              <span>25 yrs</span>
              <span>50 yrs</span>
            </div>
          </div>

          <div className="md:col-span-3 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-foreground">Migration Time (Y years):</span>
              <span className="font-mono font-bold text-foreground text-sm">{migrationTimeY} years</span>
            </div>
            <div className="h-1.5 w-full bg-subtle rounded-lg relative">
              <div className="h-full bg-cyan-400/50 rounded-lg w-[30%]" />
            </div>
            <div className="text-[10px] text-quiet">Non-interactive fixed migration baseline (3.0 yrs)</div>
          </div>

          <div className="md:col-span-3 rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3 flex flex-col justify-center">
            <span className="text-[10px] text-quiet font-mono uppercase">Required Protection Window</span>
            <span className="text-lg font-bold font-mono text-cyan-300">
              X + Y = {dataSensitivityX + migrationTimeY} years
            </span>
          </div>
        </div>

        {/* Algorithm Timeline Bars */}
        <div className="space-y-4">
          <div className="text-xs font-semibold text-foreground">
            Discovered Cryptographic Primitives vs Threat Horizons:
          </div>

          {timelineItems.length === 0 ? (
            <div className="p-8 text-center text-xs text-quiet border border-dashed border-subtle rounded-lg">
              No project algorithms loaded. Evaluating standard catalog baselines:
            </div>
          ) : null}

          <div className="space-y-3">
            {(timelineItems.length > 0
              ? timelineItems
              : [
                  { algorithm: "RSA-1024", z_years: 3.0, asset_count: 1 },
                  { algorithm: "RSA-2048", z_years: 9.0, asset_count: 2 },
                  { algorithm: "ECDSA-256", z_years: 7.0, asset_count: 1 },
                  { algorithm: "AES-128", z_years: 30.0, asset_count: 1 },
                  { algorithm: "ML-KEM-768", z_years: 999.0, asset_count: 1 },
                ]
            ).map((item, idx) => {
              const z = item.z_years ?? 9.0;
              const isSafe = z >= 100;
              const totalNeeded = dataSensitivityX + migrationTimeY;
              const deficit = totalNeeded - z;
              const hasDeficit = deficit > 0 && !isSafe;
              const ratio = z > 0 ? (totalNeeded / z).toFixed(2) : "∞";

              // Scale axis to max(totalNeeded, z, 35)
              const maxAxis = Math.max(totalNeeded, isSafe ? 40 : z, 35);
              const fillPct = Math.min(100, (totalNeeded / maxAxis) * 100);
              const markerPct = Math.min(100, (z / maxAxis) * 100);

              return (
                <div key={idx} className="p-3 rounded-lg border border-subtle bg-canvas/40 space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-xs text-foreground">{item.algorithm}</span>
                      {item.asset_count && (
                        <span className="text-[10px] text-quiet">({item.asset_count} asset{item.asset_count > 1 ? "s" : ""})</span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-xs">
                      {isSafe ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          SAFE (Z=999y)
                        </span>
                      ) : (
                        <>
                          <span className="text-[11px] text-quiet">
                            CRQC Horizon: <strong className="text-foreground">{z} yrs</strong>
                          </span>
                          <span className={`text-xs font-mono font-bold ${hasDeficit ? "text-rose-400" : "text-emerald-400"}`}>
                            Ratio: {ratio} {hasDeficit ? "(Deficit!)" : "(Secure)"}
                          </span>
                        </>
                      )}
                    </div>
                  </div>

                  {!isSafe ? (
                    <div className="space-y-1">
                      <div className="h-4 w-full bg-subtle rounded relative overflow-hidden">
                        {/* Fill representing X+Y */}
                        <div
                          style={{ width: `${fillPct}%` }}
                          className={`h-full transition-all duration-200 ${
                            hasDeficit ? "bg-rose-500" : "bg-cyan-500"
                          }`}
                        />
                        {/* Red vertical marker at Z */}
                        <div
                          style={{ left: `${markerPct}%` }}
                          className="absolute top-0 bottom-0 w-1 bg-red-600 shadow-sm z-10"
                          title={`Z deadline: ${z} years`}
                        />
                      </div>
                      <div className="flex justify-between text-[10px] text-quiet font-mono pt-0.5">
                        <span>0 yrs</span>
                        <span className="text-red-400 font-bold">Threat Deadline (Z={z}y)</span>
                        <span>{maxAxis} yrs</span>
                      </div>
                    </div>
                  ) : (
                    <div className="text-[11px] text-emerald-400/90 font-medium">
                      ✓ Post-quantum resistant lattice primitive. Threat horizon exceeds 100+ years.
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════════
          SECTION 5 — HNDL Attack Surface Map (2x2 Grid)
          ════════════════════════════════════════════════════════════════ */}
      <div className="rounded-xl border border-subtle bg-surface p-5 space-y-4">
        <div className="border-b border-subtle pb-3">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-rose-400" />
            <h2 className="text-sm font-bold tracking-tight text-foreground">
              Harvest Now, Decrypt Later (HNDL) Attack Surface Map
            </h2>
          </div>
          <p className="text-xs text-rose-400/90 font-medium mt-1">
            RSA-2048 on your TLS endpoints means every encrypted packet sent today can be stored and decrypted retroactively in ~2033.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Surface 1: Network / TLS */}
          <div className="rounded-lg border border-subtle bg-canvas/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-foreground">
                <Network className="h-4 w-4 text-cyan-400" />
                <span>Network &amp; TLS Endpoints</span>
              </div>
              <span className="text-[10px] font-mono text-quiet">{surfaceAssets.network.length} assets</span>
            </div>
            <p className="text-[11px] text-quiet">
              TLS handshakes transmitting session keys. Immediate target of state-sponsored passive eavesdropping.
            </p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {surfaceAssets.network.length > 0 ? (
                surfaceAssets.network.map((a, i) => {
                  const algo = a.algorithm || a.name || "";
                  const isShor = /RSA|ECDSA|ECDH|DH/i.test(algo);
                  const isSafe = /ML-?KEM|KYBER|AES-256|SHA-256/i.test(algo);
                  return (
                    <span
                      key={i}
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isShor
                          ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                          : isSafe
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      }`}
                      title={isShor ? "Shor Vulnerable (Harvested NOW)" : isSafe ? "Quantum Safe" : "Grover Weakened"}
                    >
                      {algo}
                    </span>
                  );
                })
              ) : (
                <span className="text-[11px] text-quiet italic">No vulnerable network endpoints recorded</span>
              )}
            </div>
          </div>

          {/* Surface 2: Source Code */}
          <div className="rounded-lg border border-subtle bg-canvas/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-foreground">
                <Code2 className="h-4 w-4 text-cyan-400" />
                <span>Source Code Primitives</span>
              </div>
              <span className="text-[10px] font-mono text-quiet">{surfaceAssets.source.length} assets</span>
            </div>
            <p className="text-[11px] text-quiet">
              Hardcoded keys, cryptographic API calls, and signature routines in application codebase.
            </p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {surfaceAssets.source.length > 0 ? (
                surfaceAssets.source.map((a, i) => {
                  const algo = a.algorithm || a.name || "";
                  const isShor = /RSA|ECDSA|ECDH|DH/i.test(algo);
                  const isSafe = /ML-?KEM|KYBER|AES-256|SHA-256/i.test(algo);
                  return (
                    <span
                      key={i}
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isShor
                          ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                          : isSafe
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      }`}
                      title={isShor ? "Shor Vulnerable (Harvested NOW)" : isSafe ? "Quantum Safe" : "Grover Weakened"}
                    >
                      {algo}
                    </span>
                  );
                })
              ) : (
                <span className="text-[11px] text-quiet italic">No vulnerable source code primitives recorded</span>
              )}
            </div>
          </div>

          {/* Surface 3: Binary & Firmware */}
          <div className="rounded-lg border border-subtle bg-canvas/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-foreground">
                <Binary className="h-4 w-4 text-cyan-400" />
                <span>Binary &amp; Firmware Artifacts</span>
              </div>
              <span className="text-[10px] font-mono text-quiet">{surfaceAssets.binary.length} assets</span>
            </div>
            <p className="text-[11px] text-quiet">
              Compiled ELF/Mach-O/PE binaries, firmware images, and static cryptographic tables.
            </p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {surfaceAssets.binary.length > 0 ? (
                surfaceAssets.binary.map((a, i) => {
                  const algo = a.algorithm || a.name || "";
                  const isShor = /RSA|ECDSA|ECDH|DH/i.test(algo);
                  const isSafe = /ML-?KEM|KYBER|AES-256|SHA-256/i.test(algo);
                  return (
                    <span
                      key={i}
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isShor
                          ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                          : isSafe
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      }`}
                      title={isShor ? "Shor Vulnerable" : isSafe ? "Quantum Safe" : "Grover Weakened"}
                    >
                      {algo}
                    </span>
                  );
                })
              ) : (
                <span className="text-[11px] text-quiet italic">No binary cryptographic assets recorded</span>
              )}
            </div>
          </div>

          {/* Surface 4: Certificates */}
          <div className="rounded-lg border border-subtle bg-canvas/50 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-bold text-foreground">
                <FileCode className="h-4 w-4 text-cyan-400" />
                <span>Certificates &amp; PKI Infrastructure</span>
              </div>
              <span className="text-[10px] font-mono text-quiet">{surfaceAssets.certificate.length} assets</span>
            </div>
            <p className="text-[11px] text-quiet">
              X.509 certificates and trust anchors. Shor allows complete forgery of CA signatures.
            </p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {surfaceAssets.certificate.length > 0 ? (
                surfaceAssets.certificate.map((a, i) => {
                  const algo = a.algorithm || a.name || "";
                  const isShor = /RSA|ECDSA|ECDH|DH/i.test(algo);
                  const isSafe = /ML-?DSA|DILITHIUM|SLH-?DSA|SPHINCS/i.test(algo);
                  return (
                    <span
                      key={i}
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        isShor
                          ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                          : isSafe
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                          : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                      }`}
                      title={isShor ? "Shor Forgery Vulnerable" : isSafe ? "Quantum Safe" : "Weakened"}
                    >
                      {algo}
                    </span>
                  );
                })
              ) : (
                <span className="text-[11px] text-quiet italic">No certificate assets recorded</span>
              )}
            </div>
          </div>
        </div>

        <div className="p-3 rounded-lg bg-canvas/40 border border-subtle flex items-center gap-2 text-xs text-quiet">
          <Info className="h-4 w-4 text-cyan-400 shrink-0" />
          <span>
            Red chips denote public-key primitives vulnerable to Shor&apos;s algorithm that are currently targeted by HNDL interceptors.
            Transition to NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) eliminates this threat surface.
          </span>
        </div>
      </div>
    </div>
  );
}
