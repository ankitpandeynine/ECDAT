"""
ECDAT V4 P1.1 Test Suite: Advanced Source-Code & Dependency Cryptographic Intelligence.

Covers:
1. Import only != actual use
2. Dependency only != actual use
3. Comment != actual use
4. String literal != actual use
5. Python RSA actual use
6. Python AES actual use
7. Java Cipher actual use
8. Java KeyPairGenerator actual use
9. C/C++ OpenSSL actual use
10. Go AES actual use
11. Rust AES actual use
12. JS crypto actual use
13. TypeScript crypto actual use
14. Direct constant propagation
15. Unknown constant handling
16. Cross-file constant propagation
17. Simple call graph extraction
18. requirements.txt manifest parsing
19. pyproject.toml manifest parsing
20. package.json manifest parsing
21. package-lock.json lockfile parsing
22. pom.xml manifest parsing
23. go.mod manifest parsing
24. Cargo.toml manifest parsing
25. Broken syntax fallback & error handling
26. Asset graph CALLS relationship integration
"""
import pytest
from engine.asset_graph import AssetGraphService, AssetType, CryptoAsset, RelationshipType
from engine.dependency_scanner import get_dependency_scanner
from engine.evidence_model import EvidenceLevel, EvidenceState, ObservationType
from engine.sink_database import get_sink_database
from engine.source_scan import python_findings, scan_sources
from engine.treesitter_scanner import ConstructType, get_treesitter_scanner


@pytest.fixture
def ts_scanner():
    scanner = get_treesitter_scanner()
    if not scanner.is_available("python"):
        pytest.skip("Tree-sitter parser is not available in this environment")
    return scanner


@pytest.fixture
def dep_scanner():
    return get_dependency_scanner()


@pytest.fixture
def sink_db():
    return get_sink_database()


# ==============================================================================
# 1. FALSE POSITIVE CONTROL: IMPORT != ACTUAL USE
# ==============================================================================
def test_import_only_not_actual_use(ts_scanner):
    code = """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
import Crypto.Cipher.AES
"""
    res = ts_scanner.parse_and_scan(code, "python", "test_import.py")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 0
    assert len(res["findings"]) == 0

    obs_types = [o["construct_type"] for o in res["observations"]]
    assert all(ot != "ACTUAL_USE" for ot in obs_types)
    assert any(ot == "IMPORT" for ot in obs_types)


# ==============================================================================
# 2. FALSE POSITIVE CONTROL: DEPENDENCY != ACTUAL USE
# ==============================================================================
def test_dependency_only_not_actual_use(dep_scanner):
    req_content = """
cryptography==42.0.5
pycryptodome>=3.20.0
"""
    res = dep_scanner.scan_manifest_or_lockfile("requirements.txt", req_content)
    assert res["total_dependencies"] == 2
    for dep in res["dependencies"]:
        assert dep["is_crypto"] is True
        assert dep["actual_use"] is False
        assert len(dep["crypto_capabilities"]) > 0

    # Verify that emitted evidence does not claim actual use
    for ev in res["evidence"]:
        assert ev["observation_type"] == ObservationType.DEPENDENCY_DECLARATION
        assert ev["level"] in (EvidenceLevel.E0, EvidenceLevel.E2)


# ==============================================================================
# 3. FALSE POSITIVE CONTROL: COMMENT != ACTUAL USE
# ==============================================================================
def test_comment_is_not_actual_use(ts_scanner):
    code = """
// TODO: migrate our legacy RSA-1024 and DES systems to AES-256-GCM
// Note: We used MD5 in the 1990s but deprecated it.
int x = 42;
"""
    res = ts_scanner.parse_and_scan(code, "c_cpp", "crypto_comments.c")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 0
    assert len(res["findings"]) == 0
    obs_types = [o["construct_type"] for o in res["observations"]]
    assert "COMMENT" in obs_types
    assert "ACTUAL_USE" not in obs_types


# ==============================================================================
# 4. FALSE POSITIVE CONTROL: STRING LITERAL != ACTUAL USE
# ==============================================================================
def test_string_literal_is_candidate_only(ts_scanner):
    code = """
app_banner = "Welcome to AES-256-GCM Secure Portal"
doc_title = "RSA"
print(app_banner)
"""
    res = ts_scanner.parse_and_scan(code, "python", "banner.py")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 0
    assert len(res["findings"]) == 0
    obs_types = [o["construct_type"] for o in res["observations"]]
    assert "STRING_LITERAL" in obs_types
    assert "ACTUAL_USE" not in obs_types


# ==============================================================================
# 5. ACTUAL USE: PYTHON RSA
# ==============================================================================
def test_python_rsa_actual_use(ts_scanner):
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
    res = ts_scanner.parse_and_scan(code, "python", "rsa_service.py")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 1
    assert len(res["findings"]) == 1

    finding = res["findings"][0]
    assert finding["primitive"] == "RSA-2048"
    assert finding["actual_use"] is True
    assert finding["calling_scope"] == "generate_key"
    assert finding["severity"] == "HIGH"


# ==============================================================================
# 6. ACTUAL USE: PYTHON AES
# ==============================================================================
def test_python_aes_actual_use(ts_scanner):
    code = """
from Crypto.Cipher import AES

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher
"""
    res = ts_scanner.parse_and_scan(code, "python", "aes_service.py")
    assert res["status"] == "success"
    assert res["actual_use_count"] >= 1
    primitives = [f["primitive"] for f in res["findings"]]
    assert any("AES" in p for p in primitives)


# ==============================================================================
# 7. ACTUAL USE: JAVA CIPHER
# ==============================================================================
def test_java_cipher_actual_use(ts_scanner):
    code = """
package com.bank.crypto;
import javax.crypto.Cipher;

public class Encryptor {
    public void execute() throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    }
}
"""
    res = ts_scanner.parse_and_scan(code, "java", "Encryptor.java")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 1
    finding = res["findings"][0]
    assert finding["primitive"] == "AES-GCM"
    assert finding["actual_use"] is True
    assert finding["calling_scope"] == "execute"


# ==============================================================================
# 8. ACTUAL USE: JAVA KEYPAIRGENERATOR
# ==============================================================================
def test_java_keypair_generator_actual_use(ts_scanner):
    code = """
import java.security.KeyPairGenerator;

public class KeyService {
    public void setup() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
    }
}
"""
    res = ts_scanner.parse_and_scan(code, "java", "KeyService.java")
    assert res["status"] == "success"
    assert res["actual_use_count"] >= 1
    primitives = [f["primitive"] for f in res["findings"]]
    assert any("RSA" in p for p in primitives)


# ==============================================================================
# 9. ACTUAL USE: C/C++ OPENSSL
# ==============================================================================
def test_c_cpp_openssl_actual_use(ts_scanner):
    code = """
#include <openssl/evp.h>
#include <openssl/rsa.h>

void setup_crypto() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
}
"""
    res = ts_scanner.parse_and_scan(code, "c_cpp", "crypto.c")
    assert res["status"] == "success"
    assert res["actual_use_count"] >= 1
    assert any(f["actual_use"] for f in res["findings"])


# ==============================================================================
# 10. ACTUAL USE: GO AES
# ==============================================================================
def test_go_aes_actual_use(ts_scanner):
    code = """
package main
import "crypto/aes"

func securePayload(key []byte) {
    block, err := aes.NewCipher(key)
    _ = block
}
"""
    res = ts_scanner.parse_and_scan(code, "golang", "main.go")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 1
    assert res["findings"][0]["primitive"] == "AES"
    assert res["findings"][0]["actual_use"] is True


# ==============================================================================
# 11. ACTUAL USE: RUST AES-GCM
# ==============================================================================
def test_rust_aes_actual_use(ts_scanner):
    code = """
use aes_gcm::{Aes256Gcm, KeyInit};

fn encrypt_payload(key: &[u8; 32]) {
    let cipher = Aes256Gcm::new(key.into());
}
"""
    res = ts_scanner.parse_and_scan(code, "rust", "main.rs")
    assert res["status"] == "success"
    assert res["actual_use_count"] >= 1
    assert res["findings"][0]["primitive"] == "AES-256-GCM"


# ==============================================================================
# 12. ACTUAL USE: JAVASCRIPT CRYPTO
# ==============================================================================
def test_javascript_crypto_actual_use(ts_scanner):
    code = """
const crypto = require('crypto');

function encrypt(data, key, iv) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher.update(data);
}
"""
    res = ts_scanner.parse_and_scan(code, "javascript", "crypto_service.js")
    assert res["status"] == "success"
    assert res["actual_use_count"] == 1
    assert res["findings"][0]["primitive"] == "AES-CBC"
    assert res["findings"][0]["actual_use"] is True


# ==============================================================================
# 13. ACTUAL USE: TYPESCRIPT CRYPTO
# ==============================================================================
def test_typescript_crypto_actual_use(ts_scanner):
    code = """
import * as crypto from 'crypto';

export class TokenSigner {
    sign(): void {
        const hash = crypto.createHash('sha256');
    }
}
"""
    res = ts_scanner.parse_and_scan(code, "typescript", "signer.ts")
    assert res["status"] == "success"
    assert res["actual_use_count"] >= 1
    primitives = [f["primitive"] for f in res["findings"]]
    assert any("SHA" in p or "Hash" in p for p in primitives)


# ==============================================================================
# 14. CONSTANT PROPAGATION: DIRECT CONSTANT
# ==============================================================================
def test_direct_constant_propagation(ts_scanner):
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_SIZE = 4096

def gen():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
"""
    res = ts_scanner.parse_and_scan(code, "python", "keygen.py")
    assert res["status"] == "success"
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    assert finding["primitive"] == "RSA-4096"
    assert finding["key_size"] == 4096


# ==============================================================================
# 15. CONSTANT PROPAGATION: UNKNOWN DYNAMIC VALUE
# ==============================================================================
def test_unknown_constant_handling(ts_scanner):
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

def get_dynamic_size():
    return int(os.environ.get("BITS", 2048))

def gen():
    return rsa.generate_private_key(public_exponent=65537, key_size=get_dynamic_size())
"""
    res = ts_scanner.parse_and_scan(code, "python", "keygen.py")
    assert res["status"] == "success"
    assert len(res["findings"]) == 1
    finding = res["findings"][0]
    # Never guesses when unresolved: reports UNKNOWN
    assert finding["key_size"] == "UNKNOWN"


# ==============================================================================
# 16. CROSS-FILE CONSTANT PROPAGATION
# ==============================================================================
def test_cross_file_constant_propagation():
    files = [
        {"path": "config.py", "content": "KEY_SIZE = 2048\n"},
        {"path": "auth.py", "content": "from config import KEY_SIZE\n"},
        {"path": "crypto_ops.py", "content": "from auth import KEY_SIZE\nfrom cryptography.hazmat.primitives.asymmetric import rsa\nk = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)\n"}
    ]
    res = scan_sources(files)
    assert res["status"] == "success"
    rsa_findings = [f for f in res["findings"] if "RSA" in f["primitive"]]
    assert len(rsa_findings) == 1
    assert rsa_findings[0]["primitive"] == "RSA-2048"


# ==============================================================================
# 17. LIGHTWEIGHT CALL GRAPH EXTRACTION
# ==============================================================================
def test_simple_call_graph(ts_scanner):
    code = """
from cryptography.hazmat.primitives.asymmetric import rsa

def sign_token():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def authenticate():
    return sign_token()
"""
    res = ts_scanner.parse_and_scan(code, "python", "auth_flow.py")
    assert res["status"] == "success"
    cg = res["call_graph"]
    assert len(cg) >= 1
    assert any(c["caller"] == "sign_token" and "RSA" in c["callee"] for c in cg)


# ==============================================================================
# 18. DEPENDENCY SCANNING: requirements.txt
# ==============================================================================
def test_manifest_requirements_txt(dep_scanner):
    content = """
# Production requirements
cryptography>=42.0.0
flask==3.0.0
pytest>=8.0.0
"""
    res = dep_scanner.scan_manifest_or_lockfile("requirements.txt", content)
    crypto_deps = [d["name"] for d in res["crypto_dependencies"]]
    assert "cryptography" in crypto_deps
    assert "flask" not in crypto_deps


# ==============================================================================
# 19. DEPENDENCY SCANNING: pyproject.toml
# ==============================================================================
def test_manifest_pyproject_toml(dep_scanner):
    content = """
[project]
name = "secure-core"
version = "1.0.0"
dependencies = [
    "cryptography>=42.0.0",
    "pydantic>=2.0.0",
]
"""
    res = dep_scanner.scan_manifest_or_lockfile("pyproject.toml", content)
    crypto_deps = [d["name"] for d in res["crypto_dependencies"]]
    assert "cryptography" in crypto_deps


# ==============================================================================
# 20. DEPENDENCY SCANNING: package.json
# ==============================================================================
def test_manifest_package_json(dep_scanner):
    content = """
{
  "name": "gateway",
  "dependencies": {
    "jsonwebtoken": "^9.0.2",
    "express": "^4.19.0"
  },
  "devDependencies": {
    "typescript": "^5.4.0"
  }
}
"""
    res = dep_scanner.scan_manifest_or_lockfile("package.json", content)
    crypto_deps = [d["name"] for d in res["crypto_dependencies"]]
    assert "jsonwebtoken" in crypto_deps
    assert "express" not in crypto_deps


# ==============================================================================
# 21. LOCKFILE SCANNING: package-lock.json
# ==============================================================================
def test_lockfile_package_lock_json(dep_scanner):
    content = """
{
  "name": "gateway",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/crypto-js": {
      "version": "4.2.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21"
    }
  }
}
"""
    res = dep_scanner.scan_manifest_or_lockfile("package-lock.json", content)
    crypto_deps = [d["name"] for d in res["crypto_dependencies"]]
    assert "crypto-js" in crypto_deps
    assert res["dependencies"][0]["is_locked"] is True


# ==============================================================================
# 22. DEPENDENCY SCANNING: pom.xml
# ==============================================================================
def test_manifest_pom_xml(dep_scanner):
    content = """
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>33.0.0-jre</version>
    </dependency>
  </dependencies>
</project>
"""
    res = dep_scanner.scan_manifest_or_lockfile("pom.xml", content)
    crypto_deps = [d["name"] for d in res["crypto_dependencies"]]
    assert any("bouncycastle" in d or "bcprov" in d for d in crypto_deps)


# ==============================================================================
# 23. DEPENDENCY SCANNING: go.mod
# ==============================================================================
def test_manifest_go_mod(dep_scanner):
    content = """
module example.com/crypto-service
go 1.22
require (
    golang.org/x/crypto v0.21.0
    github.com/gin-gonic/gin v1.9.1
)
"""
    res = dep_scanner.scan_manifest_or_lockfile("go.mod", content)
    names = [d["name"] for d in res["dependencies"]]
    assert "golang.org/x/crypto" in names
    assert "github.com/gin-gonic/gin" in names


# ==============================================================================
# 24. DEPENDENCY SCANNING: Cargo.toml
# ==============================================================================
def test_manifest_cargo_toml(dep_scanner):
    content = """
[package]
name = "pqc-vault"
version = "0.1.0"

[dependencies]
aes-gcm = "0.10.3"
serde = "1.0"
ring = "0.17"
"""
    res = dep_scanner.scan_manifest_or_lockfile("Cargo.toml", content)
    crypto_deps = [d["name"] for d in res["crypto_dependencies"]]
    assert "aes-gcm" in crypto_deps
    assert "ring" in crypto_deps
    assert "serde" not in crypto_deps


# ==============================================================================
# 25. BROKEN SYNTAX & SCANNER UNAVAILABLE FALLBACK
# ==============================================================================
def test_broken_syntax_fallback(ts_scanner):
    from engine.ast_scanner import scan_code
    # Missing parentheses, incomplete statement
    broken_code = "def incomplete_func(\n  hashlib.md5(broken"
    findings = scan_code(broken_code)
    # Fast regex fallback still flags MD5 without crashing
    assert any("MD5" in f["primitive"] for f in findings)

    # Unsupported language returns explicit unavailable state
    unsupported_res = ts_scanner.parse_and_scan("content", "unsupported_xyz_lang")
    assert unsupported_res["status"] == "scanner_unavailable"
    assert unsupported_res["available"] is False
    assert unsupported_res["inconclusive"] is True


# ==============================================================================
# 26. ASSET GRAPH INTEGRATION WITH CALLS RELATIONSHIPS
# ==============================================================================
def test_asset_graph_calls_integration(tmp_path):
    from engine.scan_store import ScanStore
    store = ScanStore(tmp_path / "graph_test.sqlite3")
    graph = store.graph

    with store.connect() as db:
        db.execute(
            """INSERT OR IGNORE INTO scans (
                id, project, kind, status, created_at, input_hash
            ) VALUES (?, ?, 'code', 'completed', ?, 'test-hash')""",
            ("scan-s1", "test_proj", "2026-09-17T00:00:00Z"),
        )



    graph.create_asset(

        project="test_proj",
        asset_type=AssetType.SERVICE,
        name="auth_handler",
        scan_id="scan-s1",
        asset_id="svc-test-auth_handler",
    )
    graph.create_asset(
        project="test_proj",
        asset_type=AssetType.ALGORITHM,
        name="RSA-2048",
        scan_id="scan-s1",
        algorithm="RSA",
        key_size=2048,
        asset_id="asset-test-rsa_2048",
    )

    graph.add_relationship(
        project="test_proj",
        source_id="svc-test-auth_handler",
        source_type="SERVICE",
        relationship=RelationshipType.CALLS,
        target_id="asset-test-rsa_2048",
        target_type="ALGORITHM",
        scan_id="scan-s1",
    )


    neighbors = graph.get_neighbors("svc-test-auth_handler", direction="outgoing")
    assert len(neighbors["outgoing"]) == 1
    edge = neighbors["outgoing"][0]
    assert edge["relationship"] == "CALLS"
    assert edge["target_id"] == "asset-test-rsa_2048"
    target_asset = graph.get_asset(edge["target_id"])
    assert target_asset.name == "RSA-2048"

