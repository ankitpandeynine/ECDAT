"""Tests for network traffic estimation, project patch ZIP download, and real web PCAP dissection."""
import io
import zipfile
from fastapi.testclient import TestClient
from main import app
from engine.website_inspector import estimate_probable_traffic
from engine.pcap_engine import PcapEngine

client = TestClient(app)


def test_estimate_probable_traffic_cloudflare():
    headers = {
        "server": "cloudflare",
        "cf-ray": "8c591873192078a1-SJC",
        "cf-cache-status": "HIT",
        "strict-transport-security": "max-age=31536000; includeSubDomains"
    }
    traffic = estimate_probable_traffic(headers, response_header_ms=38.4)
    assert traffic["estimated_tier"] == "Enterprise High Volume"
    assert "Cloudflare" in traffic["cdn_provider"]
    assert "5,000,000" in traffic["probable_daily_requests"]
    assert traffic["traffic_scale"] == "HIGH"
    assert "Ultra Fast" in traffic["latency_rating"]
    assert traffic["security_headers"]["hsts"] is True


def test_estimate_probable_traffic_direct_origin():
    headers = {
        "server": "nginx/1.18.0",
        "content-type": "text/html"
    }
    traffic = estimate_probable_traffic(headers, response_header_ms=180.0)
    assert traffic["estimated_tier"] == "Standard Web / Dedicated Proxy"
    assert traffic["cdn_provider"] == "Nginx Reverse Proxy / Load Balancer"
    assert "25,000" in traffic["probable_daily_requests"]
    assert traffic["traffic_scale"] == "MODERATE"
    assert "Moderate" in traffic["latency_rating"]


def test_download_patched_project_with_override_files():
    files = [
        {
            "path": "services/crypto_utils.py",
            "content": "import hashlib\ndef get_hash(data):\n    return hashlib.md5(data).hexdigest()\n",
            "language": "python"
        },
        {
            "path": "config/settings.json",
            "content": '{"app": "test", "version": 1}',
            "language": "json"
        }
    ]
    with TestClient(app) as tc:
        resp = tc.post("/api/patch/download-project", json={"project_id": "test_proj", "override_files": files})
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert "test_proj_patched_project.zip" in resp.headers["content-disposition"]

        # Verify ZIP contents
        with zipfile.ZipFile(io.BytesIO(resp.content), "r") as zf:
            namelist = zf.namelist()
            assert "services/crypto_utils.py" in namelist
            assert "config/settings.json" in namelist
            assert "ECDAT_MIGRATION_REPORT.md" in namelist

            py_content = zf.read("services/crypto_utils.py").decode("utf-8")
            assert "hashlib.sha256" in py_content
            assert "hashlib.md5" not in py_content

            json_content = zf.read("config/settings.json").decode("utf-8")
            assert '"app": "test"' in json_content

            report = zf.read("ECDAT_MIGRATION_REPORT.md").decode("utf-8")
            assert "MD5_TO_SHA256_PYTHON" in report
            assert "ML-KEM-768" in report


def test_real_web_traffic_pcap_generation_and_dissection():
    # Test generation of realistic multi-session web traffic
    pcap_data = PcapEngine.generate_realistic_web_pcap()
    assert len(pcap_data) > 300

    result = PcapEngine.parse_pcap_bytes(pcap_data)
    assert result.status == "success"
    assert result.packets_analyzed == 6  # 3 sessions x 2 packets (ClientHello + ServerHello)
    assert result.tls_handshakes_detected == 3

    # Ensure SNIs and algorithms are parsed
    snis = [s.sni for s in result.sessions]
    assert "www.cloudflare.com" in snis
    assert "api.github.com" in snis
    assert "gateway.internal.bank" in snis

    # Verify PQC hybrid detection
    assert result.pqc_sessions_count >= 1
    pqc_session = next(s for s in result.sessions if s.sni == "www.cloudflare.com")
    assert pqc_session.has_pqc_hybrid is True
    assert pqc_session.is_quantum_vulnerable is False


def test_scan_pcap_real_traffic_endpoint():
    with TestClient(app) as tc:
        resp = tc.post("/api/scan/pcap/real-traffic?project=pcap_real_test")
        assert resp.status_code == 202
        data = resp.json()
        assert data["kind"] == "pcap"


def test_polyglot_scanner_all_languages():
    from engine.polyglot_scanner import scan_polyglot_code

    # 1. Rust
    rust_code = "use md5; fn test() { let d = md5::compute(b\"test\"); let k = RsaPrivateKey::new(&mut rng, 1024); }"
    rust_res = scan_polyglot_code(rust_code, "rust")
    assert rust_res["total_findings"] >= 2
    assert any(f["primitive"] == "MD5" for f in rust_res["findings"])
    assert any("RSA" in f["primitive"] for f in rust_res["findings"])

    # 2. C#
    cs_code = "using var md5 = MD5.Create(); var des = DESCryptoServiceProvider.Create(); var rsa = new RSACryptoServiceProvider(1024);"
    cs_res = scan_polyglot_code(cs_code, "csharp")
    assert cs_res["total_findings"] >= 3
    assert any(f["primitive"] == "MD5" for f in cs_res["findings"])
    assert any(f["primitive"] == "DES" for f in cs_res["findings"])

    # 3. PHP
    php_code = "<?php $hash = md5($pwd); $enc = openssl_encrypt($data, 'des-ecb', $key); $cfg = ['private_key_bits' => 1024];"
    php_res = scan_polyglot_code(php_code, "php")
    assert php_res["total_findings"] >= 2
    assert any(f["primitive"] == "MD5" for f in php_res["findings"])

    # 4. Ruby
    rb_code = "token = Digest::MD5.hexdigest(data); cipher = OpenSSL::Cipher::DES.new; key = OpenSSL::PKey::RSA.generate(1024)"
    rb_res = scan_polyglot_code(rb_code, "ruby")
    assert rb_res["total_findings"] >= 3
    assert any(f["primitive"] == "MD5" for f in rb_res["findings"])

    # 5. Swift
    swift_code = "CC_MD5(bytes, len, &digest); let key = SecKeyCreateRandomKey(attrs, &err); // RSA 1024"
    swift_res = scan_polyglot_code(swift_code, "swift")
    assert any(f["primitive"] == "MD5" for f in swift_res["findings"])

    # 6. Kotlin
    kt_code = "val md = MessageDigest.getInstance(\"MD5\"); val c = Cipher.getInstance(\"DES\"); kpg.initialize(1024)"
    kt_res = scan_polyglot_code(kt_code, "kotlin")
    assert kt_res["total_findings"] >= 3
    assert any(f["primitive"] == "MD5" for f in kt_res["findings"])

    # 7. Universal fallback for unknown / random judge language
    random_lang_code = "val broken_hash = md5(random_data)\nval legacy_cipher = des.encrypt()\nval key = rsa_1024_gen()"
    universal_res = scan_polyglot_code(random_lang_code, "obscure_judge_language_xyz")
    assert universal_res["language"] == "universal"
    assert universal_res["total_findings"] >= 2
    assert any(f["primitive"] == "MD5" for f in universal_res["findings"])


def test_ai_copilot_chat_and_test_key():
    from engine.gemini_assistant import GeminiSecurityAssistant

    # 1. Test test_key validation
    empty_res = GeminiSecurityAssistant.test_api_key("gemini", "")
    assert empty_res["ok"] is False

    invalid_provider_res = GeminiSecurityAssistant.test_api_key("unknown_provider", "key123")
    assert invalid_provider_res["ok"] is False

    gem_dummy = GeminiSecurityAssistant.test_api_key("gemini", "dummy_key")
    assert gem_dummy["ok"] is False
    assert "not valid" in gem_dummy["error"].lower() or "http" in gem_dummy["error"].lower()
    assert "404" not in gem_dummy["error"]  # 404 must not be returned for model

    nv_dummy = GeminiSecurityAssistant.test_api_key("nvidia", "dummy_key")
    assert nv_dummy["ok"] is False
    assert "410" not in nv_dummy["error"]  # 410 Gone must never be returned!

    # 2. Test chat_with_context deterministic fallback with active page context
    ctx = {
        "active_page": "Quantum Risk Matrix",
        "project_name": "Core Banking Hub",
        "total_assets": 42,
        "quantum_vulnerable_assets": 19,
        "critical_assets": 7,
        "security_score": 64,
        "mosca_deficit": "2.4 years"
    }

    res = GeminiSecurityAssistant.chat_with_context(
        question="Which active page am I on and what is my quantum exposure?",
        context=ctx,
        provider="auto"
    )
    assert res["is_authoritative"] is False
    assert "Quantum Risk Matrix" in res["reply"]
    assert "19" in res["reply"] or "42" in res["reply"]
    assert res["active_page"] == "Quantum Risk Matrix"

    # 3. Test API endpoint /api/ai/chat
    with TestClient(app) as tc:
        resp = tc.post("/api/ai/chat", json={
            "question": "What is Mosca's theorem?",
            "context": ctx,
            "provider": "auto"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "reply" in data
        assert "Mosca" in data["reply"]
        assert data["is_authoritative"] is False


def test_autopatch_batch_multi_language_and_cross_language_families():
    from engine.patch_engine import AutoPatchEngine

    mixed_code = """from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib

# Finding at line 5: RSA-2048
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Finding at line 8: SHA-1
old_hash = hashlib.sha1(b"legacy").digest()

# Finding at line 11: JS RSA
const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

# Finding at line 14: JS MD5
const h = crypto.createHash('md5').update(payload).digest('hex');
"""

    res = AutoPatchEngine.batch_patch_code(
        source_code=mixed_code,
        file_path="frontend/src/app/dashboard/page.tsx",
        allowed_pattern_ids=["RSA_2048_TO_MLKEM_PYTHON", "MD5_TO_SHA256_PYTHON"]
    )

    assert res["total_patched"] >= 3
    patched = res["patched_code"]
    # Python RSA remediated to ML-KEM-768
    assert "mlkem.generate_hybrid_keypair" in patched
    # JS RSA remediated to ML-KEM-768 via family mapping
    assert "mlkem.generateKeyPairSync('ml-kem-768'" in patched
    # JS MD5 remediated to SHA-256 via family mapping
    assert "crypto.createHash('sha256')" in patched
    # Detailed logs present
    assert any("[ AST TRANSFORM ]" in log for log in res["execution_logs"])
    assert any("[ PASS ]" in log for log in res["execution_logs"])


def test_get_scan_result_dict_coverage_and_network_binary():
    import uuid
    import json
    from main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        store = getattr(app.state, "store", None)
        assert store is not None

        scan_id = str(uuid.uuid4())
        res_data = json.dumps({
            "coverage": {"addresses_tested": 1, "limitations": ["bounded"]},
            "findings": [],
            "probable_traffic": {"traffic_scale": "HIGH"}
        })
        with store.connect() as db:
            db.execute(
                "INSERT INTO scans (id, project, kind, status, created_at, finished_at, input_hash, payload, result) "
                "VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?, ?)",
                (scan_id, "default", "network", "completed", "dummyhash", '{"targets": ["api.internal"]}', res_data)
            )

        res = client.get(f"/api/scans/{scan_id}/result?project=default")
        assert res.status_code == 200
        data = res.json()
        assert data["kind"] == "network"
        assert data["files_scanned"] == 1
        assert data["ast_coverage_pct"] == 100
        assert data["findings"] == []
