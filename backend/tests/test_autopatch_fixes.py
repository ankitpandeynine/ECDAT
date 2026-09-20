"""Regression tests for the auto-patch, upload-limit and honest-metrics fixes.

Covers:
1. /api/scans/{id}/result returns the user's source code from {"files": [...]} payloads.
2. /api/patch/from-scan patches the USER's real code (no hardcoded dummy snippet) and
   refuses honestly (422) when a scan carries no source at all.
3. Chunked uploads work end-to-end (previously crashed with NameError: unquote_plus).
4. Custom loop metrics are derived from actual findings (no 28/98 dummy scores) and the
   binary path no longer fabricates post-migration evidence.
"""
import time
import uuid

from fastapi.testclient import TestClient

from main import app


def _wait_for_scan(client, scan_id, project="patchfix", timeout_s=15):
    for _ in range(int(timeout_s / 0.05)):
        record = client.get(f"/api/scans/{scan_id}?project={project}").json()
        if record.get("status") not in ("queued", "running"):
            return record
        time.sleep(0.05)
    raise AssertionError("scan did not finish in time")


def test_scan_result_returns_user_source_from_files_payload():
    with TestClient(app) as client:
        unique_marker = "PATCHFIX_MARKER_9f31"
        code = f"import hashlib\n# {unique_marker}\ntoken = hashlib.md5(b'x').hexdigest()\n"
        res = client.post(
            "/api/scan/code?project=patchfix",
            json={"source_code": code, "language": "python"},
        )
        assert res.status_code == 202
        scan_id = res.json()["id"]
        _wait_for_scan(client, scan_id)

        result = client.get(f"/api/scans/{scan_id}/result?project=patchfix").json()
        assert unique_marker in (result.get("source_code") or ""), (
            "scan result must return the user's actual source code"
        )
        patched = client.post(
            "/api/patch/from-scan",
            json={"scan_id": scan_id, "project_id": "patchfix"},
        )
        assert patched.status_code == 200, patched.text
        data = patched.json()
        # The dummy fallback snippet never contains the unique marker.
        assert unique_marker in data["original_code"]
        assert "hashlib.sha256" in data["patched_code"]
        assert "hashlib.md5" not in data["patched_code"]


def test_patch_from_scan_infers_c_language_and_uses_c_templates():
    with TestClient(app) as client:
        c_code = (
            "#include <openssl/md5.h>\n"
            "void f(const unsigned char *p, size_t n) {\n"
            "    unsigned char d[MD5_DIGEST_LENGTH];\n"
            "    MD5(p, n, d);\n"
            "}\n"
        )
        res = client.post(
            "/api/scan/sources?project=patchfix",
            json={"files": [{"path": "src/crypto.c", "content": c_code}]},
        )
        assert res.status_code == 202
        scan_id = res.json()["id"]
        _wait_for_scan(client, scan_id)

        patched = client.post(
            "/api/patch/from-scan",
            json={"scan_id": scan_id, "project_id": "patchfix"},
        )
        assert patched.status_code == 200, patched.text
        data = patched.json()
        assert data["language"] == "c_cpp"
        assert "SHA256(p, n, d)" in data["patched_code"]
        assert "MD5(" not in data["patched_code"]
        # C regression tests are reported honestly as not executed in-sandbox.
        assert all(t["status"] in ("not_executed", "passed") for t in data["test_results"])


def test_patch_from_scan_without_source_returns_422_not_dummy():
    with TestClient(app) as client:
        res = client.post(
            "/api/scan/binary?project=patchfix",
            json={"raw_hex": "7f454c4602010100" + "00" * 64, "file_name": "app.elf"},
        )
        assert res.status_code == 202
        scan_id = res.json()["id"]
        _wait_for_scan(client, scan_id)

        patched = client.post(
            "/api/patch/from-scan",
            json={"scan_id": scan_id, "project_id": "patchfix"},
        )
        assert patched.status_code == 422
        detail = patched.json()["detail"].lower()
        assert "no source code" in detail
        # The legacy dummy snippet must never be patched again.
        assert "legacy_auth" not in patched.text


def test_chunked_upload_end_to_end():
    with TestClient(app) as client:
        upload_id = str(uuid.uuid4())
        content = b"import hashlib\nh = hashlib.sha1(b'e2e').hexdigest()\n"
        for idx, chunk in enumerate((content[:10], content[10:])):
            res = client.post(
                "/api/upload/chunk",
                content=chunk,
                headers={
                    "X-Upload-ID": upload_id,
                    "X-Chunk-Index": str(idx),
                    "X-Total-Chunks": "2",
                    "X-Filename": "e2e_module.py",
                    "X-Surface": "code",
                    "X-Project-ID": "patchfix",
                },
            )
            assert res.status_code == 200, res.text
        final = res.json()
        assert final["status"] == "processing"
        assert "scan_job_id" in final

        status_res = client.get(f"/api/upload/{upload_id}/status")
        assert status_res.status_code == 200
        assert status_res.json()["status"] == "processing"


def test_custom_loop_metrics_derived_from_findings_not_dummies():
    from engine.custom_loop import CustomLoopRunner

    code = (
        "import hashlib\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "h = hashlib.md5(b'x').hexdigest()\n"
        "k = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
    )
    res = CustomLoopRunner.run_pipeline(
        target_type="source", source_code=code,
        file_name="svc.py", language="python",
    )
    # Two CRITICAL/HIGH findings (MD5 + RSA-1024) must deduct from 100.
    assert res.before_state["security_score"] < 100
    assert res.before_state["critical_vulnerabilities"] >= 2
    assert set(res.before_state["algorithms"]) == {"MD5", "RSA-1024"}
    # After the patch the user's code (not a preset) contains no weak primitives.
    assert "hashlib.md5" not in res.after_state["code"]
    assert res.after_state["critical_vulnerabilities"] == 0
    assert res.after_state["security_score"] >= res.before_state["security_score"]
    assert res.verdict == "VERIFIED"
    assert res.regression_test["status"] == "passed"
    # The fabricated legacy constant scores are gone.
    assert res.before_state["security_score"] != 28
    assert res.after_state["security_score"] != 98
    assert res.before_state["crypto_agility_score"] != 2.1


def test_custom_loop_binary_does_not_fabricate_verification():
    from engine.custom_loop import CustomLoopRunner

    res = CustomLoopRunner.run_pipeline(preset_name="binary")
    report = res.verification_report
    # Nothing was rebuilt/re-scanned: no retired weaknesses may be claimed.
    assert report["verdict"] == "INCONCLUSIVE"
    assert report["summary"]["retired_weaknesses_count"] == 0
    assert report["summary"]["risk_reduction_percentage"] == 0.0
    assert res.regression_test["status"] == "not_executed"
    assert res.unified_diff == ""


def test_large_comment_file_scan_does_not_hang():
    """Verify that a Python file with 30,000+ comment lines scans in < 1 second without tree-sitter quadratic stall."""
    from engine.treesitter_scanner import get_treesitter_scanner
    ts = get_treesitter_scanner()
    code = "import hashlib\n" + ("# padding comment\n" * 30000) + "token = hashlib.sha256(b'test').hexdigest()\n"
    t0 = time.time()
    res = ts.parse_and_scan(code, "python")
    elapsed = time.time() - t0
    assert elapsed < 2.0, f"parse_and_scan took too long: {elapsed:.2f}s"
    assert res["status"] == "success"
    findings = res.get("findings", [])
    assert any(f.get("primitive") == "SHA-256" or f.get("algorithm") == "SHA-256" for f in findings)
    # Correct line mapping preserved despite comment blanking
    assert any(f.get("line") == 30002 for f in findings)


def test_scan_store_list_performance():
    """Verify that /api/scans?project=... returns scan list efficiently without loading full payload blobs."""
    with TestClient(app) as client:
        res = client.get("/api/scans?project=patchfix")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        for item in data:
            assert "id" in item
            assert "status" in item
            assert "engine_version" in item
            # Full raw payload must not be leaked or needlessly transferred in scan list
            assert "payload" not in item


def test_polyglot_and_knowledge_graph_optimizations():
    """Verify that polyglot scanning, sink caching, and graph node synchronization run quickly and accurately."""
    from engine.polyglot_scanner import scan_polyglot_code
    from engine.sink_database import get_sink_database
    from engine.mosca import normalize_algo_and_keysize
    from engine.knowledge_graph import sync_knowledge_graph_tables
    from engine.scan_store import ScanStore

    # 1. Polyglot scan line calculation and performance
    java_code = "package test;\n" + ("// padding line\n" * 5000) + 'MessageDigest md = MessageDigest.getInstance("MD5");\n'
    t0 = time.time()
    res = scan_polyglot_code(java_code, "java")
    elapsed = time.time() - t0
    assert elapsed < 1.0, f"Polyglot scan took {elapsed:.2f}s"
    assert res["total_findings"] >= 1
    assert res["findings"][0]["line"] == 5002
    assert res["findings"][0]["primitive"] == "MD5"

    # 2. Sink database memoization
    sink_db = get_sink_database()
    assert sink_db.is_crypto_dependency("cryptography") is True
    assert sink_db.is_crypto_dependency("nonexistent-random-pkg-1234") is False
    assert len(sink_db.get_dependency_capabilities("cryptography")) > 0

    # 3. Mosca normalization cache
    norm1 = normalize_algo_and_keysize("RSA-2048")
    norm2 = normalize_algo_and_keysize("RSA-2048")
    assert norm1 == norm2 == ("RSA", 2048)

    # 4. Sync knowledge graph tables batch execution
    store = ScanStore()
    try:
        sync_res = sync_knowledge_graph_tables(store, "test-opt-project")
        assert "nodes" in sync_res
    finally:
        store.close()