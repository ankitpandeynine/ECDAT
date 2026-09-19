import os
import shutil
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from main import app
from engine.github_scanner import scan_github_repo

client = TestClient(app)


def test_github_scanner_invalid_url():
    with pytest.raises(ValueError, match="Repository URL must start with 'https://github.com/'"):
        scan_github_repo("https://gitlab.com/attacker/repo")

    with pytest.raises(ValueError, match="Repository URL must start with 'https://github.com/'"):
        scan_github_repo("http://github.com/insecure/repo")


def test_github_scanner_mock_repo():
    # Create a mock cloned directory
    temp_repo = tempfile.mkdtemp(prefix="test_gh_repo_")
    try:
        # Create sample crypto files
        crypto_py = os.path.join(temp_repo, "crypto_service.py")
        with open(crypto_py, "w", encoding="utf-8") as f:
            f.write("""
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

key = RSA.generate(2048)
cipher = AES.new(b"0123456789abcdef0123456789abcdef", AES.MODE_GCM)
legacy_hash = hashlib.sha1(b"data").hexdigest()
""")

        # Create oversized file (>500KB) to test skipping safeguard
        oversized = os.path.join(temp_repo, "large_blob.py")
        with open(oversized, "wb") as f:
            f.write(b"x" * (510 * 1024))

        # Create ignored folder
        node_mods = os.path.join(temp_repo, "node_modules")
        os.makedirs(node_mods, exist_ok=True)
        with open(os.path.join(node_mods, "skip_me.js"), "w") as f:
            f.write("const crypto = require('crypto');")

        # Mock subprocess.run for git clone
        def fake_subprocess_run(cmd, *args, **kwargs):
            # Target dir is last arg
            target_dir = cmd[-1]
            # Copy test_repo contents to target_dir
            for item in os.listdir(temp_repo):
                s = os.path.join(temp_repo, item)
                d = os.path.join(target_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)
            res = MagicMock()
            res.returncode = 0
            res.stdout = "Cloned successfully"
            res.stderr = ""
            return res

        with patch("subprocess.run", side_effect=fake_subprocess_run):
            res = scan_github_repo("https://github.com/enterprise/crypto-core", token="test_token_secret")

            assert res["status"] == "success"
            assert res["files_scanned"] >= 1
            assert res["files_skipped"] >= 1  # Oversized file + node_modules
            assert "evidence_records" in res
            assert res["repo_url"] == "https://github.com/enterprise/crypto-core"
            assert res["branch"] == "main"

            # Check that findings caught RSA/AES/SHA1
            primitives = [f.get("primitive") for f in res.get("findings", [])]
            assert any("RSA" in str(p) or "AES" in str(p) or "SHA" in str(p) for p in primitives)

    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


def test_api_scan_github_endpoint():
    with TestClient(app) as client:
        # Test rejection of non-github URL
        bad_res = client.post("/api/scan/github", json={
            "repo_url": "https://bitbucket.org/org/repo",
            "project_id": "default"
        })
        assert bad_res.status_code == 400
        assert "https://github.com/" in bad_res.json()["detail"]

        # Test queueing with mock worker
        with patch("routes.scans.scan_github_repo") as mock_scanner:
            mock_scanner.return_value = {
                "status": "success",
                "files_scanned": 1,
                "files_skipped": 0,
                "evidence_records": [],
                "findings": [],
                "repo_url": "https://github.com/enterprise/core",
                "branch": "main"
            }

            res = client.post("/api/scan/github", json={
                "repo_url": "https://github.com/enterprise/core",
                "branch": "main",
                "subdir": "src/crypto",
                "project_id": "default"
            })

            assert res.status_code == 202
            data = res.json()
            assert "scan_id" in data or "id" in data
            assert data["kind"] == "github"
            assert data["status"] in ("queued", "running", "completed")
