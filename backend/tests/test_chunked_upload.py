import os
import io
import uuid
import pytest
from fastapi.testclient import TestClient
from main import app

def test_chunked_upload_source_flow():
    with TestClient(app) as client:
        upload_id = str(uuid.uuid4())
        filename = "crypto_module.py"
        full_content = (
            b"import hashlib\nfrom Crypto.PublicKey import RSA\n"
            b"key = RSA.generate(2048)\nh = hashlib.sha1(b'hello').hexdigest()\n"
        )
        
        # Split into 2 chunks
        chunk_size = len(full_content) // 2
        chunk_0 = full_content[:chunk_size]
        chunk_1 = full_content[chunk_size:]

        # Send chunk 0
        res0 = client.post(
            "/api/upload/chunk",
            content=chunk_0,
            headers={
                "X-Upload-ID": upload_id,
                "X-Chunk-Index": "0",
                "X-Total-Chunks": "2",
                "X-Filename": filename,
                "X-Surface": "code",
                "X-Project-ID": "default"
            }
        )
        assert res0.status_code == 200
        data0 = res0.json()
        assert data0["upload_id"] == upload_id
        assert data0["received_chunks"] == 1
        assert data0["status"] == "uploading"

        # Check status endpoint
        st_res = client.get(f"/api/upload/{upload_id}/status")
        assert st_res.status_code == 200
        st_data = st_res.json()
        assert st_data["upload_id"] == upload_id
        assert st_data["received_chunks"] == 1
        assert st_data["total_chunks"] == 2
        assert st_data["status"] == "uploading"

        # Send chunk 1 (final chunk)
        res1 = client.post(
            "/api/upload/chunk",
            content=chunk_1,
            headers={
                "X-Upload-ID": upload_id,
                "X-Chunk-Index": "1",
                "X-Total-Chunks": "2",
                "X-Filename": filename,
                "X-Surface": "code",
                "X-Project-ID": "default"
            }
        )
        assert res1.status_code == 200
        data1 = res1.json()
        assert data1["upload_id"] == upload_id
        assert data1["status"] == "processing"
        assert "scan_job_id" in data1
        scan_job_id = data1["scan_job_id"]

        # Check status endpoint after completion
        st_res2 = client.get(f"/api/upload/{upload_id}/status")
        assert st_res2.status_code == 200
        assert st_res2.json()["status"] == "processing"
        assert st_res2.json()["scan_job_id"] == scan_job_id


def test_chunked_upload_binary_flow():
    with TestClient(app) as client:
        upload_id = str(uuid.uuid4())
        filename = "target.elf"
        full_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100

        res = client.post(
            "/api/upload/chunk",
            content=full_content,
            headers={
                "X-Upload-ID": upload_id,
                "X-Chunk-Index": "0",
                "X-Total-Chunks": "1",
                "X-Filename": filename,
                "X-Surface": "binary",
                "X-Project-ID": "default"
            }
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "processing"
        assert "scan_job_id" in data


def test_chunked_upload_validation_errors():
    with TestClient(app) as client:
        # Missing headers
        res = client.post("/api/upload/chunk", content=b"data")
        assert res.status_code == 400

        # Invalid chunk index
        res2 = client.post(
            "/api/upload/chunk",
            content=b"data",
            headers={
                "X-Upload-ID": "test-id",
                "X-Chunk-Index": "5",
                "X-Total-Chunks": "2",
                "X-Filename": "test.py",
                "X-Surface": "code"
            }
        )
        assert res2.status_code == 400
