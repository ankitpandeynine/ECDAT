"""Scan routes including GitHub repository ingestion."""
from typing import Optional
from urllib.parse import unquote_plus

from fastapi import APIRouter, Request, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from engine.github_scanner import scan_github_repo
from engine.binary_deep import MAX_BYTES
from engine.limits import MAX_CHUNKED_UPLOAD_BYTES, MAX_SOURCE_FILE_CHARS, human_mb

router = APIRouter(tags=["scans"])


class GithubScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository HTTPS URL")
    token: Optional[str] = Field(None, description="Personal access token for private repositories")
    branch: Optional[str] = Field(None, description="Branch to checkout (defaults to default branch)")
    subdir: Optional[str] = Field(None, description="Subdirectory filter within the repository")
    project_id: str = Field(default="default", description="Target ECDAT project ID")


@router.post("/scan/github", status_code=status.HTTP_202_ACCEPTED)
@router.post("/api/scan/github", status_code=status.HTTP_202_ACCEPTED)
def scan_github(req: GithubScanRequest, request: Request):
    """
    Queue an asynchronous GitHub repository cryptographic discovery scan.
    Clones the repository with --depth 1, extracts AST sources and manifests,
    and fuses detected cryptographic evidence into the project's SQLite knowledge graph.
    """
    # 1. Validate repository URL starts with https://github.com/
    if not req.repo_url or not req.repo_url.strip().startswith("https://github.com/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Repository URL must start with 'https://github.com/'"
        )

    # 2. Extract store from application state
    store = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan store is not initialized"
        )

    # 3. Sanitize payload: NEVER store token or credentials in database (Rule 10)
    safe_payload = {
        "repo_url": req.repo_url.strip(),
        "branch": req.branch.strip() if req.branch else "main",
        "subdir": req.subdir.strip() if req.subdir else None,
        "is_private": bool(req.token and req.token.strip()),
    }

    # Captured closure passes token in memory only
    token_in_memory = req.token.strip() if req.token else None
    repo_url_val = req.repo_url.strip()
    branch_val = req.branch.strip() if req.branch else None
    subdir_val = req.subdir.strip() if req.subdir else None

    def _worker(payload):
        return scan_github_repo(
            repo_url=repo_url_val,
            token=token_in_memory,
            branch=branch_val,
            subdir=subdir_val
        )

    from urllib.parse import unquote_plus as _uq  # noqa: F401 (kept for clarity)
    proj = unquote_plus(req.project_id or "default")
    if "%" in proj:
        proj = unquote_plus(proj)
    proj = proj.strip() or "default"

    try:
        job = store.submit(
            proj,
            "github",
            safe_payload,
            _worker
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc

    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content={
            "id": job["id"],
            "scan_id": job["id"],
            "project": req.project_id,
            "kind": "github",
            "status": job["status"],
            "created_at": job["created_at"],
            "message": "GitHub repository scan job queued successfully",
        }
    )


@router.post("/upload/chunk")
@router.post("/api/upload/chunk")
async def upload_chunk(request: Request):
    """
    Chunked upload endpoint for large source code files and binaries (up to 500MB).
    Receives raw binary chunks and appends them sequentially to an on-disk session file.
    On the final chunk, marks session 'assembling', triggers the target scanner, and returns 200 + scan_job_id.
    """
    upload_id = request.headers.get("X-Upload-ID") or request.headers.get("x-upload-id")
    chunk_index_raw = request.headers.get("X-Chunk-Index") or request.headers.get("x-chunk-index")
    total_chunks_raw = request.headers.get("X-Total-Chunks") or request.headers.get("x-total-chunks")
    filename = request.headers.get("X-Filename") or request.headers.get("x-filename")
    surface = request.headers.get("X-Surface") or request.headers.get("x-surface")
    project_id = request.headers.get("X-Project-ID") or request.headers.get("x-project-id") or request.query_params.get("project", "default")
    if project_id:
        project_id = unquote_plus(project_id)
        if "%" in project_id:
            project_id = unquote_plus(project_id)
        project_id = project_id.strip() or "default"

    if not all([upload_id, chunk_index_raw is not None, total_chunks_raw is not None, filename, surface]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required chunk headers (X-Upload-ID, X-Chunk-Index, X-Total-Chunks, X-Filename, X-Surface)"
        )

    try:
        chunk_index = int(chunk_index_raw)
        total_chunks = int(total_chunks_raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Chunk-Index and X-Total-Chunks must be valid integers"
        )

    if chunk_index < 0 or total_chunks < 1 or chunk_index >= total_chunks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid chunk index {chunk_index} for total chunks {total_chunks}"
        )

    store = getattr(request.app.state, "store", None)
    if not store:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan store is not initialized"
        )

    chunk_data = await request.body()
    if not chunk_data and total_chunks > 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty chunk received"
        )

    import os
    import tempfile
    import zipfile
    from engine.source_scan import scan_sources, EXTENSIONS, is_manifest_file
    from engine.binary_deep import scan_upload, scan_one

    ecdat_temp_dir = os.getenv("ECDAT_TEMP_DIR", tempfile.gettempdir())
    os.makedirs(ecdat_temp_dir, exist_ok=True)
    safe_filename = os.path.basename(filename.replace("\\", "/"))
    temp_path = os.path.join(ecdat_temp_dir, f"ecdat_upload_{upload_id}_{safe_filename}")

    # Chunk 0: initialize session and create file
    if chunk_index == 0:
        with open(temp_path, "wb") as f:
            f.write(chunk_data)
        existing = store.get_upload_session(upload_id)
        if not existing:
            store.create_upload_session(
                upload_id=upload_id,
                project_id=project_id,
                filename=safe_filename,
                surface=surface,
                total_chunks=total_chunks,
                temp_path=temp_path,
            )
        else:
            store.update_upload_session(
                upload_id=upload_id,
                received_chunks=1,
                status="uploading"
            )
    else:
        session = store.get_upload_session(upload_id)
        if not session:
            store.create_upload_session(
                upload_id=upload_id,
                project_id=project_id,
                filename=safe_filename,
                surface=surface,
                total_chunks=total_chunks,
                temp_path=temp_path,
            )
        with open(temp_path, "ab") as f:
            f.write(chunk_data)
        store.update_upload_session(
            upload_id=upload_id,
            received_chunks=chunk_index + 1,
            status="uploading"
        )

    # Enforce maximum assembled file size (ECDAT_MAX_CHUNKED_MB, default 1 GiB)
    current_size = os.path.getsize(temp_path)
    if current_size > MAX_CHUNKED_UPLOAD_BYTES:
        store.update_upload_session(upload_id, status="failed")
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum allowed size of {human_mb(MAX_CHUNKED_UPLOAD_BYTES)}"
        )

    # Last chunk (index == total - 1): mark assembling, then trigger scanner
    if chunk_index == total_chunks - 1:
        store.update_upload_session(
            upload_id=upload_id,
            received_chunks=total_chunks,
            status="assembling"
        )

        surf_lower = surface.lower()
        if surf_lower in ("code", "source", "source_code"):
            def _source_worker(payload):
                fpath = payload["file_path"]
                fname = payload["filename"]
                try:
                    files_to_scan = []
                    if zipfile.is_zipfile(fpath):
                        with zipfile.ZipFile(fpath, "r") as zf:
                            for member in zf.infolist():
                                if member.is_dir():
                                    continue
                                ext = os.path.splitext(member.filename)[1].lower()
                                if ext in EXTENSIONS or is_manifest_file(member.filename):
                                    try:
                                        with zf.open(member) as ms:
                                            txt = ms.read(MAX_SOURCE_FILE_CHARS).decode("utf-8", errors="replace")
                                        files_to_scan.append({"path": member.filename, "content": txt})
                                    except Exception:
                                        pass
                    else:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as sf:
                            txt = sf.read(MAX_SOURCE_FILE_CHARS)
                        files_to_scan.append({"path": fname, "content": txt})
                    return scan_sources(files_to_scan) if files_to_scan else {
                        "findings": [], "total_findings": 0, "status": "success", "evidence": []
                    }
                finally:
                    if os.path.exists(fpath):
                        try:
                            os.remove(fpath)
                        except Exception:
                            pass

            scan_job = store.submit(
                project_id,
                "code",
                {"filename": safe_filename, "file_path": temp_path, "upload_id": upload_id},
                _source_worker
            )
        else:
            def _binary_worker(payload):
                fpath = payload["file_path"]
                fname = payload["filename"]
                try:
                    with open(fpath, "rb") as bf:
                        raw = bf.read()
                    if len(raw) <= MAX_BYTES:
                        return scan_upload(raw, fname)
                    return scan_one(raw, fname)
                finally:
                    if os.path.exists(fpath):
                        try:
                            os.remove(fpath)
                        except Exception:
                            pass

            scan_job = store.submit(
                project_id,
                "binary",
                {"filename": safe_filename, "file_path": temp_path, "upload_id": upload_id},
                _binary_worker
            )

        store.update_upload_session(
            upload_id=upload_id,
            status="processing",
            scan_job_id=scan_job["id"]
        )

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "upload_id": upload_id,
                "scan_job_id": scan_job["id"],
                "status": "processing"
            }
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "upload_id": upload_id,
            "received_chunks": chunk_index + 1,
            "total_chunks": total_chunks,
            "status": "uploading"
        }
    )


@router.get("/upload/{upload_id}/status")
@router.get("/api/upload/{upload_id}/status")
def get_upload_status(upload_id: str, request: Request):
    """
    Returns the current assembly and processing status of an upload session.
    """
    store = getattr(request.app.state, "store", None)
    if not store:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan store is not initialized"
        )
    session = store.get_upload_session(upload_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Upload session '{upload_id}' not found"
        )
    current_status = session["status"]
    scan_job_id = session.get("scan_job_id")
    if current_status == "processing" and scan_job_id:
        try:
            with store.connect() as db:
                row = db.execute("SELECT status FROM scans WHERE id = ?", (scan_job_id,)).fetchone()
                if row and row[0] in ("completed", "failed", "cancelled"):
                    current_status = row[0]
                    store.update_upload_session(upload_id, status=current_status)
        except Exception:
            pass

    return {
        "upload_id": session["upload_id"],
        "received_chunks": session["received_chunks"],
        "total_chunks": session["total_chunks"],
        "status": current_status,
        "scan_job_id": scan_job_id,
    }
