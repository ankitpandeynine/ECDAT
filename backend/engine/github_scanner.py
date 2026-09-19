"""GitHub repository scanner with shallow clone, size/count safeguards, and AST source scan."""
import os
import shutil
import tempfile
import subprocess
import logging
from typing import Optional, Dict, Any, List
from .source_scan import scan_sources, EXTENSIONS, is_manifest_file, LANGUAGES

logger = logging.getLogger("ecdat.github_scanner")

SKIP_DIRS = {
    "node_modules", "vendor", ".git", "dist", "build", "__pycache__",
    ".venv", "venv", "env", ".idea", ".vscode", "target"
}

MAX_FILE_SIZE_BYTES = 500 * 1024  # 500 KB limit per file
MAX_TOTAL_FILES = 2000            # Up to 2000 files examined


def scan_github_repo(
    repo_url: str,
    token: Optional[str] = None,
    branch: Optional[str] = None,
    subdir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Clones a GitHub repository with shallow depth (--depth 1), traverses source files,
    applies size and skip heuristics, and runs cryptographic source scan analysis.
    """
    # Validation: must start with https://github.com/
    if not repo_url or not repo_url.startswith("https://github.com/"):
        raise ValueError("Repository URL must start with 'https://github.com/'")

    # Format clone URL with optional token for private repositories
    # Token is used strictly for authenticated git clone and never written to DB or logs
    if token and token.strip():
        clean_token = token.strip()
        clone_url = repo_url.replace("https://github.com/", f"https://x-access-token:{clean_token}@github.com/")
    else:
        clone_url = repo_url

    temp_dir = tempfile.mkdtemp(prefix="ecdat_gh_")
    files_scanned = 0
    files_skipped = 0

    try:
        cmd = ["git", "clone", "--depth", "1"]
        if branch and branch.strip():
            cmd.extend(["--branch", branch.strip()])
        cmd.extend([clone_url, temp_dir])

        # Execute shallow clone with 120s timeout
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone timed out after 120 seconds")

        if proc.returncode != 0:
            err_msg = proc.stderr or proc.stdout or "Unknown git clone error"
            if token and token.strip():
                err_msg = err_msg.replace(token.strip(), "[REDACTED_TOKEN]")
            raise RuntimeError(f"Git clone failed: {err_msg}")

        # Subdirectory filter
        scan_root = temp_dir
        if subdir and subdir.strip():
            clean_subdir = subdir.strip().lstrip("/\\")
            candidate = os.path.normpath(os.path.join(temp_dir, clean_subdir))
            if os.path.commonpath([temp_dir, candidate]) != temp_dir:
                raise ValueError("Subdirectory traversal outside repository boundary is forbidden")
            if os.path.exists(candidate):
                scan_root = candidate
            else:
                logger.warning(f"Specified subdir '{subdir}' not found; scanning repo root.")

        files_to_scan: List[Dict[str, str]] = []
        total_seen = 0

        for root, dirs, filenames in os.walk(scan_root):
            # Prune skipped directory trees in-place
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith(".")]

            for fname in filenames:
                total_seen += 1
                if total_seen > MAX_TOTAL_FILES:
                    files_skipped += 1
                    continue

                file_path = os.path.join(root, fname)

                # Skip symbolic links to avoid directory traversal
                if os.path.islink(file_path):
                    files_skipped += 1
                    continue

                # Skip files larger than 500KB
                try:
                    size = os.path.getsize(file_path)
                    if size > MAX_FILE_SIZE_BYTES:
                        files_skipped += 1
                        continue
                except OSError:
                    files_skipped += 1
                    continue

                rel_path = os.path.relpath(file_path, temp_dir).replace("\\", "/")
                ext = os.path.splitext(fname)[1].lower()

                # Supported language extension or manifest/lockfile
                if ext in EXTENSIONS or is_manifest_file(fname):
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read(500_000)
                        files_to_scan.append({
                            "path": rel_path,
                            "content": content
                        })
                        files_scanned += 1
                    except Exception as exc:
                        logger.warning(f"Failed to read {rel_path}: {exc}")
                        files_skipped += 1
                else:
                    files_skipped += 1

        if files_skipped > 0:
            logger.info(f"GitHub repository scan skipped {files_skipped} non-source/oversized files.")

        # Run source_scan logic on scanned files
        scan_result = scan_sources(files_to_scan) if files_to_scan else {
            "findings": [],
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "coverage": [],
            "dependencies": [],
            "evidence": [],
            "call_graph": [],
            "observations": [],
            "status": "success",
        }

        evidence_records = scan_result.get("evidence", [])

        return {
            "status": "success",
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "evidence_records": evidence_records,
            "evidence": evidence_records,
            "findings": scan_result.get("findings", []),
            "dependencies": scan_result.get("dependencies", []),
            "coverage": scan_result.get("coverage", []),
            "call_graph": scan_result.get("call_graph", []),
            "observations": scan_result.get("observations", []),
            "repo_url": repo_url,
            "branch": branch or "main",
            "total_findings": scan_result.get("total_findings", len(scan_result.get("findings", []))),
            "critical_count": scan_result.get("critical_count", 0),
            "high_count": scan_result.get("high_count", 0),
            "limitations": scan_result.get("limitations", []) + [
                f"Shallow git clone depth 1; scanned {files_scanned} files ({files_skipped} skipped)."
            ]
        }

    finally:
        # Always delete temp directory in finally block
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
