"""
ECDAT Secure Archive Lab — Analysis & Internal Cryptographic Discovery Engine.
Inspects encrypted and unencrypted archives, evaluates cipher/KDF mechanisms,
safely extracts authorized archives in resource-bounded sandboxes, and feeds
contents into normal ECDAT asset and evidence discovery.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import io
import os
import shutil
import struct
import tempfile
from typing import Any, Dict, List, Optional
import uuid
import zipfile

from .binary_deep import scan_upload
from .source_scan import scan_sources


MAX_ARCHIVE_BYTES = 8 * 1024 * 1024  # 8 MiB
MAX_FILES = 100
MAX_DECOMPRESSED_BYTES = 16 * 1024 * 1024  # 16 MiB


def detect_archive_format(data: bytes) -> str:
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        return "ZIP"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if data.startswith(b"\x1f\x8b"):
        return "GZIP"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "TAR"
    return "UNKNOWN"


def inspect_zip_encryption(data: bytes) -> Dict[str, Any]:
    """Inspect ZIP structures for ZipCrypto vs WinZip AES-256."""
    info = {
        "is_encrypted": False,
        "encryption_type": "NONE",
        "kdf": "NONE",
        "header_encrypted": False,
        "password_dependent": False,
        "file_count": 0,
        "compressed_size": len(data),
        "uncompressed_size": 0,
        "file_list": []
    }

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            info["file_count"] = len(zf.infolist())
            total_uncomp = 0
            for item in zf.infolist():
                total_uncomp += item.file_size
                info["file_list"].append({
                    "filename": item.filename,
                    "file_size": item.file_size,
                    "compress_size": item.compress_size,
                    "is_encrypted": item.flag_bits & 0x1 != 0
                })
                if item.flag_bits & 0x1:
                    info["is_encrypted"] = True
                    info["password_dependent"] = True
                    # Check extra field for WinZip AES (ID 0x9901)
                    if b"\x01\x99" in item.extra:
                        info["encryption_type"] = "WinZip AES-256"
                        info["kdf"] = "PBKDF2-HMAC-SHA1"
                    elif info["encryption_type"] == "NONE":
                        info["encryption_type"] = "PKWARE ZipCrypto (Legacy / Weak)"
                        info["kdf"] = "CRC32-Linear (Weak)"
            info["uncompressed_size"] = total_uncomp
    except zipfile.BadZipFile:
        # Check raw bytes for encrypted PK header
        if b"PK\x03\x04" in data:
            idx = data.find(b"PK\x03\x04")
            if len(data) >= idx + 8:
                flag = struct.unpack("<H", data[idx+6:idx+8])[0]
                if flag & 0x1:
                    info["is_encrypted"] = True
                    info["encryption_type"] = "Encrypted ZIP"
                    info["password_dependent"] = True

    return info


class SecureArchiveLab:
    def __init__(self, store=None):
        self.store = store

    def analyze_archive(
        self,
        raw_bytes: bytes,
        filename: str = "archive.zip",
        password: Optional[str] = None,
        project_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Analyze archive cryptographic properties.
        If credentials provided, safely extract and discover internal crypto assets.
        """
        if len(raw_bytes) > MAX_ARCHIVE_BYTES:
            raise ValueError(f"Archive exceeds maximum size of {MAX_ARCHIVE_BYTES // (1024*1024)} MiB")

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        fmt = detect_archive_format(raw_bytes)

        res: Dict[str, Any] = {
            "analysis_id": f"arch-{uuid.uuid4().hex[:12]}",
            "filename": filename,
            "format": fmt,
            "sha256": sha256_hash,
            "size_bytes": len(raw_bytes),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "project_id": project_id,
            "encryption_detected": False,
            "encryption_type": "NONE",
            "kdf_detected": "NONE",
            "content_status": "UNKNOWN / NOT DECRYPTED",
            "file_count": 0,
            "uncompressed_size_bytes": 0,
            "files": [],
            "discovered_assets": [],
            "discovered_evidence": [],
            "security_assessment": {},
            "recommendations": []
        }

        if fmt == "ZIP":
            zip_info = inspect_zip_encryption(raw_bytes)
            res["encryption_detected"] = zip_info["is_encrypted"]
            res["encryption_type"] = zip_info["encryption_type"]
            res["kdf_detected"] = zip_info["kdf"]
            res["file_count"] = zip_info["file_count"]
            res["uncompressed_size_bytes"] = zip_info["uncompressed_size"]
            res["files"] = zip_info["file_list"]

            # Security evaluation
            if zip_info["encryption_type"] == "PKWARE ZipCrypto (Legacy / Weak)":
                res["security_assessment"] = {
                    "verdict": "VULNERABLE",
                    "severity": "CRITICAL",
                    "explanation": "PKWARE Traditional ZipCrypto is vulnerable to known-plaintext attacks (Biham-Kocher / pkcrack) and can be broken in minutes."
                }
                res["recommendations"].append("Repackage using AES-256-GCM or ECDAT Protected Vault (.ecvault).")
            elif zip_info["encryption_type"] == "WinZip AES-256":
                res["security_assessment"] = {
                    "verdict": "CLASSICAL_STRONG",
                    "severity": "MEDIUM",
                    "explanation": "AES-256 encryption provides classical confidentiality, but PBKDF2-SHA1 KDF is vulnerable to GPU/ASIC password cracking if password entropy is low."
                }
                res["recommendations"].append("Upgrade KDF to Argon2id / memory-hard KDF; evaluate PQC hybrid key encapsulation.")
            elif not zip_info["is_encrypted"]:
                res["security_assessment"] = {
                    "verdict": "UNENCRYPTED",
                    "severity": "HIGH",
                    "explanation": "Archive contains unencrypted plaintext without confidentiality protection."
                }
                res["recommendations"].append("Encrypt sensitive contents using Password or Recipient Vault.")

            # Process contents if password provided or unencrypted
            if not zip_info["is_encrypted"] or password:
                try:
                    discovered = self._extract_and_scan(raw_bytes, password, project_id, filename)
                    res["content_status"] = "SUCCESSFULLY_DECRYPTED_AND_ANALYZED" if zip_info["is_encrypted"] else "ANALYZED_UNENCRYPTED"
                    res["discovered_assets"] = discovered["assets"]
                    res["discovered_evidence"] = discovered["evidence"]
                except Exception as ex:
                    res["content_status"] = f"DECRYPTION_FAILED: {str(ex)}"
                    res["security_assessment"]["decryption_error"] = str(ex)
            else:
                res["content_status"] = "ENCRYPTED_CREDENTIALS_REQUIRED"
                res["recommendations"].append("Provide authorized password/key to inspect embedded cryptographic assets.")

        elif fmt == "7z":
            res["encryption_detected"] = True
            res["encryption_type"] = "7z AES-256 (Probable)"
            res["kdf_detected"] = "SHA-256 iterations"
            res["security_assessment"] = {
                "verdict": "CLASSICAL_STRONG",
                "severity": "LOW",
                "explanation": "7-Zip format supports header encryption and AES-256 with 2^19 SHA-256 iterations."
            }
            res["content_status"] = "7Z_CONTAINER_METADATA_ANALYZED"
        else:
            res["security_assessment"] = {
                "verdict": "UNKNOWN_FORMAT",
                "severity": "INFO",
                "explanation": f"Archive format '{fmt}' metadata analyzed."
            }

        return res

    def _extract_and_scan(self, raw_bytes: bytes, password: Optional[str], project_id: str, archive_name: str) -> Dict[str, Any]:
        """Bounded safe extraction inside temporary directory with path traversal guards."""
        assets: List[Dict[str, Any]] = []
        evidence_items: List[Dict[str, Any]] = []

        with tempfile.TemporaryDirectory(prefix="ecdat_arch_") as tmpdir:
            pwd_bytes = password.encode('utf-8') if password else None
            total_decomp = 0
            file_count = 0

            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as zf:
                for member in zf.infolist():
                    file_count += 1
                    if file_count > MAX_FILES:
                        break
                    total_decomp += member.file_size
                    if total_decomp > MAX_DECOMPRESSED_BYTES:
                        break

                    # Zip-Slip / Path Traversal Guard
                    target_path = os.path.abspath(os.path.join(tmpdir, member.filename))
                    if not target_path.startswith(os.path.abspath(tmpdir)):
                        continue  # Malicious path traversal attempted

                    if member.is_dir():
                        os.makedirs(target_path, exist_ok=True)
                        continue

                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    try:
                        content = zf.read(member, pwd=pwd_bytes)
                    except Exception:
                        continue

                    with open(target_path, "wb") as f:
                        f.write(content)

                    # Scan extracted file for crypto
                    ext = os.path.splitext(member.filename)[1].lower()
                    if ext in [".py", ".java", ".c", ".cpp", ".go", ".js", ".ts", ".rs"]:
                        try:
                            src_text = content.decode('utf-8', errors='replace')
                            lang_map = {".py": "python", ".java": "java", ".c": "c_cpp", ".cpp": "c_cpp", ".go": "golang", ".js": "javascript", ".ts": "javascript"}
                            lang = lang_map.get(ext, "python")
                            findings = scan_sources([{"path": member.filename, "content": src_text, "language": lang}])
                            for f_item in findings.get("findings", []):
                                asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                                asset_dict = {
                                    "id": asset_id,
                                    "name": f"{f_item.get('algorithm', 'CRYPTO')} in {member.filename}",
                                    "algorithm": f_item.get("algorithm", "UNKNOWN"),
                                    "asset_type": "ALGORITHM",
                                    "source_surface": "ARCHIVE_FILE",
                                    "location": f"{archive_name}:{member.filename}:{f_item.get('line', 1)}",
                                    "status": "OBSERVED",
                                    "confidence": 0.85
                                }
                                assets.append(asset_dict)
                                evidence_items.append({
                                    "asset_id": asset_id,
                                    "level": "E2",
                                    "observation_type": "ARCHIVE_SOURCE_CODE",
                                    "description": f_item.get("description", "Cryptographic API observed inside archive file")
                                })
                        except Exception:
                            pass

                    elif ext in [".bin", ".exe", ".elf", ".so", ".dll", ".dylib"]:
                        try:
                            b_res = scan_upload(content, member.filename)
                            for d in b_res.get("detections", []):
                                asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                                assets.append({
                                    "id": asset_id,
                                    "name": f"{d.get('name', 'Binary Crypto')} in {member.filename}",
                                    "algorithm": d.get("name", "UNKNOWN"),
                                    "asset_type": "BINARY_SIGNATURE",
                                    "source_surface": "ARCHIVE_BINARY",
                                    "location": f"{archive_name}:{member.filename}",
                                    "status": "OBSERVED",
                                    "confidence": 0.80
                                })
                        except Exception:
                            pass

                    elif ext in [".pem", ".crt", ".cer", ".der", ".key"]:
                        # Certificate / Key found in archive!
                        asset_id = f"asset-{uuid.uuid4().hex[:8]}"
                        algo = "RSA-2048" if b"BEGIN RSA PRIVATE KEY" in content or b"BEGIN CERTIFICATE" in content else "ASYMMETRIC_KEY"
                        assets.append({
                            "id": asset_id,
                            "name": f"Embedded Key/Cert: {member.filename}",
                            "algorithm": algo,
                            "asset_type": "KEY" if "key" in ext else "CERTIFICATE",
                            "source_surface": "ARCHIVE_ARTIFACT",
                            "location": f"{archive_name}:{member.filename}",
                            "status": "OBSERVED",
                            "confidence": 0.95
                        })
                        evidence_items.append({
                            "asset_id": asset_id,
                            "level": "E3",
                            "observation_type": "ARCHIVE_CERTIFICATE",
                            "description": f"Private key or certificate discovered in archive container {member.filename}"
                        })

        return {"assets": assets, "evidence": evidence_items}
