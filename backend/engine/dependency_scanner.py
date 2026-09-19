"""
ECDAT V4 Dependency & Lockfile Cryptographic Intelligence Engine.

Multi-ecosystem parsing for:
- Python: requirements.txt, pyproject.toml, poetry.lock
- Node: package.json, package-lock.json, yarn.lock
- Java: pom.xml, build.gradle
- Go: go.mod, go.sum
- Rust: Cargo.toml, Cargo.lock

Core Research Principle:
DEPENDENCY != ACTUAL_USE
A declared or locked dependency indicates cryptographic capability,
NEVER proof of actual invocation or runtime execution.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET

# Python 3.11+ standard library tomllib
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
from .sink_database import get_sink_database


class DependencyScanner:
    def __init__(self):
        self.sink_db = get_sink_database()

    def scan_manifest_or_lockfile(self, file_path: str, content: str) -> Dict[str, Any]:
        """
        Parses a package manifest or lockfile, detects cryptographic capabilities,
        and generates P0 Evidence objects without implying actual cryptographic use.
        """
        lower_path = file_path.lower().replace("\\", "/")
        filename = lower_path.split("/")[-1]

        dependencies: List[Dict[str, Any]] = []

        if filename == "requirements.txt" or filename.endswith(".requirements.txt"):
            dependencies = self._parse_requirements_txt(file_path, content)
        elif filename == "pyproject.toml":
            dependencies = self._parse_pyproject_toml(file_path, content)
        elif filename == "poetry.lock":
            dependencies = self._parse_poetry_lock(file_path, content)
        elif filename == "package.json":
            dependencies = self._parse_package_json(file_path, content)
        elif filename == "package-lock.json":
            dependencies = self._parse_package_lock_json(file_path, content)
        elif filename == "yarn.lock":
            dependencies = self._parse_yarn_lock(file_path, content)
        elif filename == "pom.xml":
            dependencies = self._parse_pom_xml(file_path, content)
        elif filename == "build.gradle" or filename.endswith(".gradle"):
            dependencies = self._parse_build_gradle(file_path, content)
        elif filename == "go.mod":
            dependencies = self._parse_go_mod(file_path, content)
        elif filename == "go.sum":
            dependencies = self._parse_go_sum(file_path, content)
        elif filename == "cargo.toml":
            dependencies = self._parse_cargo_toml(file_path, content)
        elif filename == "cargo.lock":
            dependencies = self._parse_cargo_lock(file_path, content)

        # Enrich each dependency with crypto capabilities
        evidence_list: List[Dict[str, Any]] = []
        for dep in dependencies:
            name = dep["name"]
            is_crypto = self.sink_db.is_crypto_dependency(name)
            capabilities = self.sink_db.get_dependency_capabilities(name) if is_crypto else []
            dep["is_crypto"] = is_crypto
            dep["crypto_capabilities"] = capabilities
            dep["actual_use"] = False  # Strict mandate: Dependency != Actual Use

            # Construct P0 Evidence
            obs_type = (
                ObservationType.DEPENDENCY_LOCKFILE
                if dep.get("is_locked")
                else ObservationType.DEPENDENCY_DECLARATION
            )
            ev = Evidence(
                state=EvidenceState.DECLARED,
                level=EvidenceLevel.E2 if dep.get("is_locked") else EvidenceLevel.E0,
                confidence=0.95,
                source_engine="dependency-scanner",
                engine_version="4.0.0",
                observation_type=obs_type,
                artifact_type="dependency",
                symbol=name,
                file_path=file_path,
                description=f"Declared dependency: {name} ({dep.get('version', 'unspecified')})",
                limitations=["Dependency declaration does not prove runtime cryptographic use."],
                raw_details={
                    "package": name,
                    "version": dep.get("version"),
                    "ecosystem": dep.get("ecosystem"),
                    "is_locked": dep.get("is_locked"),
                    "capabilities": capabilities,
                },
                provenance=Provenance(
                    input_hash=hashlib.sha256(f"{name}:{dep.get('version', '')}".encode()).hexdigest(),
                    source_engine="dependency-scanner",
                    engine_version="4.0.0",
                    location=file_path,
                ),
            )
            evidence_list.append(ev.to_dict())

        return {
            "file": file_path,
            "filename": filename,
            "total_dependencies": len(dependencies),
            "crypto_dependencies": [d for d in dependencies if d.get("is_crypto")],
            "dependencies": dependencies,
            "evidence": evidence_list,
        }

    # ==========================================
    # PYTHON PARSERS
    # ==========================================
    def _parse_requirements_txt(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "@", "http")):
                continue
            # match package and version specifier
            m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:([><=~!^]+)\s*([a-zA-Z0-9_\-\.\*]+))?", line)
            if m:
                name = m.group(1).lower()
                version = f"{m.group(2) or ''}{m.group(3) or ''}".strip()
                deps.append({
                    "name": name,
                    "version": version or "any",
                    "ecosystem": "python",
                    "source_file": file_path,
                    "scope": "dependencies",
                    "is_locked": False,
                })
        return deps

    def _parse_pyproject_toml(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        if not tomllib:
            return deps
        try:
            data = tomllib.loads(content)
            # Standard PEP 621 [project.dependencies]
            project_deps = data.get("project", {}).get("dependencies", [])
            for dep_str in project_deps:
                m = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(.*)", dep_str)
                if m:
                    deps.append({
                        "name": m.group(1).lower(),
                        "version": m.group(2).strip() or "any",
                        "ecosystem": "python",
                        "source_file": file_path,
                        "scope": "dependencies",
                        "is_locked": False,
                    })
            # Poetry [tool.poetry.dependencies]
            poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for name, ver in poetry_deps.items():
                if name.lower() != "python":
                    deps.append({
                        "name": name.lower(),
                        "version": str(ver),
                        "ecosystem": "python",
                        "source_file": file_path,
                        "scope": "dependencies",
                        "is_locked": False,
                    })
        except Exception:
            pass
        return deps

    def _parse_poetry_lock(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        if not tomllib:
            return deps
        try:
            data = tomllib.loads(content)
            for pkg in data.get("package", []):
                deps.append({
                    "name": pkg.get("name", "").lower(),
                    "version": pkg.get("version", ""),
                    "ecosystem": "python",
                    "source_file": file_path,
                    "scope": "locked",
                    "is_locked": True,
                })
        except Exception:
            pass
        return deps

    # ==========================================
    # NODE PARSERS
    # ==========================================
    def _parse_package_json(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            data = json.loads(content)
            for group in ("dependencies", "devDependencies", "peerDependencies"):
                for name, ver in data.get(group, {}).items():
                    deps.append({
                        "name": name.lower(),
                        "version": str(ver),
                        "ecosystem": "npm",
                        "source_file": file_path,
                        "scope": group,
                        "is_locked": False,
                    })
        except Exception:
            pass
        return deps

    def _parse_package_lock_json(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            data = json.loads(content)
            # lockfile v2 / v3
            packages = data.get("packages", {})
            for pkg_path, details in packages.items():
                if not pkg_path:
                    continue
                name = pkg_path.split("node_modules/")[-1].lower()
                version = details.get("version", "")
                deps.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "npm",
                    "source_file": file_path,
                    "scope": "locked",
                    "is_locked": True,
                })
            # fallback for lockfile v1
            if not deps and "dependencies" in data:
                for name, details in data.get("dependencies", {}).items():
                    deps.append({
                        "name": name.lower(),
                        "version": details.get("version", ""),
                        "ecosystem": "npm",
                        "source_file": file_path,
                        "scope": "locked",
                        "is_locked": True,
                    })
        except Exception:
            pass
        return deps

    def _parse_yarn_lock(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        # simple yarn.lock block parsing
        blocks = content.split("\n\n")
        for b in blocks:
            lines = [line.strip() for line in b.splitlines() if line.strip()]
            if not lines:
                continue
            header = lines[0]
            if header.startswith("#"):
                continue
            m = re.match(r"^\"?(@?[a-zA-Z0-9_\-\.\/]+)@", header)
            if m:
                name = m.group(1).lower()
                ver = ""
                for line in lines[1:]:
                    if line.startswith("version"):
                        ver = line.split("version")[-1].strip().strip("\"'")
                deps.append({
                    "name": name,
                    "version": ver or "locked",
                    "ecosystem": "npm",
                    "source_file": file_path,
                    "scope": "locked",
                    "is_locked": True,
                })
        return deps

    # ==========================================
    # JAVA PARSERS
    # ==========================================
    def _parse_pom_xml(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            # Strip namespaces for simple parsing
            clean_xml = re.sub(r' xmlns="[^"]+"', '', content, count=1)
            root = ET.fromstring(clean_xml)
            for dep in root.findall(".//dependency"):
                group_id = dep.findtext("groupId", "").strip()
                artifact_id = dep.findtext("artifactId", "").strip()
                version = dep.findtext("version", "unspecified").strip()
                scope = dep.findtext("scope", "compile").strip()
                name = f"{group_id}:{artifact_id}".lower() if group_id else artifact_id.lower()
                deps.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "maven",
                    "source_file": file_path,
                    "scope": scope,
                    "is_locked": False,
                })
        except Exception:
            pass
        return deps

    def _parse_build_gradle(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        # regex for implementation 'group:artifact:version' or implementation("group:artifact:version")
        pattern = r"(?:implementation|api|compileOnly|testImplementation)\s*[\(\'\"]([a-zA-Z0-9_\-\.\:]+)[\'\"]\)"
        for m in re.finditer(pattern, content):
            full_str = m.group(1)
            parts = full_str.split(":")
            if len(parts) >= 2:
                name = f"{parts[0]}:{parts[1]}".lower()
                ver = parts[2] if len(parts) > 2 else "any"
            else:
                name = parts[0].lower()
                ver = "any"
            deps.append({
                "name": name,
                "version": ver,
                "ecosystem": "gradle",
                "source_file": file_path,
                "scope": "dependencies",
                "is_locked": False,
            })
        return deps

    # ==========================================
    # GO PARSERS
    # ==========================================
    def _parse_go_mod(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line.startswith(")"):
                in_require = False
                continue
            if in_require:
                parts = line.split()
                if len(parts) >= 2 and not line.startswith("//"):
                    deps.append({
                        "name": parts[0].lower(),
                        "version": parts[1],
                        "ecosystem": "go",
                        "source_file": file_path,
                        "scope": "dependencies",
                        "is_locked": False,
                    })
            elif line.startswith("require "):
                parts = line[len("require "):].strip().split()
                if len(parts) >= 2:
                    deps.append({
                        "name": parts[0].lower(),
                        "version": parts[1],
                        "ecosystem": "go",
                        "source_file": file_path,
                        "scope": "dependencies",
                        "is_locked": False,
                    })
        return deps

    def _parse_go_sum(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        seen = set()
        for line in content.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0].lower()
                ver = parts[1].replace("/go.mod", "")
                key = f"{name}@{ver}"
                if key not in seen:
                    seen.add(key)
                    deps.append({
                        "name": name,
                        "version": ver,
                        "ecosystem": "go",
                        "source_file": file_path,
                        "scope": "locked",
                        "is_locked": True,
                    })
        return deps

    # ==========================================
    # RUST PARSERS
    # ==========================================
    def _parse_cargo_toml(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        if not tomllib:
            return deps
        try:
            data = tomllib.loads(content)
            for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                for name, details in data.get(group, {}).items():
                    if isinstance(details, str):
                        ver = details
                    elif isinstance(details, dict):
                        ver = details.get("version", "any")
                    else:
                        ver = "any"
                    deps.append({
                        "name": name.lower(),
                        "version": str(ver),
                        "ecosystem": "cargo",
                        "source_file": file_path,
                        "scope": group,
                        "is_locked": False,
                    })
        except Exception:
            pass
        return deps

    def _parse_cargo_lock(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        if not tomllib:
            return deps
        try:
            data = tomllib.loads(content)
            for pkg in data.get("package", []):
                deps.append({
                    "name": pkg.get("name", "").lower(),
                    "version": pkg.get("version", ""),
                    "ecosystem": "cargo",
                    "source_file": file_path,
                    "scope": "locked",
                    "is_locked": True,
                })
        except Exception:
            pass
        return deps


# Global singleton
_GLOBAL_DEPENDENCY_SCANNER: Optional[DependencyScanner] = None


def get_dependency_scanner() -> DependencyScanner:
    global _GLOBAL_DEPENDENCY_SCANNER
    if _GLOBAL_DEPENDENCY_SCANNER is None:
        _GLOBAL_DEPENDENCY_SCANNER = DependencyScanner()
    return _GLOBAL_DEPENDENCY_SCANNER
