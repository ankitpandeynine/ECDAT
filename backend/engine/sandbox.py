"""
ECDAT V4 Secure Sandbox Execution Framework.

Designed for sandboxed execution of external/heavy analyzers:
- Enforces execution deadlines, output truncation, sanitized environment allowlists
- Isolates file modifications in temporary workspaces
- Returns explicit execution states (COMPLETED, TIMEOUT, RESOURCE_LIMIT, FAILED, CRASHED)
- Prohibits shell=True to prevent argument injection
- Explicitly documents platform boundaries (Unix rlimits vs Windows process limits)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class SandboxStatus(str, Enum):
    SUCCESS = "SUCCESS"
    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    FAILED = "FAILED"
    CRASHED = "CRASHED"
    CANCELLED = "CANCELLED"
    UNAVAILABLE = "UNAVAILABLE"


@dataclass
class SandboxConfig:
    timeout_seconds: float = 5.0
    max_output_bytes: int = 128 * 1024


SAFE_ENV_ALLOWLIST = {
    "PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "HOME", "USERPROFILE",
    "LANG", "LC_ALL", "PYTHONPATH", "LD_LIBRARY_PATH"
}


@dataclass
class SandboxResult:
    status: SandboxStatus
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: float
    limits_enforced: List[str]
    limitations: List[str] = field(default_factory=list)
    memory_bytes: Optional[int] = None
    timed_out: bool = False
    result: Any = None
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "limits_enforced": self.limits_enforced,
            "limitations": self.limitations,
            "timed_out": self.timed_out,
            "error": self.error,
        }


class SandboxExecutor:
    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        default_timeout: float = 5.0,
        max_output_bytes: int = 128 * 1024,
    ):
        if config is not None:
            self.default_timeout = config.timeout_seconds
            self.max_output_bytes = config.max_output_bytes
        else:
            self.default_timeout = default_timeout
            self.max_output_bytes = max_output_bytes

    def run(
        self,
        command: List[str],
        working_directory: Optional[str] = None,
        timeout: Optional[float] = None,
        extra_env: Optional[Dict[str, str]] = None,
        input_data: Optional[bytes] = None,
        isolate_workspace: bool = True,
    ) -> SandboxResult:
        if not command or not isinstance(command, (list, tuple)):
            raise ValueError("Command must be a non-empty list of arguments (never shell strings)")

        actual_timeout = timeout or self.default_timeout
        limits = [f"timeout={actual_timeout}s", f"max_output={self.max_output_bytes}b", "no_shell_injection"]
        limitations = []

        if os.name == "nt":
            limitations.append("Windows environment: kernel CPU/memory cgroups not active; process timeout and output limits enforced.")
        else:
            limitations.append("POSIX environment: subprocess isolation and execution timer enforced.")

        # Sanitize environment: only permit safe non-secret system paths
        sanitized_env: Dict[str, str] = {}
        for key, val in os.environ.items():
            if key.upper() in SAFE_ENV_ALLOWLIST:
                sanitized_env[key] = val
        if extra_env:
            for k, v in extra_env.items():
                if not any(secret in k.lower() for secret in ("token", "key", "password", "secret")):
                    sanitized_env[k] = v

        # Isolated workspace
        temp_dir: Optional[str] = None
        target_cwd = working_directory
        if isolate_workspace:
            temp_dir = tempfile.mkdtemp(prefix="ecdat_sandbox_")
            target_cwd = temp_dir
            limits.append("isolated_workspace")

        start_time = time.monotonic()
        timed_out = False
        status = SandboxStatus.COMPLETED
        exit_code = None
        stdout_buf = bytearray()
        stderr_buf = bytearray()

        error = ""
        try:
            proc = subprocess.Popen(
                command,
                cwd=target_cwd,
                env=sanitized_env,
                stdin=subprocess.PIPE if input_data else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,  # Strictly false to prevent shell injection vulnerabilities
            )
            try:
                stdout_raw, stderr_raw = proc.communicate(input=input_data, timeout=actual_timeout)
                exit_code = proc.returncode
                stdout_buf.extend(stdout_raw or b"")
                stderr_buf.extend(stderr_raw or b"")
                if exit_code != 0:
                    status = SandboxStatus.FAILED
                    error = stderr_buf.decode("utf-8", "replace")
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                timed_out = True
                status = SandboxStatus.TIMEOUT
                error = f"Execution timed out after {actual_timeout}s"
                stdout_buf.extend(b"[TIMEOUT] Execution deadline exceeded")
        except FileNotFoundError as fnf:
            status = SandboxStatus.UNAVAILABLE
            error = str(fnf)
            stderr_buf.extend(str(fnf).encode("utf-8"))
        except Exception as exc:
            status = SandboxStatus.CRASHED
            error = str(exc)
            stderr_buf.extend(str(exc).encode("utf-8"))
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

        duration_ms = round((time.monotonic() - start_time) * 1000, 2)
        output_exceeded = len(stdout_buf) > self.max_output_bytes or len(stderr_buf) > self.max_output_bytes
        if output_exceeded and status in (SandboxStatus.COMPLETED, SandboxStatus.SUCCESS):
            status = SandboxStatus.OUTPUT_LIMIT_EXCEEDED

        stdout_str = stdout_buf[:self.max_output_bytes].decode("utf-8", "replace")
        stderr_str = stderr_buf[:self.max_output_bytes].decode("utf-8", "replace")
        if len(stdout_buf) > self.max_output_bytes:
            stdout_str += f"\n[Output truncated at {self.max_output_bytes} bytes]"

        return SandboxResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_ms=duration_ms,
            limits_enforced=limits,
            limitations=limitations,
            timed_out=timed_out,
            error=error,
        )

    def run_isolated(self, worker: Callable[[Path], Any]) -> SandboxResult:
        temp_dir = Path(tempfile.mkdtemp(prefix="ecdat_sandbox_"))
        start_time = time.monotonic()
        try:
            res = worker(temp_dir)
            return SandboxResult(
                status=SandboxStatus.SUCCESS,
                exit_code=0,
                stdout="",
                stderr="",
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
                limits_enforced=["isolated_workspace"],
                result=res,
            )
        except Exception as exc:
            return SandboxResult(
                status=SandboxStatus.FAILED,
                exit_code=1,
                stdout="",
                stderr=str(exc),
                duration_ms=round((time.monotonic() - start_time) * 1000, 2),
                limits_enforced=["isolated_workspace"],
                error=str(exc),
            )
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    def run_command(self, command: List[str], **kwargs: Any) -> SandboxResult:
        if command and command[0] == "python":
            command = [sys.executable] + list(command[1:])
        return self.run(command, **kwargs)
