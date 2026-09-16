"""
agent/sandbox.py

Resource-limited execution wrapper.

This is NOT a full container escape boundary. It is a practical first line of
defense for local tool runs:
  - wall-clock timeout
  - CPU time soft limit (Unix)
  - address-space / memory soft limit (Unix)
  - no new privileges where possible
  - restricted environment
  - capture stdout/stderr with size caps

For true isolation use Docker/Podman outside this process. The agent treats
this sandbox as the default for any subprocess it launches.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_sec: float
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error


def _apply_limits(cpu_sec: int, mem_mb: int) -> None:
    """Called in child preexec (Unix only)."""
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_sec, cpu_sec + 1))
    except (ValueError, resource.error, OSError):
        pass
    try:
        mem = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
    except (ValueError, resource.error, OSError):
        pass
    try:
        # no core dumps
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error, OSError):
        pass
    try:
        # limit number of processes somewhat
        nproc = 32
        resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))
    except (ValueError, resource.error, OSError):
        pass


def run_sandboxed(
    argv: Sequence[str],
    *,
    timeout_sec: float = 15.0,
    cpu_sec: int = 10,
    mem_mb: int = 512,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    input_data: Optional[bytes] = None,
    max_output_bytes: int = 200_000,
) -> SandboxResult:
    """
    Run a command with resource limits.
    Never passes shell=True.
    """
    import time
    if not argv:
        return SandboxResult(1, "", "", False, 0.0, error="empty argv")

    # Optional Docker path for higher isolation
    if os.getenv("CTF_TUTOR_USE_DOCKER", "auto") not in ("0", "false", "False"):
        try:
            from agent.docker_sandbox import docker_available, run_in_docker
            if docker_available():
                return run_in_docker(
                    argv,
                    timeout_sec=timeout_sec,
                    mem_mb=mem_mb,
                    mount_ro=cwd,
                )
        except Exception as e:
            # fall through to local rlimits
            pass

    clean_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": tempfile.gettempdir(),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if env:
        # only allow non-secret looking keys
        for k, v in env.items():
            if any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
                continue
            clean_env[k] = v

    preexec = None
    if sys.platform != "win32":
        def preexec():
            _apply_limits(cpu_sec, mem_mb)
            try:
                os.setsid()
            except OSError:
                pass

    t0 = time.time()
    try:
        proc = subprocess.run(
            list(argv),
            input=input_data,
            capture_output=True,
            timeout=timeout_sec,
            cwd=cwd,
            env=clean_env,
            preexec_fn=preexec,
            shell=False,
        )
        out = proc.stdout[:max_output_bytes].decode("utf-8", errors="replace")
        err = proc.stderr[:max_output_bytes].decode("utf-8", errors="replace")
        return SandboxResult(
            returncode=proc.returncode,
            stdout=out,
            stderr=err,
            timed_out=False,
            duration_sec=time.time() - t0,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"")[:max_output_bytes].decode("utf-8", errors="replace")
        err = (e.stderr or b"")[:max_output_bytes].decode("utf-8", errors="replace")
        return SandboxResult(
            returncode=-1,
            stdout=out,
            stderr=err,
            timed_out=True,
            duration_sec=time.time() - t0,
            error=f"timeout after {timeout_sec}s",
        )
    except FileNotFoundError as e:
        return SandboxResult(127, "", "", False, time.time() - t0, error=str(e))
    except OSError as e:
        return SandboxResult(1, "", "", False, time.time() - t0, error=str(e))


def safe_which(cmd: str) -> Optional[str]:
    """Resolve a binary on PATH without shell."""
    from shutil import which
    return which(cmd)
