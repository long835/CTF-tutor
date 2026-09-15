"""
agent/docker_sandbox.py

Optional Docker-based isolation for higher-risk analysis.

If Docker is unavailable, callers should fall back to agent.sandbox.run_sandboxed.
This module never pulls images or enables network by default.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from typing import List, Optional, Sequence

from agent.sandbox import SandboxResult


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def run_in_docker(
    argv: Sequence[str],
    *,
    image: str = "python:3.12-slim",
    timeout_sec: float = 20.0,
    mem_mb: int = 512,
    cpus: str = "0.5",
    workdir: str = "/work",
    mount_ro: Optional[str] = None,
    network: str = "none",
) -> SandboxResult:
    """
    Run argv inside a disposable container.
    network defaults to 'none'. mount_ro is mounted read-only at /work.
    """
    if not docker_available():
        return SandboxResult(127, "", "", False, 0.0, error="docker not available")

    cmd: List[str] = [
        "docker", "run", "--rm",
        "--network", network,
        "--memory", f"{mem_mb}m",
        "--cpus", cpus,
        "--read-only",
        "--tmpfs", "/tmp:size=64m",
        "--user", "65534:65534",  # nobody
    ]
    if mount_ro:
        cmd.extend(["-v", f"{mount_ro}:{workdir}:ro"])
        cmd.extend(["-w", workdir])
    cmd.append(image)
    cmd.extend(list(argv))

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout_sec,
            shell=False,
        )
        out = proc.stdout[:200_000].decode("utf-8", errors="replace")
        err = proc.stderr[:200_000].decode("utf-8", errors="replace")
        return SandboxResult(
            returncode=proc.returncode,
            stdout=out,
            stderr=err,
            timed_out=False,
            duration_sec=time.time() - t0,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"")[:200_000].decode("utf-8", errors="replace")
        err = (e.stderr or b"")[:200_000].decode("utf-8", errors="replace")
        return SandboxResult(-1, out, err, True, time.time() - t0, error="docker timeout")
    except OSError as e:
        return SandboxResult(1, "", "", False, time.time() - t0, error=str(e))
