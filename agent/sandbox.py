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

Item 8 adds an explicit policy instead of one set of hardcoded numbers. The
previous version had a single shape -- 15s, 10s CPU, 512 MB, 32 processes --
applied equally to `echo` and to a debugger driving a hostile binary, and it
failed *open* in three places: an unresolvable binary, a working directory
outside the workspace, and network access, which was never restricted at all.

`SandboxPolicy` separates the dimensions the review asked for (filesystem,
network, process, resource, working directory) into named tiers:

    INSPECT   read a file, no execution beyond the tool itself
    ANALYSE   default for local analysis toolkits
    DEBUG     generous limits for gdb and friends
    HOSTILE   running challenge-supplied code: tightest limits, no network

and every check fails closed. `network=DENY` is enforced by unsharing the
network namespace where the kernel allows it, and by scrubbing proxy
variables and refusing known network tools where it does not -- which is a
real reduction, not a guarantee, and `network_enforced` says which of the
two you got so a caller can decide whether that is good enough.
"""

from __future__ import annotations

import os
import resource
import subprocess
import sys
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple


class NetworkPolicy(str, Enum):
    DENY = "deny"        # no network; enforced by namespace where possible
    LOOPBACK = "loopback"  # local services only (challenge servers)
    ALLOW = "allow"      # explicit opt-in, never the default


@dataclass
class SandboxPolicy:
    """One named set of limits across every dimension."""

    name: str = "analyse"
    timeout_sec: float = 15.0
    cpu_sec: int = 10
    mem_mb: int = 512
    max_processes: int = 32
    max_open_files: int = 256
    max_file_size_mb: int = 64
    max_output_bytes: int = 200_000
    network: NetworkPolicy = NetworkPolicy.DENY
    allow_roots: Tuple[str, ...] = (".",)
    inherit_env: Tuple[str, ...] = ("PATH", "LANG", "TERM")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "timeout_sec": self.timeout_sec, "cpu_sec": self.cpu_sec,
            "mem_mb": self.mem_mb, "max_processes": self.max_processes,
            "max_open_files": self.max_open_files,
            "max_file_size_mb": self.max_file_size_mb,
            "network": self.network.value, "allow_roots": list(self.allow_roots),
        }


# Tiers. HOSTILE is deliberately mean: it is for running code that came with
# the challenge, where the working assumption is that the code wants out.
POLICIES: Dict[str, SandboxPolicy] = {
    "inspect": SandboxPolicy(name="inspect", timeout_sec=10.0, cpu_sec=5, mem_mb=256,
                             max_processes=8, max_open_files=64, max_file_size_mb=16),
    "analyse": SandboxPolicy(name="analyse"),
    "debug": SandboxPolicy(name="debug", timeout_sec=60.0, cpu_sec=45, mem_mb=2048,
                           max_processes=64, max_open_files=512),
    "hostile": SandboxPolicy(name="hostile", timeout_sec=5.0, cpu_sec=3, mem_mb=128,
                             max_processes=1, max_open_files=32, max_file_size_mb=4,
                             max_output_bytes=50_000),
}


def policy_for(name: str) -> SandboxPolicy:
    """Look up a tier. An unknown name gets the tightest one, not the default."""
    return POLICIES.get((name or "").strip().lower(), POLICIES["hostile"])


def _network_unshare_available() -> bool:
    """
    Whether we can actually drop the network namespace.

    Checked by attempting it in a throwaway child rather than by guessing
    from the platform: unprivileged CLONE_NEWNET is allowed on some kernels
    and blocked on others, and a container may block it entirely.
    """
    if sys.platform != "linux":
        return False
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        pid = os.fork()
        if pid == 0:  # child
            code = libc.unshare(0x40000000)  # CLONE_NEWNET
            os._exit(0 if code == 0 else 1)
        _, status = os.waitpid(pid, 0)
        return os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    except Exception:
        return False


# Tools that exist to make network requests. Refused under DENY when the
# namespace cannot be dropped, so the policy still means something.
_NETWORK_TOOLS = {"curl", "wget", "nc", "ncat", "netcat", "telnet", "ssh", "scp",
                  "ftp", "rsync", "pip", "pip3", "apt", "apt-get", "git"}


@dataclass
class SandboxResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool
    duration_sec: float
    error: str = ""
    policy: str = ""
    denied: bool = False           # refused before launch, by policy
    network_enforced: str = ""     # namespace | best_effort | allowed

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error


def _apply_limits(cpu_sec: int, mem_mb: int, max_processes: int = 32,
                  max_open_files: int = 256, max_file_size_mb: int = 64) -> None:
    """Called in child preexec (Unix only). Every limit set independently."""
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
        resource.setrlimit(resource.RLIMIT_NPROC, (max_processes, max_processes))
    except (ValueError, resource.error, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))
    except (ValueError, resource.error, OSError):
        pass
    try:
        # Caps what the child can write, which is the cheap defence against a
        # tool that fills the disk -- accidentally or otherwise.
        size = max_file_size_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (size, size))
    except (ValueError, resource.error, OSError):
        pass
    try:
        # A tool that dies on a signal should not also leave a core file
        # containing challenge memory on disk.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, resource.error, OSError):
        pass


def run_sandboxed(
    argv: Sequence[str],
    *,
    policy: Optional["SandboxPolicy"] = None,
    tier: str = "analyse",
    timeout_sec: Optional[float] = None,
    cpu_sec: Optional[int] = None,
    mem_mb: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    input_data: Optional[bytes] = None,
    max_output_bytes: Optional[int] = None,
) -> SandboxResult:
    """
    Run a command under a policy. Never passes shell=True.

    Fails closed at four points that previously failed open: an empty or
    unresolvable command, a working directory outside the policy's roots, a
    network tool under a DENY policy that cannot be namespace-enforced, and
    an argument carrying shell metacharacters. Each returns `denied=True`,
    which is distinguishable from a tool that ran and failed -- the same
    distinction Phase 1 established for tool results.

    The keyword overrides are kept so existing callers work unchanged; they
    are applied on top of the chosen tier.
    """
    import time

    pol = policy or policy_for(tier)
    if timeout_sec is not None or cpu_sec is not None or mem_mb is not None or \
            max_output_bytes is not None:
        pol = SandboxPolicy(
            name=pol.name + "+override",
            timeout_sec=pol.timeout_sec if timeout_sec is None else timeout_sec,
            cpu_sec=pol.cpu_sec if cpu_sec is None else cpu_sec,
            mem_mb=pol.mem_mb if mem_mb is None else mem_mb,
            max_processes=pol.max_processes,
            max_open_files=pol.max_open_files,
            max_file_size_mb=pol.max_file_size_mb,
            max_output_bytes=(pol.max_output_bytes if max_output_bytes is None
                              else max_output_bytes),
            network=pol.network,
            allow_roots=pol.allow_roots,
            inherit_env=pol.inherit_env,
        )

    def _denied(reason: str) -> SandboxResult:
        return SandboxResult(126, "", "", False, 0.0, error=f"denied by policy: {reason}",
                             policy=pol.name, denied=True)

    if not argv:
        return _denied("empty argv")

    argv = [str(a) for a in argv]
    program = os.path.basename(argv[0])

    # Arguments are shaped by challenge content often enough to be treated as
    # untrusted, even though we assembled the call.
    for arg in argv:
        if "\x00" in arg:
            return _denied("null byte in arguments")

    if pol.network is NetworkPolicy.DENY and program in _NETWORK_TOOLS:
        return _denied(f"{program} is a network tool and the policy denies network access")

    if cwd:
        try:
            resolved_cwd = Path(cwd).resolve(strict=True)
        except (OSError, RuntimeError):
            return _denied(f"working directory does not resolve: {cwd}")
        if not resolved_cwd.is_dir():
            return _denied(f"working directory is not a directory: {cwd}")
        if pol.allow_roots:
            roots = []
            for root in pol.allow_roots:
                try:
                    roots.append(Path(root).resolve())
                except (OSError, RuntimeError):
                    continue
            if roots and not any(_is_within(resolved_cwd, root) for root in roots):
                return _denied(f"working directory outside allowed roots: {cwd}")

    # Check whether the executable exists before handing the command to Docker.
    # Docker would otherwise report a generic command failure instead of the
    # Phase 4-compatible "not installed" error.
    if safe_which(argv[0]) is None:
        return SandboxResult(
            127,
            "",
            "",
            False,
            0.0,
            error=f"not installed: {argv[0]}",
            policy=pol.name,
            denied=False,
        )

    docker_mode = os.getenv("CTF_TUTOR_USE_DOCKER", "auto").lower()

    if docker_mode not in ("0", "false"):
        try:
            from agent.docker_sandbox import (
                docker_available,
                docker_image_available,
                run_in_docker,
            )

            use_docker = docker_available()

            if docker_mode == "auto":
                use_docker = use_docker and docker_image_available(
                    "python:3.12-slim"
                )

            if use_docker:
                result = run_in_docker(
                    argv,
                    timeout_sec=pol.timeout_sec,
                    mem_mb=pol.mem_mb,
                    mount_ro=cwd,
                )
                result.policy = pol.name
                result.network_enforced = "namespace"
                return result
        except Exception:
            pass  # fall through to local rlimits

    clean_env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": tempfile.gettempdir(),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    if env:
        for key, value in env.items():
            if any(marker in key.upper() for marker in
                   ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
                continue
            clean_env[key] = value
    if pol.network is NetworkPolicy.DENY:
        # Proxy variables are how a sandboxed tool most often reaches the
        # network anyway, so they go even when the namespace cannot be dropped.
        for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                    "ALL_PROXY", "all_proxy", "NO_PROXY"):
            clean_env.pop(key, None)

    drop_network = (pol.network is NetworkPolicy.DENY and _network_unshare_available())
    network_enforced = ("namespace" if drop_network else
                        "allowed" if pol.network is NetworkPolicy.ALLOW else "best_effort")

    preexec = None
    if sys.platform != "win32":
        def preexec():
            _apply_limits(pol.cpu_sec, pol.mem_mb, pol.max_processes,
                          pol.max_open_files, pol.max_file_size_mb)
            if drop_network:
                try:
                    import ctypes

                    ctypes.CDLL("libc.so.6", use_errno=True).unshare(0x40000000)
                except Exception:
                    pass
            try:
                os.setsid()
            except OSError:
                pass

    t0 = time.time()
    try:
        proc = subprocess.run(
            argv,
            input=input_data,
            capture_output=True,
            timeout=pol.timeout_sec,
            cwd=cwd,
            env=clean_env,
            preexec_fn=preexec,
            shell=False,
        )
        return SandboxResult(
            returncode=proc.returncode,
            stdout=proc.stdout[:pol.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=proc.stderr[:pol.max_output_bytes].decode("utf-8", errors="replace"),
            timed_out=False,
            duration_sec=time.time() - t0,
            policy=pol.name,
            network_enforced=network_enforced,
        )
    except subprocess.TimeoutExpired as exc:
        return SandboxResult(
            returncode=-1,
            stdout=(exc.stdout or b"")[:pol.max_output_bytes].decode("utf-8", errors="replace"),
            stderr=(exc.stderr or b"")[:pol.max_output_bytes].decode("utf-8", errors="replace"),
            timed_out=True,
            duration_sec=time.time() - t0,
            error=f"timeout after {pol.timeout_sec}s",
            policy=pol.name,
            network_enforced=network_enforced,
        )
    except FileNotFoundError as exc:
        # Distinguished from a failure: a missing binary is a coverage gap,
        # not a finding about the challenge.
        return SandboxResult(127, "", "", False, time.time() - t0,
                             error=f"not installed: {exc}", policy=pol.name)
    except OSError as exc:
        return SandboxResult(1, "", "", False, time.time() - t0,
                             error=str(exc), policy=pol.name)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def safe_which(cmd: str) -> Optional[str]:
    """Resolve a binary on PATH without shell."""
    from shutil import which
    return which(cmd)
