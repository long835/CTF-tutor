"""First-class environment facts for exploit/tooling reasoning."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Any, Dict


def environment_snapshot() -> Dict[str, Any]:
    def _has(cmd: str) -> bool:
        return shutil.which(cmd) is not None

    snap = {
        "arch": platform.machine(),
        "system": platform.system(),
        "python": platform.python_version(),
        "docker": _has("docker"),
        "gdb": _has("gdb"),
        "ghidra": _has("ghidra") or _has("analyzeHeadless"),
        "pwntools": False,
        "checksec": _has("checksec"),
    }
    try:
        import pwn  # noqa: F401
        snap["pwntools"] = True
    except Exception:
        pass
    try:
        import ctypes
        snap["libc_name"] = ctypes.util.find_library("c") if hasattr(ctypes, "util") else None
    except Exception:
        snap["libc_name"] = None
    return snap
