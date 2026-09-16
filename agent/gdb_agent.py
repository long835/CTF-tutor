"""
agent/gdb_agent.py

Sandboxed GDB helper for educational binary inspection.

NOT a full interactive pwn IDE. Provides:
  - file / info functions / disassemble / x commands
  - strict timeouts via agent.sandbox
  - no unrestricted shell

Requires `gdb` on PATH. Optional pwndbg is detected but not required.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.sandbox import run_sandboxed, safe_which


def gdb_available() -> bool:
    return safe_which("gdb") is not None


def run_gdb_batch(
    binary: str,
    commands: List[str],
    *,
    timeout_sec: float = 12.0,
    mem_mb: int = 512,
) -> Dict[str, Any]:
    """
    Run gdb -batch -nx with a command list against a local binary.
    """
    if not gdb_available():
        return {"ok": False, "error": "gdb not installed"}
    bin_path = Path(binary).resolve()
    if not bin_path.is_file():
        return {"ok": False, "error": f"binary not found: {binary}"}

    # Write command file
    cmd_lines = ["set pagination off", "set confirm off"]
    cmd_lines.extend(commands)
    cmd_lines.append("quit")

    with tempfile.TemporaryDirectory() as td:
        cmd_file = Path(td) / "cmds.gdb"
        cmd_file.write_text("\n".join(cmd_lines) + "\n", encoding="utf-8")
        argv = [
            "gdb", "-batch", "-nx",
            "-x", str(cmd_file),
            str(bin_path),
        ]
        # Prefer docker if enabled
        result = run_sandboxed(
            argv,
            timeout_sec=timeout_sec,
            mem_mb=mem_mb,
            cwd=str(bin_path.parent),
        )
        return {
            "ok": result.ok,
            "stdout": result.stdout[-8000:],
            "stderr": result.stderr[-2000:],
            "timed_out": result.timed_out,
            "error": result.error,
            "duration_sec": result.duration_sec,
        }


def inspect_binary(binary: str) -> Dict[str, Any]:
    """Common educational inspection sequence."""
    cmds = [
        "info file",
        "info functions",
        "disassemble main",
        "info variables",
    ]
    return run_gdb_batch(binary, cmds)


def disassemble_function(binary: str, function: str = "main") -> Dict[str, Any]:
    safe = "".join(c for c in function if c.isalnum() or c in "_")
    if not safe:
        return {"ok": False, "error": "invalid function name"}
    return run_gdb_batch(binary, [f"disassemble {safe}"])
