"""Wrapper around the native/dotnet_inspect C# tool for .NET/C# `rev`
challenges -- same graceful-degradation pattern as tools/ghidra_headless.py:
skip cleanly (return a structured "unavailable" note) if the `dotnet` SDK
isn't installed, never raise for a missing optional dependency.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

_PROJECT_DIR = Path(__file__).resolve().parent.parent / "native" / "dotnet_inspect"
_TIMEOUT_SECONDS = 30


def is_available() -> bool:
    return shutil.which("dotnet") is not None


def inspect_dotnet_binary(binary_path: str) -> Optional[dict]:
    """Runs the C# metadata inspector against `binary_path`.

    Returns a dict with the parsed JSON metadata on success, or a dict
    with an "error"/"unavailable" key on any failure -- callers (e.g.
    static_analysis.py) should treat both the same way they already treat
    a missing checksec/binwalk/ghidra: as evidence that's simply not
    there, not as a reason to abort the pipeline.
    """
    path = Path(binary_path)
    if not path.is_file():
        return {"error": f"file not found: {binary_path}"}

    if not is_available():
        return {"unavailable": "dotnet SDK is not installed"}

    try:
        completed = subprocess.run(
            ["dotnet", "run", "--project", str(_PROJECT_DIR), "--", str(path)],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": "dotnet-inspect timed out"}
    except OSError as exc:
        return {"error": f"failed to run dotnet-inspect: {exc}"}

    if completed.returncode != 0:
        return {"error": completed.stderr.strip() or "dotnet-inspect failed"}

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"error": "dotnet-inspect returned invalid JSON"}
