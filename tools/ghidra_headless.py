"""
tools/ghidra_headless.py

Thin wrapper around Ghidra's `analyzeHeadless` so the tutor can hand the LLM
a decompiled listing of a rev/pwn binary as extra evidence, the same way
tools/static_analysis.py hands it `file`/`strings`/`checksec` output.

Requires a local Ghidra install (https://ghidra-sre.org/) -- this module
does NOT bundle Ghidra itself (it's a multi-hundred-MB Java application with
its own JDK requirement, well outside the scope of a pip install). Point
GHIDRA_INSTALL_DIR at your install, or put `analyzeHeadless` on PATH.

Runs the bundled tools/ghidra_scripts/DumpDecompiled.py as a Ghidra
post-script, which decompiles every function Ghidra's analysis found and
writes it to a temp file this wrapper then reads back in.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
from typing import Optional

SCRIPT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts")
SCRIPT_NAME = "DumpDecompiled.py"
DEFAULT_CACHE_DIR = os.path.join("data", "ghidra_cache")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cache_path(binary_path: str, cache_dir: str) -> str:
    os.makedirs(cache_dir, exist_ok=True)
    # Cache identity includes the binary and the bundled post-script, so
    # changing the analysis logic cannot silently reuse stale decompilation.
    script_path = os.path.join(SCRIPT_DIR, SCRIPT_NAME)
    digest = hashlib.sha256()
    for path in (binary_path, script_path):
        digest.update(_sha256_file(path).encode())
    return os.path.join(cache_dir, digest.hexdigest() + ".c")


def find_analyze_headless() -> Optional[str]:
    """Locate Ghidra's analyzeHeadless: prefer $GHIDRA_INSTALL_DIR/support/analyzeHeadless
    (the standard install layout), fall back to whatever's on PATH."""
    install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if install_dir:
        candidate = os.path.join(install_dir, "support", "analyzeHeadless")
        if os.path.isfile(candidate):
            return candidate
    return shutil.which("analyzeHeadless")


def _remove_quiet(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def decompile_with_ghidra(
    binary_path: str,
    timeout: int = 300,
    project_dir: Optional[str] = None,
    cache_dir: Optional[str] = None,
) -> str:
    """
    Run Ghidra headless analysis + decompilation on a binary and return the
    decompiled output as text. Successful results are cached under
    data/ghidra_cache/<binary+script-sha256>.c so a second --decompile on the same file
    skips the full headless pass.
    """
    analyze_headless = find_analyze_headless()
    if analyze_headless is None:
        return (
            "[Ghidra not found -- set GHIDRA_INSTALL_DIR or put analyzeHeadless "
            "on PATH to enable decompilation (https://ghidra-sre.org/)]"
        )
    if not os.path.isfile(binary_path):
        return f"[binary not found: {binary_path}]"

    resolved_cache = cache_dir if cache_dir is not None else os.environ.get(
        "GHIDRA_CACHE_DIR", DEFAULT_CACHE_DIR
    )
    cached = _cache_path(binary_path, resolved_cache)
    if os.path.isfile(cached) and os.path.getsize(cached) > 0:
        with open(cached, "r", errors="replace") as f:
            return f.read()

    owns_project_dir = project_dir is None
    if owns_project_dir:
        project_dir = tempfile.mkdtemp(prefix="ghidra_proj_")
    output_fd, output_path = tempfile.mkstemp(prefix="ghidra_decompiled_", suffix=".c")
    os.close(output_fd)

    cmd = [
        analyze_headless,
        project_dir,
        "ctf_tutor_project",
        "-import", binary_path,
        "-postScript", SCRIPT_NAME, output_path,
        "-scriptPath", SCRIPT_DIR,
        "-deleteProject",
    ]

    try:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return f"[Ghidra headless analysis timed out after {timeout}s]"
        except Exception as e:
            return f"[Ghidra headless analysis failed to start: {e}]"

        if result.returncode != 0 or not os.path.exists(output_path) or os.path.getsize(output_path) == 0:
            stderr_tail = (result.stderr or "").strip()[-2000:]
            return f"[Ghidra headless analysis produced no output (exit {result.returncode})\n{stderr_tail}]"

        with open(output_path, "r", errors="replace") as f:
            text = f.read()
        try:
            with open(cached, "w", encoding="utf-8", errors="replace") as f:
                f.write(text)
        except OSError:
            pass
        return text
    finally:
        _remove_quiet(output_path)
        if owns_project_dir:
            shutil.rmtree(project_dir, ignore_errors=True)
