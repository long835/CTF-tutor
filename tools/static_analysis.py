import subprocess
import shutil
from typing import Optional


def _run(cmd: list, timeout: int = 15) -> str:
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"[{exe} not installed -- skip this check or `apt install {exe}`]"
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        output = result.stdout.strip()
        if result.stderr.strip():
            output += f"\n[stderr] {result.stderr.strip()}"
        return output or "[no output]"
    except subprocess.TimeoutExpired:
        return f"[{exe} timed out after {timeout}s]"
    except Exception as e:
        return f"[{exe} failed: {e}]"


def identify_file(path: str) -> str:
    return _run(["file", path])


def extract_strings(path: str, min_len: int = 6, limit: int = 200) -> str:
    out = _run(["strings", "-n", str(min_len), path])
    lines = out.splitlines()
    if len(lines) > limit:
        lines = lines[:limit] + [f"... [{len(out.splitlines()) - limit} more lines truncated]"]
    return "\n".join(lines)


def check_binary_protections(path: str) -> str:
    """
    Two different tools both go by `checksec` and take different flags:
      - checksec.py (pip install checksec.py)  -> positional arg, no flag:
            checksec <file_or_directory>...
      - checksec.sh (the classic bash script)  -> single --file=path arg:
            checksec.sh --file=<path>   (or `checksec --file=<path>` if
            it's the only one on PATH named `checksec`)
    Passing "--file", path as two separate argv entries (the old code) never
    matches either tool's real syntax, so probe --help output to tell them
    apart instead of guessing.
    """
    if shutil.which("checksec") is None:
        return "[checksec not installed -- skip this check or `pip install checksec.py`]"

    help_text = _run(["checksec", "--help"])
    if "--file=" in help_text or "checksec.sh" in help_text.lower():
        return _run(["checksec", f"--file={path}"])
    return _run(["checksec", path])


def run_binwalk(path: str) -> str:
    return _run(["binwalk", path])


def extract_metadata(path: str) -> str:
    return _run(["exiftool", path])


def full_recon(path: str, category_hint: Optional[str] = None) -> dict:
    evidence = {"file_type": identify_file(path)}
    evidence["strings_sample"] = extract_strings(path)
    if category_hint in (None, "pwn", "rev"):
        evidence["binary_protections"] = check_binary_protections(path)
    if category_hint in (None, "forensics", "misc"):
        evidence["binwalk"] = run_binwalk(path)
        evidence["metadata"] = extract_metadata(path)
    return evidence
