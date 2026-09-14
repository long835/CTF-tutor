import subprocess
import shutil
from typing import Optional

from tools.ghidra_headless import decompile_with_ghidra
from tools import web_recon, crypto_toolkit, forensics_toolkit


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


def list_symbols(path: str, dynamic_only: bool = True) -> str:
    """nm -- exported/imported function names, often gives away which libc
    functions are linked (system, execve, gets, strcpy, ...) before you even
    open a decompiler."""
    cmd = ["nm", "-D", path] if dynamic_only else ["nm", path]
    return _run(cmd)


def read_elf_headers(path: str) -> str:
    """readelf -h -d -- ELF header + dynamic section (architecture, entry
    point, linked shared libraries). Cheap and often enough to plan an
    approach before reaching for objdump/Ghidra."""
    return _run(["readelf", "-h", "-d", path])


def disassemble(path: str, function: Optional[str] = None, limit_lines: int = 300) -> str:
    """objdump -d -- quick disassembly without needing Ghidra installed.
    Pass `function` to disassemble just one function (objdump --disassemble=NAME)
    when you already know what you're looking for; omit it to dump everything
    (truncated to limit_lines, since a full binary's disassembly can be huge)."""
    cmd = ["objdump", "-d", "-M", "intel"]
    if function:
        cmd.append(f"--disassemble={function}")
    cmd.append(path)
    out = _run(cmd)
    lines = out.splitlines()
    if len(lines) > limit_lines:
        lines = lines[:limit_lines] + [f"... [{len(out.splitlines()) - limit_lines} more lines truncated]"]
    return "\n".join(lines)


def full_recon(
    path: str,
    category_hint: Optional[str] = None,
    include_decompile: bool = False,
) -> dict:
    """
    Run the cheap, fast checks (file/strings, and category-specific analysis).
    
    - pwn/rev: binary analysis (checksec, nm, readelf, objdump, optional Ghidra)
    - web: source code analysis (framework detection, JWT scanning, auth patterns)
    - crypto: hash identification, RSA key analysis, cipher pattern detection
    - forensics: PCAP analysis, memory dumps, disk images, steganography detection
    - misc: binwalk, exiftool (file carving, steganography, metadata)
    
    Ghidra decompilation is opt-in via include_decompile=True since it's much
    slower (a real headless analysis pass, not a one-shot CLI call) and
    requires a local Ghidra install -- see tools/ghidra_headless.py.
    """
    evidence = {"file_type": identify_file(path)}
    evidence["strings_sample"] = extract_strings(path)
    
    if category_hint in (None, "pwn", "rev"):
        # Binary exploitation / reverse engineering
        evidence["binary_protections"] = check_binary_protections(path)
        evidence["dynamic_symbols"] = list_symbols(path)
        evidence["elf_headers"] = read_elf_headers(path)
        if include_decompile:
            evidence["decompiled"] = decompile_with_ghidra(path)
    
    elif category_hint == "web":
        # Web challenges: analyze source code / application files
        try:
            web_analysis = web_recon.analyze_source_file(path)
            evidence["web_framework"] = web_analysis.get("framework", {})
            evidence["web_jwt_tokens"] = web_analysis.get("jwt_tokens", [])
            evidence["web_headers"] = web_analysis.get("headers", {})
            evidence["web_auth_patterns"] = web_analysis.get("auth_patterns", {})
        except Exception as e:
            evidence["web_analysis_error"] = str(e)
    
    elif category_hint == "crypto":
        # Cryptography challenges: identify hashes, RSA keys, cipher patterns
        try:
            crypto_analysis = crypto_toolkit.analyze_crypto_file(path)
            evidence["crypto_hashes"] = crypto_analysis.get("hashes_found", [])
            evidence["crypto_rsa_analysis"] = crypto_analysis.get("rsa_key_analysis", {})
            evidence["crypto_patterns"] = crypto_analysis.get("crypto_patterns", {})
        except Exception as e:
            evidence["crypto_analysis_error"] = str(e)
    
    elif category_hint == "forensics":
        # Forensics challenges: PCAP, memory dumps, disk images, steganography
        try:
            forensics_analysis = forensics_toolkit.analyze_forensics_file(path)
            evidence["forensics_pcap"] = forensics_analysis.get("pcap_metadata", {})
            evidence["forensics_memory"] = forensics_analysis.get("memory_dump_metadata", {})
            evidence["forensics_disk"] = forensics_analysis.get("disk_image_metadata", {})
            evidence["forensics_steg"] = forensics_analysis.get("steganography_indicators", {})
            evidence["forensics_archive"] = forensics_analysis.get("archive_metadata", {})
        except Exception as e:
            evidence["forensics_analysis_error"] = str(e)
    
    elif category_hint in (None, "misc"):
        # Misc/generic: file carving, steganography, metadata
        evidence["binwalk"] = run_binwalk(path)
        evidence["metadata"] = extract_metadata(path)
    
    return evidence
