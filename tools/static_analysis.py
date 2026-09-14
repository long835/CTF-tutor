import os
import subprocess
import shutil
from typing import Callable, Dict, Optional

from tools.ghidra_headless import decompile_with_ghidra
from tools import crypto_toolkit, web_recon, forensics_toolkit, osint_toolkit


def _posix_rlimits():
    try:
        import resource
        mem = 512 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    except (ImportError, ValueError, OSError):
        return


def _run(cmd: list, timeout: int = 15) -> str:
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"[{exe} not installed -- skip this check or `apt install {exe}`]"
    kwargs = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
    }
    if os.name == "posix":
        kwargs["preexec_fn"] = _posix_rlimits
    try:
        result = subprocess.run(cmd, **kwargs)
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
    cmd = ["nm", "-D", path] if dynamic_only else ["nm", path]
    return _run(cmd)


def read_elf_headers(path: str) -> str:
    return _run(["readelf", "-h", "-d", path])


def disassemble(path: str, function: Optional[str] = None, limit_lines: int = 300) -> str:
    cmd = ["objdump", "-d", "-M", "intel"]
    if function:
        cmd.append(f"--disassemble={function}")
    cmd.append(path)
    out = _run(cmd)
    lines = out.splitlines()
    if len(lines) > limit_lines:
        lines = lines[:limit_lines] + [f"... [{len(out.splitlines()) - limit_lines} more lines truncated]"]
    return "\n".join(lines)


def java_decompile(path: str) -> str:
    """javap disassembly for .class/.jar -- Java reversing without Ghidra."""
    lower = path.lower()
    if not (lower.endswith(".class") or lower.endswith(".jar")):
        return "[not a .class/.jar -- skip javap]"
    if shutil.which("javap"):
        return _run(["javap", "-c", "-p", path], timeout=30)
    if shutil.which("cfr"):
        return _run(["cfr", path], timeout=30)
    return "[javap/cfr not installed -- skip Java decompile]"


def dotnet_hint(path: str) -> str:
    strings = extract_strings(path, min_len=8, limit=80)
    markers = [s for s in ("mscoree", "System.Runtime", ".NET", "mscorlib") if s.lower() in strings.lower()]
    if not markers and not path.lower().endswith((".exe", ".dll")):
        return "[no obvious .NET markers]"
    if shutil.which("ilspycmd"):
        return _run(["ilspycmd", path], timeout=40)[:4000]
    return (
        "Possible .NET binary (markers: "
        + (", ".join(markers) or "extension only")
        + "). Install ilspycmd or use ILSpy/dnSpy locally -- not bundled here."
    )


def full_recon(
    path: Optional[str],
    category_hint: Optional[str] = None,
    include_decompile: bool = False,
    target_url: Optional[str] = None,
    domain: Optional[str] = None,
) -> dict:
    """
    Cheap, fast checks always. Category-specific plugins fill the historic
    gap where web/crypto/osint gathered almost no evidence.
    """
    evidence = {}
    strings_blob = ""
    if path:
        evidence["file_type"] = identify_file(path)
        strings_blob = extract_strings(path)
        evidence["strings_sample"] = strings_blob
        lower = path.lower()
        if lower.endswith((".class", ".jar")) or category_hint == "rev":
            java = java_decompile(path)
            if not java.startswith("[not a"):
                evidence["java"] = java
        if category_hint in (None, "rev", "pwn"):
            evidence["dotnet"] = dotnet_hint(path)

    if category_hint in (None, "pwn", "rev") and path:
        evidence["binary_protections"] = check_binary_protections(path)
        evidence["dynamic_symbols"] = list_symbols(path)
        evidence["elf_headers"] = read_elf_headers(path)
        if include_decompile:
            evidence["decompiled"] = decompile_with_ghidra(path)

    if category_hint in (None, "forensics", "misc") and path:
        evidence["binwalk"] = run_binwalk(path)
        evidence["metadata"] = extract_metadata(path)
        evidence.update(forensics_toolkit.gather_forensics_evidence(path))

    if category_hint in (None, "web"):
        evidence.update(web_recon.gather_web_evidence(path, target_url=target_url))

    if category_hint in (None, "crypto"):
        evidence.update(crypto_toolkit.gather_crypto_evidence(path, strings_blob=strings_blob))

    if category_hint in (None, "osint"):
        evidence.update(osint_toolkit.gather_osint_evidence(path, domain=domain))

    if category_hint == "blockchain" and path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                src = f.read(50_000)
            evidence["solidity_excerpt"] = src[:2000]
        except OSError:
            pass

    if not evidence:
        evidence["note"] = "no file or URL given -- text-only decomposition"
    return evidence


RECON_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "identify_file",
            "description": "Run the `file` command on the challenge path.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_strings",
            "description": "Extract printable strings from the challenge file.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_binary_protections",
            "description": "Run checksec on a pwn/rev binary.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "identify_hash",
            "description": "Guess hash family from a hex or modular-crypt string found in the challenge. Does not crack it.",
            "parameters": {
                "type": "object",
                "properties": {"blob": {"type": "string"}},
                "required": ["blob"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_jwt",
            "description": "Decode a JWT header and payload only (no signature verification or forgery).",
            "parameters": {
                "type": "object",
                "properties": {"token": {"type": "string"}},
                "required": ["token"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_headers",
            "description": "HEAD/GET response headers for a URL the learner already provided.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_gps",
            "description": "Read GPS tags from an image with exiftool.",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
]


def _dispatch_recon_tool(name: str, args: dict, path: Optional[str], target_url: Optional[str]) -> str:
    handlers: Dict[str, Callable[[], str]] = {
        "identify_file": lambda: identify_file(path) if path else "[no file]",
        "extract_strings": lambda: extract_strings(path) if path else "[no file]",
        "check_binary_protections": lambda: check_binary_protections(path) if path else "[no file]",
        "identify_hash": lambda: crypto_toolkit.identify_hash(str(args.get("blob", ""))),
        "decode_jwt": lambda: web_recon.decode_jwt(str(args.get("token", ""))),
        "get_headers": lambda: web_recon.get_headers(str(args.get("url") or target_url or "")),
        "extract_gps": lambda: osint_toolkit.extract_gps(path) if path else "[no file]",
    }
    handler = handlers.get(name)
    if handler is None:
        return f"[unknown recon tool {name}]"
    try:
        return handler()
    except Exception as e:
        return f"[{name} failed: {e}]"


def guided_recon(
    path: Optional[str],
    category_hint: Optional[str] = None,
    include_decompile: bool = False,
    target_url: Optional[str] = None,
    model: str = "",
    challenge_description: str = "",
) -> dict:
    """Let the local model pick recon tools via Ollama tool-calling.
    Falls back to full_recon if the model never invokes a tool."""
    from llm_client import DEFAULT_MODEL, call_ollama_with_tools

    model = model or DEFAULT_MODEL
    collected: dict = {}

    def impl(name: str, args: dict) -> str:
        result = _dispatch_recon_tool(name, args, path, target_url)
        collected[name] = result
        return result[:4000]

    user = (
        f"Challenge:\n{challenge_description}\n"
        f"Category hint: {category_hint or 'unknown'}\n"
        f"File: {path or 'none'}\n"
        f"URL: {target_url or 'none'}\n"
        "Call the recon tools you actually need, then stop. Do not solve the challenge."
    )
    final = call_ollama_with_tools(
        "You gather evidence for a CTF tutor. Use tools; do not produce flags or exploits.",
        user,
        tools=RECON_TOOL_SCHEMAS,
        tool_impl=impl,
        model=model,
        max_rounds=5,
    )
    if final:
        collected["model_note"] = final
    if include_decompile and path and category_hint in (None, "pwn", "rev"):
        collected["decompiled"] = decompile_with_ghidra(path)
    if len(collected) <= 1:
        collected.update(
            full_recon(
                path,
                category_hint=category_hint,
                include_decompile=include_decompile,
                target_url=target_url,
            )
        )
    return collected
