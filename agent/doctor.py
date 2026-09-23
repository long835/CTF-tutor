"""
agent/doctor.py

What actually works on this machine (items 42, 43, 44).

Local-first means the install is the product. A user on Windows with no
Docker, no Ghidra and a CPU-only machine will get silent failures from
tools that assume a Linux box with a toolchain — and because those failures
surface as "the agent found nothing", they look like the agent being bad
rather than the environment being incomplete.

`probe()` checks what is present, grouped into tiers so nobody is told to
install Ghidra in order to do crypto challenges:

    core      → without this, nothing works
    model     → the local LLM and its backend
    analysis  → per-category CTF tooling
    dev       → tests and development
    gpu       → acceleration, optional by definition

The output that matters is not the tick list. It is
`degraded_categories()`, which turns missing binaries into a statement
about capability: "forensics is degraded — exiftool and tshark are
missing", which is what a user can act on. Nothing here installs anything
or phones home; it reports.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

Tier = str
CORE, MODEL, ANALYSIS, DEV, GPU = "core", "model", "analysis", "dev", "gpu"


@dataclass
class Check:
    """One probe and its outcome."""

    name: str
    tier: Tier
    ok: bool
    detail: str = ""
    optional: bool = True
    remedy: str = ""
    categories: List[str] = field(default_factory=list)

    @property
    def symbol(self) -> str:
        if self.ok:
            return "✓"
        return "⚠" if self.optional else "✗"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "ok": self.ok,
            "detail": self.detail,
            "optional": self.optional,
            "remedy": self.remedy,
            "categories": list(self.categories),
        }


# Binaries the toolkit reaches for, with the categories each supports. Names
# are probed with shutil.which, which is the portable way to ask — .exe
# resolution on Windows included.
BINARIES: List[Tuple[str, Tier, List[str], str]] = [
    ("file", ANALYSIS, ["forensics", "rev", "misc"], "part of coreutils/file on most systems"),
    ("strings", ANALYSIS, ["rev", "pwn", "forensics"], "install binutils"),
    ("readelf", ANALYSIS, ["pwn", "rev"], "install binutils"),
    ("objdump", ANALYSIS, ["pwn", "rev"], "install binutils"),
    ("gdb", ANALYSIS, ["pwn"], "install gdb (pwndbg/GEF recommended)"),
    ("exiftool", ANALYSIS, ["forensics", "osint"], "install libimage-exiftool-perl"),
    ("tshark", ANALYSIS, ["forensics"], "install wireshark CLI tools"),
    ("binwalk", ANALYSIS, ["forensics"], "pip install binwalk"),
    ("docker", ANALYSIS, ["pwn", "web"], "install Docker for sandboxed execution"),
    ("ollama", MODEL, [], "install from ollama.com for local models"),
    ("cargo", DEV, [], "install Rust if building the native XOR module"),
    ("dotnet", ANALYSIS, ["rev"], "install .NET SDK for .NET decompilation"),
    ("git", DEV, [], "install git"),
]

PACKAGES: List[Tuple[str, Tier, bool, str]] = [
    ("requests", CORE, False, "pip install requests"),
    ("chromadb", CORE, True, "pip install chromadb (vector retrieval; lexical fallback exists)"),
    ("dotenv", CORE, True, "pip install python-dotenv"),
    ("pytest", DEV, True, "pip install pytest (the suite also runs under unittest)"),
    ("yt_dlp", DEV, True, "pip install yt-dlp (only for video ingestion)"),
]

WRITABLE_DIRS = ["data", "data/traces", "data/workspaces", "data/replays"]


def _binary(name: str) -> Tuple[bool, str]:
    path = shutil.which(name)
    return (bool(path), path or "not on PATH")


def _package(name: str) -> Tuple[bool, str]:
    """Import-check without importing: cheap, and avoids heavy side effects."""
    import importlib.util

    try:
        spec = importlib.util.find_spec(name)
    except (ImportError, ValueError):
        return False, "not importable"
    if spec is None:
        return False, "not installed"
    return True, getattr(spec, "origin", "") or "installed"


def hardware() -> Dict[str, Any]:
    """
    Machine facts relevant to model choice.

    Reuses the detection in `agent.model_profile` when available so there is
    one answer to "how much VRAM is there", not two that disagree.
    """
    info: Dict[str, Any] = {
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count() or 1,
    }
    try:
        from agent.model_profile import detect_hardware

        detected = detect_hardware()
        info.update(detected if isinstance(detected, dict) else detected.to_dict())
    except Exception:
        try:
            with open("/proc/meminfo", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("MemTotal"):
                        info["ram_gb"] = round(int(line.split()[1]) / 1024 / 1024, 1)
                        break
        except Exception:
            pass
    return info


def probe(include_model: bool = True) -> List[Check]:
    """Run every check. Never raises: a broken probe is itself a finding."""
    checks: List[Check] = []

    version_ok = sys.version_info >= (3, 10)
    checks.append(Check(
        name=f"python {platform.python_version()}",
        tier=CORE, ok=version_ok, optional=False,
        detail=sys.executable,
        remedy="" if version_ok else "this project needs Python 3.10 or newer",
    ))

    for name, tier, optional, remedy in PACKAGES:
        ok, detail = _package(name)
        checks.append(Check(name=f"python package: {name}", tier=tier, ok=ok,
                            detail=detail, optional=optional,
                            remedy="" if ok else remedy))

    for name, tier, categories, remedy in BINARIES:
        ok, detail = _binary(name)
        checks.append(Check(name=name, tier=tier, ok=ok, detail=detail,
                            optional=True, categories=categories,
                            remedy="" if ok else remedy))

    for directory in WRITABLE_DIRS:
        path = Path(directory)
        try:
            path.mkdir(parents=True, exist_ok=True)
            probe_file = path / ".doctor"
            probe_file.write_text("ok", encoding="utf-8")
            probe_file.unlink()
            ok, detail = True, "writable"
        except Exception as exc:
            ok, detail = False, str(exc)[:120]
        checks.append(Check(name=f"writable: {directory}", tier=CORE, ok=ok,
                            detail=detail, optional=False,
                            remedy="" if ok else "check filesystem permissions"))

    info = hardware()
    vram = float(info.get("vram_gb") or 0)
    ram = float(info.get("ram_gb") or 0)
    checks.append(Check(
        name="GPU acceleration", tier=GPU, ok=vram > 0,
        detail=f"{vram:.1f} GB VRAM" if vram else "no GPU detected — CPU inference",
        optional=True,
        remedy="" if vram else "CPU-only works; expect slower inference and prefer Q4 models",
    ))
    checks.append(Check(
        name="system RAM", tier=CORE, ok=(ram == 0 or ram >= 8),
        detail=f"{ram:.1f} GB" if ram else "unknown",
        optional=True,
        remedy="" if (ram == 0 or ram >= 8) else "8 GB+ recommended for a 7-8B local model",
    ))

    if include_model:
        checks.append(_model_check())
    return checks


def _model_check(timeout: float = 1.5) -> Check:
    """
    Whether a local model is actually reachable.

    Reported separately from the ollama binary: an installed backend with no
    model pulled is the most common cause of "the agent does nothing", and
    the two states deserve different advice. The timeout is deliberately
    short — `doctor` must stay fast enough to run before every session.
    """
    try:
        import requests

        from llm_client import OLLAMA_BASE_URL, DEFAULT_MODEL

        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=timeout)
        response.raise_for_status()
        names = [str(m.get("name", "")) for m in (response.json().get("models") or [])]
        if not names:
            return Check(name="local model", tier=MODEL, ok=False,
                         detail=f"backend reachable at {OLLAMA_BASE_URL}, no models pulled",
                         remedy=f"run: ollama pull {DEFAULT_MODEL}")
        configured = any(DEFAULT_MODEL.split(":")[0] in n for n in names)
        return Check(
            name="local model", tier=MODEL, ok=configured,
            detail=f"{len(names)} available: {', '.join(names[:3])}",
            remedy="" if configured else
                   f"configured model {DEFAULT_MODEL} is not among them — "
                   f"pull it or change OLLAMA_MODEL in .env",
        )
    except Exception as exc:
        reachable, _ = _binary("ollama")
        return Check(
            name="local model", tier=MODEL, ok=False,
            detail=f"backend not reachable ({str(exc)[:70]})",
            remedy=("start the backend: ollama serve" if reachable
                    else "install Ollama, or set an OpenAI-compatible endpoint in .env"),
        )


def degraded_categories(checks: Sequence[Check]) -> Dict[str, List[str]]:
    """
    Which challenge categories are weakened, and by what.

    This is the translation that makes the report useful: a user does not
    need to know that `tshark` is missing, they need to know that pcap
    challenges will not work until it is there.
    """
    out: Dict[str, List[str]] = {}
    for check in checks:
        if check.ok:
            continue
        for category in check.categories:
            out.setdefault(category, []).append(check.name)
    return out


def summary(checks: Sequence[Check]) -> Dict[str, Any]:
    blocking = [c for c in checks if not c.ok and not c.optional]
    missing = [c for c in checks if not c.ok and c.optional]
    return {
        "checks": len(checks),
        "passed": len([c for c in checks if c.ok]),
        "blocking": [c.name for c in blocking],
        "missing_optional": [c.name for c in missing],
        "degraded_categories": degraded_categories(checks),
        "usable": not blocking,
        "hardware": hardware(),
    }


def render_report(checks: Optional[Sequence[Check]] = None) -> str:
    """The `ctf-tutor doctor` output."""
    checks = list(checks if checks is not None else probe())
    info = hardware()
    lines = [
        "CTF-Tutor environment report",
        f"  {info.get('os')} {info.get('release')} · {info.get('machine')} · "
        f"Python {info.get('python')} · {info.get('cpu_count')} CPU",
        "",
    ]
    tier_titles = [
        (CORE, "Core (required)"),
        (MODEL, "Model backend"),
        (ANALYSIS, "Analysis tooling (per category)"),
        (GPU, "Acceleration"),
        (DEV, "Development"),
    ]
    for tier, title in tier_titles:
        tier_checks = [c for c in checks if c.tier == tier]
        if not tier_checks:
            continue
        lines.append(title)
        for check in tier_checks:
            line = f"  {check.symbol} {check.name}"
            if check.detail:
                line += f" — {check.detail}"
            lines.append(line)
            if not check.ok and check.remedy:
                lines.append(f"      → {check.remedy}")
        lines.append("")

    degraded = degraded_categories(checks)
    if degraded:
        lines.append("Degraded categories")
        for category, missing in sorted(degraded.items()):
            lines.append(f"  {category}: missing {', '.join(missing)}")
        lines.append("")

    blocking = [c for c in checks if not c.ok and not c.optional]
    if blocking:
        lines.append("BLOCKING: " + ", ".join(c.name for c in blocking))
    else:
        lines.append("No blocking problems. Optional tools only affect the "
                     "categories listed above.")
    return "\n".join(lines)
