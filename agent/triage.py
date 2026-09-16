"""
agent/triage.py

Automatic challenge inventory before the agent starts reasoning.

Scans a directory or single path and produces a structured artifact graph
the rest of the agent can consume (no LLM required).
"""

from __future__ import annotations

import hashlib
import mimetypes
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# Extension → coarse type
_EXT_MAP = {
    ".elf": "binary", "": "binary",  # no ext often ELF on Linux CTFs
    ".bin": "binary", ".exe": "binary", ".dll": "binary", ".so": "binary",
    ".o": "binary", ".out": "binary",
    ".py": "source", ".c": "source", ".cpp": "source", ".cc": "source",
    ".h": "source", ".hpp": "source", ".java": "source", ".js": "source",
    ".ts": "source", ".go": "source", ".rs": "source", ".php": "source",
    ".rb": "source", ".pl": "source", ".sh": "source", ".asm": "source",
    ".s": "source", ".cs": "source",
    ".zip": "archive", ".gz": "archive", ".tar": "archive", ".tgz": "archive",
    ".bz2": "archive", ".7z": "archive", ".rar": "archive", ".xz": "archive",
    ".pcap": "network", ".pcapng": "network", ".cap": "network",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image", ".ico": "image",
    ".wav": "audio", ".mp3": "audio", ".ogg": "audio",
    ".pdf": "document", ".txt": "text", ".md": "text", ".log": "text",
    ".json": "text", ".xml": "text", ".csv": "text", ".yml": "text",
    ".yaml": "text", ".conf": "text", ".cfg": "text",
    ".db": "database", ".sqlite": "database", ".sql": "database",
    ".apk": "mobile", ".ipa": "mobile", ".dex": "mobile",
    ".wasm": "binary", ".class": "bytecode", ".jar": "archive",
    ".dockerfile": "config", ".env": "config",
}


@dataclass
class Artifact:
    path: str
    name: str
    size: int
    sha256: str
    kind: str  # binary|source|archive|network|image|text|...
    extension: str
    magic_hint: str = ""
    is_executable: bool = False
    interesting: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ChallengeInventory:
    root: str
    artifacts: List[Artifact] = field(default_factory=list)
    categories_hint: List[str] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    file_count: int = 0
    total_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "categories_hint": self.categories_hint,
            "recommended_tools": self.recommended_tools,
            "notes": self.notes,
            "artifacts": [a.to_dict() for a in self.artifacts],
        }

    def paths_of_kind(self, kind: str) -> List[str]:
        return [a.path for a in self.artifacts if a.kind == kind]

    def primary_binary(self) -> Optional[str]:
        bins = [a for a in self.artifacts if a.kind == "binary" and a.is_executable]
        if not bins:
            bins = [a for a in self.artifacts if a.kind == "binary"]
        if not bins:
            return None
        bins.sort(key=lambda a: -a.size)
        return bins[0].path

    def primary_source(self) -> Optional[str]:
        srcs = [a for a in self.artifacts if a.kind == "source"]
        if not srcs:
            return None
        # Prefer main-ish names
        for pref in ("main.py", "app.py", "server.py", "index.js", "Main.java"):
            for a in srcs:
                if a.name == pref:
                    return a.path
        srcs.sort(key=lambda a: -a.size)
        return srcs[0].path


def _sha256_file(path: Path, limit: int = 32 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            remaining = limit
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _magic_hint(path: Path) -> str:
    """Lightweight magic via first bytes (no external `file` dependency required)."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return ""
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"MZ"):
        return "PE"
    if head.startswith(b"\x89PNG"):
        return "PNG"
    if head.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if head.startswith(b"PK\x03\x04"):
        return "ZIP"
    if head.startswith(b"\x1f\x8b"):
        return "GZIP"
    if head[:4] == b"\xd4\xc3\xb2\xa1" or head[:4] == b"\xa1\xb2\xc3\xd4":
        return "PCAP"
    if head.startswith(b"%PDF"):
        return "PDF"
    if head.startswith(b"#!/"):
        return "script"
    return ""


def _classify_kind(path: Path, magic: str) -> str:
    ext = path.suffix.lower()
    if magic == "ELF" or magic == "PE":
        return "binary"
    if magic == "PCAP":
        return "network"
    if magic in ("PNG", "JPEG"):
        return "image"
    if magic == "ZIP":
        return "archive"
    if magic == "PDF":
        return "document"
    if ext in _EXT_MAP:
        return _EXT_MAP[ext]
    # shebang / text heuristic
    if magic == "script":
        return "source"
    return "unknown"


def _interesting_flags(path: Path, kind: str, magic: str) -> List[str]:
    flags = []
    name = path.name.lower()
    if magic:
        flags.append(f"magic:{magic}")
    if kind == "binary" and os.access(path, os.X_OK):
        flags.append("executable")
    if any(x in name for x in ("flag", "secret", "key", "password", "cred")):
        flags.append("name-suggests-secret")
    if kind == "source":
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")[:8000]
            for pat, label in (
                (r"\bjwt\b|eyJ[A-Za-z0-9_-]+\.", "jwt-like"),
                (r"\bgets\s*\(|\bstrcpy\s*\(", "unsafe-c-io"),
                (r"SELECT .+ FROM|UNION SELECT", "sql-pattern"),
                (r"eval\s*\(|exec\s*\(", "dynamic-exec"),
                (r"pickle\.loads|yaml\.load\(", "deserialization"),
                (r"flag\{|ctf\{|htb\{", "flag-string"),
            ):
                if re.search(pat, text, re.I):
                    flags.append(label)
        except OSError:
            pass
    return flags


def inventory_path(
    root: str,
    max_files: int = 200,
    max_file_bytes: int = 50 * 1024 * 1024,
) -> ChallengeInventory:
    """
    Walk a challenge directory (or single file) and build an inventory.
    Hard limits prevent archive-bomb / huge-tree blowups.
    """
    root_path = Path(root).resolve()
    inv = ChallengeInventory(root=str(root_path))

    if not root_path.exists():
        inv.notes.append(f"path does not exist: {root}")
        return inv

    files: List[Path] = []
    if root_path.is_file():
        files = [root_path]
    else:
        for dirpath, dirnames, filenames in os.walk(root_path):
            # skip hidden / venv-ish
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and d not in ("node_modules", "__pycache__", ".git")]
            for fn in filenames:
                if fn.startswith("."):
                    continue
                files.append(Path(dirpath) / fn)
                if len(files) >= max_files:
                    inv.notes.append(f"truncated after {max_files} files")
                    break
            if len(files) >= max_files:
                break

    for fp in files:
        try:
            size = fp.stat().st_size
        except OSError:
            continue
        if size > max_file_bytes:
            inv.notes.append(f"skipped oversized: {fp.name} ({size} bytes)")
            continue

        magic = _magic_hint(fp)
        kind = _classify_kind(fp, magic)
        art = Artifact(
            path=str(fp),
            name=fp.name,
            size=size,
            sha256=_sha256_file(fp),
            kind=kind,
            extension=fp.suffix.lower(),
            magic_hint=magic,
            is_executable=os.access(fp, os.X_OK) and kind == "binary",
            interesting=_interesting_flags(fp, kind, magic),
        )
        inv.artifacts.append(art)
        inv.total_bytes += size

    inv.file_count = len(inv.artifacts)
    inv.categories_hint = _infer_categories(inv)
    inv.recommended_tools = _recommend_tools(inv)
    return inv


def _infer_categories(inv: ChallengeInventory) -> List[str]:
    scores: Dict[str, int] = {}
    for a in inv.artifacts:
        if a.kind == "binary" or a.magic_hint in ("ELF", "PE"):
            scores["pwn"] = scores.get("pwn", 0) + 2
            scores["rev"] = scores.get("rev", 0) + 2
        if a.kind == "source":
            scores["web"] = scores.get("web", 0) + 1
            if any(x in a.interesting for x in ("jwt-like", "sql-pattern", "deserialization")):
                scores["web"] = scores.get("web", 0) + 3
            if "unsafe-c-io" in a.interesting:
                scores["pwn"] = scores.get("pwn", 0) + 3
        if a.kind == "network":
            scores["forensics"] = scores.get("forensics", 0) + 3
        if a.kind == "image":
            scores["forensics"] = scores.get("forensics", 0) + 1
            scores["misc"] = scores.get("misc", 0) + 1
        if a.kind == "archive":
            scores["misc"] = scores.get("misc", 0) + 1
            scores["forensics"] = scores.get("forensics", 0) + 1
        if a.kind == "mobile":
            scores["mobile"] = scores.get("mobile", 0) + 3
    ranked = sorted(scores.items(), key=lambda x: -x[1])
    return [c for c, s in ranked if s >= 2][:3]


def _recommend_tools(inv: ChallengeInventory) -> List[str]:
    tools: List[str] = []
    kinds = {a.kind for a in inv.artifacts}
    if "binary" in kinds:
        tools.extend(["static_analysis", "checksec", "strings", "ghidra_headless"])
    if "source" in kinds:
        tools.append("web_recon")
        tools.append("static_analysis")
    if "network" in kinds:
        tools.append("forensics_toolkit")
    if "image" in kinds or "archive" in kinds:
        tools.extend(["forensics_toolkit", "decode_toolkit"])
    if any("jwt" in " ".join(a.interesting) for a in inv.artifacts):
        tools.insert(0, "web_recon")
    # unique preserve order
    seen: Set[str] = set()
    out = []
    for t in tools:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def apply_inventory_to_state(state, inv: ChallengeInventory) -> None:
    """Push inventory facts into AgentState."""
    from agent.state import AgentState  # local import to avoid cycles
    assert isinstance(state, AgentState)

    state.discovered_artifacts = [a.path for a in inv.artifacts]
    state.add_fact(f"Inventory: {inv.file_count} files, {inv.total_bytes} bytes under {inv.root}")
    if inv.categories_hint:
        state.add_fact(f"Triage category hints: {', '.join(inv.categories_hint)}")
        if not state.category and inv.categories_hint:
            state.category = inv.categories_hint[0]
    if inv.recommended_tools:
        state.add_fact(f"Recommended tools: {', '.join(inv.recommended_tools)}")
    for a in inv.artifacts:
        if a.interesting:
            state.add_fact(f"Artifact {a.name}: {', '.join(a.interesting)}")
    for note in inv.notes:
        state.add_fact(f"Triage note: {note}")
