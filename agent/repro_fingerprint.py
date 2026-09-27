"""Environment + corpus fingerprint for reproducibility."""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
from typing import Any, Dict


def repro_fingerprint() -> Dict[str, Any]:
    from agent.environment_snapshot import environment_snapshot

    env = environment_snapshot()
    parts = []
    for rel in [
        "data/technique_library.json",
        "data/eval/external_hard.json",
        "pyproject.toml",
    ]:
        p = Path(rel)
        if p.is_file():
            parts.append(hashlib.sha256(p.read_bytes()).hexdigest()[:16])
    corpus = Path("data/corpus/challenges.jsonl")
    corpus_hash = None
    if corpus.is_file():
        h = hashlib.sha256()
        with corpus.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        corpus_hash = h.hexdigest()[:16]
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "env": env,
        "file_hashes": parts,
        "corpus_hash": corpus_hash,
        "project_version": _version(),
    }


def _version() -> str:
    try:
        import tomllib
        data = tomllib.loads(Path("pyproject.toml").read_text())
        return data.get("project", {}).get("version", "unknown")
    except Exception:
        return "unknown"
