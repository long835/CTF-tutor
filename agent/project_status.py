"""Project status snapshot — single source of truth for docs/CI (item: doc drift)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]


def _learner_summary() -> Dict[str, Any]:
    try:
        from agent.learner_view import summary
        return summary(limit=5)
    except Exception as e:
        return {"error": str(e)}


def _experience_labs() -> Dict[str, Any]:
    man = ROOT / "data" / "samples" / "experience" / "manifest.json"
    if not man.is_file():
        return {"count": 0, "items": []}
    try:
        data = json.loads(man.read_text(encoding="utf-8"))
        items = data.get("items") or []
        return {"count": len(items), "ids": [i.get("id") for i in items]}
    except Exception as e:
        return {"error": str(e)}


def project_status() -> Dict[str, Any]:

    from agent.evidence import REQUIREMENTS
    from agent.tool_capabilities import uncovered_signals
    from agent.app_config import get_config

    lib_path = ROOT / "data" / "technique_library.json"
    techniques = 0
    if lib_path.exists():
        data = json.loads(lib_path.read_text(encoding="utf-8"))
        techniques = len(data.get("techniques") or data) if isinstance(data, dict) else len(data)

    corpus_path = ROOT / "data" / "corpus" / "challenges.jsonl"
    corpus_n = 0
    by_prov: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    if corpus_path.exists():
        with corpus_path.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                corpus_n += 1
                row = json.loads(line)
                p = row.get("provenance") or "unknown"
                k = row.get("kind") or "unknown"
                by_prov[p] = by_prov.get(p, 0) + 1
                by_kind[k] = by_kind.get(k, 0) + 1

    archive_n = len(list((ROOT / "data" / "archive").glob("*.json"))) if (ROOT / "data" / "archive").is_dir() else 0

    eval_counts = {}
    for name in ("ground_truth", "independent_public_style", "public_contest_grounded", "adversarial"):
        p = ROOT / "data" / "eval" / f"{name}.json"
        if p.exists():
            try:
                eval_counts[name] = len(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                eval_counts[name] = -1

    cfg = get_config()
    return {
        "version": "0.4.2",
        "techniques_library": techniques,
        "evidence_rubrics": len(REQUIREMENTS),
        "uncovered_signals": uncovered_signals(),
        "corpus_cards": corpus_n,
        "corpus_by_provenance": by_prov,
        "corpus_by_kind": by_kind,
        "archive_entries": archive_n,
        "eval_sets": eval_counts,
        "model": cfg.ollama_model,
        "embed_backend": cfg.embed_backend,
        "network_enabled": cfg.network_enabled,
        "api": f"{cfg.api_host}:{cfg.api_port}",
        "learner": _learner_summary(),
        "phase": "6.5-integration",
        "experience_labs": _experience_labs(),
    }


def format_status(s: Dict[str, Any] | None = None) -> str:
    s = s or project_status()
    lines = [
        f"CTF-Tutor {s['version']}",
        f"  techniques: {s['techniques_library']}  rubrics: {s['evidence_rubrics']}",
        f"  uncovered_signals: {s['uncovered_signals']}",
        f"  corpus: {s['corpus_cards']}  by_provenance={s['corpus_by_provenance']}",
        f"  archive: {s['archive_entries']}",
        f"  eval: {s['eval_sets']}",
        f"  model: {s['model']}  embed: {s['embed_backend']}  network: {s['network_enabled']}",
        f"  api: {s['api']}",
        f"  experience_labs: {s.get('experience_labs', {})}",
    ]
    return "\n".join(lines)
