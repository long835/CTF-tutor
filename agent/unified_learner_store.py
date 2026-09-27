"""
Single on-disk learner store (P2).

File: data/learner_store.json

Shape:
{
  "version": 1,
  "attempts": [ ... learner_model.Attempt dicts ... ],
  "legacy_stats": { technique: {attempts, successes, hints_used, last_seen, notes} },
  "preferred_depth": "balanced",
  "misconceptions": []
}

agent.learner_view remains the public API. This module is the persistence
backend so memory.json and learner_attempts.json can be migrated in.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_PATH = os.path.join("data", "learner_store.json")


def load_store(path: str = DEFAULT_PATH) -> Dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        # migrate from legacy files if present
        store = {
            "version": 1,
            "attempts": [],
            "legacy_stats": {},
            "preferred_depth": "balanced",
            "misconceptions": [],
        }
        legacy_attempts = Path("data/learner_attempts.json")
        legacy_memory = Path("data/learner_memory.json")
        if legacy_attempts.is_file():
            try:
                data = json.loads(legacy_attempts.read_text(encoding="utf-8"))
                store["attempts"] = data.get("attempts") or []
            except Exception:
                pass
        if legacy_memory.is_file():
            try:
                data = json.loads(legacy_memory.read_text(encoding="utf-8"))
                store["legacy_stats"] = data.get("techniques") or {}
                store["preferred_depth"] = data.get("preferred_depth") or "balanced"
                store["misconceptions"] = data.get("misconceptions") or []
            except Exception:
                pass
        return store
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {
            "version": 1,
            "attempts": [],
            "legacy_stats": {},
            "preferred_depth": "balanced",
            "misconceptions": [],
        }


def save_store(store: Dict[str, Any], path: str = DEFAULT_PATH) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(store, indent=2), encoding="utf-8")
    # Keep legacy mirrors for old readers during transition
    try:
        Path("data/learner_attempts.json").write_text(
            json.dumps({"attempts": store.get("attempts") or []}, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass
    try:
        Path("data/learner_memory.json").write_text(
            json.dumps(
                {
                    "techniques": store.get("legacy_stats") or {},
                    "preferred_depth": store.get("preferred_depth") or "balanced",
                    "misconceptions": store.get("misconceptions") or [],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass


def record_attempt_unified(
    technique: str,
    *,
    success: bool,
    hint_level: int = 0,
    hints: int = 0,
    scenario: str = "",
    verified: bool = False,
) -> Dict[str, Any]:
    from datetime import datetime, timezone

    store = load_store()
    tech = technique.strip().lower()
    attempt = {
        "technique": tech,
        "success": bool(success),
        "hint_level": int(hint_level or hints or 0),
        "hints_requested": int(hints or hint_level or 0),
        "scenario": scenario or "",
        "difficulty": "medium",
        "verified": bool(verified),
        "steps_before_hint": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    store.setdefault("attempts", []).append(attempt)
    stats = store.setdefault("legacy_stats", {}).setdefault(
        tech,
        {"attempts": 0, "successes": 0, "hints_used": 0, "last_seen": "", "notes": []},
    )
    stats["attempts"] = int(stats.get("attempts") or 0) + 1
    if success:
        stats["successes"] = int(stats.get("successes") or 0) + 1
    stats["hints_used"] = int(stats.get("hints_used") or 0) + int(hints or hint_level or 0)
    stats["last_seen"] = attempt["timestamp"]
    save_store(store)
    return attempt
