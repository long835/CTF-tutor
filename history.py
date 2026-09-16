"""
history.py

A local, append-only log of past main.run() sessions -- what challenge was
worked on, what techniques it involved, what hint depth was reached. Two
things this unlocks:

- "Challenge history": list/replay what you worked on and when.
- "User learning progress": summarize() aggregates technique tags across
  every logged session, so you can see what you've practiced a lot vs.
  what's still thin -- a cheap, honest stand-in for real progress tracking
  without inventing a scoring system nobody asked for.

Stored as JSON Lines (one JSON object per line) at data/history.jsonl by
default -- append-only, trivially diffable, no DB dependency. Each line is
independent, so a corrupted/truncated last line (e.g. from a crash
mid-write) doesn't take down the rest of the log; log_reading tools should
skip bad lines rather than fail the whole read.
"""

import json
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from config import HISTORY_MAX_ENTRIES

DEFAULT_HISTORY_PATH = "data/history.jsonl"


@dataclass
class HistoryEntry:
    timestamp: str
    challenge_description: str
    category: Optional[str]
    depth: Optional[str]
    sub_problem_count: int
    techniques: List[str] = field(default_factory=list)
    hint_depth: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "challenge_description": self.challenge_description,
            "category": self.category,
            "depth": self.depth,
            "sub_problem_count": self.sub_problem_count,
            "techniques": self.techniques,
            "hint_depth": self.hint_depth,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HistoryEntry":
        return cls(
            timestamp=data["timestamp"],
            challenge_description=data["challenge_description"],
            category=data.get("category"),
            depth=data.get("depth"),
            sub_problem_count=data.get("sub_problem_count", 0),
            techniques=data.get("techniques", []),
            hint_depth=data.get("hint_depth"),
        )


def entry_from_run_result(
    challenge_description: str,
    result: dict,
    category: Optional[str] = None,
    depth: Optional[str] = None,
) -> HistoryEntry:
    """Build a HistoryEntry from a main.run() result dict, pulling the
    techniques every sub-problem was tagged with (deduplicated, order
    preserved) so summarize() has something to aggregate."""
    techniques: List[str] = []
    seen = set()
    for sp in result.get("sub_problems", []):
        for t in getattr(sp, "likely_techniques", None) or []:
            if t not in seen:
                seen.add(t)
                techniques.append(t)

    hint_levels = []
    for ladder in (result.get("hints_by_id") or {}).values():
        for hint in ladder or []:
            level = getattr(hint, "level", None)
            value = getattr(level, "value", level)
            if isinstance(value, int):
                hint_levels.append(value)
    return HistoryEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        challenge_description=challenge_description,
        category=category,
        depth=depth,
        sub_problem_count=len(result.get("sub_problems", [])),
        techniques=techniques,
        hint_depth=(sum(hint_levels) / len(hint_levels)) if hint_levels else None,
    )


def log_entry(entry: HistoryEntry, path: str = DEFAULT_HISTORY_PATH) -> None:
    """Append one entry and rotate older entries beyond the configured cap."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
    _rotate(path, HISTORY_MAX_ENTRIES)


def _rotate(path: str, max_entries: int) -> None:
    if max_entries < 1 or not os.path.exists(path):
        return
    # Keep recent entries verbatim; corrupted lines are discarded during the
    # rewrite so rotation also prevents a damaged tail from accumulating.
    entries = read_history(path)
    if len(entries) <= max_entries:
        return
    kept = entries[-max_entries:]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for item in kept:
            f.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")
    os.replace(tmp, path)


def read_history(path: str = DEFAULT_HISTORY_PATH, limit: Optional[int] = None) -> List[HistoryEntry]:
    """Read all logged sessions, oldest first. Skips lines that fail to
    parse (e.g. a truncated last line from a crash mid-write) rather than
    raising, so one bad line doesn't lose the rest of the log. `limit`
    returns just the most recent N entries."""
    if not os.path.exists(path):
        return []
    entries = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(HistoryEntry.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyError):
                continue
    if limit is not None:
        entries = entries[-limit:]
    return entries


def summarize(entries: List[HistoryEntry]) -> Dict[str, int]:
    """Count how often each technique tag shows up across a set of history
    entries -- the "learning progress" view: what you've practiced a lot vs.
    what's still thin. Returns a dict sorted most-practiced first."""
    counts = Counter()
    for entry in entries:
        counts.update(entry.techniques)
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


def avg_hint_depth_by_technique(entries: List[HistoryEntry]) -> Dict[str, float]:
    """Average recorded hint depth attributed to each tagged technique."""
    totals = {}
    counts = Counter()
    for entry in entries:
        if entry.hint_depth is None:
            continue
        for technique in entry.techniques:
            totals[technique] = totals.get(technique, 0.0) + float(entry.hint_depth)
            counts[technique] += 1
    return dict(sorted(
        ((technique, totals[technique] / counts[technique]) for technique in totals),
        key=lambda kv: kv[1],
    ))
