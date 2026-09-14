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

DEFAULT_HISTORY_PATH = "data/history.jsonl"


@dataclass
class HistoryEntry:
    timestamp: str
    challenge_description: str
    category: Optional[str]
    depth: Optional[str]
    sub_problem_count: int
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "challenge_description": self.challenge_description,
            "category": self.category,
            "depth": self.depth,
            "sub_problem_count": self.sub_problem_count,
            "techniques": self.techniques,
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

    return HistoryEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        challenge_description=challenge_description,
        category=category,
        depth=depth,
        sub_problem_count=len(result.get("sub_problems", [])),
        techniques=techniques,
    )


def log_entry(entry: HistoryEntry, path: str = DEFAULT_HISTORY_PATH) -> None:
    """Append one entry to the history log, creating the file/directory if needed."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(entry.to_dict()) + "\n")


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
