"""
agent/memory.py

Long-term learner memory (local JSON).

Tracks mastered / weak techniques, hint usage, and preferred depth
so the tutor can adapt explanations over sessions.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


DEFAULT_PATH = os.path.join("data", "learner_memory.json")


@dataclass
class TechniqueStats:
    attempts: int = 0
    successes: int = 0
    hints_used: int = 0
    last_seen: str = ""
    notes: List[str] = field(default_factory=list)

    @property
    def mastery(self) -> float:
        if self.attempts == 0:
            return 0.0
        base = self.successes / self.attempts
        # Heavy hint use penalizes mastery slightly
        penalty = min(0.3, 0.05 * self.hints_used)
        return max(0.0, min(1.0, base - penalty))


@dataclass
class LearnerMemory:
    techniques: Dict[str, TechniqueStats] = field(default_factory=dict)
    preferred_depth: str = "balanced"  # brief | balanced | deep
    total_sessions: int = 0
    last_session: str = ""
    misconceptions: List[str] = field(default_factory=list)

    def record_attempt(self, technique: str, success: bool, hints: int = 0) -> None:
        tech = technique.strip().lower()
        if not tech:
            return
        stats = self.techniques.setdefault(tech, TechniqueStats())
        stats.attempts += 1
        if success:
            stats.successes += 1
        stats.hints_used += max(0, hints)
        stats.last_seen = datetime.now(timezone.utc).isoformat()

    def weak_techniques(self, threshold: float = 0.45, min_attempts: int = 2) -> List[str]:
        out = []
        for name, st in self.techniques.items():
            if st.attempts >= min_attempts and st.mastery < threshold:
                out.append(name)
        return sorted(out, key=lambda n: self.techniques[n].mastery)

    def mastered_techniques(self, threshold: float = 0.75, min_attempts: int = 2) -> List[str]:
        return sorted(
            [
                n for n, st in self.techniques.items()
                if st.attempts >= min_attempts and st.mastery >= threshold
            ],
            key=lambda n: -self.techniques[n].mastery,
        )

    def add_misconception(self, text: str) -> None:
        text = text.strip()
        if text and text not in self.misconceptions:
            self.misconceptions.append(text)
            self.misconceptions = self.misconceptions[-50:]

    def to_dict(self) -> dict:
        return {
            "techniques": {k: asdict(v) for k, v in self.techniques.items()},
            "preferred_depth": self.preferred_depth,
            "total_sessions": self.total_sessions,
            "last_session": self.last_session,
            "misconceptions": self.misconceptions,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LearnerMemory":
        techs = {}
        for k, v in (data.get("techniques") or {}).items():
            techs[k] = TechniqueStats(**{kk: vv for kk, vv in v.items() if kk in TechniqueStats.__dataclass_fields__})
        return cls(
            techniques=techs,
            preferred_depth=data.get("preferred_depth", "balanced"),
            total_sessions=int(data.get("total_sessions") or 0),
            last_session=data.get("last_session") or "",
            misconceptions=list(data.get("misconceptions") or []),
        )


def load_memory(path: str = DEFAULT_PATH) -> LearnerMemory:
    p = Path(path)
    if not p.exists():
        return LearnerMemory()
    try:
        with open(p, "r", encoding="utf-8") as f:
            return LearnerMemory.from_dict(json.load(f))
    except (OSError, json.JSONDecodeError, TypeError):
        return LearnerMemory()


def save_memory(mem: LearnerMemory, path: str = DEFAULT_PATH) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    mem.last_session = datetime.now(timezone.utc).isoformat()
    mem.total_sessions += 1
    with open(p, "w", encoding="utf-8") as f:
        json.dump(mem.to_dict(), f, indent=2)
