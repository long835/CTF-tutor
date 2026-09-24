"""
Spaced repetition scheduling for technique review (Phase 6.5 / learning science).

Uses a simple SM-2-inspired interval on top of the unified learner view.
Does not replace independence/transfer — it only answers: "what to review next?"
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_PATH = os.path.join("data", "spaced_repetition.json")

# Interval schedule in days after successive successful reviews
INTERVALS_DAYS = [1, 3, 7, 14, 30, 60]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass
class ReviewCard:
    technique: str
    easiness: float = 2.5
    interval_days: int = 0
    repetitions: int = 0
    due_at: str = ""
    last_result: str = ""  # again | hard | good | easy
    last_reviewed: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReviewCard":
        return cls(**{k: v for k, v in (data or {}).items() if k in cls.__dataclass_fields__})


@dataclass
class ReviewStore:
    cards: Dict[str, ReviewCard] = field(default_factory=dict)

    def ensure(self, technique: str) -> ReviewCard:
        tech = technique.strip().lower()
        if tech not in self.cards:
            self.cards[tech] = ReviewCard(technique=tech, due_at=_now().isoformat())
        return self.cards[tech]

    def review(self, technique: str, result: str = "good") -> ReviewCard:
        """
        result: again | hard | good | easy
        """
        card = self.ensure(technique)
        result = (result or "good").lower()
        card.last_result = result
        card.last_reviewed = _now().isoformat()

        if result == "again":
            card.repetitions = 0
            card.interval_days = 0
            card.due_at = _now().isoformat()
            card.easiness = max(1.3, card.easiness - 0.2)
        else:
            if result == "hard":
                card.easiness = max(1.3, card.easiness - 0.15)
                mult = 1.2
            elif result == "easy":
                card.easiness = min(3.0, card.easiness + 0.15)
                mult = 1.3
            else:
                mult = 1.0

            idx = min(card.repetitions, len(INTERVALS_DAYS) - 1)
            base = INTERVALS_DAYS[idx]
            days = max(1, int(base * card.easiness / 2.5 * mult))
            card.interval_days = days
            card.repetitions += 1
            card.due_at = (_now() + timedelta(days=days)).isoformat()

        return card

    def due(self, limit: int = 20) -> List[ReviewCard]:
        now = _now()
        out: List[ReviewCard] = []
        for card in self.cards.values():
            due = _parse(card.due_at) or now
            if due <= now:
                out.append(card)
        out.sort(key=lambda c: c.due_at or "")
        return out[:limit]

    def to_dict(self) -> Dict[str, Any]:
        return {"cards": {k: v.to_dict() for k, v in self.cards.items()}}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReviewStore":
        cards = {
            k: ReviewCard.from_dict(v)
            for k, v in ((data or {}).get("cards") or {}).items()
        }
        return cls(cards=cards)


def load_store(path: str = DEFAULT_PATH) -> ReviewStore:
    p = Path(path)
    if not p.is_file():
        return ReviewStore()
    try:
        return ReviewStore.from_dict(json.loads(p.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return ReviewStore()


def save_store(store: ReviewStore, path: str = DEFAULT_PATH) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(store.to_dict(), indent=2), encoding="utf-8")


def schedule_from_learner(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Seed due cards from unified learner view: techniques with activity
    but not transferred are candidates for review.
    """
    store = load_store()
    try:
        from agent.learner_view import summary
        s = summary(limit=50)
        for row in s.get("sample") or []:
            tech = row.get("technique")
            if not tech:
                continue
            status = row.get("status") or "unknown"
            if status in ("developing", "independent", "unknown"):
                store.ensure(tech)
    except Exception:
        pass
    save_store(store)
    return [c.to_dict() for c in store.due(limit=limit)]
