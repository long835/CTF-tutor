"""Pick next practice item from spaced repetition + weak techniques."""

from __future__ import annotations

from typing import Any, Dict, List


def next_practice(limit: int = 5) -> Dict[str, Any]:
    due: List[Dict[str, Any]] = []
    try:
        from agent.spaced_repetition import load_store, schedule_from_learner
        due = schedule_from_learner(limit=limit)
    except Exception:
        due = []

    weak: List[str] = []
    try:
        from agent.memory import load_memory
        weak = load_memory().weak_techniques()[:limit]
    except Exception:
        pass

    labs = []
    try:
        from agent.experience_labs import list_labs
        for lab in list_labs():
            for tech in lab.techniques:
                if any(d.get("technique") == tech for d in due) or tech in weak:
                    labs.append({"lab_id": lab.id, "technique": tech, "category": lab.category})
                    break
    except Exception:
        pass

    return {
        "due_reviews": due[:limit],
        "weak_techniques": weak[:limit],
        "suggested_labs": labs[:limit],
        "hint": "Use: python main.py agent --lab <lab_id> or python main.py review --record <technique>",
    }
