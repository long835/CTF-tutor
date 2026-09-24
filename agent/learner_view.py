"""
Unified learner view (Phase 6.5).

Canonical *read* surface over:

  agent/memory.py         — TechniqueStats (attempts/successes/hints/mastery)
  agent/learner_model.py  — independence, transfer (LearnerRecord)

Curriculum/UI/status should use this module so "mastered" is not ambiguous.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TechniqueView:
    technique: str
    attempts: int = 0
    successes: int = 0
    hints_used: int = 0
    legacy_mastery: float = 0.0
    independence: Optional[float] = None
    transfer: Optional[bool] = None
    status: str = "unknown"  # unknown | developing | independent | transferred
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _status(indep: Optional[float], transfer: Optional[bool], mastery: float) -> str:
    if transfer is True and (indep or 0) >= 0.5:
        return "transferred"
    if indep is not None and indep >= 0.6:
        return "independent"
    if mastery >= 0.5 or (indep is not None and indep > 0):
        return "developing"
    if mastery > 0:
        return "developing"
    return "unknown"


def unified_technique(technique: str) -> TechniqueView:
    tech = (technique or "").strip().lower()
    view = TechniqueView(technique=tech)
    if not tech:
        return view

    try:
        from agent.memory import load_memory
        mem = load_memory()
        st = mem.techniques.get(tech)
        if st is None:
            for k, v in mem.techniques.items():
                if k.lower() == tech:
                    st = v
                    break
        if st:
            view.attempts = int(st.attempts)
            view.successes = int(st.successes)
            view.hints_used = int(st.hints_used)
            view.legacy_mastery = round(float(st.mastery), 3)
            view.notes.extend(list(st.notes or [])[:5])
    except Exception as e:
        view.notes.append(f"memory: {e}")

    try:
        from agent.learner_model import load_record
        record = load_record()
        ti = record.for_technique(tech)
        rate = ti.independent_solve_rate  # property
        view.independence = None if rate is None else round(float(rate), 3)
        view.transfer = ti.transfer  # property -> Optional[bool]
        if view.attempts == 0:
            view.attempts = int(ti.attempts)
        if view.successes == 0:
            view.successes = int(ti.successes)
    except Exception as e:
        view.notes.append(f"learner_model: {e}")

    view.status = _status(view.independence, view.transfer, view.legacy_mastery)
    return view


def summary(limit: int = 20) -> Dict[str, Any]:
    names = set()
    try:
        from agent.memory import load_memory
        names.update(load_memory().techniques.keys())
    except Exception:
        pass
    try:
        from agent.learner_model import load_record
        names.update(load_record().techniques())
    except Exception:
        pass

    views = [unified_technique(n) for n in sorted(names)[:limit]]
    by_status: Dict[str, int] = {}
    for v in views:
        by_status[v.status] = by_status.get(v.status, 0) + 1
    return {
        "techniques_tracked": len(names),
        "by_status": by_status,
        "sample": [v.to_dict() for v in views[:10]],
        "canonical": "learner_view.unified_technique",
        "stores": ["agent.memory.load_memory", "agent.learner_model.load_record"],
    }


def record_learning(
    technique: str,
    *,
    success: bool,
    hints: int = 0,
    hint_level: int = 0,
    scenario: str = "",
    verified: bool = False,
) -> dict:
    """
    Canonical write path: update *both* stores so status never diverges.

    Returns the unified TechniqueView after recording.
    """
    tech = (technique or "").strip().lower()
    if not tech:
        return unified_technique("").to_dict()

    try:
        from agent.memory import load_memory, save_memory
        mem = load_memory()
        mem.record_attempt(tech, success=success, hints=hints if hints else max(0, hint_level))
        save_memory(mem)
    except Exception:
        pass

    try:
        from agent.learner_model import load_record, save_record
        record = load_record()
        record.record_attempt(
            technique=tech,
            success=success,
            hint_level=hint_level or hints,
            scenario=scenario or "",
            verified=verified,
            hints_requested=hints,
        )
        save_record(record)
    except Exception:
        pass

    return unified_technique(tech).to_dict()


def review_due(limit: int = 10) -> List[Dict[str, Any]]:
    from agent.spaced_repetition import schedule_from_learner
    return schedule_from_learner(limit=limit)


def record_review(technique: str, result: str = "good") -> Dict[str, Any]:
    from agent.spaced_repetition import load_store, save_store
    store = load_store()
    card = store.review(technique, result=result)
    save_store(store)
    return card.to_dict()
