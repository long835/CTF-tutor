"""Retrieval abstention: do not teach from weak retrieval hits."""

from __future__ import annotations

from typing import Any, Dict, List, Sequence


def should_abstain(hits: Sequence[Any], *, min_score: float = 0.25, min_hits: int = 1) -> Dict[str, Any]:
    """Return abstain decision for a list of retrieval hits with .score or dict score."""
    scores = []
    for h in hits or []:
        if isinstance(h, dict):
            scores.append(float(h.get("score") or h.get("relevance") or 0.0))
        else:
            scores.append(float(getattr(h, "score", 0.0) or 0.0))
    if not scores or len(scores) < min_hits:
        return {
            "abstain": True,
            "reason": "no retrieval hits",
            "max_score": 0.0,
            "action": "DO NOT teach from retrieved material; ask for artifact/context",
        }
    mx = max(scores)
    if mx < min_score:
        return {
            "abstain": True,
            "reason": f"max retrieval score {mx:.3f} < {min_score}",
            "max_score": mx,
            "action": "DO NOT teach from retrieved material; prefer local observation",
        }
    return {"abstain": False, "reason": "ok", "max_score": mx, "action": "retrieval usable with caution"}
