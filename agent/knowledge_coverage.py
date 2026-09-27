"""Knowledge coverage: how well the local corpus supports a technique."""

from __future__ import annotations

from typing import Any, Dict, List


def knowledge_coverage(techniques: List[str] | None = None) -> Dict[str, Any]:
    """Return 0–1 coverage score from corpus/archive presence."""
    techniques = [t for t in (techniques or []) if t]
    if not techniques:
        return {"score": 0.0, "per_technique": {}, "note": "no techniques nominated"}

    corpus_hits = {t: 0 for t in techniques}
    try:
        from pathlib import Path
        import json
        path = Path("data/corpus/challenges.jsonl")
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                techs = row.get("techniques") or row.get("expected_techniques") or []
                for t in techniques:
                    if t in techs or t in str(row):
                        corpus_hits[t] += 1
    except Exception:
        pass

    # rubric presence
    rubric = {}
    try:
        from agent.evidence import REQUIREMENTS
        for t in techniques:
            rubric[t] = t in REQUIREMENTS
    except Exception:
        rubric = {t: False for t in techniques}

    per = {}
    scores = []
    for t in techniques:
        c = corpus_hits.get(t, 0)
        r = 1.0 if rubric.get(t) else 0.0
        s = min(1.0, 0.4 * r + 0.6 * min(1.0, c / 5.0))
        per[t] = {"corpus_hits": c, "has_rubric": bool(rubric.get(t)), "score": round(s, 3)}
        scores.append(s)
    overall = sum(scores) / len(scores) if scores else 0.0
    return {"score": round(overall, 3), "per_technique": per}


def attach_coverage_to_verification(verdict: Dict[str, Any], techniques: List[str]) -> Dict[str, Any]:
    cov = knowledge_coverage(techniques)
    out = dict(verdict or {})
    out["knowledge_coverage"] = cov["score"]
    out["knowledge_detail"] = cov["per_technique"]
    if cov["score"] < 0.25:
        out["verification_unknown"] = True
        out["note"] = (out.get("note") or "") + " Low knowledge coverage — do not treat as verified."
    return out
