"""
agent/eval_agent.py

Lightweight offline evaluation of the agent loop against ground_truth.json.

Metrics:
  - category_accuracy
  - technique_hit_rate (any expected technique appears in hypotheses)
  - avg_confidence
  - avg_steps
  - status distribution

Does not require Ollama or chromadb (uses offline seeds + lexical retrieval).
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List


def load_ground_truth(path: str = "data/eval/ground_truth.json") -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_case(case: Dict[str, Any], max_steps: int = 4) -> Dict[str, Any]:
    from agent.loop import AgentLoop

    agent = AgentLoop(
        challenge_summary=case["description"],
        category=None,  # force agent to classify
        max_steps=max_steps,
        enable_trace=False,
    )
    state = agent.run(verify_at_end=True)

    expected_cat = case.get("expected_category")
    expected_techs = set(case.get("expected_techniques") or [])
    found_techs = {h.technique for h in state.hypotheses if h.technique}
    # also scan statements
    for h in state.hypotheses:
        for t in expected_techs:
            if t.replace("-", " ") in (h.statement or "").lower().replace("-", " "):
                found_techs.add(t)

    hit = bool(expected_techs & found_techs) if expected_techs else False
    cat_ok = (state.category == expected_cat) if expected_cat else False

    return {
        "id": case.get("id"),
        "difficulty": case.get("difficulty"),
        "expected_category": expected_cat,
        "got_category": state.category,
        "category_ok": cat_ok,
        "expected_techniques": sorted(expected_techs),
        "found_techniques": sorted(found_techs),
        "technique_hit": hit,
        "confidence": state.overall_confidence,
        "steps": state.step_count,
        "status": state.status,
    }


def run_eval(max_steps: int = 4) -> Dict[str, Any]:
    cases = load_ground_truth()
    results = [evaluate_case(c, max_steps=max_steps) for c in cases]
    n = max(1, len(results))
    summary = {
        "n": len(results),
        "category_accuracy": sum(1 for r in results if r["category_ok"]) / n,
        "technique_hit_rate": sum(1 for r in results if r["technique_hit"]) / n,
        "avg_confidence": sum(r["confidence"] for r in results) / n,
        "avg_steps": sum(r["steps"] for r in results) / n,
        "statuses": {},
        "difficulty_matrix": {},
        "results": results,
    }
    # difficulty × category hits from original cases
    try:
        cases_by_id = {c.get("id"): c for c in load_ground_truth()}
        matrix = {}
        for r in results:
            c = cases_by_id.get(r.get("id") or "", {})
            diff = c.get("difficulty") or "unknown"
            cat = c.get("expected_category") or "unknown"
            matrix.setdefault(diff, {})
            cell = matrix[diff].setdefault(cat, {"n": 0, "tech_hit": 0})
            cell["n"] += 1
            if r.get("technique_hit"):
                cell["tech_hit"] += 1
        summary["difficulty_matrix"] = {
            d: {cat: (v["tech_hit"] / v["n"] if v["n"] else 0) for cat, v in cats.items()}
            for d, cats in matrix.items()
        }
    except Exception:
        pass
    for r in results:
        summary["statuses"][r["status"]] = summary["statuses"].get(r["status"], 0) + 1
    return summary


if __name__ == "__main__":
    s = run_eval()
    print(json.dumps({k: v for k, v in s.items() if k != "results"}, indent=2))
    print("--- per case ---")
    for r in s["results"]:
        mark = "OK" if r["technique_hit"] else "MISS"
        print(f"[{mark}] {r['id']}: cat {r['got_category']} (exp {r['expected_category']}) "
              f"techs={r['found_techniques']} conf={r['confidence']:.2f}")
