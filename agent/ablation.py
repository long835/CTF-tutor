"""
agent/ablation.py

Compare agent variants:
  full | no_tools | no_retrieve | classify_only

Reports relative technique-hit and solve rates on ground_truth.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from agent.eval_agent import load_ground_truth


def _run_variant(case: dict, variant: str, max_steps: int = 3) -> Dict[str, Any]:
    from agent.loop import AgentLoop
    from agent.state import new_challenge_state
    from agent.hypothesis import generate_initial_hypotheses
    from classifier import classify_heuristic

    desc = case["description"]
    expected_techs = set(case.get("expected_techniques") or [])

    if variant == "classify_only":
        cat, _ = classify_heuristic(desc)
        # offline seeds only
        state = new_challenge_state(desc, category=cat)
        generate_initial_hypotheses(state)
        found = {h.technique for h in state.hypotheses if h.technique}
        hit = bool(expected_techs & found) if expected_techs else False
        return {
            "category_ok": cat == case.get("expected_category"),
            "technique_hit": hit,
            "status": "seeded",
            "confidence": state.overall_confidence,
        }

    agent = AgentLoop(desc, max_steps=max_steps, enable_trace=False)
    if variant == "no_tools":
        # bootstrap only
        state = agent.bootstrap()
        found = {h.technique for h in state.hypotheses if h.technique}
        hit = bool(expected_techs & found) if expected_techs else False
        return {
            "category_ok": state.category == case.get("expected_category"),
            "technique_hit": hit,
            "status": state.status,
            "confidence": state.overall_confidence,
        }

    # full / no_retrieve — for no_retrieve we still run but retrieve returns empty via env
    if variant == "no_retrieve":
        import os
        os.environ["CTF_TUTOR_DISABLE_RETRIEVE"] = "1"
    try:
        state = agent.run(verify_at_end=True)
    finally:
        if variant == "no_retrieve":
            import os
            os.environ.pop("CTF_TUTOR_DISABLE_RETRIEVE", None)

    found = {h.technique for h in state.hypotheses if h.technique}
    for h in state.hypotheses:
        for t in expected_techs:
            if t.replace("-", " ") in (h.statement or "").lower().replace("-", " "):
                found.add(t)
    hit = bool(expected_techs & found) if expected_techs else False
    return {
        "category_ok": state.category == case.get("expected_category"),
        "technique_hit": hit,
        "status": state.status,
        "confidence": state.overall_confidence,
        "solved": state.status in ("solved", "verified"),
    }


def run_ablation(max_cases: int = 8, max_steps: int = 3) -> Dict[str, Any]:
    cases = load_ground_truth()[:max_cases]
    variants = ["full", "no_tools", "no_retrieve", "classify_only"]
    report: Dict[str, Any] = {"n": len(cases), "variants": {}}
    for v in variants:
        rows = [_run_variant(c, v, max_steps=max_steps) for c in cases]
        n = max(1, len(rows))
        report["variants"][v] = {
            "category_accuracy": sum(1 for r in rows if r["category_ok"]) / n,
            "technique_hit_rate": sum(1 for r in rows if r["technique_hit"]) / n,
            "solve_rate": sum(1 for r in rows if r.get("solved")) / n,
            "avg_confidence": sum(r["confidence"] for r in rows) / n,
        }
    return report


if __name__ == "__main__":
    print(json.dumps(run_ablation(), indent=2))
