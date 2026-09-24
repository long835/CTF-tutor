"""
agent/core_api.py — library-facing API (item 39 partial).

Stable functions the CLI, WebUI, or a future HTTP layer can call without
parsing argparse. No network server is started here; this is the core split.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional


def classify(description: str, artifacts: Optional[List[str]] = None) -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge
    profile = classify_challenge(description, artifacts=artifacts)
    return {
        "category": profile.category,
        "primary_category": getattr(profile, "primary_category", None) or profile.category,
        "secondary_categories": list(getattr(profile, "secondary_categories", None) or []),
        "confidence": profile.confidence,
        "belief_score": profile.confidence,  # alias: not a calibrated probability
        "runner_up": getattr(profile, "runner_up", None),
        "ambiguous": getattr(profile, "ambiguous", None),
        "scores": dict(getattr(profile, "scores", {}) or {}),
        "candidate_techniques": [
            {"technique": t, "score": s}
            for t, s in (getattr(profile, "candidate_techniques", None) or [])
        ],
        "signals": [
            {"name": s.name, "category": s.category, "weight": s.weight}
            for s in (getattr(profile, "signals", None) or [])
        ],
    }


def route(task: str, model: Optional[str] = None) -> Dict[str, Any]:
    from agent.cost_router import route_task
    from agent.model_profile import get_profile
    profile = get_profile(model) if model else None
    return route_task(task, profile=profile).to_dict()


def observe_images(path: str, use_model: bool = False, limit: int = 5) -> List[Dict[str, Any]]:
    from agent.vision import observe_path
    return [o.to_dict() for o in observe_path(path, use_model=use_model, limit=limit)]


def knowledge_health() -> Dict[str, Any]:
    from agent.evidence import REQUIREMENTS
    from agent.tool_capabilities import uncovered_signals
    import json
    root = Path(__file__).resolve().parents[1]
    lib = json.loads((root / "data" / "technique_library.json").read_text(encoding="utf-8"))
    n_tech = len(lib.get("techniques") or lib) if isinstance(lib, dict) else len(lib)
    return {
        "techniques": n_tech,
        "rubrics": len(REQUIREMENTS),
        "uncovered_signals": uncovered_signals(),
    }


def run_eval(which: str = "ground_truth") -> Dict[str, Any]:
    """which: ground_truth | independent | public"""
    import json
    from agent.classify_challenge import classify_challenge
    root = Path(__file__).resolve().parents[1]
    mapping = {
        "ground_truth": root / "data" / "eval" / "ground_truth.json",
        "independent": root / "data" / "eval" / "independent_public_style.json",
        "public": root / "data" / "eval" / "public_contest_grounded.json",
    }
    path = mapping.get(which) or mapping["ground_truth"]
    cases = json.loads(path.read_text(encoding="utf-8"))
    ok = 0
    rows = []
    for c in cases:
        pred = classify_challenge(c["description"]).category
        hit = pred == c["expected_category"]
        ok += int(hit)
        rows.append({"id": c["id"], "pred": pred, "exp": c["expected_category"], "ok": hit})
    return {
        "set": which,
        "n": len(cases),
        "ok": ok,
        "accuracy": ok / len(cases) if cases else 0.0,
        "results": rows,
    }


def tutor_triage(description: str, artifacts: Optional[List[str]] = None) -> Dict[str, Any]:
    """One-shot triage: classify + route + optional image observations."""
    result: Dict[str, Any] = {
        "classification": classify(description, artifacts=artifacts),
        "routing": {
            "classify": route("classify"),
            "plan": route("plan"),
            "teach": route("teach"),
        },
    }
    if artifacts:
        images = [a for a in artifacts if Path(a).suffix.lower() in {
            ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"
        }]
        if images:
            result["vision"] = observe_images(images[0], use_model=False, limit=3)
    return result


def cost_summary() -> Dict[str, Any]:
    from agent.cost_meters import ledger_summary
    return ledger_summary()


def supported_languages() -> List[str]:
    from multilang import SUPPORTED_LANGUAGES
    return list(SUPPORTED_LANGUAGES)


def verification_snapshot(
    *,
    has_hypothesis: bool = False,
    evidence_count: int = 0,
    tool_support: bool = False,
    reproduction_ok: bool = False,
    challenge_behavior_ok: bool = False,
    flag_verified: bool = False,
    contradictions: int = 0,
    belief_score: float = 0.0,
) -> Dict[str, Any]:
    from agent.verification_levels import assess_verification
    return assess_verification(
        has_hypothesis=has_hypothesis,
        evidence_count=evidence_count,
        tool_support=tool_support,
        reproduction_ok=reproduction_ok,
        challenge_behavior_ok=challenge_behavior_ok,
        flag_verified=flag_verified,
        contradictions=contradictions,
        belief_score=belief_score,
    ).to_dict()


def learner_summary(limit: int = 20) -> Dict[str, Any]:
    from agent.learner_view import summary
    return summary(limit=limit)


def technique_learner_view(technique: str) -> Dict[str, Any]:
    from agent.learner_view import unified_technique
    return unified_technique(technique).to_dict()


def record_learning(technique: str, **kwargs) -> Dict[str, Any]:
    from agent.learner_view import record_learning as _rec
    return _rec(technique, **kwargs)


def review_due(limit: int = 10) -> List[Dict[str, Any]]:
    from agent.learner_view import review_due as _rd
    return _rd(limit=limit)


def record_review(technique: str, result: str = "good") -> Dict[str, Any]:
    from agent.learner_view import record_review as _rr
    return _rr(technique, result=result)


def list_experience_labs() -> Dict[str, Any]:
    from agent.experience_labs import labs_summary
    return labs_summary()


def get_experience_lab(lab_id: str) -> Dict[str, Any]:
    from agent.experience_labs import get_lab
    lab = get_lab(lab_id)
    return lab.to_dict() if lab else {"error": f"unknown lab: {lab_id}"}


def classify_experience_lab(lab_id: str) -> Dict[str, Any]:
    from agent.experience_labs import classify_lab
    return classify_lab(lab_id)


def attach_experience_lab(lab_id: str, challenge_id: str | None = None) -> Dict[str, Any]:
    from agent.experience_labs import attach_lab_to_workspace
    return attach_lab_to_workspace(lab_id, challenge_id=challenge_id)
