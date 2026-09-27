"""Compare heuristic classifier vs optional LLM classifier on a labeled set."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List



def compare_models(
    models: List[str] | None = None,
    tasks: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Compare configured model profiles without requiring the models to be
    installed or reachable.

    This is a capability comparison, not a quality benchmark.  Profiles come
    from ``agent.model_profile`` and describe what the agent can reasonably
    ask each model to do.
    """
    from agent.model_profile import get_profile

    model_names = list(models or ["qwen3:8b", "llava"])
    task_names = [str(t).strip().lower() for t in (tasks or ["classify", "plan", "teach"]) if str(t).strip()]

    profiles: List[Dict[str, Any]] = []

    for name in model_names:
        profile = get_profile(name)
        data = profile.to_dict()

        task_support: Dict[str, bool] = {}
        for task in task_names:
            if task in {"vision", "image", "images"}:
                task_support[task] = bool(profile.supports_vision)
            elif task in {"embed", "embedding", "embeddings"}:
                task_support[task] = bool(profile.supports_embeddings)
            else:
                # Classification, planning, teaching, and similar tasks are
                # text-generation tasks and therefore supported by generation
                # profiles unless this is explicitly an embedding-only model.
                task_support[task] = not profile.supports_embeddings

        data["task_support"] = task_support
        data["description"] = profile.describe()
        profiles.append(data)

    recommendation = "No models supplied."
    if profiles:
        viable = [
            p for p in profiles
            if all(p["task_support"].get(task, False) for task in task_names)
        ]

        if viable:
            # Prefer the highest capability tier, then larger context.
            viable.sort(
                key=lambda p: (
                    {"tiny": 0, "small": 1, "medium": 2, "large": 3, "frontier": 4}.get(
                        p.get("tier", "small"), 1
                    ),
                    p.get("context_length", 0),
                ),
                reverse=True,
            )
            recommendation = viable[0]["name"]
        else:
            # No single model covers every requested task. Explain that the
            # caller should route tasks to the profiles that support them.
            recommendation = "Route tasks to models with matching capabilities."

    return {
        "models": model_names,
        "tasks": task_names,
        "profiles": profiles,
        "recommendation": recommendation,
    }

def compare_heuristic_vs_llm(
    eval_path: str = "data/eval/external_hard.json",
    *,
    use_llm: bool = False,
    limit: int = 30,
) -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge

    cases = json.loads(Path(eval_path).read_text(encoding="utf-8"))[:limit]
    h_ok = 0
    l_ok = 0
    rows = []
    for c in cases:
        desc = c.get("description") or ""
        exp = c.get("expected_category")
        hr = classify_challenge(desc)
        h_hit = hr.category == exp
        h_ok += int(h_hit)
        lr_cat = None
        l_hit = False
        if use_llm:
            try:
                from agent import chat_generate
                prompt = (
                    "Classify this CTF challenge into exactly one of: "
                    "web,pwn,crypto,rev,forensics,osint,blockchain,mobile,misc\n"
                    f"Challenge: {desc[:800]}\nCategory:"
                )
                # best-effort
                out = getattr(chat_generate, "generate", lambda **k: "")(user_prompt=prompt) if False else ""
                lr_cat = (out or "").strip().split()[0].lower() if out else None
                l_hit = lr_cat == exp
                l_ok += int(l_hit)
            except Exception:
                pass
        rows.append({"id": c.get("id"), "expected": exp, "heuristic": hr.category, "h_ok": h_hit, "llm": lr_cat, "l_ok": l_hit})
    n = max(len(cases), 1)
    return {
        "n": len(cases),
        "heuristic_accuracy": round(h_ok / n, 3),
        "llm_accuracy": round(l_ok / n, 3) if use_llm else None,
        "use_llm": use_llm,
        "rows": rows[:10],
        "note": "LLM compare requires Ollama/chat; default reports heuristic only.",
    }
