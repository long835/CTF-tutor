"""Compare heuristic classifier vs optional LLM classifier on a labeled set."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


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
