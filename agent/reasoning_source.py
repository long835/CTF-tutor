"""Tag which subsystem produced a claim (LLM vs heuristic vs tool vs retrieved)."""

from __future__ import annotations

from typing import Any, Dict


def tag(source: str, **meta: Any) -> Dict[str, Any]:
    source = (source or "unknown").lower()
    allowed = {"llm", "heuristic", "retrieved", "tool", "human", "verifier", "unknown"}
    if source not in allowed:
        source = "unknown"
    out = {"reasoning_source": source}
    out.update(meta)
    return out
