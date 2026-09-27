"""Public entry: enhanced classify with optional LLM second opinion."""

from __future__ import annotations

from typing import Any, Optional


def classify_enhanced(
    description: str = "",
    artifacts=None,
    inventory=None,
    content_sample: str = "",
    **kwargs: Any,
) -> Any:
    try:
        from agent.ensemble import classify_enhanced as _ce
        return _ce(
            description,
            artifacts=artifacts,
            inventory=inventory,
            content_sample=content_sample,
            **kwargs,
        )
    except Exception:
        from agent.classify_challenge import classify_challenge
        return classify_challenge(
            description,
            artifacts=artifacts,
            inventory=inventory,
            content_sample=content_sample,
        )
