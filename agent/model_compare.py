"""
agent/model_compare.py — model comparison harness (item 58).

Compares ModelProfiles and routing decisions across candidate models
without requiring them to be running. Optional live probe hits Ollama tags.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from agent.cost_router import TaskKind, route_task
from agent.model_profile import ModelProfile, get_profile


DEFAULT_MODELS = [
    os.getenv("OLLAMA_MODEL", "qwen3:8b"),
    "llama3.2:3b",
    "llava",
    "mistral",
]


def _profile_row(model: str) -> Dict[str, Any]:
    p = get_profile(model)
    return {
        "name": p.name,
        "provider": p.provider,
        "tier": p.tier.value,
        "context_length": p.context_length,
        "supports_vision": p.supports_vision,
        "supports_tool_calling": p.supports_tool_calling,
        "supports_structured_output": p.supports_structured_output,
        "max_plan_steps": p.max_plan_steps,
        "min_ram_gb": p.min_ram_gb,
        "notes": p.notes,
    }


def compare_models(
    models: Optional[List[str]] = None,
    tasks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    models = models or list(DEFAULT_MODELS)
    tasks = tasks or [t.value for t in TaskKind]
    profiles = [_profile_row(m) for m in models]
    routing = []
    for m in models:
        profile = get_profile(m)
        row = {"model": m, "tier": profile.tier.value, "decisions": {}}
        for t in tasks:
            try:
                d = route_task(t, profile=profile)
                row["decisions"][t] = d.to_dict()
            except Exception as e:
                row["decisions"][t] = {"error": str(e)}
        routing.append(row)
    return {
        "models": models,
        "profiles": profiles,
        "routing": routing,
        "recommendation": _recommend(profiles),
    }


def _recommend(profiles: List[Dict[str, Any]]) -> Dict[str, str]:
    """Pick simple defaults for common roles."""
    rec: Dict[str, str] = {}
    # smallest non-vision for classify/plan budget
    text_models = [p for p in profiles if not p.get("supports_vision")]
    vision_models = [p for p in profiles if p.get("supports_vision")]
    if text_models:
        # prefer small tier name containing qwen or default first
        rec["default_text"] = text_models[0]["name"]
        for p in text_models:
            if "qwen" in p["name"].lower():
                rec["default_text"] = p["name"]
                break
    if vision_models:
        rec["vision"] = vision_models[0]["name"]
    return rec


def live_ollama_tags() -> List[str]:
    try:
        import requests
        from llm_client import OLLAMA_BASE_URL
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if r.status_code != 200:
            return []
        return [m.get("name", "") for m in r.json().get("models", []) if m.get("name")]
    except Exception:
        return []
