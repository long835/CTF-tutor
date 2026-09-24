"""
agent/cost_router.py — cost-aware model routing (item 49).

Chooses which provider/model to use for a task based on:
  - task kind (classify, plan, teach, embed, vision, verify)
  - model tier / capabilities from ModelProfile
  - estimated token cost and local-first preference

Default policy: prefer local Ollama; escalate only when the task needs
capabilities the local model lacks (vision, large context, structured JSON).
No paid API is required for core operation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

from agent.model_profile import ModelProfile, ModelTier, get_profile


class TaskKind(str, Enum):
    CLASSIFY = "classify"       # short, deterministic-leaning
    PLAN = "plan"               # multi-step plan JSON
    TEACH = "teach"             # Socratic explanation
    DECOMPOSE = "decompose"     # technique breakdown
    EMBED = "embed"
    VISION = "vision"
    VERIFY = "verify"           # grade evidence
    RESEARCH = "research"       # longer retrieval synthesis


# Rough relative cost units (local GPU/CPU time, not USD).
_COST_UNITS: Dict[TaskKind, float] = {
    TaskKind.CLASSIFY: 0.2,
    TaskKind.VERIFY: 0.3,
    TaskKind.DECOMPOSE: 0.6,
    TaskKind.PLAN: 0.8,
    TaskKind.TEACH: 1.0,
    TaskKind.RESEARCH: 1.5,
    TaskKind.EMBED: 0.4,
    TaskKind.VISION: 2.0,
}


@dataclass
class RouteDecision:
    task: str
    provider: str
    model: str
    tier: str
    estimated_cost: float
    reason: str
    use_llm: bool = True
    fallback: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RouterConfig:
    """Environment-driven policy."""
    prefer_local: bool = True
    max_cost_per_task: float = 5.0
    allow_frontier: bool = False
    default_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen3:8b"))
    vision_model: str = field(default_factory=lambda: os.getenv("OLLAMA_VISION_MODEL", "llava"))
    embed_model: str = field(default_factory=lambda: os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"))
    frontier_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", ""))

    @classmethod
    def from_env(cls) -> "RouterConfig":
        return cls(
            prefer_local=os.getenv("CTF_TUTOR_PREFER_LOCAL", "1").lower() not in ("0", "false", "no"),
            max_cost_per_task=float(os.getenv("CTF_TUTOR_MAX_COST", "5.0")),
            allow_frontier=os.getenv("CTF_TUTOR_ALLOW_FRONTIER", "0").lower() in ("1", "true", "yes"),
        )


def route_task(
    task: TaskKind | str,
    *,
    profile: Optional[ModelProfile] = None,
    config: Optional[RouterConfig] = None,
    force_model: Optional[str] = None,
) -> RouteDecision:
    """
    Select provider/model for a task.

    Classification and many triage steps can run without an LLM at all
    (heuristic path) — the router reports that as use_llm=False.
    """
    config = config or RouterConfig.from_env()
    kind = TaskKind(task) if not isinstance(task, TaskKind) else task
    profile = profile or get_profile(force_model or config.default_model)
    base_cost = _COST_UNITS.get(kind, 1.0)

    # Heuristic-only tasks: classification is already strong offline.
    if kind == TaskKind.CLASSIFY and os.getenv("CTF_TUTOR_LLM_CLASSIFY", "").lower() not in ("1", "true"):
        return RouteDecision(
            task=kind.value,
            provider="heuristic",
            model="classify_challenge",
            tier="n/a",
            estimated_cost=0.0,
            reason="formal classifier is offline and preferred for classify",
            use_llm=False,
        )

    if kind == TaskKind.VISION:
        model = force_model or config.vision_model
        return RouteDecision(
            task=kind.value,
            provider="ollama",
            model=model,
            tier=get_profile(model).tier.value,
            estimated_cost=base_cost,
            reason="vision requires a multimodal model",
            use_llm=True,
            fallback="forensic_hints_only",
        )

    if kind == TaskKind.EMBED:
        return RouteDecision(
            task=kind.value,
            provider="ollama",
            model=config.embed_model,
            tier="embed",
            estimated_cost=base_cost,
            reason="embedding model",
            use_llm=True,
        )

    # Escalate to frontier only when allowed and local tier is too small for the task.
    needs_headroom = kind in (TaskKind.RESEARCH, TaskKind.PLAN) and profile.tier.rank <= ModelTier.TINY.rank
    if needs_headroom and config.allow_frontier and config.frontier_model:
        return RouteDecision(
            task=kind.value,
            provider=os.getenv("LLM_PROVIDER", "openai_compatible"),
            model=config.frontier_model,
            tier=ModelTier.FRONTIER.value,
            estimated_cost=base_cost * 3.0,
            reason=f"local tier {profile.tier.value} too small for {kind.value}; frontier allowed",
            use_llm=True,
            fallback=config.default_model,
        )

    if base_cost > config.max_cost_per_task:
        return RouteDecision(
            task=kind.value,
            provider="local-skip",
            model=profile.name,
            tier=profile.tier.value,
            estimated_cost=base_cost,
            reason=f"estimated cost {base_cost} exceeds max {config.max_cost_per_task}",
            use_llm=False,
            fallback="deterministic_path",
        )

    return RouteDecision(
        task=kind.value,
        provider=profile.provider,
        model=force_model or profile.name,
        tier=profile.tier.value,
        estimated_cost=base_cost * (1.0 + 0.15 * profile.tier.rank),
        reason=f"local-first {profile.provider}/{profile.name} for {kind.value}",
        use_llm=True,
    )


def route_batch(tasks: List[TaskKind | str], **kwargs: Any) -> List[RouteDecision]:
    return [route_task(t, **kwargs) for t in tasks]
