"""Capability-aware planning: what the agent can vs cannot reliably do."""

from __future__ import annotations

from typing import Any, Dict, List

from agent.environment_snapshot import environment_snapshot


# Declared competence (honest ceilings)
CAN = [
    "ELF inspection (file/strings/checksec)",
    "static strings/imports",
    "controlled local execution",
    "crash observation (when binary provided)",
    "ROP-oriented reasoning / stage checklist",
    "HTTP analysis of approved targets only",
    "heuristic + optional LLM classification",
    "flag format / decoy verification",
]

CANNOT = [
    "general autonomous heap exploitation",
    "custom VM bytecode recovery",
    "advanced symbolic execution",
    "reliable anti-debug / unpacking automation",
    "unscoped internet scanning",
]


def capability_snapshot(env: Dict[str, Any] | None = None) -> Dict[str, Any]:
    env = env or environment_snapshot()
    available = {
        "gdb": bool(env.get("gdb")),
        "pwntools": bool(env.get("pwntools")),
        "docker": bool(env.get("docker")),
        "ghidra": bool(env.get("ghidra")),
        "checksec": bool(env.get("checksec")),
    }
    missing_tools = [k for k, v in available.items() if not v]
    return {
        "can": CAN,
        "cannot": CANNOT,
        "tools": available,
        "missing_tools": missing_tools,
        "honest_limit": (
            "Do not claim solve/RIP control/leak without corresponding evidence."
        ),
    }


def plan_for_category(category: str, env: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Return category workflow + capability gate."""
    category = (category or "misc").lower()
    env = env or environment_snapshot()
    cap = capability_snapshot(env)
    actions: List[str] = []
    stage = "triage"

    if category == "pwn":
        from agent.pwn_exploit_loop import initial_pwn_plan, next_pwn_actions

        plan = initial_pwn_plan(env)
        stage = plan.stage
        actions = next_pwn_actions(plan)
        if not env.get("gdb") and not env.get("pwntools"):
            actions = [
                "Limited tooling: static analysis only until gdb/pwntools available"
            ] + actions[:2]
    elif category == "rev":
        from agent.rev_dynamic_loop import RevPlan, next_rev_actions

        rp = RevPlan()
        stage = rp.stage
        actions = next_rev_actions(rp)
    elif category == "web":
        actions = [
            "Passive: review endpoints/cookies/templates",
            "Active only after approve_target() for lab host",
            "Do not scan arbitrary internet hosts",
        ]
        stage = "web_passive_or_approved"
    else:
        actions = ["Triage artifacts", "Prefer observation over guessing"]

    return {
        "category": category,
        "stage": stage,
        "next_actions": actions[:5],
        "capabilities": cap,
        "status_phrase": (
            f"Category hypothesis: {category}. Stage: {stage}. "
            f"Do not claim completion past established evidence."
        ),
    }
