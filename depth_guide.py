"""
depth_guide.py

Tiered hint ladder for one SubProblem: name the technique -> explain the
approach -> suggest specific commands -> full walkthrough. The learner asks
for exactly as much depth as they want (get_hint for one level, or
get_hint_ladder for "give me everything up through level N").

Design principle (see README): every level still refuses to hand over an
actual flag. This tool never has the learner's live challenge instance, so
even the WALKTHROUGH tier gives the complete METHOD for the learner to run
against their own instance -- it can't produce their flag for them, and
wouldn't even if it could; the point is building the learner's own skill.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List

from concurrency import map_concurrent
from llm_client import call_ollama, extract_json_object, DEFAULT_MODEL


class HintLevel(IntEnum):
    NAME = 1          # just name the likely technique
    APPROACH = 2       # explain the general strategy
    COMMANDS = 3        # concrete tools/commands/payload shapes
    WALKTHROUGH = 4       # full step-by-step method (still no flag)


def level_from_str(s: str) -> HintLevel:
    """Parse a hint level from a case-insensitive, whitespace-tolerant string
    (e.g. as typed on a CLI)."""
    normalized = s.strip().lower()
    by_name = {level.name.lower(): level for level in HintLevel}
    if normalized not in by_name:
        valid = ", ".join(by_name.keys())
        raise ValueError(f"Unknown hint level '{s}'. Valid options: {valid}")
    return by_name[normalized]


HINT_SYSTEM_PROMPTS: Dict[HintLevel, str] = {
    HintLevel.NAME: (
        "You are a CTF tutor giving the SHALLOWEST possible hint for one "
        "sub-problem: just NAME the likely technique/vulnerability class, "
        "in a sentence or two. Do not explain how it works or how to "
        "exploit it yet -- just point at what to go research.\n\n"
        "Respond ONLY with a JSON object with keys: hint (string), "
        "cited_entries (array of past challenge names, if any grounded the naming)"
    ),
    HintLevel.APPROACH: (
        "You are a CTF tutor giving an APPROACH-level hint for one "
        "sub-problem: explain the general strategy -- what to look at, "
        "what to try, why it should work in principle -- without giving "
        "specific commands, payloads, or exact syntax yet.\n\n"
        "Respond ONLY with a JSON object with keys: hint (string), "
        "cited_entries (array of past challenge names that grounded this hint)"
    ),
    HintLevel.COMMANDS: (
        "You are a CTF tutor giving a COMMANDS-level hint for one "
        "sub-problem: suggest specific tools, commands, or payload shapes "
        "the learner could try, with enough concrete detail to actually "
        "attempt it. Briefly explain why each suggestion makes sense.\n\n"
        "Respond ONLY with a JSON object with keys: hint (string), "
        "cited_entries (array of past challenge names that grounded this hint)"
    ),
    HintLevel.WALKTHROUGH: (
        "You are a CTF tutor giving a FULL WALKTHROUGH-level hint for one "
        "sub-problem: walk the learner through the complete method, step by "
        "step, as deep as you can reason about it generically. You do NOT "
        "have the learner's live challenge instance, so you still cannot "
        "produce an actual flag -- give the complete approach, and the "
        "learner runs it against their own instance to get their own "
        "flag.\n\n"
        "Respond ONLY with a JSON object with keys: hint (string), "
        "cited_entries (array of past challenge names that grounded this hint)"
    ),
}


@dataclass
class Hint:
    sub_problem_id: str
    level: HintLevel
    text: str
    cited_entries: List[str] = field(default_factory=list)


def build_user_prompt(sub_problem, matches: list, level: HintLevel) -> str:
    parts = [
        f"Sub-problem [{sub_problem.id}]: {sub_problem.description}",
        f"Requested hint level: {level.name.lower()}",
    ]
    if getattr(sub_problem, "likely_techniques", None):
        parts.append(f"Likely techniques: {', '.join(sub_problem.likely_techniques)}")
    if getattr(sub_problem, "evidence", ""):
        parts.append(f"Evidence: {sub_problem.evidence}")

    if not matches:
        parts.append("No matching past challenges were found in the archive for this piece.")
    else:
        parts.append("Closest past-challenge matches:")
        for m in matches:
            parts.append(
                f"- {m.entry.challenge_name} ({m.entry.category}, "
                f"techniques: {', '.join(m.entry.techniques)}): {m.entry.explanation}"
            )
    return "\n".join(parts)


def get_hint(sub_problem, matches: list, level: HintLevel, model: str = DEFAULT_MODEL) -> Hint:
    system_prompt = HINT_SYSTEM_PROMPTS[level]
    user_prompt = build_user_prompt(sub_problem, matches, level)
    raw = call_ollama(system_prompt, user_prompt, model=model)

    try:
        parsed = extract_json_object(raw)
        text = parsed.get("hint") or raw.strip()
        cited_entries = parsed.get("cited_entries", [])
    except ValueError:
        text = raw.strip()
        cited_entries = []

    return Hint(sub_problem_id=sub_problem.id, level=level, text=text, cited_entries=cited_entries)


def get_hint_ladder(
    sub_problem,
    matches: list,
    up_to: HintLevel = HintLevel.WALKTHROUGH,
    model: str = DEFAULT_MODEL,
    max_workers: int = 4,
) -> List[Hint]:
    """Get every hint level from NAME up through (and including) `up_to`,
    concurrently (each level is an independent Ollama call), returned in
    level order regardless of which one finishes first."""
    levels = [level for level in HintLevel if level <= up_to]
    return map_concurrent(
        lambda level: get_hint(sub_problem, matches, level, model=model),
        levels,
        max_workers=max_workers,
    )
