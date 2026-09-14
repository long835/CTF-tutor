"""
explainer.py

Turns one SubProblem (plus whatever archive matches retriever.py found for
it) into a plain-language explanation of the underlying technique -- WHY it
works, not just its name. Grounded in the learner's own past solves when a
match exists ("this resembles X, here's why"); falls back to general
knowledge, clearly labeled as such, when the archive has nothing relevant.

Design principle (see README): explain and guide, never hand over a full
solution or exact exploit steps. Both system prompts below enforce that.
"""

from dataclasses import dataclass, field
from typing import Dict, List
import logging

from concurrency import map_concurrent
from llm_client import call_ollama, extract_json_object, DEFAULT_MODEL

logger = logging.getLogger(__name__)


EXPLAIN_SYSTEM_PROMPT_GROUNDED = """You are a CTF tutor explaining ONE piece \
of a decomposed challenge to a learner in plain language. You've been given \
past archive matches that resemble this piece -- ground your explanation in \
WHY the technique works, explicitly citing which past challenge(s) it \
resembles and why, so the learner builds a transferable mental model \
instead of just memorizing a label.

Do not include a flag, a full solution, or exact exploit steps -- explain \
the underlying concept and why it applies here.

Respond ONLY with a JSON object with keys:
explanation (string), cited_entries (array of the past challenge names
actually drawn on)
"""

EXPLAIN_SYSTEM_PROMPT_UNGROUNDED = """You are a CTF tutor explaining ONE \
piece of a decomposed challenge to a learner in plain language. No matching \
past challenges were found in their archive for this piece, so explain the \
underlying concept from general security knowledge instead -- be upfront \
that this isn't grounded in one of the learner's own past solves, since \
that's worth knowing when deciding how much to trust it.

Do not include a flag, a full solution, or exact exploit steps -- explain \
the underlying concept and why it applies here.

Respond ONLY with a JSON object with keys:
explanation (string), cited_entries (array, should be empty here)
"""


@dataclass
class Explanation:
    sub_problem_id: str
    text: str
    grounded: bool
    cited_entries: List[str] = field(default_factory=list)


def build_user_prompt(sub_problem, matches: list) -> str:
    parts = [f"Sub-problem [{sub_problem.id}]: {sub_problem.description}"]
    if getattr(sub_problem, "likely_techniques", None):
        parts.append(f"Likely techniques: {', '.join(sub_problem.likely_techniques)}")
    if getattr(sub_problem, "evidence", ""):
        parts.append(f"Evidence: {sub_problem.evidence}")

    if not matches:
        parts.append("\nNo matching past challenges were found in the archive for this piece.")
    else:
        parts.append("\nClosest past-challenge matches:")
        for m in matches:
            parts.append(
                f"- {m.entry.challenge_name} ({m.entry.category}, "
                f"techniques: {', '.join(m.entry.techniques)}): {m.entry.explanation}"
            )
    return "\n".join(parts)


def explain(sub_problem, matches: list, model: str = DEFAULT_MODEL) -> Explanation:
    grounded = bool(matches)
    system_prompt = EXPLAIN_SYSTEM_PROMPT_GROUNDED if grounded else EXPLAIN_SYSTEM_PROMPT_UNGROUNDED
    user_prompt = build_user_prompt(sub_problem, matches)
    raw = call_ollama(system_prompt, user_prompt, model=model)

    try:
        parsed = extract_json_object(raw)
        text = parsed.get("explanation") or raw.strip()
        cited_entries = parsed.get("cited_entries", [])
    except ValueError:
        logger.warning("explainer model returned invalid JSON for sub-problem %s", sub_problem.id)
        text = raw.strip()
        cited_entries = []

    return Explanation(
        sub_problem_id=sub_problem.id, text=text, grounded=grounded, cited_entries=cited_entries
    )


def explain_all(sub_problems, matches_by_id: Dict[str, list], model: str = DEFAULT_MODEL, max_workers: int = 4) -> List[Explanation]:
    """Explain every sub-problem, concurrently (each is an independent
    Ollama call -- see concurrency.py for why threads help here). Sub-
    problems missing from matches_by_id are treated as having no matches
    (ungrounded) rather than raising KeyError."""
    return map_concurrent(
        lambda sp: explain(sp, matches_by_id.get(sp.id, []), model=model),
        sub_problems,
        max_workers=max_workers,
    )
