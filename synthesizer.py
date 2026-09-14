"""
synthesizer.py

Looks across ALL of a challenge's sub-problems and their retrieved archive
matches (see retriever.py) to notice when a challenge combines techniques
from more than one distinct past challenge -- e.g. this challenge's auth
bypass looks like past-challenge-A and its SSRF looks like past-challenge-B,
suggesting the two combine into a chained approach.

Runs against a local model via Ollama, same as decomposer.py. Skips the LLM
call entirely when there isn't enough distinct evidence to synthesize
anything meaningful from (no matches at all, or every sub-problem's top
match is the same single past challenge) -- cheaper and more honest than
asking the model to force a connection out of nothing.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from schema import normalize_tag
from llm_client import call_ollama, extract_json_object, DEFAULT_MODEL


SYNTHESIZE_SYSTEM_PROMPT = """You are a CTF tutor cross-referencing a \
decomposed challenge against a learner's own archive of past solved \
challenges. You've been given several sub-problems, each with its closest \
archive match(es). Your job is to notice when a challenge combines \
techniques from more than one DISTINCT past challenge -- e.g. this \
challenge's auth bypass resembles past-challenge-A and its SSRF resembles \
past-challenge-B, so the two together suggest a chained approach the \
learner may not have considered.

If the sub-problems' matches don't actually suggest a meaningful \
combination (e.g. they all point at the same past challenge, or the \
connection is tenuous), say so honestly rather than forcing a connection \
that isn't there.

Do not include a flag, a full solution, or step-by-step exploit \
instructions -- cross-referencing only.

Respond ONLY with a JSON object with keys:
combined (bool), summary (string), contributing_matches (array of the past
challenge names that meaningfully contributed to this synthesis),
shared_techniques (array of technique tags that bridge the contributing
matches)
"""


@dataclass
class Synthesis:
    """Result of cross-referencing a challenge's sub-problems against the archive."""
    combined: bool
    summary: str
    contributing_matches: List[str] = field(default_factory=list)
    shared_techniques: List[str] = field(default_factory=list)


def _worth_synthesizing(sub_problems, matches_by_id: Dict[str, list]) -> bool:
    """
    Only worth calling the LLM if at least two DIFFERENT sub-problems have
    matches, AND those matches point at at least two DIFFERENT past
    challenges (by their top match). If every sub-problem's closest match is
    the same single archive entry, there's nothing to cross-reference --
    that's just one match, not a combination.
    """
    with_matches = [sp for sp in sub_problems if matches_by_id.get(sp.id)]
    if len(with_matches) < 2:
        return False
    top_entry_names = {matches_by_id[sp.id][0].entry.challenge_name for sp in with_matches}
    return len(top_entry_names) >= 2


def build_user_prompt(overall_description: str, sub_problems, matches_by_id: Dict[str, list]) -> str:
    parts = [f"Overall challenge:\n{overall_description}", "\nSub-problems and their closest archive matches:"]
    for sp in sub_problems:
        parts.append(f"\n[{sp.id}] {sp.description}")
        if sp.likely_techniques:
            parts.append(f"  likely techniques: {', '.join(sp.likely_techniques)}")
        matches = matches_by_id.get(sp.id, [])
        if not matches:
            parts.append("  No past-challenge matches found for this sub-problem.")
        else:
            for m in matches:
                parts.append(
                    f"  - {m.entry.challenge_name} ({m.entry.category}, "
                    f"techniques: {', '.join(m.entry.techniques)}): {m.entry.explanation}"
                )
    return "\n".join(parts)


def synthesize(
    overall_description: str,
    sub_problems,
    matches_by_id: Dict[str, list],
    model: str = DEFAULT_MODEL,
) -> Synthesis:
    if not _worth_synthesizing(sub_problems, matches_by_id):
        return Synthesis(
            combined=False,
            summary="Not enough distinct past-challenge matches to cross-reference yet.",
            contributing_matches=[],
            shared_techniques=[],
        )

    user_prompt = build_user_prompt(overall_description, sub_problems, matches_by_id)
    raw = call_ollama(SYNTHESIZE_SYSTEM_PROMPT, user_prompt, model=model)

    try:
        parsed = extract_json_object(raw)
    except ValueError:
        # small local models sometimes just answer in prose despite
        # instructions -- treat that as an honest non-combination rather
        # than crashing the whole pipeline over it
        return Synthesis(combined=False, summary=raw.strip(), contributing_matches=[], shared_techniques=[])

    return Synthesis(
        combined=bool(parsed.get("combined", False)),
        summary=parsed.get("summary", ""),
        contributing_matches=parsed.get("contributing_matches", []),
        shared_techniques=[normalize_tag(t) for t in parsed.get("shared_techniques", [])],
    )
