"""
decomposer.py

Takes a raw challenge (description text + optional file) and breaks it into
a list of SubProblem objects.
"""

from typing import List, Optional

from config import EVIDENCE_CHAR_LIMIT
from schema import SubProblem, normalize_tag
from tools import static_analysis
from llm_client import call_ollama, extract_json_array, DEFAULT_MODEL


DECOMPOSE_SYSTEM_PROMPT = """You are a CTF tutor helping a learner understand \
a challenge -- NOT a solver that hands over flags. Your job right now is only \
to DECOMPOSE the challenge into distinct sub-problems, each representing a \
piece of the puzzle an experienced player would separately investigate.

For each sub-problem, output:
- a short id (lowercase-hyphenated slug)
- a plain-language description of what that piece is asking
- a list of likely technique tags (lowercase-hyphenated, e.g. "jwt-alg-confusion",
  "stack-buffer-overflow", "padding-oracle") -- your best guess, can be more
  than one and can be uncertain/multiple candidates
- the evidence in the challenge/recon output that points to this

Respond ONLY with a JSON array of objects with keys:
id, description, likely_techniques, evidence

Do not include a flag, a full solution, or step-by-step exploit instructions.
Sub-problem identification only.
"""

JSON_RETRY_REMINDER = (
    "Your previous reply was not a JSON array. Respond ONLY with a JSON array "
    "of objects with keys: id, description, likely_techniques, evidence. "
    "No markdown, no prose outside the array."
)


def truncate_evidence_blob(value: str, limit: int = EVIDENCE_CHAR_LIMIT) -> str:
    """Keep the head and tail of long recon output so a large binary/pcap
    does not lose the interesting ending just because the middle is huge."""
    if len(value) <= limit:
        return value
    marker = "\n... [middle truncated] ...\n"
    budget = limit - len(marker)
    head = budget // 2
    tail = budget - head
    return value[:head] + marker + value[-tail:]


def build_user_prompt(
    challenge_description: str,
    category: Optional[str] = None,
    evidence: Optional[dict] = None,
) -> str:
    parts = [f"Challenge description:\n{challenge_description}"]
    if category:
        parts.append(f"\nStated category: {category}")
    if evidence:
        parts.append("\nStatic analysis / recon evidence:")
        for key, value in evidence.items():
            snippet = truncate_evidence_blob(str(value))
            parts.append(f"--- {key} ---\n{snippet}")
    return "\n".join(parts)


def _items_from_model_output(raw: str) -> list:
    try:
        items = extract_json_array(raw)
    except (ValueError, TypeError):
        return []
    return items if isinstance(items, list) else []


def _subproblems_from_items(items: list) -> List[SubProblem]:
    sub_problems = []
    for item in items:
        if not isinstance(item, dict):
            continue
        techniques = []
        for t in item.get("likely_techniques", []) or []:
            try:
                techniques.append(normalize_tag(str(t)))
            except ValueError:
                continue
        sub_problems.append(
            SubProblem(
                id=item.get("id", "unnamed"),
                description=item.get("description", ""),
                likely_techniques=techniques,
                evidence=item.get("evidence", ""),
            )
        )
    return sub_problems


def decompose(
    challenge_description: str,
    category: Optional[str] = None,
    file_path: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    include_decompile: bool = False,
    target_url: Optional[str] = None,
    guided_recon: bool = False,
) -> List[SubProblem]:
    evidence = None
    if file_path or target_url:
        if guided_recon:
            evidence = static_analysis.guided_recon(
                file_path,
                category_hint=category,
                include_decompile=include_decompile,
                target_url=target_url,
                model=model,
                challenge_description=challenge_description,
            )
        else:
            evidence = static_analysis.full_recon(
                file_path,
                category_hint=category,
                include_decompile=include_decompile,
                target_url=target_url,
            )

    user_prompt = build_user_prompt(challenge_description, category, evidence)
    raw = call_ollama(DECOMPOSE_SYSTEM_PROMPT, user_prompt, model=model)
    items = _items_from_model_output(raw)
    if not items:
        retry_prompt = user_prompt + "\n\n" + JSON_RETRY_REMINDER
        raw = call_ollama(DECOMPOSE_SYSTEM_PROMPT, retry_prompt, model=model)
        items = _items_from_model_output(raw)

    return _subproblems_from_items(items)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python decomposer.py \"<challenge description>\" [file_path] [category]")
        sys.exit(1)

    desc = sys.argv[1]
    fpath = sys.argv[2] if len(sys.argv) > 2 else None
    cat = sys.argv[3] if len(sys.argv) > 3 else None

    results = decompose(desc, category=cat, file_path=fpath)
    for sp in results:
        print(f"\n[{sp.id}]")
        print(f"  description: {sp.description}")
        print(f"  likely techniques: {', '.join(sp.likely_techniques)}")
        print(f"  evidence: {sp.evidence}")
