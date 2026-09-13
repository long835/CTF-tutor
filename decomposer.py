"""
decomposer.py

Takes a raw challenge (description text + optional file) and breaks it into
a list of SubProblem objects -- the way an experienced player would mentally
split up a challenge before diving in.

Runs entirely against a LOCAL model via Ollama (free, no API key, no cost).
Install Ollama from https://ollama.com, then:

    ollama pull qwen3:8b          # or devstral:24b / qwen3:14b if your
                                   # hardware can handle a bigger model

Ollama exposes an OpenAI-compatible-ish chat API at
http://localhost:11434/api/chat -- we hit it directly with `requests`
so there's no extra SDK dependency.
"""

from typing import List, Optional

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
            # keep prompt size sane -- truncate long tool output
            snippet = value if len(value) < 1500 else value[:1500] + "... [truncated]"
            parts.append(f"--- {key} ---\n{snippet}")
    return "\n".join(parts)


def decompose(
    challenge_description: str,
    category: Optional[str] = None,
    file_path: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> List[SubProblem]:
    """
    Main entry point. Optionally pass file_path to a challenge binary/pcap/etc.
    so real static-analysis evidence grounds the decomposition instead of the
    model guessing purely from the text prompt.
    """
    evidence = None
    if file_path:
        evidence = static_analysis.full_recon(file_path, category_hint=category)

    user_prompt = build_user_prompt(challenge_description, category, evidence)
    raw = call_ollama(DECOMPOSE_SYSTEM_PROMPT, user_prompt, model=model)
    items = extract_json_array(raw)

    sub_problems = []
    for item in items:
        techniques = [normalize_tag(t) for t in item.get("likely_techniques", [])]
        sub_problems.append(
            SubProblem(
                id=item.get("id", "unnamed"),
                description=item.get("description", ""),
                likely_techniques=techniques,
                evidence=item.get("evidence", ""),
            )
        )
    return sub_problems


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
