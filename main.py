"""
main.py

CLI entrypoint that wires the whole pipeline together:

    decomposer  -> break the challenge into sub-problems
    retriever   -> find similar past challenges per sub-problem
    synthesizer -> notice when sub-problems combine techniques from
                   different past challenges
    explainer   -> plain-language explanation per sub-problem
    depth_guide -> (optional) tiered hints per sub-problem, up to a
                   requested depth

If chromadb/Ollama-embeddings aren't set up yet (or this is running
somewhere that can't reach them, like a test sandbox), retrieval degrades
gracefully to "no matches" rather than crashing the whole run -- you still
get decomposition and ungrounded explanations.

Usage:
    python main.py "A login portal issues JWTs signed with RS256. \\
The admin panel trusts the role claim in the token." \\
        --category web --file ./challenge_files/app.js --depth approach
"""

import argparse
import sys
from typing import Dict, Optional

import decomposer
import synthesizer
import explainer
import depth_guide
from depth_guide import HintLevel, level_from_str
from retriever import Retriever
from llm_client import DEFAULT_MODEL


def run(
    challenge_description: str,
    category: Optional[str] = None,
    file_path: Optional[str] = None,
    retriever: Optional[Retriever] = None,
    depth: Optional[HintLevel] = None,
    model: str = DEFAULT_MODEL,
) -> dict:
    """
    Run the full pipeline and return a dict with keys:
    sub_problems, matches_by_id, synthesis, explanations, hints_by_id
    (hints_by_id is {} unless `depth` is given).
    """
    sub_problems = decomposer.decompose(
        challenge_description, category=category, file_path=file_path, model=model
    )

    if retriever is None:
        try:
            retriever = Retriever()
        except RuntimeError:
            # no chromadb / no embedding model set up -- degrade gracefully
            retriever = None

    if retriever is None:
        matches_by_id: Dict[str, list] = {sp.id: [] for sp in sub_problems}
    else:
        matches_by_id = {
            sp.id: retriever.query_sub_problem(sp, category=category) for sp in sub_problems
        }

    synthesis = synthesizer.synthesize(challenge_description, sub_problems, matches_by_id, model=model)
    explanations = explainer.explain_all(sub_problems, matches_by_id, model=model)

    hints_by_id: Dict[str, list] = {}
    if depth is not None:
        for sp in sub_problems:
            hints_by_id[sp.id] = depth_guide.get_hint_ladder(
                sp, matches_by_id.get(sp.id, []), up_to=depth, model=model
            )

    return {
        "sub_problems": sub_problems,
        "matches_by_id": matches_by_id,
        "synthesis": synthesis,
        "explanations": explanations,
        "hints_by_id": hints_by_id,
    }


def _print_report(result: dict) -> None:
    print("=== Sub-problems ===")
    for sp in result["sub_problems"]:
        print(f"\n[{sp.id}] {sp.description}")
        if sp.likely_techniques:
            print(f"  likely techniques: {', '.join(sp.likely_techniques)}")
        if sp.evidence:
            print(f"  evidence: {sp.evidence}")
        matches = result["matches_by_id"].get(sp.id, [])
        if matches:
            print("  closest archive matches:")
            for m in matches:
                print(f"    - {m.entry.challenge_name}  (score {m.score:.2f})")
        else:
            print("  no archive matches found")

    print("\n=== Cross-reference ===")
    synthesis = result["synthesis"]
    print(synthesis.summary)
    if synthesis.combined:
        if synthesis.contributing_matches:
            print(f"  drawing on: {', '.join(synthesis.contributing_matches)}")
        if synthesis.shared_techniques:
            print(f"  shared techniques: {', '.join(synthesis.shared_techniques)}")

    print("\n=== Explanations ===")
    for exp in result["explanations"]:
        tag = "grounded in your archive" if exp.grounded else "general knowledge"
        print(f"\n[{exp.sub_problem_id}] ({tag})")
        print(f"  {exp.text}")
        if exp.cited_entries:
            print(f"  cites: {', '.join(exp.cited_entries)}")

    hints_by_id = result.get("hints_by_id") or {}
    if hints_by_id:
        print("\n=== Hints ===")
        for sp_id, hints in hints_by_id.items():
            print(f"\n[{sp_id}]")
            for hint in hints:
                print(f"  ({hint.level.name.lower()}) {hint.text}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="A free, local, learning-focused CTF assistant. Does NOT auto-solve or submit flags."
    )
    parser.add_argument("challenge_description", help="the challenge prompt/description")
    parser.add_argument("--category", default=None, help="web | pwn | crypto | rev | forensics | misc")
    parser.add_argument("--file", dest="file_path", default=None, help="path to a challenge binary/pcap/etc.")
    parser.add_argument(
        "--depth", default=None,
        help="how deep to hint: name | approach | commands | walkthrough (omit for no hints)",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model to use (default: {DEFAULT_MODEL})")
    return parser


def main(argv=None) -> int:
    args = _build_arg_parser().parse_args(argv)

    depth = None
    if args.depth is not None:
        try:
            depth = level_from_str(args.depth)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    result = run(
        args.challenge_description,
        category=args.category,
        file_path=args.file_path,
        depth=depth,
        model=args.model,
    )
    _print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
