"""
main.py

CLI entrypoint that wires the whole pipeline together:

    classifier  -> (optional) auto-detect category if not given
    decomposer  -> break the challenge into sub-problems
    retriever   -> find similar past challenges per sub-problem
    synthesizer -> notice when sub-problems combine techniques from
                   different past challenges
    explainer   -> plain-language explanation per sub-problem
    depth_guide -> (optional) tiered hints per sub-problem, up to a
                   requested depth, or walked interactively one level at a
                   time with --interactive
    history     -> (optional, on by default for CLI runs) logs each session
                   to data/history.jsonl for challenge history / progress

If chromadb/Ollama-embeddings aren't set up yet (or this is running
somewhere that can't reach them, like a test sandbox), retrieval degrades
gracefully to "no matches" rather than crashing the whole run -- you still
get decomposition and ungrounded explanations.

Subcommands:
    run       run the full pipeline against a challenge (default if omitted)
    search    query your archive directly
    list      list archive entries on disk, grouped by category
    history   show past sessions / a technique-frequency progress summary

Usage:
    python main.py "A login portal issues JWTs signed with RS256. \\
The admin panel trusts the role claim in the token." \\
        --category web --file ./challenge_files/app.js --depth approach

    python main.py search "jwt alg none bypass"
    python main.py list --category pwn
    python main.py history --summary
"""

import argparse
import os
import sys
from typing import Dict, Optional

import classifier
import decomposer
import history
import llm_client
import synthesizer
import explainer
import depth_guide
from concurrency import map_concurrent
from depth_guide import HintLevel, level_from_str
from progress import Spinner
from retriever import Retriever
from schema import ArchiveEntry
from llm_client import DEFAULT_MODEL


def run(
    challenge_description: str,
    category: Optional[str] = None,
    file_path: Optional[str] = None,
    retriever: Optional[Retriever] = None,
    depth: Optional[HintLevel] = None,
    model: str = DEFAULT_MODEL,
    include_decompile: bool = False,
    verbose: bool = False,
) -> dict:
    """
    Run the full pipeline and return a dict with keys:
    sub_problems, matches_by_id, synthesis, explanations, hints_by_id
    (hints_by_id is {} unless `depth` is given).

    verbose=True prints a one-line status before each stage (decomposing,
    searching the archive, cross-referencing, explaining, hinting) so a
    slow run shows visible progress instead of sitting silent until the
    very end. Off by default so library callers/tests get a clean return
    value with no stdout side effects; the CLI turns it on.
    """
    if verbose:
        print(f"[1/4] Decomposing challenge...")
    sub_problems = decomposer.decompose(
        challenge_description,
        category=category,
        file_path=file_path,
        model=model,
        include_decompile=include_decompile,
    )
    if verbose:
        print(f"      -> {len(sub_problems)} sub-problem(s) found")

    if retriever is None:
        try:
            retriever = Retriever()
        except RuntimeError:
            # no chromadb / no embedding model set up -- degrade gracefully
            retriever = None

    if verbose:
        print("[2/4] Searching your archive...")
    if retriever is None:
        matches_by_id: Dict[str, list] = {sp.id: [] for sp in sub_problems}
    else:
        # each sub-problem's archive lookup is independent -- run them
        # concurrently rather than one at a time (see concurrency.py)
        results = map_concurrent(
            lambda sp: retriever.query_sub_problem(sp, category=category), sub_problems
        )
        matches_by_id = {sp.id: matches for sp, matches in zip(sub_problems, results)}

    if verbose:
        print("[3/4] Cross-referencing and explaining (this is usually the slow part)...")
    synthesis = synthesizer.synthesize(challenge_description, sub_problems, matches_by_id, model=model)
    explanations = explainer.explain_all(sub_problems, matches_by_id, model=model)

    hints_by_id: Dict[str, list] = {}
    if depth is not None:
        if verbose:
            print("[4/4] Building hints...")
        ladders = map_concurrent(
            lambda sp: depth_guide.get_hint_ladder(
                sp, matches_by_id.get(sp.id, []), up_to=depth, model=model
            ),
            sub_problems,
        )
        hints_by_id = {sp.id: ladder for sp, ladder in zip(sub_problems, ladders)}

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


def run_interactive_hints(
    sub_problems,
    matches_by_id: Dict[str, list],
    model: str = DEFAULT_MODEL,
    input_func=input,
) -> None:
    """
    Walk the hint ladder one level at a time per sub-problem, asking before
    revealing each level instead of dumping the whole ladder at once --
    "only as deep as you ask for" taken literally. 'y' shows the hint and
    offers the next level up; anything else (including a blank line) skips
    to the next sub-problem; 'q' stops entirely.

    Takes input_func as a seam for testing: pass a fake that returns a
    canned queue of answers instead of real stdin.
    """
    for sp in sub_problems:
        print(f"\n[{sp.id}] {sp.description}")
        matches = matches_by_id.get(sp.id, [])
        for level in HintLevel:
            answer = input_func(f"  get {level.name.lower()} hint? [y/N/q] ").strip().lower()
            if answer == "q":
                return
            if answer != "y":
                break
            hint = depth_guide.get_hint(sp, matches, level, model=model)
            print(f"  ({level.name.lower()}) {hint.text}")


def _build_run_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py run",
        description="Run the full pipeline against a challenge. Does NOT auto-solve or submit flags.",
    )
    parser.add_argument("challenge_description", help="the challenge prompt/description")
    parser.add_argument(
        "--category", default=None,
        help="web | pwn | crypto | rev | forensics | misc (auto-detected from the description if omitted)",
    )
    parser.add_argument("--file", dest="file_path", default=None, help="path to a challenge binary/pcap/etc.")
    parser.add_argument(
        "--depth", default=None,
        help="how deep to hint: name | approach | commands | walkthrough (omit for no hints)",
    )
    parser.add_argument(
        "--interactive", action="store_true",
        help="walk the hint ladder one level at a time, asking before each reveal (overrides --depth)",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model to use (default: {DEFAULT_MODEL})")
    parser.add_argument(
        "--decompile", action="store_true",
        help="also run Ghidra headless decompilation on --file (slow; requires a local Ghidra install)",
    )
    parser.add_argument(
        "--no-history", action="store_true",
        help="don't log this session to data/history.jsonl",
    )
    parser.add_argument(
        "--no-warmup", action="store_true",
        help="skip the model warm-up ping (use if you know it's already loaded, e.g. running several challenges back to back)",
    )
    return parser


def cmd_run(argv) -> int:
    args = _build_run_parser().parse_args(argv)

    depth = None
    if args.depth is not None and not args.interactive:
        try:
            depth = level_from_str(args.depth)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1

    # Warm the model up FIRST, before classification or the pipeline touch
    # it -- otherwise the (sometimes tens-of-seconds) cold-load delay lands
    # on whichever stage happens to make the first call, which is exactly
    # what makes a cold Ollama server feel like it's randomly stuttering.
    # Doing it once, up front, with visible progress turns that into one
    # predictable wait instead of several unpredictable ones.
    try:
        if not args.no_warmup:
            with Spinner(f"Waking up {args.model} (first call can be slow while it loads)"):
                llm_client.warm_up(model=args.model)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    category = args.category
    if category is None:
        try:
            category = classifier.classify(args.challenge_description, model=args.model)
        except RuntimeError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"(no --category given -- auto-detected: {category})")

    try:
        result = run(
            args.challenge_description,
            category=category,
            file_path=args.file_path,
            depth=depth,
            model=args.model,
            include_decompile=args.decompile,
            verbose=True,
        )
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    _print_report(result)

    if args.interactive:
        run_interactive_hints(result["sub_problems"], result["matches_by_id"], model=args.model)

    if not args.no_history:
        entry = history.entry_from_run_result(
            args.challenge_description, result, category=category,
            depth=args.depth if not args.interactive else "interactive",
        )
        history.log_entry(entry, path=history.DEFAULT_HISTORY_PATH)

    return 0


def _build_search_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py search", description="Search your archive directly.")
    parser.add_argument("query", help="free-text search query")
    parser.add_argument("--category", default=None, help="filter to one category")
    parser.add_argument("-n", "--n-results", type=int, default=5, help="max results (default: 5)")
    return parser


def cmd_search(argv) -> int:
    args = _build_search_parser().parse_args(argv)
    try:
        retriever = Retriever()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    matches = retriever.query(args.query, n_results=args.n_results, category=args.category)
    if not matches:
        print("no matches found")
        return 0
    for m in matches:
        print(f"\n[{m.entry.category}] {m.entry.challenge_name}  (score {m.score:.2f})")
        print(f"  techniques: {', '.join(m.entry.techniques)}")
        print(f"  {m.entry.explanation}")
    return 0


def _build_list_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py list", description="List archive entries on disk (data/archive/*.json)."
    )
    parser.add_argument("--dir", dest="archive_dir", default="data/archive", help="archive directory to scan")
    parser.add_argument("--category", default=None, help="filter to one category")
    return parser


def cmd_list(argv) -> int:
    args = _build_list_parser().parse_args(argv)
    if not os.path.isdir(args.archive_dir):
        print(f"no archive directory at {args.archive_dir}")
        return 0

    entries = []
    for filename in sorted(os.listdir(args.archive_dir)):
        if not filename.lower().endswith(".json"):
            continue
        try:
            entries.append(ArchiveEntry.load(os.path.join(args.archive_dir, filename)))
        except Exception:
            continue

    if args.category:
        entries = [e for e in entries if e.category == args.category]

    if not entries:
        print("no archive entries found")
        return 0

    by_category: Dict[str, list] = {}
    for e in entries:
        by_category.setdefault(e.category, []).append(e)

    for category in sorted(by_category):
        print(f"\n{category} ({len(by_category[category])}):")
        for e in by_category[category]:
            print(f"  - {e.challenge_name}  [{', '.join(e.techniques)}]")
    return 0


def _build_history_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="main.py history", description="Show past sessions and technique progress.")
    parser.add_argument("-n", "--limit", type=int, default=10, help="show the last N sessions (default: 10)")
    parser.add_argument(
        "--summary", action="store_true",
        help="show technique-frequency progress summary instead of a session list",
    )
    return parser


def cmd_history(argv) -> int:
    args = _build_history_parser().parse_args(argv)
    entries = history.read_history(path=history.DEFAULT_HISTORY_PATH, limit=None if args.summary else args.limit)

    if not entries:
        print("no history yet -- run a challenge first")
        return 0

    if args.summary:
        counts = history.summarize(entries)
        if not counts:
            print("no techniques logged yet")
            return 0
        print(f"technique frequency across {len(entries)} session(s):")
        for technique, count in counts.items():
            print(f"  {count:>3}  {technique}")
        return 0

    for e in entries:
        print(f"\n{e.timestamp}  [{e.category or 'uncategorized'}]  depth={e.depth or 'none'}")
        print(f"  {e.challenge_description[:100]}")
        if e.techniques:
            print(f"  techniques: {', '.join(e.techniques)}")
    return 0


SUBCOMMAND_NAMES = ["run", "search", "list", "history"]


def main(argv=None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)

    if not argv or argv[0] in ("-h", "--help"):
        print("usage: main.py {run,search,list,history} ...")
        print()
        print("A free, local, learning-focused CTF assistant. Does NOT auto-solve or submit flags.")
        print()
        print("subcommands:")
        print("  run       run the full pipeline against a challenge (default if omitted)")
        print("  search    query your archive directly")
        print("  list      list archive entries on disk, grouped by category")
        print("  history   show past sessions / a technique-frequency progress summary")
        print()
        print("run `python main.py <subcommand> --help` for that subcommand's options.")
        if not argv:
            print()
            print("(no challenge description given -- showing this instead of 'run's help)")
        return 0

    # Backward-compat: `python main.py "<description>" ...` (no subcommand)
    # is treated as `python main.py run "<description>" ...`.
    if argv[0] not in SUBCOMMAND_NAMES:
        argv = ["run"] + argv

    subcommand, rest = argv[0], argv[1:]
    handler = globals()[f"cmd_{subcommand}"]  # dynamic lookup so tests can patch cmd_* directly
    return handler(rest)


if __name__ == "__main__":
    sys.exit(main())
