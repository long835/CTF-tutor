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
    chat      chat with the local CTF tutor
    generate  generate a safe local CTF challenge specification
    session   manage multi-language challenge sessions

Usage:
    python main.py "A login portal issues JWTs signed with RS256. \\
The admin panel trusts the role claim in the token." \\
        --category web --file ./challenge_files/app.js --depth approach

    python main.py search "jwt alg none bypass"
    python main.py list --category pwn
    python main.py history --summary
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, Optional

import classifier
import decomposer
import history
import llm_client
import synthesizer
import explainer
import depth_guide
import chat_generate
import multilang
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
    parser.add_argument("--difficulty", default=None, help="filter to one difficulty (easy/medium/hard/insane)")
    parser.add_argument("-n", "--n-results", type=int, default=5, help="max results (default: 5)")
    return parser


def cmd_search(argv) -> int:
    args = _build_search_parser().parse_args(argv)
    try:
        retriever = Retriever()
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    matches = retriever.query(args.query, n_results=args.n_results, category=args.category, difficulty=args.difficulty)
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
        avg = history.avg_hint_depth_by_technique(entries)
        if avg:
            print("average recorded hint depth by technique (lower can indicate less assistance needed):")
            for technique, value in avg.items():
                print(f"  {value:>6.2f}  {technique}")
        return 0

    for e in entries:
        print(f"\n{e.timestamp}  [{e.category or 'uncategorized'}]  depth={e.depth or 'none'}")
        print(f"  {e.challenge_description[:100]}")
        if e.techniques:
            print(f"  techniques: {', '.join(e.techniques)}")
    return 0



def _build_chat_parser():
    parser = argparse.ArgumentParser(prog="main.py chat", description="Chat with the local CTF tutor.")
    parser.add_argument("prompt")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    return parser

def cmd_chat(argv) -> int:
    args = _build_chat_parser().parse_args(argv)
    try:
        print(chat_generate.chat(args.prompt, model=args.model))
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0

def _build_generate_parser():
    parser = argparse.ArgumentParser(prog="main.py generate", description="Generate a safe local CTF challenge specification.")
    parser.add_argument("prompt")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--output", default=None, help="write JSON to this file")
    return parser

def cmd_generate(argv) -> int:
    args = _build_generate_parser().parse_args(argv)
    try:
        obj = chat_generate.generate(args.prompt, model=args.model)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(obj, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0

def _build_session_parser():
    parser = argparse.ArgumentParser(prog="main.py session", description="Manage a shared multi-language CTF session.")
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("create"); p.add_argument("challenge_name"); p.add_argument("--language", default="python", choices=multilang.SUPPORTED_LANGUAGES); p.add_argument("--root", default="data/sessions")
    p = sub.add_parser("switch"); p.add_argument("workspace"); p.add_argument("language", choices=multilang.SUPPORTED_LANGUAGES)
    p = sub.add_parser("run"); p.add_argument("workspace"); p.add_argument("source"); p.add_argument("--language", choices=multilang.SUPPORTED_LANGUAGES); p.add_argument("--timeout", type=int, default=10)
    p = sub.add_parser("note"); p.add_argument("workspace"); p.add_argument("text")
    sub.add_parser("list")
    return parser

def cmd_session(argv) -> int:
    args = _build_session_parser().parse_args(argv)
    try:
        if args.action == "create":
            s = multilang.MultiLanguageSession.create(args.challenge_name, root=args.root, language=args.language); print(s.workspace); return 0
        if args.action == "list":
            print(json.dumps(multilang.list_sessions(), indent=2)); return 0
        s = multilang.MultiLanguageSession.load(args.workspace)
        if args.action == "switch": s.switch(args.language); print(s.current_language); return 0
        if args.action == "note": s.add_note(args.text); return 0
        if args.action == "run":
            with open(args.source, "r", encoding="utf-8") as f: source = f.read()
            r = s.run_source(source, language=args.language, timeout=args.timeout); print(json.dumps(r.to_dict(), indent=2)); return 0 if r.returncode == 0 else 1
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 1


def cmd_agent(argv) -> int:
    """Closed-loop investigative agent (hypotheses → tools → observe → verify)."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="main.py agent",
        description="Run the closed-loop CTF agent (state + hypotheses + tools + verification).",
    )
    parser.add_argument("description", help="Challenge description or question")
    parser.add_argument("--category", default=None, help="Optional category hint")
    parser.add_argument("--path", default=None, help="Local challenge directory or file to triage")
    parser.add_argument("--fetch", default=None, help="Fetch public GitHub/zip source first, then triage it")
    parser.add_argument("--max-steps", type=int, default=10, help="Max agent steps (default 10)")
    parser.add_argument("--hint-level", type=int, default=2, help="Teaching hint depth 1-6 (default 2)")
    parser.add_argument("--quiet", action="store_true", help="Suppress step-by-step trace")
    parser.add_argument("--json", action="store_true", help="Emit final AgentState as JSON")
    parser.add_argument("--writeup", action="store_true", help="Print structured writeup only")
    args = parser.parse_args(argv)

    # Optional public fetch before agent run
    if args.fetch:
        from agent.challenge_fetch import fetch_auto
        fr = fetch_auto(args.fetch)
        if not fr.ok:
            print(f"fetch failed: {fr.error}", file=sys.stderr)
            return 1
        args.path = fr.local_path
        print(f"fetched → {fr.local_path} ({fr.files} files)")

    from agent.loop import run_agent, AgentLoop
    # Use AgentLoop directly so we can set hint_level
    events = []
    def on_event(name, payload):
        if args.quiet:
            return
        if name == "triage_done":
            events.append(f"⊞ triage: {payload.get('files', 0)} files")
        elif name == "action_planned":
            events.append(f"→ plan: {payload.get('tool')} — {str(payload.get('reason',''))[:80]}")
        elif name == "action_finished":
            ok = "ok" if payload.get("success") else "FAIL"
            events.append(f"  [{ok}] {payload.get('tool')}: {str(payload.get('summary',''))[:100]}")
        elif name == "verification":
            events.append(f"✓ verify: {payload.get('verdict')} ({payload.get('confidence', 0):.2f})")
        elif name == "finished":
            events.append(f"done: status={payload.get('status')} conf={payload.get('confidence', 0):.2f}")

    agent = AgentLoop(
        challenge_summary=args.description,
        category=args.category,
        max_steps=args.max_steps,
        on_event=on_event,
        challenge_path=args.path,
    )
    agent.hint_level = max(1, min(6, args.hint_level))
    state = agent.run()
    if not args.quiet:
        print("\n".join(events))
        print()
        print(agent.teaching_summary())
    if args.writeup:
        from agent.writeup import render_writeup
        print(render_writeup(state))
    if args.json:
        print(state.to_json())
    return 0



def cmd_fetch(argv) -> int:
    """Fetch public CTF challenges from GitHub or archive URLs into a local workspace."""
    import argparse
    import json
    parser = argparse.ArgumentParser(
        prog="main.py fetch",
        description="Download public challenge material (GitHub repo/path or .zip URL) for local study.",
    )
    parser.add_argument("source", nargs="?", help="GitHub URL|owner/repo[/path] or https://.../chal.zip")
    parser.add_argument("--search", default=None, help="Search public GitHub repos for CTF challenges")
    parser.add_argument("--ctftime", type=int, default=None, help="Fetch public CTFtime event metadata by id")
    parser.add_argument("--id", default=None, help="Workspace challenge id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    from agent.challenge_fetch import fetch_auto, search_github_challenges, fetch_ctftime_event

    if args.search:
        results = search_github_challenges(args.search)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            for r in results:
                if "error" in r:
                    print("error:", r["error"])
                else:
                    print(f"{r.get('stars', 0):5}  {r.get('full_name')}  {r.get('url')}")
                    if r.get("description"):
                        print(f"       {r['description'][:100]}")
        return 0

    if args.ctftime is not None:
        meta = fetch_ctftime_event(args.ctftime)
        print(json.dumps(meta, indent=2))
        return 0 if "error" not in meta else 1

    if not args.source:
        parser.error("source required unless --search or --ctftime")

    result = fetch_auto(args.source, challenge_id=args.id)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        if result.ok:
            print(f"OK  source={result.source}  id={result.challenge_id}")
            print(f"    path={result.local_path}")
            print(f"    files={result.files}  bytes={result.bytes}")
            print(f"    next: python main.py agent --path {result.local_path} \"<description>\"")
        else:
            print(f"FAIL  {result.error}")
            return 1
    return 0 if result.ok else 1



def cmd_experiment(argv) -> int:
    """Run a reproducible agent experiment or full benchmark."""
    import argparse, json
    p = argparse.ArgumentParser(prog="main.py experiment")
    p.add_argument("description", nargs="?", help="Single challenge text")
    p.add_argument("--benchmark", action="store_true", help="Run all ground_truth cases")
    p.add_argument("--ablation", action="store_true", help="Run ablation study")
    p.add_argument("--max-steps", type=int, default=4)
    args = p.parse_args(argv)
    if args.ablation:
        from agent.ablation import run_ablation
        print(json.dumps(run_ablation(max_steps=args.max_steps), indent=2))
        return 0
    if args.benchmark:
        from agent.experiment import run_benchmark, ExperimentConfig
        s = run_benchmark(ExperimentConfig(max_steps=args.max_steps, enable_trace=False))
        print(json.dumps({k: v for k, v in s.items() if k != "rows"}, indent=2))
        return 0
    if not args.description:
        p.error("description required unless --benchmark/--ablation")
    from agent.experiment import run_experiment, ExperimentConfig
    r = run_experiment(args.description, ExperimentConfig(max_steps=args.max_steps))
    print(json.dumps(r.to_dict(), indent=2))
    return 0


def cmd_corpus(argv) -> int:
    """Build local 100+ challenge/technique corpus."""
    import argparse, json
    p = argparse.ArgumentParser(prog="main.py corpus")
    p.add_argument("--min", type=int, default=120, help="Minimum entries (default 120)")
    args = p.parse_args(argv)
    from agent.corpus_builder import build_corpus
    print(json.dumps(build_corpus(args.min), indent=2))
    return 0


def cmd_platform(argv) -> int:
    """Query optional CTFd / HTB APIs (tokens via env)."""
    import argparse, json
    p = argparse.ArgumentParser(prog="main.py platform")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("ctfd"); c.add_argument("base_url"); c.add_argument("--id", type=int, default=None)
    h = sub.add_parser("htb"); h.add_argument("--profile", action="store_true"); h.add_argument("--limit", type=int, default=20)
    args = p.parse_args(argv)
    if args.cmd == "ctfd":
        from agent.platforms import ctfd_list_challenges, ctfd_challenge_detail
        if args.id:
            print(json.dumps(ctfd_challenge_detail(args.base_url, args.id), indent=2))
        else:
            print(json.dumps(ctfd_list_challenges(args.base_url), indent=2))
    else:
        from agent.platforms import htb_list_machines, htb_profile
        if args.profile:
            print(json.dumps(htb_profile(), indent=2))
        else:
            print(json.dumps(htb_list_machines(args.limit), indent=2))
    return 0


def cmd_webui(argv) -> int:
    """Start MVP web UI (http://127.0.0.1:8765)."""
    from webui.server import main as web_main
    web_main()
    return 0


def cmd_curriculum(argv) -> int:
    """Build a personalised study plan from your recorded history."""
    import argparse, json
    p = argparse.ArgumentParser(
        prog="main.py curriculum",
        description="What to study next, based on what you've actually done.",
    )
    p.add_argument("--goal", default=None, help="Target technique, e.g. ret2libc")
    p.add_argument("-n", "--length", type=int, default=5, help="Number of lessons (default 5)")
    p.add_argument("--solved", dest="last", action="store_true", help="Last attempt succeeded (nudge difficulty up)")
    p.add_argument("--stuck", dest="last", action="store_false", help="Last attempt failed (nudge difficulty down)")
    p.add_argument("--json", action="store_true", help="Emit raw JSON")
    p.set_defaults(last=None)
    args = p.parse_args(argv)

    from agent.curriculum import build_curriculum, render_curriculum
    from agent.memory import load_memory

    plan = build_curriculum(load_memory(), goal=args.goal, length=args.length, last_success=args.last)
    print(json.dumps(plan, indent=2) if args.json else render_curriculum(plan))
    return 0


def cmd_graph(argv) -> int:
    """Explore how challenges in the archive/corpus relate to each other."""
    import argparse, json
    p = argparse.ArgumentParser(
        prog="main.py graph",
        description="Neighbours, warm-ups, and next steps around a challenge or technique.",
    )
    p.add_argument("query", nargs="?", help="Challenge name or technique to centre on")
    p.add_argument("--stats", action="store_true", help="Show graph statistics instead")
    p.add_argument("--path", nargs=2, metavar=("FROM", "TO"), help="Shortest route between two challenges")
    p.add_argument("--dot", action="store_true", help="Emit Graphviz DOT")
    p.add_argument("--no-corpus", action="store_true", help="Archive entries only")
    p.add_argument("-n", "--limit", type=int, default=5)
    args = p.parse_args(argv)

    from agent.challenge_graph import get_graph, render_neighborhood

    graph = get_graph(force_reload=True, include_corpus=not args.no_corpus)

    if args.stats:
        print(json.dumps(graph.stats(), indent=2))
        return 0
    if args.dot:
        print(graph.to_dot())
        return 0
    if args.path:
        start = graph.find(args.path[0], limit=1)
        goal = graph.find(args.path[1], limit=1)
        if not start or not goal:
            print("Could not match one or both endpoints. Try `python main.py graph <name>` first.")
            return 1
        route = graph.shortest_path(start[0].id, goal[0].id)
        if not route:
            print(f"No route from {start[0].name} to {goal[0].name} in the current graph.")
            return 1
        for i, node_id in enumerate(route, 1):
            node = graph.nodes[node_id]
            print(f"{i}. {node.name} ({node.category}/{node.difficulty})")
        return 0
    if not args.query:
        print(json.dumps(graph.stats(), indent=2))
        return 0

    print(render_neighborhood(graph, args.query, limit=args.limit))
    return 0


def cmd_audit(argv) -> int:
    """Check archive quality: provenance, versioning, contradictions."""
    import argparse, json
    p = argparse.ArgumentParser(
        prog="main.py audit",
        description="Validate the archive and report where its knowledge came from.",
    )
    p.add_argument("--sync", action="store_true", help="Register new/changed entries in the provenance index")
    p.add_argument("--verify", metavar="ENTRY_ID", help="Mark an entry as human-verified")
    p.add_argument("--strict", action="store_true", help="Exit non-zero if anything is wrong (for CI)")
    p.add_argument("--json", action="store_true", help="Emit raw JSON")
    args = p.parse_args(argv)

    from agent.provenance import ProvenanceStore, audit_archive, render_audit, sync_archive

    if args.verify:
        store = ProvenanceStore()
        if store.mark_verified(args.verify):
            store.save()
            print(f"marked {args.verify} as verified")
            return 0
        print(f"no provenance record for {args.verify!r} — run `--sync` first")
        return 1

    if args.sync:
        result = sync_archive()
        print(json.dumps(result, indent=2) if args.json else
              f"tracked {result['tracked']} entries "
              f"(+{len(result['added'])} new, {len(result['revised'])} revised, "
              f"{len(result['orphaned'])} orphaned)")
        if not args.json:
            print()

    report = audit_archive()
    print(json.dumps(report, indent=2) if args.json else render_audit(report))

    if args.strict and not report.get("clean"):
        return 1
    return 0


def cmd_dashboard(argv) -> int:
    """Render offline results as browsable HTML."""
    import argparse
    p = argparse.ArgumentParser(
        prog="main.py dashboard",
        description="Build a self-contained HTML dashboard and agent trace viewer.",
    )
    p.add_argument("--eval", action="store_true", help="Run the offline evaluator first")
    p.add_argument("--trace", nargs="?", const="", default=None,
                   help="Also render a trace (newest one if no path given)")
    p.add_argument("--out", default="data/reports/dashboard.html")
    args = p.parse_args(argv)

    from agent.dashboard import write_dashboard, write_trace_view

    path = write_dashboard(out_path=args.out, run_eval=args.eval)
    print(f"dashboard: {path}")

    if args.trace is not None:
        trace_path = write_trace_view(trace_path=args.trace or None)
        if trace_path:
            print(f"trace:     {trace_path}")
        else:
            print("trace:     none found under data/traces/ — run the agent with tracing on")

    print("open either file directly in a browser (no server needed)")
    return 0


def cmd_plugins(argv) -> int:
    """List discovered plugins and the tools they register."""
    import argparse, json
    p = argparse.ArgumentParser(
        prog="main.py plugins",
        description="Third-party toolkits loaded from the plugins/ directory.",
    )
    p.add_argument("--dir", default=None, help="Plugin directory (default: plugins/)")
    p.add_argument("--json", action="store_true", help="Emit raw JSON")
    args = p.parse_args(argv)

    from agent.plugins import PLUGIN_DIR, render_status, status

    report = status(args.dir or PLUGIN_DIR)
    print(json.dumps(report, indent=2) if args.json else render_status(report))
    return 0


def cmd_doctor(argv) -> int:
    """Report what this machine can actually run (items 42, 43, 44)."""
    p = argparse.ArgumentParser(
        prog="main.py doctor",
        description="Check Python, packages, CTF tooling, model backend and hardware.",
    )
    p.add_argument("--json", action="store_true", help="Emit raw JSON")
    p.add_argument("--skip-model", action="store_true",
                   help="Do not probe the model backend (faster, fully offline)")
    args = p.parse_args(argv)

    from agent.doctor import probe, render_report, summary

    checks = probe(include_model=not args.skip_model)
    if args.json:
        print(json.dumps({"summary": summary(checks),
                          "checks": [c.to_dict() for c in checks]}, indent=2, default=str))
    else:
        print(render_report(checks))
    # Non-zero only for genuinely blocking problems: a missing optional tool
    # must not fail someone's CI.
    return 0 if summary(checks)["usable"] else 1


def cmd_replay(argv) -> int:
    """Record and replay investigations deterministically (items 26, 27)."""
    p = argparse.ArgumentParser(
        prog="main.py replay",
        description="Record an agent run, or replay a saved one against the current code.",
    )
    sub = p.add_subparsers(dest="action", required=True)

    rec = sub.add_parser("record", help="run an investigation and save a replayable record")
    rec.add_argument("challenge")
    rec.add_argument("--category", default=None)
    rec.add_argument("--path", default=None, help="challenge files to triage")
    rec.add_argument("--max-steps", type=int, default=8)
    rec.add_argument("--out", default=None)

    rep = sub.add_parser("run", help="replay a saved record and diff the decisions")
    rep.add_argument("record")
    rep.add_argument("--json", action="store_true")

    show = sub.add_parser("show", help="summarise a saved record")
    show.add_argument("record")

    args = p.parse_args(argv)
    from agent.replay import RunRecord, diff_records, record_run, replay

    if args.action == "record":
        state, record = record_run(
            challenge=args.challenge,
            category=args.category,
            max_steps=args.max_steps,
            challenge_path=args.path,
        )
        path = record.save(args.out)
        print(f"recorded {len(record.steps)} step(s) -> {path}")
        print(f"status: {record.final_status} (confidence {record.final_confidence:.2f})")
        return 0

    record = RunRecord.load(args.record)

    if args.action == "show":
        print(f"challenge: {record.challenge[:100]}")
        print(f"category:  {record.category or 'unknown'} | steps: {len(record.steps)}")
        print(f"outcome:   {record.final_status} ({record.final_confidence:.2f})")
        print("decisions: " + " -> ".join(record.decisions()) or "(none)")
        if record.metrics:
            print("metrics:   " + json.dumps(record.metrics))
        return 0

    state, executor = replay(record)
    diff = diff_records(record, state, executor)
    print(json.dumps(diff.to_dict(), indent=2) if args.json else diff.render())
    return 1 if diff.regressed else 0


def cmd_metrics(argv) -> int:
    """Score a recorded run on every evaluation axis (items 21, 59, 60)."""
    p = argparse.ArgumentParser(
        prog="main.py metrics",
        description="Efficiency, hallucination and per-dimension scores for a saved run.",
    )
    p.add_argument("record", help="a replay record, or a workspace state JSON")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    from agent.metrics import detect_hallucinations, efficiency, score_run
    from agent.state import AgentState

    raw = json.loads(Path(args.record).read_text(encoding="utf-8"))
    if "steps" in raw and "challenge" in raw:
        # A replay record: re-derive the state by replaying it, which is
        # cheaper and more faithful than storing a second copy of the state.
        from agent.replay import RunRecord, replay

        state, _ = replay(RunRecord.from_dict(raw))
    else:
        state = AgentState.from_dict(raw)

    graph = None
    try:
        from agent.evidence_graph import build_graph

        graph = build_graph(state)
    except Exception:
        graph = None

    if args.json:
        print(json.dumps({
            "efficiency": efficiency(state).to_dict(),
            "hallucination": detect_hallucinations(state, graph=graph).to_dict(),
            "dimensions": score_run(state, graph=graph).to_dict(),
        }, indent=2, default=str))
    else:
        from agent.metrics import scorecard

        print(scorecard(state, graph=graph))
    return 0


def cmd_adversarial(argv) -> int:
    """Run the adversarial evaluation suite (item 22)."""
    p = argparse.ArgumentParser(
        prog="main.py adversarial",
        description="Challenges built to fool the agent. Reports trap avoidance, "
                    "not solve rate.",
    )
    p.add_argument("--data", default=None, help="path to an adversarial case file")
    p.add_argument("--trap", default=None, help="run only one trap type")
    p.add_argument("--max-steps", type=int, default=5)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    from agent.adversarial import ADVERSARIAL_PATH, default_runner, load_cases, run_suite

    cases = load_cases(Path(args.data) if args.data else ADVERSARIAL_PATH)
    if args.trap:
        cases = [c for c in cases if c.trap == args.trap]
    if not cases:
        print("no adversarial cases found")
        return 1

    report = run_suite(lambda case: default_runner(case, max_steps=args.max_steps), cases)
    print(json.dumps(report.to_dict(), indent=2) if args.json else report.render())
    # Non-zero when any trap was walked into: this is a suite you want in CI.
    return 0 if report.avoided == len(report.results) else 1


def cmd_trust(argv) -> int:
    """Show the trust policy and scan text for injection attempts (items 45/46)."""
    p = argparse.ArgumentParser(
        prog="main.py trust",
        description="Trust levels, and what counts as an instruction-position attempt.",
    )
    p.add_argument("--scan", default=None, help="a file to scan for injection attempts")
    args = p.parse_args(argv)

    from agent.trust import Trust, detect_injection, render_trust_policy

    print(render_trust_policy())
    if args.scan:
        text = Path(args.scan).read_text(encoding="utf-8", errors="replace")
        findings = detect_injection(text, Trust.CHALLENGE)
        print()
        if not findings:
            print(f"{args.scan}: no instruction-position attempts found")
        else:
            print(f"{args.scan}: {len(findings)} attempt(s)")
            for finding in findings:
                print(f"  {finding}")
    return 0


SUBCOMMAND_NAMES = [
    "run", "search", "list", "history", "chat", "generate", "session", "agent",
    "fetch", "experiment", "corpus", "platform", "webui",
    "curriculum", "graph", "audit", "dashboard", "plugins",
    "doctor", "replay", "metrics", "adversarial", "trust",
]


def main(argv=None) -> int:
    argv = list(sys.argv[1:]) if argv is None else list(argv)

    if not argv or argv[0] in ("-h", "--help"):
        print("usage: main.py <subcommand> [options]")
        print()
        print("A free, local, learning-focused CTF assistant. Does NOT auto-solve or submit flags.")
        print()
        print("learning:")
        print("  run         run the full pipeline against a challenge (default if omitted)")
        print("  agent       closed-loop investigative agent (hypotheses, tools, verification)")
        print("  curriculum  what to study next, based on your recorded history")
        print("  chat        chat with the local CTF tutor")
        print("  history     show past sessions / a technique-frequency progress summary")
        print()
        print("knowledge:")
        print("  search      query your archive directly")
        print("  list        list archive entries on disk, grouped by category")
        print("  graph       see how challenges relate: warm-ups, next steps, routes")
        print("  corpus      rebuild the local study corpus from the technique library")
        print("  audit       check archive provenance, versions, and contradictions")
        print("  fetch       download public challenges (GitHub / zip URL) for local study")
        print()
        print("workflow:")
        print("  session     manage multi-language challenge sessions")
        print("  generate    generate a safe local CTF challenge specification")
        print("  experiment  run/benchmark/ablation harness")
        print("  dashboard   render results and agent traces as browsable HTML")
        print("  webui       start the local web UI")
        print("  plugins     list third-party toolkits from plugins/")
        print("  platform    query optional CTFd / HTB APIs")
        print()
        print("diagnostics:")
        print("  doctor      check what this machine can actually run")
        print("  replay      record a run, or replay a saved one against current code")
        print("  metrics     efficiency, hallucination and per-axis scores for a run")
        print("  adversarial run the trap suite: can the agent avoid wrong answers?")
        print("  trust       trust policy, and scan a file for injection attempts")
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
