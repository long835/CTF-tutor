"""Quality / ops CLI commands (eval, status, gate, cost, route, …)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional


def cmd_status(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py status")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    from agent.project_status import project_status, format_status
    s = project_status()
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        print(format_status(s))
    return 0


def cmd_gate(argv: Optional[List[str]] = None) -> int:
    import subprocess
    import sys
    gate = Path(__file__).resolve().parents[1] / "scripts" / "release_gate.py"
    return subprocess.call([sys.executable, str(gate), *(argv or [])], cwd=str(gate.parent.parent))


def cmd_eval(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py eval")
    p.add_argument("--data", default=None)
    p.add_argument("--independent", action="store_true")
    p.add_argument("--public", action="store_true")
    p.add_argument("--external", action="store_true", help="external hard set (unlike taxonomy wording)")
    p.add_argument("--imported", action="store_true", help="imported literature cases")
    p.add_argument("--classifier", default="formal", choices=["formal", "heuristic"])
    p.add_argument("--decompose", action="store_true")
    p.add_argument("--model", default="")
    args = p.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    if args.imported:
        data = root / "data" / "eval" / "imported" / "public_literature.json"
    elif args.external:
        data = root / "data" / "eval" / "external_hard.json"
    elif args.public:
        data = root / "data" / "eval" / "public_contest_grounded.json"
    elif args.independent:
        data = root / "data" / "eval" / "independent_public_style.json"
    elif args.data:
        data = Path(args.data)
    else:
        data = root / "data" / "eval" / "ground_truth.json"
    import eval as eval_mod
    return eval_mod.run(data, args.decompose, args.model, args.classifier)


def cmd_review(argv: Optional[List[str]] = None) -> int:
    """Spaced-repetition due list and recording."""
    p = argparse.ArgumentParser(prog="main.py review")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--record", default=None, help="technique to mark reviewed")
    p.add_argument("--result", default="good", choices=["again", "hard", "good", "easy"])
    args = p.parse_args(argv)
    from agent.learner_view import review_due, record_review
    if args.record:
        print(json.dumps(record_review(args.record, result=args.result), indent=2))
    due = review_due(limit=args.limit)
    print(json.dumps({"due": due, "count": len(due)}, indent=2))
    return 0


def cmd_outcome(argv: Optional[List[str]] = None) -> int:
    """Run learning-outcome benchmark scaffold (pre/post/transfer)."""
    p = argparse.ArgumentParser(prog="main.py outcome")
    p.add_argument("--record", action="store_true", help="write learner attempts while running")
    args = p.parse_args(argv)
    from agent.learning_outcome import run_benchmark
    report = run_benchmark(record=args.record)
    print(json.dumps(report, indent=2))
    return 0


def cmd_labs(argv: Optional[List[str]] = None) -> int:
    """List or classify experience labs."""
    p = argparse.ArgumentParser(prog="main.py labs")
    p.add_argument("lab_id", nargs="?", default=None, help="lab id to show/classify")
    p.add_argument("--classify", action="store_true")
    p.add_argument("--attach", action="store_true", help="copy lab into a workspace")
    p.add_argument("--workspace-id", default=None)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    from agent.experience_labs import classify_lab, get_lab, labs_summary, list_labs
    if args.lab_id:
        if args.attach:
            from agent.experience_labs import attach_lab_to_workspace
            data = attach_lab_to_workspace(args.lab_id, challenge_id=args.workspace_id)
        elif args.classify:
            data = classify_lab(args.lab_id)
        else:
            lab = get_lab(args.lab_id)
            data = lab.to_dict() if lab else {"error": f"unknown lab: {args.lab_id}"}
        print(json.dumps(data, indent=2) if args.json or True else data)
        return 0 if "error" not in data else 1
    summary = labs_summary()
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(f"Experience labs: {summary['count']}")
        for lab in summary["labs"]:
            art = lab.get("artifact") or "-"
            print(f"  {lab['id']:18}  {lab['category']:10}  {art}")
    return 0


def cmd_next(argv: Optional[List[str]] = None) -> int:
    """Suggest next practice from spaced repetition + weak techniques."""
    p = argparse.ArgumentParser(prog="main.py next")
    p.add_argument("--limit", type=int, default=5)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    from agent.curriculum_next import next_practice
    data = next_practice(limit=args.limit)
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print("Due reviews:", len(data.get("due_reviews") or []))
        for d in data.get("due_reviews") or []:
            print(f"  review  {d.get('technique')}")
        print("Weak techniques:", ", ".join(data.get("weak_techniques") or []) or "(none)")
        print("Suggested labs:")
        for lab in data.get("suggested_labs") or []:
            print(f"  {lab['lab_id']:20}  {lab['category']:10}  {lab['technique']}")
        if not data.get("suggested_labs"):
            print("  (none matched — try: python main.py labs)")
        print(data.get("hint") or "")
    return 0


def cmd_calibrate(argv: Optional[List[str]] = None) -> int:
    """Confidence calibration report on external_hard."""
    p = argparse.ArgumentParser(prog="main.py calibrate")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    from agent.calibration import calibration_report, format_calibration
    rep = calibration_report()
    if args.json:
        print(json.dumps(rep, indent=2))
    else:
        print(format_calibration(rep))
    return 0


def cmd_diagnose(argv: Optional[List[str]] = None) -> int:
    """Coherent pipeline: classify → arbitrate → capability plan."""
    p = argparse.ArgumentParser(prog="main.py diagnose")
    p.add_argument("description", nargs="?", default="")
    p.add_argument("--json", action="store_true")
    p.add_argument("--llm", action="store_true", help="force LLM second opinion")
    args = p.parse_args(argv)
    from agent.classify_pipeline import classify_pipeline
    from agent.capability_plan import plan_for_category
    from agent.knowledge_coverage import knowledge_coverage
    data = classify_pipeline(args.description, use_llm=True if args.llm else None)
    plan = plan_for_category(data.get("category") or "misc")
    data["capability_plan"] = plan
    techs = []
    for pair in (data.get("profile") or {}).get("candidate_techniques") or []:
        if isinstance(pair, (list, tuple)) and pair:
            techs.append(pair[0])
        elif isinstance(pair, str):
            techs.append(pair)
    data["knowledge_coverage"] = knowledge_coverage(techs)
    if args.json:
        print(json.dumps(data, indent=2, default=str))
    else:
        print(
            "category:", data.get("category"),
            "belief:", data.get("belief_score"),
            "decision:", data.get("decision"),
            "arbitration:", data.get("arbitration"),
        )
        if data.get("calibrated_probability") is not None:
            print("calibrated_probability:", data.get("calibrated_probability"))
        print("discriminators:")
        for d in data.get("discriminators") or []:
            print(" -", d)
        print("plan:", plan.get("status_phrase"))
        for a in plan.get("next_actions") or []:
            print(" next:", a)
        cannot = (plan.get("capabilities") or {}).get("cannot") or []
        print("cannot reliably:", "; ".join(cannot[:3]))
        print("knowledge_coverage:", data["knowledge_coverage"].get("score"))
    return 0


def cmd_perf(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py perf")
    p.add_argument("--iterations", type=int, default=50)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    from agent.perf_bench import run_microbench
    rep = run_microbench(iterations=args.iterations)
    print(json.dumps(rep, indent=2) if args.json else rep)
    return 0


def cmd_compare_models(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py compare-models")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--llm", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    from agent.model_compare import compare_heuristic_vs_llm
    rep = compare_heuristic_vs_llm(limit=args.limit, use_llm=args.llm)
    print(json.dumps(rep, indent=2) if args.json else rep)
    return 0


def cmd_fit_calibration(argv: Optional[List[str]] = None) -> int:
    from agent.calibration_fit import fit_bin_calibration
    rep = fit_bin_calibration()
    print(json.dumps(rep, indent=2))
    return 0
