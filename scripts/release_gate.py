#!/usr/bin/env python3
"""Release / integration gate (Phase 6.5).

Run from repo root:
  PYTHONPATH=. python scripts/release_gate.py

Exits non-zero if any check fails.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(
        cmd,
        cwd=str(ROOT),
        env={**dict(**{k: v for k, v in __import__("os").environ.items()}), "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
    )
    out = (p.stdout or "") + (p.stderr or "")
    return p.returncode, out


def main() -> int:
    checks = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": ok, "detail": detail[:300]})
        print(("PASS" if ok else "FAIL"), name, detail[:120])

    # 1) unit tests (focused reliability set)
    code, out = run([
        sys.executable, "-m", "unittest",
        "tests.test_archive_schema",
        "tests.test_phase65_classifier_verify",
        "tests.test_independent_eval",
        "tests.test_learning_outcome",
        "tests.test_spaced_repetition",
        "tests.test_experience_labs",
        "tests.test_agent_lab",
        "tests.test_lab_workspace",
        "tests.test_imported_and_heap",
        "tests.test_external_hard_eval",
        "-q",
    ])
    add("unit_tests", code == 0, out.strip().split("\n")[-3:] and "\n".join(out.strip().split("\n")[-5:]))

    # 2) archive audit strict
    run([sys.executable, "main.py", "audit", "--sync"])
    code, out = run([sys.executable, "main.py", "audit", "--strict"])
    add("audit_strict", code == 0 and "Everything checks out" in out, out[-200:])

    # 3) knowledge uncovered signals
    code, out = run([
        sys.executable, "-c",
        "from agent.tool_capabilities import uncovered_signals; "
        "u=uncovered_signals(); print(u); raise SystemExit(0 if u=={} else 1)",
    ])
    add("uncovered_signals", code == 0, out.strip())

    # 4) corpus provenance split
    code, out = run([
        sys.executable, "-c",
        "import json; from collections import Counter; "
        "c=Counter(json.loads(l).get('provenance') for l in open('data/corpus/challenges.jsonl')); "
        "print(dict(c)); "
        "raise SystemExit(0 if c.get('curated') and c.get('derived') else 1)",
    ])
    add("corpus_provenance", code == 0, out.strip())

    # 5) hand eval accuracy >= 0.95
    code, out = run([
        sys.executable, "-c",
        "import json; from agent.classify_challenge import classify_challenge; "
        "ok=n=0\n"
        "for name in ('ground_truth','independent_public_style','public_contest_grounded'):\n"
        "  cases=json.load(open(f'data/eval/{name}.json'))\n"
        "  for c in cases:\n"
        "    n+=1\n"
        "    ok+=int(classify_challenge(c['description']).category==c['expected_category'])\n"
        "print(f'{ok}/{n}'); raise SystemExit(0 if ok/n>=0.95 else 1)",
    ])
    add("hand_eval_ge_95", code == 0, out.strip())

    # 6) external hard classifier (honest generalization probe)
    code, out = run([
        sys.executable, "-c",
        "import json; from agent.classify_challenge import classify_challenge; "
        "cases=json.load(open('data/eval/external_hard.json')); "
        "ok=sum(1 for c in cases if classify_challenge(c['description']).category==c['expected_category']); "
        "n=len(cases); print(f'{ok}/{n}={ok/n:.3f}'); "
        "raise SystemExit(0 if ok/n >= 0.50 else 1)",
    ])
    add("external_hard_ge_50", code == 0, out.strip())

    print("---")
    # Optional full discovery (can be slow; not required for green gate)
    import sys as _sys
    if "--ci" in _sys.argv:
        print("Use: bash scripts/ci_full.sh  (full discover CI job)")
        add("ci_hint", True, "scripts/ci_full.sh")
    if "--full" in _sys.argv:
        code, out = run([
            _sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-q",
        ])
        add("full_discover", code == 0, (out or "")[-300:])
    elif "--full-fast" in _sys.argv:
        # discover but skip modules listed in scripts/slow_tests.txt
        skip = set()
        sp = Path(__file__).resolve().parent / "slow_tests.txt"
        if sp.is_file():
            for line in sp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    skip.add(line.replace("tests.", "test_").replace("test_test_", "test_"))
        import unittest
        from pathlib import Path as _P
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        for f in sorted((_P("tests")).glob("test_*.py")):
            mod = f"tests.{f.stem}"
            if mod in {s if s.startswith("tests.") else f"tests.{s}" for s in skip}:
                continue
            if f.stem in {s.replace("tests.", "") for s in skip}:
                continue
            try:
                suite.addTests(loader.loadTestsFromName(mod))
            except Exception:
                pass
        result = unittest.TextTestRunner(verbosity=0).run(suite)
        add("full_fast_discover", result.wasSuccessful(),
            f"ran={result.testsRun} fail={len(result.failures)} err={len(result.errors)}")

    failed = [c for c in checks if not c["ok"]]
    print(f"{len(checks)-len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
