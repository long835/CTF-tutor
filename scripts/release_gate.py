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

    failed = [c for c in checks if not c["ok"]]
    print("---")
    print(f"{len(checks)-len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
