"""Cheap calibration check against external_hard (or any labeled set)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


def calibration_report(path: str = "data/eval/external_hard.json") -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge

    cases = json.loads(Path(path).read_text(encoding="utf-8"))
    buckets = {i: {"n": 0, "correct": 0} for i in range(0, 11)}  # 0.0–1.0 by 0.1
    rows = []
    for c in cases:
        r = classify_challenge(c.get("description") or "")
        conf = float(getattr(r, "confidence", 0.0) or 0.0)
        ok = r.category == c.get("expected_category")
        b = min(10, max(0, int(conf * 10)))
        buckets[b]["n"] += 1
        buckets[b]["correct"] += int(ok)
        rows.append({"id": c.get("id"), "conf": conf, "ok": ok, "pred": r.category})

    table = []
    ece = 0.0
    total = max(len(cases), 1)
    for i in range(11):
        n = buckets[i]["n"]
        if not n:
            continue
        acc = buckets[i]["correct"] / n
        mid = i / 10 + 0.05
        ece += (n / total) * abs(acc - mid)
        table.append({"bucket": f"{i/10:.1f}-{(i+1)/10:.1f}", "n": n, "accuracy": round(acc, 3)})

    return {
        "cases": len(cases),
        "accuracy": round(sum(1 for r in rows if r["ok"]) / total, 3),
        "ece_approx": round(ece, 3),
        "buckets": table,
        "note": "ECE is approximate; confidence is heuristic belief, not calibrated probability.",
    }


def format_calibration(report: Dict[str, Any] | None = None) -> str:
    report = report or calibration_report()
    lines = [
        f"Calibration vs external set: accuracy={report['accuracy']} ECE≈{report['ece_approx']}",
        report.get("note") or "",
    ]
    for b in report.get("buckets") or []:
        lines.append(f"  {b['bucket']}: n={b['n']} acc={b['accuracy']}")
    return chr(10).join(lines)
