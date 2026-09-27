"""Fit a simple reliability map from labeled eval → apply as calibrated_probability.

This is NOT neural Platt scaling; it is empirical bin calibration on external_hard
(or any labeled JSON). Still report belief_score separately.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

FIT_PATH = Path("data/calibration_map.json")


def fit_bin_calibration(eval_path: str = "data/eval/external_hard.json", bins: int = 10) -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge

    cases = json.loads(Path(eval_path).read_text(encoding="utf-8"))
    bucket: Dict[int, List[int]] = {i: [] for i in range(bins)}
    for c in cases:
        r = classify_challenge(c.get("description") or "")
        conf = float(getattr(r, "confidence", 0.0) or 0.0)
        ok = int(r.category == c.get("expected_category"))
        b = min(bins - 1, max(0, int(conf * bins)))
        bucket[b].append(ok)

    mapping = []
    for i in range(bins):
        ys = bucket[i]
        acc = sum(ys) / len(ys) if ys else None
        lo, hi = i / bins, (i + 1) / bins
        mapping.append({"lo": lo, "hi": hi, "n": len(ys), "empirical_acc": acc})

    payload = {"bins": bins, "source": eval_path, "mapping": mapping}
    FIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def load_map() -> Dict[str, Any] | None:
    if not FIT_PATH.is_file():
        return None
    try:
        return json.loads(FIT_PATH.read_text(encoding="utf-8"))
    except Exception:
        return None


def calibrated_probability(belief_score: float, fit: Dict[str, Any] | None = None) -> float | None:
    fit = fit or load_map()
    if not fit:
        return None
    bins = int(fit.get("bins") or 10)
    b = min(bins - 1, max(0, int(float(belief_score) * bins)))
    row = (fit.get("mapping") or [None] * bins)[b]
    if not row or row.get("empirical_acc") is None:
        return None
    return float(row["empirical_acc"])


def present_with_calibration(belief_score: float) -> Dict[str, Any]:
    cal = calibrated_probability(belief_score)
    return {
        "belief_score": round(float(belief_score), 3),
        "belief_score_is_probability": False,
        "calibrated_probability": None if cal is None else round(cal, 3),
        "calibration_source": str(FIT_PATH) if cal is not None else None,
        "disclaimer": "calibrated_probability is empirical bin accuracy on the fit set, not a guarantee.",
    }


def fit_isotonic(eval_path: str = "data/eval/external_hard.json"):
    """Monotonic (PAVA-style) fit via agent.calibration_isotonic if available."""
    try:
        from agent.calibration_isotonic import fit_isotonic as _fit
        return _fit(eval_path)
    except Exception:
        try:
            from agent import calibration_isotonic as ci
            if hasattr(ci, "fit"):
                return ci.fit(eval_path)
        except Exception as e:
            return {"ok": False, "error": str(e)}
    return {"ok": False, "error": "isotonic unavailable"}
