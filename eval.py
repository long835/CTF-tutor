"""Local ground-truth evaluator for CTF-Tutor.

Default mode is dependency-light and evaluates classification only.  With
--decompose it also calls the configured local Ollama model and reports
technique precision/recall/F1 against data/eval/ground_truth.json.
"""
import argparse
import json
from pathlib import Path
from typing import Iterable, Set

import classifier

ROOT = Path(__file__).resolve().parent
DEFAULT_DATA = ROOT / "data" / "eval" / "ground_truth.json"


def _metrics(expected: Iterable[str], actual: Iterable[str]) -> tuple[float, float, float]:
    e, a = set(expected), set(actual)
    tp = len(e & a)
    precision = tp / len(a) if a else 0.0
    recall = tp / len(e) if e else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0
    return precision, recall, f1


def load_cases(path: Path):
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("ground-truth file must contain a JSON array")
    return data


def _predict(desc: str, which: str, model: str) -> str:
    """
    Pick a classifier.

    The formal classifier always returns a category; the legacy heuristic
    returns None whenever it is unsure, which scores as a miss. Both are kept
    so the difference stays measurable rather than becoming folklore.
    """
    if which == "formal":
        from agent.classify_challenge import classify_formal

        return classify_formal(desc)
    if model:
        return classifier.classify(desc, model=model)
    return classifier.classify_heuristic(desc)[0]


def run(path: Path = DEFAULT_DATA, decompose: bool = False, model: str = "",
        which: str = "formal") -> int:
    cases = load_cases(path)
    category_ok = 0
    tp = fp = fn = 0
    for case in cases:
        desc = str(case["description"])
        predicted = _predict(desc, which, model)
        ok = predicted == case["expected_category"]
        category_ok += int(ok)
        print(f"{case['id']}: category={predicted!r} expected={case['expected_category']!r} {'OK' if ok else 'MISS'}")
        if decompose:
            import decomposer
            subproblems = decomposer.decompose(desc, category=case["expected_category"], model=model)
            actual: Set[str] = {t for sp in subproblems for t in sp.likely_techniques}
            expected = set(case.get("expected_techniques", []))
            p, r, f1 = _metrics(expected, actual)
            tp += len(expected & actual); fp += len(actual - expected); fn += len(expected - actual)
            print(f"  techniques: precision={p:.3f} recall={r:.3f} f1={f1:.3f} actual={sorted(actual)}")
    accuracy = category_ok / len(cases) if cases else 0.0
    print(f"\nclassification accuracy: {category_ok}/{len(cases)} = {accuracy:.3f}")
    if decompose:
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        print(f"technique micro-precision: {precision:.3f}")
        print(f"technique micro-recall:    {recall:.3f}")
        print(f"technique micro-F1:        {f1:.3f}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--decompose", action="store_true", help="also evaluate technique tags using local Ollama")
    parser.add_argument("--model", default="", help="Ollama model for --decompose")
    parser.add_argument("--classifier", default="formal", choices=["formal", "heuristic"],
                        help="formal (agent/classify_challenge.py) or the legacy heuristic")
    args = parser.parse_args()
    raise SystemExit(run(args.data, args.decompose, args.model, args.classifier))
