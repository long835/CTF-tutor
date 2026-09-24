"""Blind / public-style classification eval (not corpus-wording)."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEPENDENT = ROOT / "data" / "eval" / "independent_public_style.json"
PUBLIC = ROOT / "data" / "eval" / "public_contest_grounded.json"


class TestIndependentEval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with INDEPENDENT.open(encoding="utf-8") as f:
            cls.cases = json.load(f)
        assert isinstance(cls.cases, list) and cls.cases

    def test_file_has_at_least_20_cases(self):
        self.assertGreaterEqual(len(self.cases), 20)

    def test_formal_classifier_accuracy_at_least_80_percent(self):
        from agent.classify_challenge import classify_challenge

        ok = 0
        misses = []
        for case in self.cases:
            pred = classify_challenge(case["description"]).category
            if pred == case["expected_category"]:
                ok += 1
            else:
                misses.append((case["id"], pred, case["expected_category"]))
        accuracy = ok / len(self.cases)
        self.assertGreaterEqual(
            accuracy,
            0.80,
            f"accuracy {accuracy:.3f} below 0.80; misses={misses}",
        )

    def test_cases_carry_source_style_marker(self):
        for case in self.cases:
            self.assertEqual(case.get("source_style"), "public-contest-paraphrase")


class TestPublicContestGroundedEval(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with PUBLIC.open(encoding="utf-8") as f:
            cls.cases = json.load(f)
        assert isinstance(cls.cases, list) and cls.cases

    def test_file_has_at_least_10_cases(self):
        self.assertGreaterEqual(len(self.cases), 10)

    def test_formal_classifier_accuracy_at_least_80_percent(self):
        from agent.classify_challenge import classify_challenge

        ok = 0
        misses = []
        for case in self.cases:
            pred = classify_challenge(case["description"]).category
            if pred == case["expected_category"]:
                ok += 1
            else:
                misses.append((case["id"], pred, case["expected_category"]))
        accuracy = ok / len(self.cases)
        self.assertGreaterEqual(
            accuracy,
            0.80,
            f"accuracy {accuracy:.3f} below 0.80; misses={misses}",
        )

    def test_cases_are_public_contest_grounded(self):
        for case in self.cases:
            self.assertEqual(case.get("source_style"), "public-contest-grounded")
            self.assertTrue(case.get("attribution"))


class TestGroundTruthStillStrong(unittest.TestCase):
    def test_ground_truth_at_least_90_percent(self):
        from agent.classify_challenge import classify_challenge

        path = ROOT / "data" / "eval" / "ground_truth.json"
        cases = json.loads(path.read_text(encoding="utf-8"))
        ok = sum(
            1
            for c in cases
            if classify_challenge(c["description"]).category == c["expected_category"]
        )
        self.assertGreaterEqual(ok / len(cases), 0.90)


if __name__ == "__main__":
    unittest.main()
