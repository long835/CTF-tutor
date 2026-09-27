"""External hard classifier set — wording deliberately unlike taxonomy."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads((ROOT / "data/eval/external_hard.json").read_text())


class TestExternalHard(unittest.TestCase):
    def test_cases_exist(self):
        self.assertGreaterEqual(len(CASES), 20)

    def test_accuracy_floor(self):
        """Honest floor — not the generated-benchmark 96% number."""
        from agent.classify_challenge import classify_challenge
        ok = sum(
            1
            for c in CASES
            if classify_challenge(c["description"]).category == c["expected_category"]
        )
        rate = ok / len(CASES)
        # Floor tracks real generalization pressure; raise only with real gains.
        self.assertGreaterEqual(rate, 0.55, f"external_hard {ok}/{len(CASES)}={rate:.3f}")

    def test_report_current(self):
        from agent.classify_challenge import classify_challenge
        ok = sum(
            1
            for c in CASES
            if classify_challenge(c["description"]).category == c["expected_category"]
        )
        # Always print for visibility in -v runs
        print(f"\nexternal_hard accuracy: {ok}/{len(CASES)} = {ok/len(CASES):.3f}")


if __name__ == "__main__":
    unittest.main()
