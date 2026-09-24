"""Phase 6.5: blind classifier gains, multi-category, verification levels."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestBlindClassifierGain(unittest.TestCase):
    def test_generated_sample_at_least_70_percent(self):
        from agent.classify_challenge import classify_challenge
        path = ROOT / "data" / "eval" / "generated_ground_truth.json"
        cases = json.loads(path.read_text(encoding="utf-8"))[:200]
        ok = sum(
            1
            for c in cases
            if classify_challenge(c["description"]).category == c["expected_category"]
        )
        self.assertGreaterEqual(ok / len(cases), 0.90, f"got {ok}/{len(cases)}")

    def test_hand_sets_still_strong(self):
        from agent.classify_challenge import classify_challenge
        for name in ("ground_truth", "independent_public_style", "public_contest_grounded"):
            cases = json.loads((ROOT / "data" / "eval" / f"{name}.json").read_text())
            ok = sum(
                1
                for c in cases
                if classify_challenge(c["description"]).category == c["expected_category"]
            )
            self.assertGreaterEqual(ok / len(cases), 0.95, name)


class TestMultiCategory(unittest.TestCase):
    def test_profile_has_secondary_field(self):
        from agent.classify_challenge import classify_challenge
        r = classify_challenge("64-bit ELF with gets overflow and a win function")
        self.assertEqual(r.category, "pwn")
        self.assertTrue(hasattr(r, "secondary_categories"))


class TestVerificationLevels(unittest.TestCase):
    def test_hierarchy(self):
        from agent.verification_levels import assess_verification
        r0 = assess_verification(has_hypothesis=False)
        self.assertEqual(r0.level, 0)
        r1 = assess_verification(has_hypothesis=True, evidence_count=2, belief_score=0.6)
        self.assertEqual(r1.level, 1)
        r5 = assess_verification(
            has_hypothesis=True,
            evidence_count=2,
            tool_support=True,
            reproduction_ok=True,
            challenge_behavior_ok=True,
            flag_verified=True,
            belief_score=0.9,
        )
        self.assertEqual(r5.level, 5)
        self.assertIn("belief_score", r5.as_tutor_line())


if __name__ == "__main__":
    unittest.main()
