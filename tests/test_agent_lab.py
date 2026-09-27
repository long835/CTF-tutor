"""agent --lab and confidence policy."""

from __future__ import annotations

import unittest


class TestConfidencePolicy(unittest.TestCase):
    def test_not_probability(self):
        from agent.confidence_policy import present_confidence
        p = present_confidence(0.82, has_hypothesis=True, evidence_count=2)
        self.assertFalse(p["belief_score_is_probability"])
        self.assertIn("verification_level", p)
        self.assertIn("not a calibrated", p["disclaimer"])


class TestAgentLabAttach(unittest.TestCase):
    def test_lab_prep(self):
        from agent.experience_labs import attach_lab_to_workspace, get_lab
        lab = get_lab("pwn_bof")
        self.assertIsNotNone(lab)
        r = attach_lab_to_workspace("pwn_bof", challenge_id="test-agent-lab")
        self.assertTrue(r["copied"])


class TestFmtLab(unittest.TestCase):
    def test_binary(self):
        from pathlib import Path
        p = Path(__file__).resolve().parents[1] / "data/samples/experience/pwn_fmt/vuln"
        self.assertTrue(p.is_file())


if __name__ == "__main__":
    unittest.main()
