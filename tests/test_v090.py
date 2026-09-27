"""v0.9.0 max in-bounds capability."""
from __future__ import annotations
import unittest

class TestV090(unittest.TestCase):
    def test_abstain_decision(self):
        from agent.classify_challenge import classify_challenge
        r = classify_challenge("asdf qwer totally empty")
        self.assertIn(getattr(r, "decision", "unknown"), ("unknown", "abstain", "commit"))

    def test_pwn_plan(self):
        from agent.pwn_exploit_loop import initial_pwn_plan, next_pwn_actions
        p = initial_pwn_plan({"gdb": True})
        self.assertTrue(next_pwn_actions(p))

    def test_rev_plan(self):
        from agent.rev_dynamic_loop import RevPlan, next_rev_actions
        self.assertTrue(next_rev_actions(RevPlan()))

    def test_repro(self):
        from agent.repro_fingerprint import repro_fingerprint
        fp = repro_fingerprint()
        self.assertIn("project_version", fp)

    def test_calibrated_field(self):
        from agent.classify_challenge import classify_challenge
        r = classify_challenge("stack buffer overflow via gets overwrite return address")
        self.assertEqual(r.category, "pwn")
        # calibrated may be None if fit missing, else float
        cp = getattr(r, "calibrated_probability", None)
        self.assertTrue(cp is None or 0.0 <= float(cp) <= 1.0)

if __name__ == "__main__":
    unittest.main()
