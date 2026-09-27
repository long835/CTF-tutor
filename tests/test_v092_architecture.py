"""v0.9.2 coherent architecture tests."""
from __future__ import annotations
import unittest

class TestArch(unittest.TestCase):
    def test_pipeline(self):
        from agent.classify_pipeline import classify_pipeline
        d = classify_pipeline("ELF crashes after long input", use_llm=False)
        self.assertIn(d["category"], ("pwn", "rev", "misc", "web"))
        self.assertIn("arbitration", d)
        self.assertIn("decision", d)

    def test_capability(self):
        from agent.capability_plan import plan_for_category, capability_snapshot
        c = capability_snapshot()
        self.assertTrue(c["can"] and c["cannot"])
        p = plan_for_category("pwn")
        self.assertEqual(p["category"], "pwn")
        self.assertTrue(p["next_actions"])

    def test_arbitrate_artifact_authoritative(self):
        from agent.classify_challenge import classify_challenge
        from agent.classify_pipeline import arbitrate
        # Force artifact kinds on profile
        p = classify_challenge("maybe web maybe pwn")
        p.artifact_kinds = ["elf"]
        p.confidence = 0.6
        p.decision = "commit"
        p.category = "pwn"
        out = arbitrate(p, {"ok": True, "category": "web", "confidence": 0.9})
        self.assertEqual(out["category"], "pwn")
        self.assertEqual(out["arbitration"], "artifact_authoritative")

if __name__ == "__main__":
    unittest.main()
