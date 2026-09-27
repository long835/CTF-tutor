"""v0.5.1 unified store + curriculum next + new labs."""
from __future__ import annotations
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class TestUnifiedStore(unittest.TestCase):
    def test_record(self):
        from agent.unified_learner_store import record_attempt_unified, load_store
        record_attempt_unified("test-tech-v051", success=True, hint_level=1, scenario="unit")
        store = load_store()
        self.assertTrue(any(a.get("technique") == "test-tech-v051" for a in store.get("attempts") or []))

class TestCurriculumNext(unittest.TestCase):
    def test_next(self):
        from agent.curriculum_next import next_practice
        d = next_practice(limit=3)
        self.assertIn("due_reviews", d)
        self.assertIn("suggested_labs", d)

class TestNewLabs(unittest.TestCase):
    def test_ret2win(self):
        self.assertTrue((ROOT / "data/samples/experience/pwn_ret2win/vuln").is_file())
    def test_decoy_name(self):
        p = ROOT / "data/samples/experience/forensics_decoy_name/invoice.pdf"
        self.assertTrue(p.is_file())
        self.assertTrue(p.read_bytes().startswith(b"\x89PNG"))

if __name__ == "__main__":
    unittest.main()
