"""Spaced repetition and experience samples."""
from __future__ import annotations
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
class TestSpacedRepetition(unittest.TestCase):
    def test_review_cycle(self):
        from agent.spaced_repetition import ReviewStore
        store = ReviewStore()
        c = store.review("ret2win", result="good")
        self.assertGreaterEqual(c.repetitions, 1)
        store.review("ret2win", result="again")
        self.assertEqual(store.ensure("ret2win").repetitions, 0)
class TestExperienceSamples(unittest.TestCase):
    def test_manifest(self):
        import json
        m = json.loads((ROOT / "data/samples/experience/manifest.json").read_text())
        self.assertGreaterEqual(len(m["items"]), 3)
        for item in m["items"]:
            self.assertTrue((ROOT / "data/samples/experience" / item["path"]).exists())
class TestCliQualityImport(unittest.TestCase):
    def test_import(self):
        from cli.quality import cmd_status, cmd_review
        self.assertTrue(callable(cmd_status))
if __name__ == "__main__":
    unittest.main()
