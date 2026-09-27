"""Imported provenance + heap lab."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestImported(unittest.TestCase):
    def test_load(self):
        from agent.imported_cases import load_imported, validate_all
        cases = load_imported()
        self.assertGreaterEqual(len(cases), 3)
        for c in cases:
            self.assertEqual(c["provenance"]["type"], "imported")
        self.assertGreaterEqual(validate_all()["cases"], 3)

    def test_classify_imported(self):
        from agent.classify_challenge import classify_challenge
        from agent.imported_cases import load_imported
        ok = 0
        for c in load_imported():
            r = classify_challenge(c["description"])
            if r.category == c["expected_category"]:
                ok += 1
        self.assertGreaterEqual(ok / len(load_imported()), 0.8)


class TestHeapLab(unittest.TestCase):
    def test_binary(self):
        p = ROOT / "data/samples/experience/pwn_heap/vuln"
        self.assertTrue(p.is_file())
        self.assertGreater(p.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
