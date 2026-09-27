"""Ambiguous JWT lab exists for hypothesis elimination practice."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestAmbiguousLab(unittest.TestCase):
    def test_present(self):
        d = ROOT / "data/samples/experience/web_jwt_ambiguous"
        self.assertTrue((d / "token.txt").is_file())
        self.assertTrue((d / "notes.txt").is_file())
        from agent.experience_labs import get_lab
        lab = get_lab("web_jwt_ambiguous")
        self.assertIsNotNone(lab)
        self.assertEqual(lab.category, "web")


if __name__ == "__main__":
    unittest.main()
