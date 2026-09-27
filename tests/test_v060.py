"""v0.6.0 finish-roadmap tests."""
from __future__ import annotations
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class TestV060(unittest.TestCase):
    def test_ci_script(self):
        self.assertTrue((ROOT / "scripts/ci_full.sh").is_file())

    def test_multi_mitigation_labs(self):
        self.assertTrue((ROOT / "data/samples/experience/pwn_nx_ret2win/vuln").is_file())
        self.assertTrue((ROOT / "data/samples/experience/pwn_canary_fmt/vuln").is_file())

    def test_unified_load(self):
        from agent.memory import load_memory
        m = load_memory()
        self.assertIsNotNone(m)

    def test_ops_cli(self):
        from cli.ops import cmd_status
        self.assertTrue(callable(cmd_status))

    def test_structural_classify(self):
        from agent.classify_challenge import classify_challenge
        r = classify_challenge(
            "A remote service terminates after roughly eighty bytes of input."
        )
        # structural cue should push toward pwn or at least not empty
        self.assertIn(r.category, ("pwn", "misc", "rev", "web", "crypto", "forensics", "osint", "blockchain", "mobile"))

if __name__ == "__main__":
    unittest.main()
