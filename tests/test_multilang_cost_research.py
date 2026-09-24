"""Multilang runners, cost meters, research tier ranking."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path


class TestMultilang(unittest.TestCase):
    def test_supported_includes_systems(self):
        from multilang import SUPPORTED_LANGUAGES
        for lang in ("python", "c", "cpp", "go", "rust", "java", "dotnet"):
            self.assertIn(lang, SUPPORTED_LANGUAGES)

    def test_python_run(self):
        from multilang import MultiLanguageSession
        with tempfile.TemporaryDirectory() as td:
            sess = MultiLanguageSession.create("unit-test", root=td, language="python")
            rec = sess.run_source("print(40+2)\n", language="python", timeout=5)
            self.assertFalse(rec.timed_out)
            self.assertEqual(rec.returncode, 0)
            self.assertIn("42", rec.stdout)


class TestCostMeters(unittest.TestCase):
    def test_estimate_and_record(self):
        from agent.cost_meters import estimate_usd, record_usage, ledger_summary
        usd = estimate_usd(1_000_000, 1_000_000)
        self.assertGreater(usd, 0)
        ev = record_usage(
            "plan",
            provider="openai_compatible",
            model="gpt-test",
            prompt_tokens=1000,
            completion_tokens=500,
            note="unit",
        )
        self.assertEqual(ev.task, "plan")
        self.assertGreaterEqual(ev.usd_estimate, 0)
        summary = ledger_summary()
        self.assertIn("events", summary)


class TestResearchTiers(unittest.TestCase):
    def test_domain_tiers(self):
        from agent.research import rank_source_tier
        self.assertEqual(rank_source_tier("https://docs.python.org/3/library/os.html"), 1)
        self.assertEqual(rank_source_tier("https://portswigger.net/web-security/sqli"), 2)
        self.assertEqual(rank_source_tier("https://unknown.example/x"), 4)

    def test_rank_hits_orders_by_tier(self):
        import time
        from agent.research import ResearchHit, rank_hits
        hits = [
            ResearchHit("web", "https://x", "s", 4, "web", time.time()),
            ResearchHit("docs", "https://y", "s", 1, "concept", time.time()),
        ]
        ordered = rank_hits(hits)
        self.assertEqual(ordered[0].title, "docs")


if __name__ == "__main__":
    unittest.main()
