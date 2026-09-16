"""Tests for corpus, gdb helper, platforms dispatch, webui import."""

import json
import unittest
from pathlib import Path


class TestCorpus(unittest.TestCase):
    def test_build_min_120(self):
        from agent.corpus_builder import build_corpus, OUT_FILE
        summary = build_corpus(120)
        self.assertGreaterEqual(summary["total"], 120)
        self.assertTrue(Path(OUT_FILE).exists())
        lines = Path(OUT_FILE).read_text().strip().splitlines()
        self.assertGreaterEqual(len(lines), 120)
        row = json.loads(lines[0])
        self.assertIn("category", row)


class TestGdbHelper(unittest.TestCase):
    def test_gdb_available_bool(self):
        from agent.gdb_agent import gdb_available
        self.assertIsInstance(gdb_available(), bool)

    def test_missing_binary(self):
        from agent.gdb_agent import inspect_binary
        r = inspect_binary("/nonexistent/bin")
        self.assertFalse(r.get("ok", True))


class TestPlatformsOffline(unittest.TestCase):
    def test_htb_without_token(self):
        import os
        os.environ.pop("HTB_TOKEN", None)
        os.environ.pop("HACKTHEBOX_TOKEN", None)
        from agent.platforms import htb_list_machines
        r = htb_list_machines()
        self.assertFalse(r["ok"])
        self.assertIn("HTB_TOKEN", r["error"])

    def test_ctfd_bad_url(self):
        from agent.platforms import ctfd_list_challenges
        r = ctfd_list_challenges("http://127.0.0.1:1")
        self.assertFalse(r["ok"])


class TestWebuiImport(unittest.TestCase):
    def test_handler_exists(self):
        from webui.server import Handler, HTML
        self.assertIn("CTF-Tutor", HTML)
        self.assertTrue(hasattr(Handler, "do_POST"))


if __name__ == "__main__":
    unittest.main()
