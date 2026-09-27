"""v0.7.0 remaining-requirements coverage."""

from __future__ import annotations

import unittest


class TestV070(unittest.TestCase):
    def test_active_classify(self):
        from agent.active_classify import active_classify
        d = active_classify("A service crashes after long input to a binary.")
        self.assertIn("discriminators", d)
        self.assertIn("profile", d)

    def test_knowledge_coverage(self):
        from agent.knowledge_coverage import knowledge_coverage
        c = knowledge_coverage(["sql-injection", "stack-buffer-overflow"])
        self.assertIn("score", c)

    def test_retrieval_abstain(self):
        from agent.retrieval_abstain import should_abstain
        self.assertTrue(should_abstain([]).get("abstain"))
        self.assertTrue(should_abstain([{"score": 0.1}]).get("abstain"))
        self.assertFalse(should_abstain([{"score": 0.9}]).get("abstain"))

    def test_tool_result_empty_success(self):
        from agent.tool_result_schema import normalize_tool_result
        r = normalize_tool_result("strings", True, "")
        self.assertEqual(r.status, "success")
        self.assertEqual(r.coverage, "partial")

    def test_ssrf_blocks_localhost(self):
        from agent.challenge_fetch import _url_host_allowed
        ok, reason = _url_host_allowed("http://127.0.0.1/x")
        self.assertFalse(ok)

    def test_env_snapshot(self):
        from agent.environment_snapshot import environment_snapshot
        s = environment_snapshot()
        self.assertIn("python", s)

    def test_held_out_exists(self):
        from pathlib import Path
        import json
        p = Path("data/eval/held_out_mixed.json")
        self.assertTrue(p.is_file())
        self.assertGreaterEqual(len(json.loads(p.read_text())), 20)


if __name__ == "__main__":
    unittest.main()
