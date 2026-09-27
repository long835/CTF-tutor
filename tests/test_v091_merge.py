"""v0.9.1 merge integrity."""
from __future__ import annotations
import unittest

class TestMerge(unittest.TestCase):
    def test_ensemble_import(self):
        from agent.ensemble import classify_enhanced
        p = classify_enhanced("ELF crashes after long input", use_llm=False)
        self.assertTrue(getattr(p, "category", None))

    def test_pwn_rev_still_here(self):
        from agent.pwn_exploit_loop import initial_pwn_plan
        from agent.rev_dynamic_loop import RevPlan
        from agent.repro_fingerprint import repro_fingerprint
        self.assertTrue(initial_pwn_plan())
        self.assertTrue(RevPlan())
        self.assertIn("project_version", repro_fingerprint())

    def test_multilang_sandbox_path(self):
        import multilang
        src = open(multilang.__file__).read()
        self.assertIn("run_sandboxed", src)

    def test_ssrf(self):
        from agent.challenge_fetch import _url_host_allowed
        ok, _ = _url_host_allowed("http://127.0.0.1/x")
        self.assertFalse(ok)

if __name__ == "__main__":
    unittest.main()
