"""v0.8.0 in-bounds remaining items."""
from __future__ import annotations
import unittest

class TestV080(unittest.TestCase):
    def test_calibration_fit(self):
        from agent.calibration_fit import fit_bin_calibration, calibrated_probability
        fit_bin_calibration()
        p = calibrated_probability(0.8)
        self.assertTrue(p is None or 0.0 <= p <= 1.0)

    def test_independent_checks(self):
        from agent.independent_checks import independent_static_checks
        r = independent_static_checks("service crashes after long input")
        self.assertGreaterEqual(r["count"], 1)

    def test_active_web_requires_approval(self):
        from agent import active_web
        active_web.clear_target()
        r = active_web.safe_get("/")
        self.assertFalse(r.get("ok"))

    def test_perf(self):
        from agent.perf_bench import run_microbench
        r = run_microbench(10)
        self.assertIn("per_call_ms", r)

    def test_model_compare(self):
        from agent.model_compare import compare_heuristic_vs_llm
        r = compare_heuristic_vs_llm(limit=5)
        self.assertIn("heuristic_accuracy", r)

if __name__ == "__main__":
    unittest.main()
