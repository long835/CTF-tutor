"""Unit tests for agent state, planner, and loop (no live Ollama required)."""

import unittest
from agent.state import (
    AgentState, Hypothesis, Evidence, new_challenge_state, ActionStatus,
)
from agent.planner import plan_next_action, SAFE_TOOLS
from agent.observer import observe
from agent.hypothesis import rank_hypotheses, _heuristic_update


class TestAgentState(unittest.TestCase):
    def test_new_state(self):
        s = new_challenge_state("JWT login portal with alg=none", category="web")
        self.assertEqual(s.category, "web")
        self.assertEqual(s.status, "investigating")
        self.assertEqual(s.step_count, 0)

    def test_add_hypothesis_and_rank(self):
        s = new_challenge_state("test challenge")
        h1 = s.add_hypothesis("SQL injection possible", technique="sql-injection", confidence=0.4)
        h2 = s.add_hypothesis("JWT none bypass", technique="jwt-none-bypass", confidence=0.7)
        ranked = rank_hypotheses(s)
        self.assertEqual(ranked[0].id, h2.id)
        self.assertEqual(s.top_hypothesis().technique, "jwt-none-bypass")

    def test_evidence_and_confidence(self):
        s = new_challenge_state("test")
        s.add_hypothesis("JWT issue", confidence=0.5)
        s.add_evidence("web_recon", "Found alg=none in code", finding="alg=none present")
        s.recompute_overall_confidence()
        self.assertGreater(s.overall_confidence, 0.0)

    def test_serialization_roundtrip(self):
        s = new_challenge_state("roundtrip challenge", category="crypto")
        s.add_hypothesis("weak RSA", technique="rsa-small-e", confidence=0.6)
        s.add_fact("n is 256 bits")
        blob = s.to_json()
        s2 = AgentState.from_json(blob)
        self.assertEqual(s2.challenge_summary, s.challenge_summary)
        self.assertEqual(len(s2.hypotheses), 1)
        self.assertEqual(s2.hypotheses[0].technique, "rsa-small-e")
        self.assertIn("n is 256 bits", s2.known_facts)

    def test_action_lifecycle(self):
        s = new_challenge_state("x")
        a = s.record_action("classify", {"description": "x"}, reason="seed")
        self.assertEqual(a.status, ActionStatus.PLANNED.value)
        s.mark_action_result(a.id, ActionStatus.SUCCEEDED.value, result_summary="web")
        self.assertEqual(s.actions[0].status, ActionStatus.SUCCEEDED.value)


class TestPlanner(unittest.TestCase):
    def test_first_action_is_classify_when_empty(self):
        s = new_challenge_state("A mysterious binary crashes on long input")
        plan = plan_next_action(s)
        self.assertIsNotNone(plan)
        self.assertEqual(plan.tool, "classify")

    def test_web_hypothesis_selects_web_recon(self):
        s = new_challenge_state("login portal", category="web")
        s.add_hypothesis("JWT alg confusion", technique="jwt-alg-confusion", category="web", confidence=0.6)
        # No source path → falls back to archive retrieval
        plan = plan_next_action(s)
        self.assertIn(plan.tool, ("web_recon", "retrieve_archive"))
        # With a path, prefers web_recon
        s.discovered_artifacts.append("app.py")
        plan2 = plan_next_action(s)
        self.assertEqual(plan2.tool, "web_recon")

    def test_crypto_hypothesis_selects_crypto(self):
        s = new_challenge_state("encrypted messages", category="crypto")
        s.add_hypothesis("single byte xor", technique="xor-single-byte", category="crypto", confidence=0.6)
        plan = plan_next_action(s)
        self.assertIn(plan.tool, ("crypto_toolkit", "auto_decode"))

    def test_safe_tools_catalogue(self):
        self.assertIn("retrieve_archive", SAFE_TOOLS)
        self.assertIn("static_analysis", SAFE_TOOLS)
        self.assertNotIn("shell", SAFE_TOOLS)
        self.assertNotIn("network_scan", SAFE_TOOLS)


class TestObserverHeuristic(unittest.TestCase):
    def test_observe_adds_evidence(self):
        s = new_challenge_state("test")
        s.add_hypothesis("something", confidence=0.5)
        e = observe(s, "web_recon", "Found JWT header alg=none", success=True)
        self.assertTrue(e.finding)
        self.assertEqual(len(s.evidence), 1)
        self.assertTrue(any("web_recon" in f for f in s.known_facts))

    def test_heuristic_update_raises_on_keyword_match(self):
        s = new_challenge_state("x")
        h = s.add_hypothesis("JWT none bypass", technique="jwt-none-bypass", confidence=0.4)
        _heuristic_update(s, "The token accepts alg none and skips signature verification")
        self.assertGreater(h.confidence, 0.4)


class TestAgentLoopSmoke(unittest.TestCase):
    def test_bootstrap_without_llm(self):
        """Bootstrap must not crash when Ollama is unavailable."""
        from agent.loop import AgentLoop
        agent = AgentLoop(
            "A login portal issues JWTs and accepts alg=none",
            category="web",
            max_steps=3,
        )
        # Force offline path by not requiring live model
        state = agent.bootstrap()
        self.assertTrue(len(state.hypotheses) >= 1)
        self.assertEqual(state.category, "web")

    def test_run_respects_max_steps(self):
        from agent.loop import AgentLoop
        agent = AgentLoop(
            "Some unknown challenge description with no files",
            max_steps=2,
        )
        state = agent.run(verify_at_end=False)
        self.assertLessEqual(state.step_count, 2)


if __name__ == "__main__":
    unittest.main()
