"""Tests for the Phase 1 reliability work: tool results, structured output,
model profiles, context management, and evidence requirements."""

import json
import os
import unittest


class TestToolResultSemantics(unittest.TestCase):
    """The core bug: failure and emptiness must not look the same."""

    def test_empty_is_evidence_of_absence(self):
        from agent.tool_result import ToolResult, ToolStatus
        r = ToolResult(tool="strings", status=ToolStatus.EMPTY).finalize()
        self.assertTrue(r.is_evidence_of_absence)
        self.assertTrue(r.ok)
        self.assertFalse(r.found_something)

    def test_failure_is_not_evidence_of_absence(self):
        from agent.tool_result import ToolResult, ToolStatus
        for status in (ToolStatus.ERROR, ToolStatus.TIMEOUT, ToolStatus.UNAVAILABLE, ToolStatus.DENIED):
            r = ToolResult(tool="ghidra", status=status, error="boom").finalize()
            self.assertFalse(r.is_evidence_of_absence, f"{status} must not read as absence")
            self.assertFalse(r.ok)
            self.assertTrue(r.status.is_failure)

    def test_ok_with_no_content_becomes_empty(self):
        from agent.tool_result import ToolResult, ToolStatus
        r = ToolResult(tool="x", status=ToolStatus.OK).finalize()
        self.assertIs(r.status, ToolStatus.EMPTY)

    def test_retryable_only_for_transient_failures(self):
        from agent.tool_result import ToolResult, ToolStatus
        self.assertTrue(ToolResult(tool="x", status=ToolStatus.TIMEOUT).finalize().retryable)
        self.assertFalse(ToolResult(tool="x", status=ToolStatus.UNAVAILABLE).finalize().retryable)
        self.assertFalse(ToolResult(tool="x", status=ToolStatus.DENIED).finalize().retryable)

    def test_error_classification(self):
        from agent.tool_result import ToolStatus, classify_error
        self.assertIs(classify_error("operation timed out"), ToolStatus.TIMEOUT)
        self.assertIs(classify_error("permission denied"), ToolStatus.DENIED)
        self.assertIs(classify_error("command not found: ghidra"), ToolStatus.UNAVAILABLE)
        self.assertIs(classify_error("ValueError: bad input"), ToolStatus.ERROR)

    def test_legacy_tuple_round_trip(self):
        from agent.tool_result import ToolResult
        r = ToolResult.from_tuple("t", (True, '{"category": "web"}', ""))
        self.assertTrue(r.ok)
        ok, out, err = r.to_tuple()
        self.assertTrue(ok)
        self.assertIn("web", out)

    def test_success_payload_announcing_unavailability_is_reclassified(self):
        """A tool that 'succeeded' while saying it is unavailable is not OK."""
        from agent.tool_result import ToolResult, ToolStatus
        r = ToolResult.from_tuple("retrieve", (True, '{"matches": [], "note": "retrieval unavailable: x"}', ""))
        self.assertIs(r.status, ToolStatus.UNAVAILABLE)
        self.assertFalse(r.is_evidence_of_absence)

    def test_observations_extracted_from_payload(self):
        from agent.tool_result import observations_from_payload
        obs = observations_from_payload('{"matches":[{"name":"A","score":0.9}],"category":"web"}', "retrieve")
        kinds = {o.kind for o in obs}
        self.assertIn("retrieval_match", kinds)
        self.assertIn("classification", kinds)

    def test_run_tool_safely_converts_exceptions(self):
        from agent.tool_result import run_tool_safely
        def boom(args):
            raise RuntimeError("kaboom")
        r = run_tool_safely("bad", boom)
        self.assertFalse(r.ok)
        self.assertIn("kaboom", r.error)
        self.assertFalse(r.is_evidence_of_absence)

    def test_merge_separates_failed_from_empty(self):
        from agent.tool_result import ToolResult, ToolStatus, merge
        summary = merge([
            ToolResult(tool="a", status=ToolStatus.EMPTY).finalize(),
            ToolResult(tool="b", status=ToolStatus.ERROR, error="x").finalize(),
            ToolResult(tool="c", raw_output="found").finalize(),
        ])
        self.assertEqual(summary["empty"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["productive"], 1)


class TestRetrieveNoLongerLiesAboutEmptiness(unittest.TestCase):
    def test_working_retrieval_reports_searched(self):
        from agent.executor import _run_retrieve
        ok, out, _ = _run_retrieve({"query": "jwt alg none", "category": "web"})
        payload = json.loads(out)
        self.assertTrue(ok)
        self.assertTrue(payload["searched"])
        self.assertIn(payload["status"], ("ok", "empty"))

    def test_disabled_retrieval_is_marked_skipped_not_empty(self):
        from agent.executor import _run_retrieve
        os.environ["CTF_TUTOR_DISABLE_RETRIEVE"] = "1"
        try:
            _, out, _ = _run_retrieve({"query": "anything"})
            payload = json.loads(out)
            self.assertEqual(payload["status"], "skipped")
            self.assertFalse(payload["searched"])
        finally:
            os.environ.pop("CTF_TUTOR_DISABLE_RETRIEVE", None)


class TestStructuredOutput(unittest.TestCase):
    def test_clean_json(self):
        from agent.structured import CLASSIFY_SCHEMA, parse_structured
        r = parse_structured('{"category":"web","confidence":0.9}', CLASSIFY_SCHEMA)
        self.assertTrue(r.ok)
        self.assertEqual(r.method, "direct")

    def test_repairs(self):
        from agent.structured import CLASSIFY_SCHEMA, parse_structured
        cases = {
            '```json\n{"category":"web"}\n```': "strip_fences",
            '<think>hmm</think>{"category":"web"}': "strip_thinking",
            "{'category': 'web',}": "fix_trailing_commas",
            'Here: {"category": "web", "confidence": True}': "fix_python_literals",
            '{"category": "web", "confidence": 0.5': "close_brackets",
        }
        for raw, expected in cases.items():
            r = parse_structured(raw, CLASSIFY_SCHEMA)
            self.assertTrue(r.ok, f"failed to repair: {raw}")
            self.assertEqual(r.data["category"], "web")
            self.assertIn(expected, r.repairs)

    def test_value_clamping_and_case_normalisation(self):
        from agent.structured import CLASSIFY_SCHEMA, parse_structured
        r = parse_structured('{"category":"CRYPTO","confidence":1.5}', CLASSIFY_SCHEMA)
        self.assertEqual(r.data["category"], "crypto")
        self.assertEqual(r.data["confidence"], 1.0)

    def test_string_to_list_coercion(self):
        from agent.structured import VERIFY_SCHEMA, parse_structured
        r = parse_structured('{"verdict":"pass","reasons":"one; two"}', VERIFY_SCHEMA)
        self.assertEqual(r.data["reasons"], ["one", "two"])

    def test_unparseable_is_reported_not_raised(self):
        from agent.structured import CLASSIFY_SCHEMA, parse_structured
        r = parse_structured("no json at all", CLASSIFY_SCHEMA)
        self.assertFalse(r.ok)
        self.assertEqual(r.method, "unparseable")

    def test_fallback_is_used(self):
        from agent.structured import CLASSIFY_SCHEMA, parse_structured
        r = parse_structured("garbage", CLASSIFY_SCHEMA, fallback=lambda t: {"category": "misc"})
        self.assertTrue(r.ok)
        self.assertEqual(r.method, "fallback")

    def test_invalid_choice_rejected_not_invented(self):
        from agent.structured import CLASSIFY_SCHEMA, parse_structured
        r = parse_structured('{"category":"banana"}', CLASSIFY_SCHEMA)
        self.assertFalse(r.ok)
        self.assertTrue(any("category" in p for p in r.problems))

    def test_retry_path(self):
        from agent.structured import CLASSIFY_SCHEMA, request_structured
        attempts = []
        def model(system, user):
            attempts.append(system)
            return "garbage" if len(attempts) == 1 else '{"category":"pwn","confidence":0.8}'
        r = request_structured(model, "sys", "usr", CLASSIFY_SCHEMA, max_attempts=2)
        self.assertTrue(r.ok)
        self.assertEqual(r.attempts, 2)
        self.assertIn("Exact shape", attempts[1])

    def test_model_exception_does_not_propagate(self):
        from agent.structured import CLASSIFY_SCHEMA, request_structured
        def model(system, user):
            raise ConnectionError("model down")
        r = request_structured(model, "s", "u", CLASSIFY_SCHEMA, max_attempts=2)
        self.assertFalse(r.ok)
        self.assertIn("category", r.data)


class TestModelProfile(unittest.TestCase):
    def test_tiers(self):
        from agent.model_profile import ModelTier, get_profile
        self.assertIs(get_profile("phi-3").tier, ModelTier.TINY)
        self.assertIs(get_profile("qwen3:8b").tier, ModelTier.SMALL)
        self.assertIs(get_profile("llama3:70b").tier, ModelTier.LARGE)
        self.assertIs(get_profile("gpt-4o").tier, ModelTier.FRONTIER)

    def test_specific_size_beats_generic_family_pattern(self):
        from agent.model_profile import ModelTier, get_profile
        self.assertIs(get_profile("llama3:70b").tier, ModelTier.LARGE)
        self.assertIs(get_profile("llama3.2:3b").tier, ModelTier.TINY)

    def test_unknown_model_gets_conservative_defaults(self):
        from agent.model_profile import ModelTier, get_profile
        p = get_profile("totally-made-up-model")
        self.assertIs(p.tier, ModelTier.SMALL)
        self.assertIn("Unrecognised", p.notes)

    def test_budgets_scale_with_tier(self):
        from agent.model_profile import get_profile
        self.assertLess(get_profile("phi-3").max_plan_steps, get_profile("gpt-4o").max_plan_steps)

    def test_quantization_detected(self):
        from agent.model_profile import get_profile
        self.assertEqual(get_profile("mymodel-13b-q4_k_m").quantization, "Q4_K_M")
        self.assertEqual(get_profile("mymodel:14b-q8_0").quantization, "Q8_0")

    def test_qwen_thinking_flag(self):
        from agent.model_profile import get_profile
        self.assertTrue(get_profile("qwen3:8b").emits_thinking_blocks)

    def test_context_budget_leaves_headroom(self):
        from agent.model_profile import get_profile
        p = get_profile("qwen3:8b")
        self.assertLess(p.context_budget, p.context_length)

    def test_env_override(self):
        from agent.model_profile import get_profile
        os.environ["CTF_TUTOR_MODEL_CONTEXT"] = "2048"
        try:
            self.assertEqual(get_profile("qwen3:8b").context_length, 2048)
        finally:
            os.environ.pop("CTF_TUTOR_MODEL_CONTEXT", None)

    def test_hardware_detection_never_raises(self):
        from agent.model_profile import detect_hardware
        hw = detect_hardware()
        self.assertIsInstance(hw.to_dict(), dict)

    def test_hosted_models_ignore_local_resources(self):
        from agent.model_profile import Hardware, get_profile
        ok, _ = Hardware(ram_gb=2.0).can_run(get_profile("gpt-4o"))
        self.assertTrue(ok)


class TestContextManager(unittest.TestCase):
    def test_token_estimate_is_positive(self):
        from agent.context import estimate_tokens
        self.assertGreater(estimate_tokens("hello world"), 0)
        self.assertEqual(estimate_tokens(""), 0)

    def test_low_value_items_dropped_first(self):
        from agent.context import ContextBudget, ContextManager, Priority, Scope
        m = ContextManager(ContextBudget(total=1000))
        m.add_task("find the overflow")
        m.add("NOISE " * 2000, Scope.TOOL, Priority.LOW, "noise")
        text, report = m.build(query="overflow")
        self.assertIn("find the overflow", text)
        self.assertIn("noise", report["dropped"])

    def test_pinned_survives_pressure(self):
        from agent.context import ContextBudget, ContextManager
        m = ContextManager(ContextBudget(total=600))
        m.add_task("critical task text")
        for i in range(30):
            m.add(f"filler {i} " * 200, label=f"f{i}")
        text, _ = m.build()
        self.assertIn("critical task text", text)

    def test_truncation_is_announced(self):
        from agent.context import truncate_middle
        out = truncate_middle("A" * 6000, 200, "big file")
        self.assertIn("omitted from the middle", out)
        self.assertIn("big file", out)

    def test_challenge_switch_clears_contamination(self):
        from agent.context import ContextManager, Priority, Scope
        m = ContextManager(challenge_id="c1")
        m.add("PIE disabled", Scope.CHALLENGE, Priority.HIGH, "fact")
        m.add("student knows overflow", Scope.STUDENT, Priority.MEDIUM, "student")
        removed = m.switch_challenge("c2")
        self.assertEqual(removed, 1)
        text, _ = m.build()
        self.assertNotIn("PIE disabled", text)
        self.assertIn("student knows overflow", text)

    def test_same_challenge_switch_is_noop(self):
        from agent.context import ContextManager
        m = ContextManager(challenge_id="c1")
        self.assertEqual(m.switch_challenge("c1"), 0)

    def test_failed_tool_recorded_as_non_absence(self):
        from agent.context import ContextManager
        from agent.tool_result import ToolResult, ToolStatus
        m = ContextManager()
        m.add_tool_result(ToolResult(tool="ghidra", status=ToolStatus.ERROR, error="missing").finalize())
        text, _ = m.build()
        self.assertIn("not evidence of absence", text)

    def test_empty_tool_recorded_as_finding(self):
        from agent.context import ContextManager
        from agent.tool_result import ToolResult, ToolStatus
        m = ContextManager()
        m.add_tool_result(ToolResult(tool="strings", status=ToolStatus.EMPTY).finalize())
        text, _ = m.build()
        self.assertIn("IS a finding", text)

    def test_relevance_prefers_matching_keywords(self):
        from agent.context import ContextBudget, ContextManager, Priority, Scope
        m = ContextManager(ContextBudget(total=900))
        m.add("something about jwt algorithm confusion", Scope.TOOL, Priority.MEDIUM, "relevant")
        m.add("unrelated notes about cake recipes", Scope.TOOL, Priority.MEDIUM, "irrelevant")
        text, _ = m.build(query="jwt algorithm")
        self.assertLess(text.index("jwt algorithm confusion"), text.index("cake") if "cake" in text else 10**9)

    def test_budget_from_profile(self):
        from agent.context import ContextBudget
        from agent.model_profile import get_profile
        small = ContextBudget.from_profile(get_profile("phi-3"))
        big = ContextBudget.from_profile(get_profile("gpt-4o"))
        self.assertLess(small.available, big.available)


class TestEvidenceRequirements(unittest.TestCase):
    def test_full_signals_support_the_claim(self):
        from agent.evidence import SupportLevel, assess
        a = assess("stack-buffer-overflow",
                   "binary uses gets() into a 64 byte local buffer, NX enabled, win function present")
        self.assertIs(a.level, SupportLevel.SUPPORTED)

    def test_contradicting_signal_refutes(self):
        from agent.evidence import SupportLevel, assess
        a = assess("sql-injection", "the login query uses prepared statement placeholders")
        self.assertIs(a.level, SupportLevel.REFUTED)

    def test_weak_signal_is_uncertain_not_concluded(self):
        """'printf exists' must not become 'format string vulnerability'."""
        from agent.evidence import SupportLevel, assess
        a = assess("format-string", "printf is called somewhere in the binary")
        self.assertIn(a.level, (SupportLevel.UNCERTAIN, SupportLevel.INSUFFICIENT_EVIDENCE))
        self.assertTrue(a.open_alternatives)

    def test_unknown_technique_returns_insufficient(self):
        from agent.evidence import SupportLevel, assess
        a = assess("not-a-real-technique", "lots of text")
        self.assertIs(a.level, SupportLevel.INSUFFICIENT_EVIDENCE)

    def test_alternatives_present_for_ambiguous_signals(self):
        from agent.evidence import assess
        a = assess("packed-binary", "high entropy section detected")
        self.assertTrue(any("compress" in alt.lower() for alt in a.open_alternatives))

    def test_next_evidence_is_actionable(self):
        from agent.evidence import assess, next_evidence_to_seek
        steps = next_evidence_to_seek(assess("format-string", "printf appears"))
        self.assertTrue(steps)

    def test_refuted_tells_agent_to_abandon(self):
        from agent.evidence import assess, next_evidence_to_seek
        steps = next_evidence_to_seek(assess("sql-injection", "uses prepared statement"))
        self.assertIn("abandon", steps[0])

    def test_every_requirement_is_well_formed(self):
        from agent.evidence import REQUIREMENTS
        for name, req in REQUIREMENTS.items():
            self.assertEqual(name, req.technique)
            self.assertTrue(req.required, f"{name} has no required signals")
            self.assertTrue(req.alternatives, f"{name} has no negative knowledge")
            self.assertTrue(req.verification, f"{name} has no verification hint")


class TestVerifierEvidenceGate(unittest.TestCase):
    def _state(self, summary, facts):
        from agent.state import AgentState
        s = AgentState(challenge_id="test", challenge_summary=summary)
        for f in facts:
            s.add_fact(f)
        return s

    def test_model_cannot_upgrade_a_verdict_past_evidence(self):
        """A 'pass' from the model must not survive missing required signals."""
        from agent.evidence import SupportLevel, assess_state
        s = self._state("a web challenge", ["printf appears in the source"])
        s.add_hypothesis("format string bug", technique="format-string", confidence=0.9)
        a = assess_state(s)
        self.assertNotIn(a.level, (SupportLevel.SUPPORTED,))

    def test_contradiction_produces_fail(self):
        from agent.verifier import verify_solution
        s = self._state(
            "login page",
            ["the query uses prepared statement placeholders", "input is escaped"],
        )
        s.add_hypothesis("sqli in login", technique="sql-injection", confidence=0.9)
        result = verify_solution(s, candidate="sql injection in the login form")
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("evidence_assessment", result)


if __name__ == "__main__":
    unittest.main()
