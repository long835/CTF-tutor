"""Tests for the Phase 2 reasoning layer: evidence graph, belief updating,
recovery, tool capabilities, and the reasoning state machine.

Each test names the failure it prevents rather than the function it calls,
because most of these guard against a wrong *conclusion* the agent could
draw, not a crash.
"""

import unittest

from agent.state import new_challenge_state
from agent.tool_result import ToolResult, ToolStatus


def _binary_result(tool, *observations, status=ToolStatus.OK):
    result = ToolResult(tool=tool, status=status)
    for kind, value in observations:
        result.add(kind, value)
    return result.finalize()


class TestEvidenceGraphIngestion(unittest.TestCase):
    """A failed tool must not look like a tool that found nothing."""

    def test_failed_tool_adds_no_observations(self):
        from agent.evidence_graph import EvidenceGraph, NodeKind
        g = EvidenceGraph()
        failed = ToolResult(tool="ghidra", status=ToolStatus.ERROR, error="jvm crash").finalize()
        created = g.add_tool_result(failed, artifact="./bin")
        self.assertEqual(created, [])
        self.assertEqual(g.nodes_of_kind(NodeKind.OBSERVATION), [])
        self.assertEqual(len(g.coverage_gaps), 1)
        self.assertIn("ghidra", str(g.coverage_gaps[0]))

    def test_clean_empty_run_is_a_negative_observation(self):
        from agent.evidence_graph import EvidenceGraph, NodeKind
        g = EvidenceGraph()
        empty = ToolResult(tool="strings", status=ToolStatus.EMPTY).finalize()
        created = g.add_tool_result(empty)
        self.assertEqual(len(created), 1)
        self.assertTrue(created[0].negative)
        self.assertEqual(len(g.coverage_gaps), 0)
        self.assertEqual(len(g.nodes_of_kind(NodeKind.OBSERVATION)), 1)

    def test_two_tools_corroborate_one_tool_twice_does_not(self):
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph()
        g.add_tool_result(_binary_result("readelf", ("mitigation", "NX enabled")))
        g.add_tool_result(_binary_result("readelf", ("mitigation", "NX enabled")))
        node = g.node("obs:mitigation-nx-enabled")
        self.assertIsNotNone(node)
        self.assertEqual(node.independence, 1, "same tool twice is not corroboration")
        g.add_tool_result(_binary_result("checksec", ("mitigation", "NX enabled")))
        self.assertEqual(g.node("obs:mitigation-nx-enabled").independence, 2)
        self.assertEqual(g.stats()["corroborated"], 1)

    def test_artifact_is_linked_to_its_observations(self):
        from agent.evidence_graph import EdgeKind, EvidenceGraph
        g = EvidenceGraph()
        g.add_tool_result(_binary_result("readelf", ("import", "gets")), artifact="./vuln")
        chain = g.provenance("obs:import-gets")
        self.assertTrue(any("./vuln" in line for line in chain))
        self.assertTrue(g.edges_to("obs:import-gets", EdgeKind.YIELDS))

    def test_edges_to_unknown_nodes_are_refused(self):
        from agent.evidence_graph import EdgeKind, EvidenceGraph
        g = EvidenceGraph()
        self.assertIsNone(g.add_edge("nope", "also-nope", EdgeKind.SUPPORTS))


class TestEvidenceGraphContamination(unittest.TestCase):
    """Reference material must never support a claim about this challenge."""

    def test_retrieval_lands_as_knowledge_not_observation(self):
        from agent.evidence_graph import EvidenceGraph, NodeKind
        g = EvidenceGraph()
        g.add_tool_result(_binary_result(
            "retrieve_archive", ("retrieval_match", "Pattern WEB: JWT Validation")))
        self.assertEqual(g.nodes_of_kind(NodeKind.OBSERVATION), [])
        self.assertEqual(len(g.nodes_of_kind(NodeKind.KNOWLEDGE)), 1)

    def test_knowledge_cannot_raise_a_technique_score(self):
        from agent.evidence import SupportLevel
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph()
        g.add_tool_result(_binary_result(
            "retrieve_archive",
            ("retrieval_match", "JWT alg=none bypass: check the algorithm field"),
        ))
        support = g.assess_technique("jwt-none-bypass")
        self.assertEqual(support.supporting, [])
        self.assertIn(support.level,
                      (SupportLevel.INSUFFICIENT_EVIDENCE, SupportLevel.UNCERTAIN))

    def test_knowledge_may_still_nominate_a_candidate(self):
        from agent.evidence_graph import EdgeKind, EvidenceGraph
        g = EvidenceGraph()
        g.add_tool_result(_binary_result("retrieve_archive", ("match", "jwt algorithm confusion")))
        g.attach_technique("jwt-none-bypass")
        suggests = [e for e in g.edges if e.kind is EdgeKind.SUGGESTS]
        self.assertTrue(suggests, "retrieval should nominate techniques")

    def test_user_description_does_not_corroborate_a_tool(self):
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph()
        g.add_observation("uses gets into a fixed buffer", source="user")
        g.add_observation("buffer on the stack", source="static_analysis")
        support = g.assess_technique("stack-buffer-overflow")
        self.assertEqual(support.independent_sources, 1)


class TestEvidenceGraphAssessment(unittest.TestCase):
    def test_contradicting_observation_refutes(self):
        from agent.evidence import SupportLevel
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph()
        g.add_observation("query uses prepared statement placeholders", source="static_analysis")
        support = g.assess_technique("sql-injection")
        self.assertIs(support.level, SupportLevel.REFUTED)
        self.assertTrue(support.refuting)

    def test_missing_required_signal_becomes_a_gap(self):
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph()
        g.add_observation("a jwt is issued at login", source="web_recon")
        support = g.assess_technique("jwt-none-bypass")
        self.assertTrue(support.gaps)
        self.assertIn("alg|algorithm", g.missing_signals("jwt-none-bypass"))

    def test_single_source_support_carries_a_caveat(self):
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph()
        g.add_observation("jwt token present", source="web_recon")
        g.add_observation("algorithm field read from the header", source="web_recon")
        support = g.assess_technique("jwt-none-bypass")
        self.assertEqual(support.independent_sources, 1)
        self.assertIn("single tool", support.caveat)

    def test_unknown_technique_is_insufficient_not_fine(self):
        from agent.evidence import SupportLevel
        from agent.evidence_graph import EvidenceGraph
        support = EvidenceGraph().assess_technique("quantum-telepathy")
        self.assertIs(support.level, SupportLevel.INSUFFICIENT_EVIDENCE)

    def test_round_trip_preserves_nodes_edges_and_gaps(self):
        from agent.evidence_graph import EvidenceGraph
        g = EvidenceGraph("chal-x")
        g.add_tool_result(_binary_result("readelf", ("mitigation", "NX enabled")), artifact="./b")
        g.add_tool_result(ToolResult(tool="gdb", status=ToolStatus.TIMEOUT, error="slow").finalize())
        g.attach_technique("stack-buffer-overflow")
        restored = EvidenceGraph.from_dict(g.to_dict())
        self.assertEqual(len(restored.nodes), len(g.nodes))
        self.assertEqual(len(restored.edges), len(g.edges))
        self.assertEqual(len(restored.coverage_gaps), 1)

    def test_build_graph_from_state_splits_errors_out(self):
        from agent.evidence_graph import build_graph, NodeKind
        s = new_challenge_state("binary reads input", category="pwn")
        s.add_evidence(source="static_analysis", content="gets() found", finding="gets() found")
        s.add_evidence(source="ghidra", content="ERROR: jvm crash", finding="ghidra failed")
        g = build_graph(s)
        self.assertEqual(len(g.coverage_gaps), 1)
        labels = [n.label for n in g.nodes_of_kind(NodeKind.OBSERVATION)]
        self.assertTrue(any("gets()" in l for l in labels))


class TestBeliefUpdating(unittest.TestCase):
    """Evidence moves belief; repetition and model opinion do not."""

    def setUp(self):
        self.state = new_challenge_state("login portal issues a jwt", category="web")
        self.jwt = self.state.add_hypothesis(
            "verifier honours alg=none", technique="jwt-none-bypass", confidence=0.35)
        self.sqli = self.state.add_hypothesis(
            "username concatenated into sql", technique="sql-injection", confidence=0.35)

    def test_one_observation_can_raise_one_and_refute_another(self):
        from agent.belief import update_beliefs
        update_beliefs(self.state, "jwt header contains an algorithm field", source="web_recon")
        self.assertGreater(self.jwt.confidence, 0.35)
        update_beliefs(self.state, "queries use prepared statement placeholders",
                       source="static_analysis")
        self.assertEqual(self.sqli.status, "rejected")

    def test_repeating_the_same_observation_changes_nothing(self):
        from agent.belief import update_beliefs
        update_beliefs(self.state, "jwt algorithm field is read from the header",
                       source="web_recon")
        after_first = self.jwt.confidence
        update_beliefs(self.state, "jwt algorithm field is read from the header",
                       source="web_recon")
        self.assertEqual(self.jwt.confidence, after_first,
                         "a repeated tool result must not compound confidence")

    def test_a_different_tool_seeing_it_does_count(self):
        from agent.belief import update_beliefs
        update_beliefs(self.state, "jwt algorithm field present", source="web_recon")
        after_first = self.jwt.confidence
        update_beliefs(self.state, "jwt algorithm field present", source="static_analysis")
        self.assertGreater(self.jwt.confidence, after_first)

    def test_no_single_observation_reaches_certainty(self):
        from agent.belief import update_beliefs
        update_beliefs(
            self.state,
            "jwt json web token alg algorithm none header honoured "
            "verify without allowlist decode without verify",
            source="web_recon",
        )
        self.assertLess(self.jwt.confidence, 0.95)

    def test_confidence_stays_in_range(self):
        from agent.belief import update_beliefs
        for _ in range(12):
            update_beliefs(self.state, "jwt alg none header honoured", source=f"t{_}")
        self.assertLessEqual(self.jwt.confidence, 1.0)
        self.assertGreaterEqual(self.jwt.confidence, 0.0)

    def test_irrelevant_observation_moves_nothing(self):
        from agent.belief import update_beliefs
        before = (self.jwt.confidence, self.sqli.confidence)
        update_beliefs(self.state, "the weather is mild today", source="ask_user")
        self.assertEqual((self.jwt.confidence, self.sqli.confidence), before)

    def test_exclusive_rival_is_damped_by_a_leader(self):
        from agent.belief import apply_competition, are_exclusive
        self.assertTrue(are_exclusive("jwt-none-bypass", "jwt-alg-confusion"))
        self.assertFalse(are_exclusive("jwt-none-bypass", "sql-injection"))
        s = new_challenge_state("x", category="web")
        leader = s.add_hypothesis("none", technique="jwt-none-bypass", confidence=0.8)
        rival = s.add_hypothesis("confusion", technique="jwt-alg-confusion", confidence=0.5)
        apply_competition(s)
        self.assertLess(rival.confidence, 0.5)
        self.assertEqual(leader.confidence, 0.8)

    def test_spread_reports_lack_of_discrimination(self):
        from agent.belief import belief_spread
        self.assertLess(belief_spread(self.state), 0.05)

    def test_audit_trail_is_recorded_and_bounded(self):
        from agent.belief import update_beliefs
        for i in range(60):
            update_beliefs(self.state, f"jwt alg algorithm observed run {i}", source=f"tool{i}")
        self.assertTrue(self.state.belief_updates)
        self.assertLessEqual(len(self.state.belief_updates), 200)

    def test_updates_survive_serialization(self):
        from agent.belief import update_beliefs
        from agent.state import AgentState
        update_beliefs(self.state, "jwt alg algorithm present", source="web_recon")
        restored = AgentState.from_json(self.state.to_json())
        self.assertEqual(len(restored.belief_updates), len(self.state.belief_updates))


class TestRecovery(unittest.TestCase):
    def _state_with_repeats(self, tool="web_recon", times=3, status="succeeded"):
        s = new_challenge_state("x", category="web")
        s.add_hypothesis("h", technique="jwt-none-bypass", confidence=0.5)
        s.step_count = times
        for _ in range(times):
            action = s.record_action(tool, {"path": "/tmp/a.py"}, reason="r")
            s.mark_action_result(action.id, status=status, result_summary="", error="boom")
        return s

    def test_repeated_action_is_detected_and_banned(self):
        from agent.recovery import apply_recovery, banned_actions, diagnose
        s = self._state_with_repeats()
        patterns = [d.pattern for d in diagnose(s)]
        self.assertIn("repeated_action", patterns)
        apply_recovery(s)
        self.assertIn("web_recon", banned_actions(s))

    def test_failing_tool_is_recorded_as_a_coverage_gap(self):
        from agent.recovery import apply_recovery, diagnose
        s = self._state_with_repeats(tool="gdb_inspect", times=2, status="failed")
        self.assertIn("failing_tool", [d.pattern for d in diagnose(s)])
        apply_recovery(s)
        self.assertTrue(any("Coverage gap" in f for f in s.known_facts))
        self.assertTrue(any("not evidence of absence" in f for f in s.known_facts))

    def test_no_discrimination_suggests_a_separating_signal(self):
        from agent.recovery import diagnose
        s = new_challenge_state("x", category="web")
        s.add_hypothesis("a", technique="jwt-none-bypass", confidence=0.5)
        s.add_hypothesis("b", technique="jwt-alg-confusion", confidence=0.5)
        s.step_count = 4
        found = [d for d in diagnose(s) if d.pattern == "no_discrimination"]
        self.assertTrue(found)
        self.assertTrue(found[0].suggestions)

    def test_discriminating_signals_exclude_shared_ones(self):
        from agent.recovery import discriminating_signals
        signals = discriminating_signals("sql-injection", "ssti")
        self.assertTrue(signals)
        self.assertFalse(any("template" in s for s in signals),
                         "a signal both techniques predict cannot separate them")

    def test_all_rejected_reopens_with_alternatives(self):
        from agent.recovery import apply_recovery, diagnose
        s = new_challenge_state("x", category="crypto")
        h = s.add_hypothesis("xor", technique="xor-single-byte", confidence=0.5)
        h.status = "rejected"
        s.step_count = 3
        self.assertIn("all_rejected", [d.pattern for d in diagnose(s)])
        apply_recovery(s)
        self.assertTrue([x for x in s.hypotheses if x.status == "active"])

    def test_refuted_leader_is_retired(self):
        from agent.evidence_graph import EvidenceGraph
        from agent.recovery import apply_recovery, diagnose
        s = new_challenge_state("x", category="web")
        leader = s.add_hypothesis("sqli", technique="sql-injection", confidence=0.7)
        g = EvidenceGraph()
        g.add_observation("uses prepared statement placeholders", source="static_analysis")
        g.attach_technique("sql-injection")
        self.assertIn("refuted_leader", [d.pattern for d in diagnose(s, graph=g)])
        apply_recovery(s, graph=g)
        self.assertEqual(leader.status, "superseded")

    def test_clean_state_is_not_diagnosed_as_stuck(self):
        from agent.recovery import diagnose, is_stuck
        s = new_challenge_state("x", category="web")
        s.add_hypothesis("h", technique="jwt-none-bypass", confidence=0.6)
        self.assertEqual(diagnose(s), [])
        self.assertFalse(is_stuck(s))

    def test_applying_an_already_applied_remedy_records_nothing(self):
        from agent.recovery import apply_recovery, diagnose
        s = self._state_with_repeats()
        repeats = [d for d in diagnose(s) if d.pattern == "repeated_action"]
        self.assertTrue(apply_recovery(s, diagnoses=repeats))
        self.assertEqual(apply_recovery(s, diagnoses=repeats), [],
                         "a satisfied remedy is not a new event")

    def test_alternative_seeding_does_not_duplicate(self):
        """Repeated plateaus must not flood the hypothesis list."""
        from agent.recovery import apply_recovery, diagnose
        s = self._state_with_repeats()
        apply_recovery(s)
        plateaus = [d for d in diagnose(s) if d.pattern == "evidence_plateau"]
        if not plateaus:
            self.skipTest("no plateau diagnosed in this state")
        apply_recovery(s, diagnoses=plateaus)
        before = len(s.hypotheses)
        apply_recovery(s, diagnoses=plateaus)
        self.assertEqual(len(s.hypotheses), before)


class TestToolCapabilities(unittest.TestCase):
    def test_every_rubric_signal_has_a_tool_behind_it(self):
        from agent.tool_capabilities import uncovered_signals
        uncovered = uncovered_signals()
        self.assertEqual(uncovered, {},
                         f"these required signals cannot be observed: {uncovered}")

    def test_signal_routes_to_the_right_tool(self):
        from agent.tool_capabilities import tools_for_signal
        self.assertIn("static_analysis", tools_for_signal("nx"))
        self.assertIn("web_recon", tools_for_signal("jwt|json web token"))
        self.assertIn("gdb_inspect", tools_for_signal("crash"))

    def test_retrieval_claims_no_observations(self):
        from agent.tool_capabilities import capability, tools_for_signal
        self.assertEqual(capability("retrieve_archive").produces, [])
        self.assertNotIn("retrieve_archive", tools_for_signal("jwt|json web token"))

    def test_shortlist_is_short_and_gap_driven(self):
        from agent.tool_capabilities import candidates
        shortlist = candidates(category="pwn", artifact_kinds=["binary"],
                               missing_signals=["nx", "crash"], limit=4)
        self.assertLessEqual(len(shortlist), 4)
        self.assertEqual(shortlist[0].tool, "static_analysis")
        self.assertTrue(shortlist[0].closes)

    def test_analysis_tool_without_an_artifact_is_not_offered(self):
        from agent.tool_capabilities import candidates
        tools = {c.tool for c in candidates(category="pwn", artifact_kinds=[],
                                            missing_signals=["nx"])}
        self.assertNotIn("static_analysis", tools)

    def test_ask_user_is_the_last_resort_only(self):
        from agent.tool_capabilities import candidates
        rich = {c.tool for c in candidates(category="pwn", artifact_kinds=["binary"],
                                           missing_signals=["nx"])}
        self.assertNotIn("ask_user", rich)
        bare = [c.tool for c in candidates(category="", artifact_kinds=[], missing_signals=[])]
        self.assertEqual(bare, ["ask_user"])

    def test_banned_tools_are_excluded_from_the_shortlist(self):
        from agent.tool_capabilities import candidates
        tools = {c.tool for c in candidates(category="pwn", artifact_kinds=["binary"],
                                            missing_signals=["nx"],
                                            exclude={"static_analysis"})}
        self.assertNotIn("static_analysis", tools)

    def test_prompt_block_lists_only_the_shortlist(self):
        from agent.tool_capabilities import candidate_prompt_block, candidates
        block = candidate_prompt_block(candidates(
            category="crypto", artifact_kinds=["text"], missing_signals=["xor|ciphertext"]))
        self.assertIn("choose exactly one", block)
        self.assertNotIn("gdb_inspect", block)


class TestReasoningMachine(unittest.TestCase):
    def setUp(self):
        self.state = new_challenge_state("elf reads input with gets()", category="pwn")
        self.state.add_hypothesis("stack overflow", technique="stack-buffer-overflow",
                                  confidence=0.5)

    def test_declared_transitions_are_allowed(self):
        from agent.reasoning import Phase, ReasoningMachine
        m = ReasoningMachine(self.state)
        self.assertTrue(m.transition(Phase.HYPOTHESIZE))
        self.assertTrue(m.transition(Phase.PLAN))
        self.assertTrue(m.transition(Phase.ACT))

    def test_undeclared_transition_is_refused_and_recorded(self):
        from agent.reasoning import Phase, ReasoningMachine
        m = ReasoningMachine(self.state)
        m.transition(Phase.HYPOTHESIZE)
        self.assertFalse(m.transition(Phase.INTERPRET))
        self.assertTrue(m.violations)
        self.assertIs(m.phase, Phase.HYPOTHESIZE)

    def test_strict_mode_raises_instead(self):
        from agent.reasoning import IllegalTransition, Phase, ReasoningMachine
        m = ReasoningMachine(self.state, strict=True)
        m.transition(Phase.HYPOTHESIZE)
        with self.assertRaises(IllegalTransition):
            m.transition(Phase.INTERPRET)

    def test_recovery_is_reachable_from_anywhere(self):
        from agent.reasoning import Phase, ReasoningMachine, can_transition
        for phase in (Phase.PLAN, Phase.ACT, Phase.VERIFY, Phase.OBSERVE):
            self.assertTrue(can_transition(phase, Phase.RECOVER))
        m = ReasoningMachine(self.state)
        m.transition(Phase.HYPOTHESIZE)
        self.assertTrue(m.transition(Phase.RECOVER))

    def test_phase_survives_serialization(self):
        from agent.reasoning import Phase, ReasoningMachine
        from agent.state import AgentState
        m = ReasoningMachine(self.state)
        m.transition(Phase.HYPOTHESIZE)
        m.transition(Phase.PLAN)
        restored = AgentState.from_json(self.state.to_json())
        self.assertIs(ReasoningMachine(restored).phase, Phase.PLAN)

    def test_rationale_states_what_would_disprove(self):
        from agent.planner import PlannedAction
        from agent.reasoning import ReasoningMachine
        plan = PlannedAction(tool="static_analysis", arguments={"path": "./v"},
                             reason="look for the copy", expected_observation="gets()")
        rationale = ReasoningMachine(self.state).rationale(plan)
        self.assertTrue(rationale.would_disprove)
        self.assertTrue(rationale.is_complete)

    def test_non_discriminating_action_is_flagged(self):
        from agent.evidence_graph import EvidenceGraph
        from agent.planner import PlannedAction
        from agent.reasoning import ReasoningMachine
        g = EvidenceGraph()
        g.attach_technique("stack-buffer-overflow")
        plan = PlannedAction(tool="retrieve_archive", arguments={},
                             reason="similar cases", expected_observation="cards")
        rationale = ReasoningMachine(self.state).rationale(plan, graph=g)
        self.assertFalse(rationale.discriminating)
        self.assertTrue(rationale.concerns)

    def test_graph_reporting_no_gaps_is_believed(self):
        """An empty gap list is an answer, not a reason to re-scan facts."""
        from agent.evidence_graph import EvidenceGraph
        from agent.reasoning import ReasoningMachine
        g = EvidenceGraph()
        g.add_observation("gets() copies into a fixed buffer on the stack",
                          source="static_analysis")
        g.attach_technique("stack-buffer-overflow")
        rationale = ReasoningMachine(self.state).rationale(graph=g)
        self.assertEqual(rationale.unknown, [])

    def test_coverage_gaps_surface_as_concerns(self):
        from agent.evidence_graph import EvidenceGraph
        from agent.reasoning import ReasoningMachine
        g = EvidenceGraph()
        g.add_tool_result(ToolResult(tool="ghidra", status=ToolStatus.ERROR,
                                     error="crash").finalize())
        rationale = ReasoningMachine(self.state).rationale(graph=g)
        self.assertTrue(any("ghidra" in c for c in rationale.concerns))


class TestPlannerGating(unittest.TestCase):
    def test_banned_tool_is_not_proposed_again(self):
        from agent.planner import plan_next_action
        s = new_challenge_state("source available", category="web")
        s.discovered_artifacts.append("/tmp/app.py")
        s.add_hypothesis("jwt", technique="jwt-none-bypass", confidence=0.6)
        s.abandoned_actions.append("web_recon")
        plan = plan_next_action(s)
        self.assertIsNotNone(plan)
        self.assertNotEqual(plan.tool, "web_recon")

    def test_planner_still_works_without_a_graph(self):
        from agent.planner import plan_next_action
        s = new_challenge_state("a challenge with no files", category="crypto")
        self.assertIsNotNone(plan_next_action(s))

    def test_arguments_are_never_invented_for_a_missing_file(self):
        from agent.planner import _fill_arguments
        s = new_challenge_state("no artifacts here", category="pwn")
        self.assertIsNone(_fill_arguments(s, "gdb_inspect"))
        self.assertIsNone(_fill_arguments(s, "static_analysis"))


class TestVerifierEvidenceGate(unittest.TestCase):
    """The offline path must not grant a pass from a confidence number."""

    def test_offline_pass_requires_the_required_observations(self):
        from agent.verifier import verify_solution
        s = new_challenge_state("a login portal", category="web")
        s.add_hypothesis("jwt none", technique="jwt-none-bypass", confidence=0.9)
        s.overall_confidence = 0.95
        for i in range(3):
            s.add_evidence(source=f"tool{i}", content="something happened", finding="something")
        verdict = verify_solution(s, "jwt alg=none bypass")
        self.assertNotEqual(verdict["verdict"], "pass")

    def test_graph_gaps_block_verification(self):
        from agent.evidence_graph import EvidenceGraph
        from agent.verifier import verify_solution
        s = new_challenge_state("a login portal issues a jwt", category="web")
        s.add_hypothesis("jwt none", technique="jwt-none-bypass", confidence=0.9)
        s.overall_confidence = 0.9
        s.add_evidence(source="web_recon", content="a jwt is issued", finding="jwt found")
        s.add_evidence(source="web_recon", content="login route found", finding="login route")
        g = EvidenceGraph()
        g.add_observation("a jwt is issued at login", source="web_recon")
        verdict = verify_solution(s, "jwt alg=none bypass", graph=g)
        self.assertEqual(verdict["verdict"], "insufficient_evidence")
        self.assertTrue(verdict["missing_evidence"])

    def test_evidence_text_excludes_reference_material(self):
        from agent.evidence import collect_evidence_text
        s = new_challenge_state("a binary", category="pwn")
        s.add_evidence(source="retrieve_archive", content="gets() and strcpy overflow patterns",
                       finding="archive card about overflows")
        self.assertNotIn("strcpy", collect_evidence_text(s))

    def test_evidence_text_excludes_hypothesis_statements(self):
        """A claim may not supply its own supporting text."""
        from agent.evidence import collect_evidence_text
        s = new_challenge_state("a binary", category="pwn")
        s.add_hypothesis("gets() overflows a stack buffer with no bounds",
                         technique="stack-buffer-overflow", confidence=0.6)
        self.assertNotIn("no bounds", collect_evidence_text(s))


if __name__ == "__main__":
    unittest.main()
