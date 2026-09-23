"""End-to-end and regression tests (items 54, 55, 56).

The existing suite is almost entirely unit-level: does this function return
what it should. That leaves the interesting question untested — does the
whole pipeline, driven from a challenge description, reach a defensible
conclusion? Those failures live in the seams, which is exactly where unit
tests do not look.

These tests drive the real `AgentLoop` with a scripted executor, so the
whole chain runs — triage, hypotheses, planning, the gate, tool results, the
evidence graph, belief updating, recovery, verification — with deterministic
tool output and no model, no network, and no toolchain.

`FIXED_CASES` at the bottom is the regression suite (item 56). Every bug
found in this project becomes a case here and stays permanently, so a later
fix cannot quietly restore an earlier wrong answer.
"""

import json
import os
import tempfile
import unittest


class ScriptedExecutor:
    """
    Stands in for the real executor with canned tool output.

    Output is keyed by tool name, so a test states what each tool sees and
    the agent decides what to do about it. Unscripted tools report as
    unavailable rather than empty — an unscripted call must not look like a
    tool that ran and found nothing.
    """

    def __init__(self, outputs=None, failures=None):
        self.outputs = dict(outputs or {})
        self.failures = dict(failures or {})
        self.calls = []

    def __call__(self, action):
        tool = str(getattr(action, "tool", ""))
        self.calls.append(tool)
        if tool in self.failures:
            return (False, "", self.failures[tool])
        if tool in self.outputs:
            return (True, self.outputs[tool], "")
        return (False, "", f"{tool}: command not found (not scripted)")

    def count(self, tool):
        return self.calls.count(tool)


def run_agent(challenge, category=None, outputs=None, failures=None, max_steps=6, path=None):
    """Drive the real loop with scripted tools."""
    from agent.loop import AgentLoop

    executor = ScriptedExecutor(outputs=outputs, failures=failures)
    agent = AgentLoop(
        challenge_summary=challenge,
        category=category,
        max_steps=max_steps,
        challenge_path=path,
        enable_trace=False,
        executor=executor,
    )
    state = agent.run()
    return state, agent, executor


class TestPipelineReachesAConclusion(unittest.TestCase):
    def test_flag_in_tool_output_is_recovered_and_verified(self):
        state, agent, _ = run_agent(
            "A base64 blob is provided; decode it.",
            category="crypto",
            outputs={"auto_decode": json.dumps({
                "final_text": "well done, the flag is CTF{decoded_layers}",
                "flags": ["CTF{decoded_layers}"],
            })},
        )
        self.assertEqual(state.flag_candidate, "CTF{decoded_layers}")
        self.assertIn(state.status, ("solved", "verified"))

    def test_a_recovered_flag_is_traceable_to_a_tool(self):
        """The anti-hallucination property: the flag must be in the record."""
        from agent.metrics import detect_hallucinations

        state, agent, _ = run_agent(
            "decode the blob", category="crypto",
            outputs={"auto_decode": json.dumps({"flags": ["CTF{real}"],
                                                "final_text": "CTF{real}"})},
        )
        report = detect_hallucinations(state, graph=agent.graph)
        self.assertNotIn("invented_flag", [f.kind for f in report.findings])

    def test_pipeline_populates_every_reasoning_subsystem(self):
        state, agent, _ = run_agent(
            "A login portal issues JWTs and the admin route trusts the token.",
            category="web",
            outputs={"web_recon": "jwt found; algorithm field read from token header; "
                                  "decode without verify"},
        )
        self.assertTrue(state.hypotheses, "hypotheses were seeded")
        self.assertTrue(state.evidence, "evidence was recorded")
        self.assertTrue(state.phase_history, "phases were tracked")
        self.assertTrue(len(agent.graph), "the evidence graph was populated")
        self.assertTrue(state.actions, "actions were executed")

    def test_no_evidence_means_no_verification(self):
        """Every tool fails: the run must end honestly, not confidently."""
        state, agent, _ = run_agent(
            "A binary is provided with no further information.",
            category="pwn",
            failures={"static_analysis": "permission denied",
                      "retrieve_archive": "vector store unavailable",
                      "research": "network unreachable",
                      "gdb_inspect": "gdb: command not found"},
            max_steps=4,
        )
        self.assertNotEqual(state.status, "verified")
        self.assertEqual(state.flag_candidate, "",
                         "no tool succeeded, so no flag may be claimed")

    def test_tool_failures_become_coverage_gaps_not_findings(self):
        state, agent, _ = run_agent(
            "Analyse the provided ELF binary.", category="pwn",
            failures={"static_analysis": "ghidra: jvm crashed",
                      "gdb_inspect": "gdb: command not found"},
            max_steps=4,
        )
        self.assertTrue(agent.graph.coverage_gaps or
                        any("not evidence of absence" in f for f in state.known_facts))


class TestPipelineRecovery(unittest.TestCase):
    def test_a_failing_tool_is_eventually_abandoned(self):
        state, agent, executor = run_agent(
            "A web application with source available.", category="web",
            failures={"web_recon": "parse error"},
            max_steps=8,
        )
        self.assertLessEqual(executor.count("web_recon"), 4,
                             "a repeatedly failing tool must stop being chosen")
        self.assertTrue(state.abandoned_actions or state.recovery_events)

    def test_recovery_is_recorded_for_the_learner(self):
        state, _, _ = run_agent(
            "A web application.", category="web",
            failures={"web_recon": "parse error", "retrieve_archive": "unavailable"},
            max_steps=8,
        )
        self.assertTrue(state.recovery_events or state.abandoned_actions)

    def test_contradicting_evidence_retires_a_hypothesis(self):
        # A source file has to exist, or the planner correctly declines to
        # choose web_recon and the contradicting output never arrives.
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "app.py")
            with open(source, "w", encoding="utf-8") as handle:
                handle.write("query = 'SELECT 1 FROM users WHERE name = ?'\n")
            state, agent, _ = run_agent(
                "A login form builds a SQL query from the username.", category="web",
                outputs={"web_recon": "all queries use prepared statement placeholders; "
                                      "input is bound, not concatenated"},
                max_steps=4, path=tmp,
            )
        retired = [h for h in state.hypotheses
                   if h.status in ("rejected", "superseded")
                   and "sql" in (h.technique or "").lower()]
        self.assertTrue(retired or state.contradictions,
                        "a contradicting observation must retire the claim")


class TestDeterministicReplay(unittest.TestCase):
    def test_a_recorded_run_replays_to_the_same_outcome(self):
        from agent.replay import diff_records, record_run, replay

        outputs = {"auto_decode": json.dumps({"flags": ["CTF{replay}"],
                                              "final_text": "CTF{replay}"})}
        state, record = record_run(
            "decode the provided blob", category="crypto", max_steps=4,
            executor=ScriptedExecutor(outputs=outputs),
        )
        self.assertTrue(record.steps)
        replayed, executor = replay(record)
        diff = diff_records(record, replayed, executor)
        self.assertTrue(diff.same_outcome, diff.render())
        self.assertFalse(diff.regressed, diff.render())

    def test_replay_needs_no_tools_at_all(self):
        """Replay must work with nothing installed — that is its purpose."""
        from agent.replay import record_run, replay

        _, record = record_run(
            "decode the blob", category="crypto", max_steps=3,
            executor=ScriptedExecutor(outputs={"auto_decode": "CTF{x}"}),
        )
        replayed, executor = replay(record)
        self.assertGreater(executor.fidelity, 0.0)
        self.assertEqual(replayed.challenge_summary, record.challenge)

    def test_record_survives_a_save_load_round_trip(self):
        from agent.replay import RunRecord, record_run

        _, record = record_run(
            "decode the blob", category="crypto", max_steps=3,
            executor=ScriptedExecutor(outputs={"auto_decode": "nothing useful"}),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "run.json")
            record.save(path)
            restored = RunRecord.load(path)
        self.assertEqual(restored.decisions(), record.decisions())
        self.assertEqual(restored.final_status, record.final_status)

    def test_unrecorded_call_reports_unavailable_not_empty(self):
        from agent.replay import ReplayExecutor, RunRecord

        executor = ReplayExecutor(RunRecord(challenge="x"))

        class _Action:
            tool = "gdb_inspect"
            arguments = {"path": "./v"}

        success, output, error = executor(_Action())
        self.assertFalse(success)
        self.assertIn("unavailable", error)
        self.assertTrue(executor.misses)


# --------------------------------------------------------------------------
# Regression suite (item 56). Each entry is a bug that was actually found.
# They stay here permanently; a fix that re-breaks one fails the build.
# --------------------------------------------------------------------------

FIXED_CASES = [
    {
        "id": "retrieval-unavailable-is-not-absence",
        "found": "phase 1",
        "bug": "_run_retrieve returned (True, {matches: []}) when the vector store "
               "was down, so the agent read a broken retriever as 'nothing is relevant'.",
    },
    {
        "id": "knowledge-card-cannot-support-a-claim",
        "found": "phase 2",
        "bug": "An archive card titled 'Pattern WEB: JWT Validation' matched the JWT "
               "rubric and was counted as evidence about the challenge being solved.",
    },
    {
        "id": "offline-verifier-does-not-pass-on-a-number",
        "found": "phase 2",
        "bug": "The offline verification path granted 'pass' from overall_confidence "
               ">= 0.7 plus two evidence items, with no rubric check at all.",
    },
    {
        "id": "hypothesis-does-not-supply-its-own-evidence",
        "found": "phase 2",
        "bug": "collect_evidence_text included hypothesis statements, so a claim's own "
               "wording satisfied the rubric that was meant to test it.",
    },
    {
        "id": "repeated-tool-does-not-compound-confidence",
        "found": "phase 2",
        "bug": "Re-running a tool re-delivered the same signals and raised confidence "
               "again, so tunnel vision was rewarded by the arithmetic.",
    },
    {
        "id": "plateau-does-not-reopen-the-same-alternatives",
        "found": "phase 3",
        "bug": "_seed_alternatives compared the raw suggestion against the stored "
               "statement, which carries a prefix, so dedupe never matched.",
    },
]


class TestRegressions(unittest.TestCase):
    """One test per historical bug. The docstring is the bug report."""

    def test_retrieval_unavailable_is_not_absence(self):
        from agent.tool_result import ToolResult, ToolStatus

        result = ToolResult.from_tuple(
            "retrieve_archive",
            (True, '{"matches": [], "note": "retrieval unavailable: chroma down"}', ""),
        )
        self.assertIs(result.status, ToolStatus.UNAVAILABLE)
        self.assertFalse(result.is_evidence_of_absence)

    def test_knowledge_card_cannot_support_a_claim(self):
        from agent.evidence_graph import EvidenceGraph
        from agent.tool_result import ToolResult, ToolStatus

        card = ToolResult(tool="retrieve_archive", status=ToolStatus.OK)
        card.add("retrieval_match", "Pattern WEB: JWT Validation — check alg and algorithm")
        graph = EvidenceGraph()
        graph.add_tool_result(card.finalize())
        self.assertEqual(graph.assess_technique("jwt-none-bypass").supporting, [])

    def test_offline_verifier_does_not_pass_on_a_number(self):
        from agent.state import new_challenge_state
        from agent.verifier import verify_solution

        state = new_challenge_state("a portal", category="web")
        state.add_hypothesis("jwt none", technique="jwt-none-bypass", confidence=0.95)
        state.overall_confidence = 0.95
        for i in range(4):
            state.add_evidence(source=f"t{i}", content="noise", finding="noise")
        self.assertNotEqual(verify_solution(state, "alg=none")["verdict"], "pass")

    def test_hypothesis_does_not_supply_its_own_evidence(self):
        from agent.evidence import collect_evidence_text
        from agent.state import new_challenge_state

        state = new_challenge_state("a binary", category="pwn")
        state.add_hypothesis("unbounded copy via gets into a stack buffer",
                             technique="stack-buffer-overflow", confidence=0.6)
        self.assertNotIn("unbounded copy", collect_evidence_text(state))

    def test_repeated_tool_does_not_compound_confidence(self):
        from agent.belief import update_beliefs
        from agent.state import new_challenge_state

        state = new_challenge_state("a portal", category="web")
        h = state.add_hypothesis("alg none", technique="jwt-none-bypass", confidence=0.4)
        update_beliefs(state, "jwt algorithm field in header", source="web_recon")
        once = h.confidence
        for _ in range(4):
            update_beliefs(state, "jwt algorithm field in header", source="web_recon")
        self.assertEqual(h.confidence, once)

    def test_plateau_does_not_reopen_the_same_alternatives(self):
        from agent.recovery import _seed_alternatives
        from agent.state import new_challenge_state

        state = new_challenge_state("x", category="crypto")
        suggestions = ["an embedded media asset", "ordinary compressed data"]
        _seed_alternatives(state, suggestions)
        count = len(state.hypotheses)
        _seed_alternatives(state, suggestions)
        self.assertEqual(len(state.hypotheses), count)

    def test_every_fixed_case_has_a_test(self):
        """The suite must not drift from the list of known bugs."""
        covered = {name[len("test_"):] for name in dir(self) if name.startswith("test_")}
        for case in FIXED_CASES:
            slug = case["id"].replace("-", "_")
            self.assertIn(slug, covered,
                          f"regression case {case['id']} has no test: {case['bug']}")


if __name__ == "__main__":
    unittest.main()
