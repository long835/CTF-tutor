"""
tests/test_knowledge_phase5.py

Phase 5: taxonomy (67), unified knowledge graph (11), learner independence
and transfer (14/15), knowledge quality scoring (69).

The audit tests are the ones that matter over time. They are written as
regressions on the *join*, not on any one table: adding a rubric for a
technique no tool can observe, or a prerequisite that points at nothing,
fails here rather than three weeks later as a stalled investigation.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import evidence, knowledge_graph, knowledge_quality, learner_model, taxonomy


# ---------------------------------------------------------------------------
# Item 67 — taxonomy
# ---------------------------------------------------------------------------


class TestTaxonomy(unittest.TestCase):
    def test_alias_resolves_to_canonical(self):
        self.assertEqual(taxonomy.canonical("buffer-overflow"), "stack-buffer-overflow")
        self.assertEqual(taxonomy.canonical("stack-smashing"), "stack-buffer-overflow")
        self.assertEqual(taxonomy.canonical("username-osint"), "osint-username")

    def test_canonical_is_idempotent(self):
        for name in ("stack-buffer-overflow", "buffer-overflow", "BOF", "bof "):
            once = taxonomy.canonical(name)
            self.assertEqual(once, taxonomy.canonical(once))

    def test_spelling_variants_normalise(self):
        self.assertEqual(taxonomy.canonical("Stack_Buffer  Overflow"), "stack-buffer-overflow")

    def test_unknown_name_survives_rather_than_vanishing(self):
        # Swallowing unknown names would hide exactly the gap the audit reports.
        self.assertEqual(taxonomy.canonical("quantum-flux-injection"), "quantum-flux-injection")
        self.assertFalse(taxonomy.is_known("quantum-flux-injection"))

    def test_no_alias_collisions(self):
        self.assertEqual(taxonomy.collisions(), [])

    def test_every_alias_targets_a_real_id(self):
        for alias, target in taxonomy.ALIASES.items():
            self.assertTrue(
                taxonomy.is_known(target),
                f"alias {alias} -> {target}, which is not a canonical id",
            )

    def test_concepts_are_not_offered_as_answers(self):
        self.assertTrue(taxonomy.is_concept("stack-layout"))
        self.assertFalse(taxonomy.is_concept("stack-buffer-overflow"))
        # Approaches, not answers.
        self.assertTrue(taxonomy.is_concept(taxonomy.canonical("static-analysis")))

    def test_path_uses_category(self):
        self.assertEqual(taxonomy.path_of("path-traversal"), "web/path-traversal")
        self.assertEqual(taxonomy.path_of("lfi"), "web/path-traversal")

    def test_duplicate_report_groups_variants(self):
        counts = {"buffer-overflow": 4, "stack-smashing": 2, "stack-buffer-overflow": 15,
                  "ssti": 17}
        rows = dict((c, (v, n)) for c, v, n in taxonomy.duplicate_report(counts))
        self.assertIn("stack-buffer-overflow", rows)
        self.assertEqual(rows["stack-buffer-overflow"][1], 21)
        self.assertNotIn("ssti", rows, "a single spelling is not a duplicate")

    def test_every_rubric_key_is_canonical(self):
        # A rubric keyed on an alias is a rubric that never fires.
        bad = [k for k in evidence.REQUIREMENTS if taxonomy.canonical(k) != k]
        self.assertEqual(bad, [], f"non-canonical rubric keys: {bad}")


# ---------------------------------------------------------------------------
# Item 11 — unified knowledge graph
# ---------------------------------------------------------------------------


class TestKnowledgeGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = knowledge_graph.get_graph(force_reload=True)

    def test_node_merges_all_sources(self):
        node = self.graph.node("stack-buffer-overflow")
        self.assertIsNotNone(node)
        self.assertTrue(node.prerequisites, "prerequisites should come from the skill graph")
        self.assertTrue(node.required_signals, "required signals should come from the rubric")
        self.assertTrue(node.tools, "tools should come from the capability registry")
        self.assertGreaterEqual(len(node.sources), 3)

    def test_lookup_is_alias_aware(self):
        self.assertIs(self.graph.node("bof"), self.graph.node("stack-buffer-overflow"))

    def test_teaching_path_ends_at_the_target(self):
        path = self.graph.teaching_path("ret2libc", mastered=set())
        self.assertEqual(path[-1], "ret2libc")
        self.assertIn("stack-buffer-overflow", path)

    def test_teaching_path_skips_what_is_mastered(self):
        full = self.graph.teaching_path("ret2libc", mastered=set())
        trimmed = self.graph.teaching_path(
            "ret2libc", mastered={"stack-buffer-overflow", "c-memory"}
        )
        self.assertLess(len(trimmed), len(full))
        self.assertNotIn("stack-buffer-overflow", trimmed[:-1])

    def test_dependents_are_the_inverse_of_prerequisites(self):
        self.assertIn("ret2libc", self.graph.dependents("stack-buffer-overflow"))

    def test_every_prerequisite_has_a_node(self):
        missing = [
            (n.technique, p)
            for n in self.graph.nodes.values()
            for p in n.prerequisites
            if p not in self.graph.nodes
        ]
        self.assertEqual(missing, [], f"prerequisites with no node: {missing}")

    def test_audit_reports_no_errors(self):
        errors = [i for i in self.graph.audit() if i.severity == "error"]
        self.assertEqual([str(e) for e in errors], [])

    def test_audit_reports_no_warnings(self):
        # Phase 5 closed every rubric and prerequisite gap the join found.
        # A new one should fail here rather than surface as a stalled run.
        warnings = [i for i in self.graph.audit() if i.severity == "warning"]
        self.assertEqual([str(w) for w in warnings], [])

    def test_audit_catches_an_unobservable_rubric(self):
        graph = knowledge_graph.build_graph()
        node = graph.node("format-string")
        node.required_signals = ["a signal no tool on earth emits"]
        node.tools = []
        kinds = {i.kind for i in graph.audit()}
        self.assertIn("unobservable_rubric", kinds)

    def test_audit_catches_a_dangling_prerequisite(self):
        graph = knowledge_graph.build_graph()
        graph.node("ret2libc").prerequisites.append("no-such-concept")
        errors = [i for i in graph.audit() if i.kind == "unknown_prerequisite"]
        self.assertTrue(errors)
        self.assertEqual(errors[0].severity, "error")

    def test_stats_count_only_canonical_nodes(self):
        stats = self.graph.stats()
        self.assertEqual(len(self.graph.nodes), stats["techniques"] + stats["concepts"])
        self.assertLessEqual(stats["canonical_corpus_tags"], stats["distinct_corpus_tags"])

    def test_graph_agrees_with_the_tool_registry(self):
        # The bug this replaces: the graph used its own looser matcher and
        # reported six fewer gaps than the registry did. One question, one
        # answer -- so the graph's tool list must equal the registry's.
        from agent.tool_capabilities import tools_for_signal, uncovered_signals

        self.assertEqual(uncovered_signals(), {})
        for name in ("sql-injection", "format-string", "heap-overflow", "reentrancy"):
            node = self.graph.node(name)
            expected = sorted({
                tool
                for signal in node.required_signals
                for tool in tools_for_signal(signal)
            })
            self.assertEqual(node.tools, expected, f"{name} disagrees with the registry")


# ---------------------------------------------------------------------------
# Items 14/15 — independence and transfer
# ---------------------------------------------------------------------------


class TestLearnerIndependence(unittest.TestCase):
    def test_rate_is_none_below_the_evidence_floor(self):
        rec = learner_model.LearnerRecord()
        rec.record_attempt("ssti", success=True, hint_level=0, scenario="a")
        prof = rec.for_technique("ssti")
        self.assertIsNone(prof.independent_solve_rate)
        self.assertEqual(prof.status, "insufficient_evidence")

    def test_deep_hints_do_not_count_as_independent(self):
        rec = learner_model.LearnerRecord()
        for i in range(3):
            rec.record_attempt("ssti", success=True, hint_level=4, scenario=f"s{i}")
        prof = rec.for_technique("ssti")
        self.assertEqual(prof.successes, 3)
        self.assertEqual(prof.independent_successes, 0)
        self.assertEqual(prof.status, "hint_dependent")

    def test_unaided_solves_register(self):
        rec = learner_model.LearnerRecord()
        for i in range(3):
            rec.record_attempt("sql-injection", success=True, hint_level=0, scenario=f"s{i}")
        prof = rec.for_technique("sql-injection")
        self.assertEqual(prof.independent_solve_rate, 1.0)
        self.assertEqual(prof.status, "transferred")

    def test_transfer_needs_two_distinct_framings(self):
        rec = learner_model.LearnerRecord()
        for _ in range(3):
            rec.record_attempt("idor", success=True, hint_level=0, scenario="same")
        prof = rec.for_technique("idor")
        self.assertIsNone(prof.transfer, "one framing three times is recall, not transfer")
        rec.record_attempt("idor", success=True, hint_level=0, scenario="different")
        self.assertTrue(rec.for_technique("idor").transfer)

    def test_record_is_alias_aware(self):
        rec = learner_model.LearnerRecord()
        rec.record_attempt("bof", success=True, hint_level=0, scenario="a")
        self.assertEqual(rec.techniques(), ["stack-buffer-overflow"])

    def test_transfer_check_verdicts(self):
        rec = learner_model.LearnerRecord()
        for i in range(3):
            rec.record_attempt("sql-injection", success=True, hint_level=4, scenario=f"s{i}")
        self.assertEqual(learner_model.transfer_check("sql-injection", rec)["verdict"], "repair")

    def test_next_variation_avoids_what_was_already_solved(self):
        scenarios = learner_model.variations_for("sql-injection")
        self.assertTrue(scenarios, "the technique library should supply framings")
        rec = learner_model.LearnerRecord()
        rec.record_attempt("sql-injection", success=True, hint_level=0, scenario=scenarios[0])
        self.assertNotEqual(learner_model.next_variation("sql-injection", rec), scenarios[0])

    def test_hint_level_drops_once_independence_is_shown(self):
        rec = learner_model.LearnerRecord()
        for i in range(3):
            rec.record_attempt("ssti", success=True, hint_level=0, scenario=f"s{i}")
        self.assertLessEqual(learner_model.recommended_hint_level("ssti", rec, default=3), 1)

    def test_unknown_technique_gets_the_caller_default(self):
        rec = learner_model.LearnerRecord()
        self.assertEqual(learner_model.recommended_hint_level("xxe", rec, default=3), 3)

    def test_round_trips_through_disk(self):
        rec = learner_model.LearnerRecord()
        rec.record_attempt("ssti", success=True, hint_level=2, scenario="a", verified=True)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "attempts.json")
            learner_model.save_record(rec, path)
            back = learner_model.load_record(path)
        self.assertEqual(len(back.attempts), 1)
        self.assertTrue(back.attempts[0].verified)

    def test_corrupt_log_is_a_missing_log_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "attempts.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{not json")
            self.assertEqual(learner_model.load_record(path).attempts, [])

    def test_independence_axis_abstains_without_evidence(self):
        self.assertIsNone(learner_model.independence_axis(learner_model.LearnerRecord())["score"])


# ---------------------------------------------------------------------------
# Item 69 — knowledge quality
# ---------------------------------------------------------------------------


class TestKnowledgeQuality(unittest.TestCase):
    def _rich_card(self):
        return {
            "challenge_name": "Pattern WEB: Token Algorithm",
            "category": "web",
            "techniques": ["jwt-none-bypass"],
            "difficulty": "medium",
            "description": "A service accepts a token whose header selects the algorithm.",
            "explanation": "The verifier trusts the declared algorithm.",
            "solve_steps": ["Read the header", "Compare declared and verified algorithms",
                            "Confirm the server accepts the change"],
            "tools_used": ["jwt_tool", "web_recon"],
            "references": ["local:ctf-tutor-curated-patterns"],
            "source": "curated",
            "version": 2,
            "updated_at": "2026-06-01T00:00:00+00:00",
        }

    def test_rich_card_outscores_a_thin_one(self):
        rich = knowledge_quality.score_card(self._rich_card(), "rich")
        thin = knowledge_quality.score_card(
            {"challenge_name": "x", "description": "solved it, obvious"}, "thin"
        )
        self.assertGreater(rich.total, thin.total)
        self.assertIn(rich.band, ("high", "adequate"))
        self.assertEqual(thin.band, "poor")

    def test_vague_phrasing_is_penalised(self):
        card = self._rich_card()
        card["explanation"] = "the flag was found, trivial"
        self.assertLess(
            knowledge_quality.score_card(card, "vague").specificity,
            knowledge_quality.score_card(self._rich_card(), "rich").specificity,
        )

    def test_unmeasurable_axis_is_excluded_not_zeroed(self):
        card = self._rich_card()
        card.pop("version")
        card.pop("updated_at")
        score = knowledge_quality.score_card(card, "undated")
        self.assertIsNone(score.freshness)
        self.assertIn("freshness", score.unmeasurable)
        # Excluding beats zeroing: an unmeasurable axis must not drag the card
        # below one that is genuinely thin on the axes we can see.
        thin = knowledge_quality.score_card({"description": "obvious"}, "thin")
        self.assertGreater(score.total, thin.total)

    def test_index_entries_are_judged_on_their_own_schema(self):
        index_card = {
            "id": "archive-x", "kind": "archive", "source": "archive",
            "provenance": "curated", "name": "Pattern", "category": "web",
            "difficulty": "easy", "description": "A short pointer.",
            "techniques": ["ssti"],
        }
        score = knowledge_quality.score_card(index_card, "archive-x")
        self.assertEqual(score.coverage, 1.0)
        self.assertIsNone(score.verification)

    def test_unresolvable_technique_tags_are_flagged(self):
        card = self._rich_card()
        card["techniques"] = ["not-a-real-technique"]
        notes = " ".join(knowledge_quality.score_card(card, "bad-tags").notes)
        self.assertIn("taxonomy", notes)

    def test_quality_feature_is_centred(self):
        knowledge_quality.clear_cache()
        rich = knowledge_quality.quality_feature(self._rich_card())
        thin = knowledge_quality.quality_feature({"description": "obvious"})
        self.assertGreater(rich, thin)
        self.assertLessEqual(rich, 1.0)
        self.assertGreaterEqual(thin, -1.0)

    def test_corpus_report_runs_over_the_shipped_data(self):
        report = knowledge_quality.corpus_report()
        self.assertGreater(report["cards"], 0)
        self.assertIn("bands", report)

    def test_quality_does_not_outrank_relevance(self):
        # A high-quality card about the wrong technique must not beat a
        # relevant one; the weight is a tie-breaker by design.
        from agent.rerank import DEFAULT_WEIGHTS

        self.assertLess(DEFAULT_WEIGHTS["quality"], DEFAULT_WEIGHTS["technique"])
        self.assertLess(DEFAULT_WEIGHTS["quality"], DEFAULT_WEIGHTS["base"])


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestPhase5CLI(unittest.TestCase):
    def _run(self, argv):
        import io
        import contextlib
        import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.main(argv)
        return code, buf.getvalue()

    def test_knowledge_describes_a_technique(self):
        code, out = self._run(["knowledge", "bof"])
        self.assertEqual(code, 0)
        self.assertIn("pwn/stack-buffer-overflow", out)

    def test_knowledge_strict_audit_passes(self):
        code, _ = self._run(["knowledge", "--strict"])
        self.assertEqual(code, 0, "the shipped knowledge base should audit clean")

    def test_knowledge_unknown_query_suggests_and_fails(self):
        code, out = self._run(["knowledge", "zzzz-not-a-technique"])
        self.assertEqual(code, 1)
        self.assertIn("No", out)

    def test_learner_reports_an_empty_record(self):
        with tempfile.TemporaryDirectory() as d:
            code, out = self._run(["learner", "--path", os.path.join(d, "a.json")])
        self.assertEqual(code, 0)
        self.assertIn("Independent solve rate", out)

    def test_learner_records_and_reads_back(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.json")
            self._run(["learner", "--record", "ssti", "solved",
                       "--hint-level", "0", "--scenario", "s1", "--path", path])
            code, out = self._run(["learner", "ssti", "--path", path])
        self.assertEqual(code, 0)
        self.assertIn("ssti", out)
