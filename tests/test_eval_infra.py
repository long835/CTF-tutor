"""Tests for the evaluation and diagnostics layer: efficiency and
hallucination metrics, the dimension scorecard, retrieval metrics,
contamination control, difficulty estimation, and the environment doctor.
"""

import unittest

from agent.state import new_challenge_state


def _state_with_run(tool="static_analysis", output="gets() found", status="succeeded", times=1):
    state = new_challenge_state("a binary reads input", category="pwn")
    state.add_hypothesis("stack overflow", technique="stack-buffer-overflow", confidence=0.6)
    state.step_count = times
    for _ in range(times):
        action = state.record_action(tool, {"path": "./v"}, reason="analyse")
        state.mark_action_result(action.id, status=status, result_summary=output[:80],
                                 raw_output=output, duration_ms=120)
        state.add_evidence(source=tool, content=output, finding=output[:60])
    return state


class TestEfficiencyMetrics(unittest.TestCase):
    def test_counts_and_ratios(self):
        from agent.metrics import efficiency
        state = _state_with_run(times=3)
        metrics = efficiency(state)
        self.assertEqual(metrics.tool_calls, 3)
        self.assertEqual(metrics.evidence_items, 3)
        self.assertEqual(metrics.wall_ms, 360)
        self.assertGreater(metrics.estimated_tokens, 0)

    def test_identical_repeats_count_as_repeated(self):
        from agent.metrics import efficiency
        metrics = efficiency(_state_with_run(times=3))
        self.assertEqual(metrics.repeated_calls, 2)
        self.assertEqual(metrics.wasted_steps, 2)

    def test_failures_are_counted_separately_from_repeats(self):
        from agent.metrics import efficiency
        metrics = efficiency(_state_with_run(status="failed", times=2))
        self.assertEqual(metrics.failed_calls, 2)
        self.assertAlmostEqual(metrics.failure_rate, 1.0)

    def test_empty_state_does_not_divide_by_zero(self):
        from agent.metrics import efficiency
        metrics = efficiency(new_challenge_state("x"))
        self.assertEqual(metrics.tokens_per_evidence, 0.0)
        self.assertEqual(metrics.failure_rate, 0.0)
        self.assertIn("steps=0", metrics.render())


class TestHallucinationDetection(unittest.TestCase):
    def test_flag_not_in_any_tool_output_is_severe(self):
        from agent.metrics import detect_hallucinations
        state = _state_with_run(output="nothing of interest")
        state.flag_candidate = "CTF{i_made_this_up}"
        report = detect_hallucinations(state)
        self.assertFalse(report.clean)
        kinds = [f.kind for f in report.findings]
        self.assertIn("invented_flag", kinds)
        self.assertLess(report.score, 0.5)

    def test_flag_present_in_output_is_clean(self):
        from agent.metrics import detect_hallucinations
        state = _state_with_run(output="found CTF{real_flag} in the strings")
        state.flag_candidate = "CTF{real_flag}"
        self.assertNotIn("invented_flag", [f.kind for f in detect_hallucinations(state).findings])

    def test_conclusion_citing_a_tool_that_never_ran(self):
        from agent.metrics import detect_hallucinations
        state = _state_with_run(tool="web_recon", output="jwt found")
        state.solution_summary = "Ghidra decompilation shows the check is trivial"
        self.assertIn("invented_tool_output",
                      [f.kind for f in detect_hallucinations(state).findings])

    def test_confirmed_technique_without_its_observations(self):
        from agent.metrics import detect_hallucinations
        state = _state_with_run(output="some output with no relevant signals")
        state.hypotheses[0].status = "confirmed"
        self.assertIn("unsupported_technique",
                      [f.kind for f in detect_hallucinations(state).findings])

    def test_success_with_no_evidence_at_all(self):
        from agent.metrics import detect_hallucinations
        state = new_challenge_state("x", category="web")
        state.status = "verified"
        self.assertIn("conclusion_without_evidence",
                      [f.kind for f in detect_hallucinations(state).findings])

    def test_overconfidence_on_thin_evidence(self):
        from agent.metrics import detect_hallucinations
        state = new_challenge_state("x", category="web")
        state.add_evidence(source="web_recon", content="a thing", finding="a thing")
        state.overall_confidence = 0.92
        self.assertIn("overconfidence",
                      [f.kind for f in detect_hallucinations(state).findings])

    def test_graph_gaps_with_high_confidence_are_flagged(self):
        from agent.evidence_graph import EvidenceGraph
        from agent.metrics import detect_hallucinations
        state = _state_with_run(tool="web_recon", output="a jwt is issued at login")
        state.overall_confidence = 0.9
        graph = EvidenceGraph()
        graph.add_observation("a jwt is issued at login", source="web_recon")
        graph.attach_technique("jwt-none-bypass")
        self.assertFalse(detect_hallucinations(state, graph=graph).clean)

    def test_clean_run_scores_one(self):
        from agent.metrics import detect_hallucinations
        state = _state_with_run(output="gets() copies into a fixed stack buffer; nx enabled")
        report = detect_hallucinations(state)
        self.assertTrue(report.clean, report.render())
        self.assertEqual(report.score, 1.0)


class TestDimensionScorecard(unittest.TestCase):
    def test_process_axes_are_scored_without_ground_truth(self):
        from agent.metrics import score_run
        scores = score_run(_state_with_run()).scores
        for axis in ("tool_selection", "tool_execution", "hallucination",
                     "explanation", "efficiency", "verification"):
            self.assertIn(axis, scores)

    def test_truth_axes_are_skipped_rather_than_guessed(self):
        from agent.metrics import score_run
        scores = score_run(_state_with_run()).scores
        self.assertNotIn("challenge_classification", scores)
        self.assertNotIn("final_correctness", scores)

    def test_category_axis_uses_ground_truth(self):
        from agent.metrics import score_run
        state = _state_with_run()
        right = score_run(state, {"expected_category": "pwn"})
        wrong = score_run(state, {"expected_category": "web"})
        self.assertEqual(right.scores["challenge_classification"], 1.0)
        self.assertEqual(wrong.scores["challenge_classification"], 0.0)

    def test_technique_axis_is_partial_credit(self):
        from agent.metrics import score_run
        scores = score_run(_state_with_run(), {
            "expected_techniques": ["stack-buffer-overflow", "ret2win"]})
        self.assertAlmostEqual(scores.scores["technique_identification"], 0.5)

    def test_declining_to_conclude_beats_a_wrong_pass(self):
        from agent.metrics import score_run
        honest = _state_with_run()
        honest.status = "stuck"
        wrong = _state_with_run()
        wrong.status = "verified"
        self.assertGreater(
            score_run(honest).scores["verification"],
            score_run(wrong, {"solvable": False}).scores["verification"],
        )

    def test_weakest_axes_are_identified(self):
        from agent.metrics import score_run
        state = _state_with_run(status="failed", times=2)
        weakest = score_run(state).weakest(2)
        self.assertEqual(len(weakest), 2)
        self.assertLessEqual(weakest[0][1], weakest[1][1])

    def test_aggregate_across_runs(self):
        from agent.metrics import aggregate, score_run
        runs = [score_run(_state_with_run()), score_run(_state_with_run(status="failed"))]
        summary = aggregate(runs)
        self.assertEqual(summary["runs"], 2)
        self.assertIn("tool_execution", summary["means"])

    def test_scorecard_renders(self):
        from agent.metrics import scorecard
        self.assertIn("Run scorecard", scorecard(_state_with_run()))


class TestRetrievalMetrics(unittest.TestCase):
    def test_recall_and_precision_at_k(self):
        from agent.retrieval_eval import precision_at_k, recall_at_k
        retrieved = ["a", "b", "c", "d", "e"]
        self.assertAlmostEqual(recall_at_k(retrieved, ["a", "z"], 5), 0.5)
        self.assertAlmostEqual(precision_at_k(retrieved, ["a", "b"], 2), 1.0)
        self.assertAlmostEqual(precision_at_k(retrieved, ["a", "b"], 5), 0.4)

    def test_k_truncates_the_result_list(self):
        from agent.retrieval_eval import recall_at_k
        self.assertEqual(recall_at_k(["x", "x", "a"], ["a"], 2), 0.0)
        self.assertEqual(recall_at_k(["x", "x", "a"], ["a"], 3), 1.0)

    def test_reciprocal_rank_rewards_early_hits(self):
        from agent.retrieval_eval import reciprocal_rank
        self.assertAlmostEqual(reciprocal_rank(["a", "b"], ["a"]), 1.0)
        self.assertAlmostEqual(reciprocal_rank(["b", "a"], ["a"]), 0.5)
        self.assertEqual(reciprocal_rank(["b", "c"], ["a"]), 0.0)

    def test_ndcg_is_one_for_ideal_ordering(self):
        from agent.retrieval_eval import ndcg_at_k
        self.assertAlmostEqual(ndcg_at_k(["a", "b", "c"], ["a", "b"], 3), 1.0)
        self.assertLess(ndcg_at_k(["c", "a", "b"], ["a", "b"], 3), 1.0)

    def test_no_relevant_documents_is_vacuously_perfect(self):
        from agent.retrieval_eval import ndcg_at_k, recall_at_k
        self.assertEqual(recall_at_k(["a"], [], 5), 1.0)
        self.assertEqual(ndcg_at_k(["a"], [], 5), 1.0)

    def test_evaluate_retrieval_over_cases(self):
        from agent.retrieval_eval import RetrievalCase, evaluate_retrieval

        corpus = {
            "jwt alg none": [{"id": "d1", "title": "jwt alg=none bypass"},
                             {"id": "d9", "title": "unrelated"}],
            "single byte xor": [{"id": "d2", "title": "xor-single-byte recovery"}],
        }
        report = evaluate_retrieval(
            [
                RetrievalCase(id="c1", query="jwt alg none", relevant_ids=["d1"],
                              techniques=["jwt-none-bypass"]),
                RetrievalCase(id="c2", query="single byte xor", relevant_ids=["d2"],
                              techniques=["xor-single-byte"]),
            ],
            search=lambda q, k: corpus.get(q, [])[:k],
            k=3,
        )
        self.assertEqual(report.cases, 2)
        self.assertAlmostEqual(report.recall, 1.0)
        self.assertAlmostEqual(report.mrr, 1.0)
        self.assertIn("MRR", report.render())

    def test_a_raising_retriever_is_not_scored_as_bad_ranking(self):
        from agent.retrieval_eval import RetrievalCase, evaluate_retrieval

        def broken(query, k):
            raise RuntimeError("vector store unavailable")

        report = evaluate_retrieval([RetrievalCase(id="c", query="q", relevant_ids=["d"])],
                                    search=broken, k=3)
        self.assertEqual(report.recall, 0.0)
        self.assertIn("error", report.per_case[0])

    def test_empty_results_are_counted(self):
        from agent.retrieval_eval import RetrievalCase, evaluate_retrieval
        report = evaluate_retrieval([RetrievalCase(id="c", query="q", relevant_ids=["d"])],
                                    search=lambda q, k: [], k=3)
        self.assertEqual(report.empty_results, 1)


class TestContaminationControl(unittest.TestCase):
    def test_verbatim_reuse_is_detected(self):
        from agent.retrieval_eval import leakage
        text = ("the admin panel trusts the role claim in the token and also accepts "
                "alg=none for verification")
        self.assertGreater(leakage(text, "writeup: " + text), 0.8)
        self.assertLess(leakage(text, "an unrelated document about pcap analysis"), 0.1)

    def test_contamination_report_flags_the_case(self):
        from agent.retrieval_eval import check_contamination
        cases = [{"id": "c1", "description": "a login portal issues jwts and accepts alg none "
                                             "for the admin panel role claim"}]
        docs = [{"id": "d1", "text": "a login portal issues jwts and accepts alg none for the "
                                     "admin panel role claim"}]
        report = check_contamination(cases, docs, threshold=0.25)
        self.assertFalse(report.clean)
        self.assertEqual(report.contaminated[0]["document"], "d1")
        self.assertIn("overlap", report.render())

    def test_clean_corpus_reports_clean(self):
        from agent.retrieval_eval import check_contamination
        report = check_contamination(
            [{"id": "c1", "description": "recover a single byte xor key from ciphertext"}],
            [{"id": "d1", "text": "how to read a pcap file with tshark filters"}],
        )
        self.assertTrue(report.clean)

    def test_family_assignment_prefers_labels(self):
        from agent.retrieval_eval import family_of
        self.assertEqual(family_of({"expected_techniques": ["jwt-none-bypass"]}), "jwt")
        self.assertEqual(family_of({"description": "recover the single byte xor key"}), "xor")

    def test_split_keeps_families_apart(self):
        from agent.retrieval_eval import family_overlap, split_by_family
        cases = [
            {"id": "1", "expected_techniques": ["jwt-none-bypass"]},
            {"id": "2", "expected_techniques": ["jwt-alg-confusion"]},
            {"id": "3", "expected_techniques": ["xor-single-byte"]},
            {"id": "4", "expected_techniques": ["sql-injection"]},
            {"id": "5", "expected_techniques": ["stack-buffer-overflow"]},
            {"id": "6", "expected_techniques": ["format-string"]},
        ]
        train, test = split_by_family(cases, holdout=0.34)
        self.assertTrue(train and test)
        self.assertEqual(family_overlap(train, test), set())

    def test_split_is_deterministic_for_a_seed(self):
        from agent.retrieval_eval import split_by_family
        cases = [{"id": str(i), "expected_techniques": [t]} for i, t in enumerate(
            ["jwt-none-bypass", "xor-single-byte", "sql-injection", "ssti"])]
        first = split_by_family(cases, seed=3)[1]
        second = split_by_family(cases, seed=3)[1]
        self.assertEqual([c["id"] for c in first], [c["id"] for c in second])

    def test_project_eval_set_is_not_contaminated_by_its_own_corpus(self):
        """The shipped ground truth must not be answerable by memorisation."""
        import json
        from pathlib import Path

        from agent.retrieval_eval import check_contamination

        eval_path = Path("data/eval/ground_truth.json")
        if not eval_path.exists():
            self.skipTest("no ground truth file")
        cases = json.loads(eval_path.read_text(encoding="utf-8"))
        docs = []
        for card in sorted(Path("data/archive").glob("*.json"))[:80]:
            try:
                docs.append(json.loads(card.read_text(encoding="utf-8")))
            except Exception:
                continue
        report = check_contamination(cases, docs, threshold=0.4)
        self.assertTrue(report.clean, report.render())


class TestDifficultyEstimation(unittest.TestCase):
    def test_more_techniques_and_heavier_tools_score_higher(self):
        from agent.difficulty import estimate
        simple = new_challenge_state("decode a base64 string", category="misc")
        simple.add_hypothesis("base64", technique="base64-decode", confidence=0.8)
        action = simple.record_action("decode_toolkit", {"path_or_text": "x"})
        simple.mark_action_result(action.id, status="succeeded")

        hard = new_challenge_state("a packed binary with a custom check", category="rev")
        for technique in ("packed-binary", "stack-buffer-overflow", "ret2libc", "format-string"):
            hard.add_hypothesis(technique, technique=technique, confidence=0.4)
        for tool in ("static_analysis", "gdb_inspect"):
            act = hard.record_action(tool, {"path": "./b"})
            hard.mark_action_result(act.id, status="succeeded")

        self.assertGreater(estimate(hard).score, estimate(simple).score)

    def test_bands_are_ordered(self):
        from agent.difficulty import band_for
        self.assertEqual(band_for(0.05), "trivial")
        self.assertEqual(band_for(0.5), "medium")
        self.assertEqual(band_for(0.95), "expert")

    def test_disagreement_with_a_stated_label_is_surfaced(self):
        from agent.difficulty import estimate
        state = new_challenge_state("trivial base64", category="misc")
        state.difficulty = "expert"
        self.assertTrue(estimate(state).disagrees_with_label)

    def test_stall_raises_the_floor(self):
        from agent.difficulty import estimate
        state = new_challenge_state("x", category="pwn")
        state.add_hypothesis("h", technique="stack-buffer-overflow", confidence=0.4)
        calm = estimate(state).score
        state.status = "stuck"
        self.assertGreater(estimate(state).score, calm)

    def test_spec_estimate_needs_no_run(self):
        from agent.difficulty import estimate_from_spec
        result = estimate_from_spec(["ret2libc", "rop"], tools=["gdb_inspect"], steps=9)
        self.assertGreater(result.score, 0.0)
        self.assertIn("specification", " ".join(result.notes))

    def test_empty_state_is_not_hard(self):
        from agent.difficulty import estimate
        self.assertLess(estimate(new_challenge_state("x")).score, 0.2)


class TestDoctor(unittest.TestCase):
    def test_probe_returns_checks_and_never_raises(self):
        from agent.doctor import probe
        checks = probe(include_model=False)
        self.assertTrue(checks)
        self.assertTrue(all(isinstance(c.ok, bool) for c in checks))

    def test_python_and_writability_are_not_optional(self):
        from agent.doctor import probe
        required = [c for c in probe(include_model=False) if not c.optional]
        self.assertTrue(any(c.name.startswith("python 3") for c in required))
        self.assertTrue(any("writable" in c.name for c in required))

    def test_missing_binaries_degrade_specific_categories(self):
        from agent.doctor import Check, degraded_categories
        checks = [Check(name="tshark", tier="analysis", ok=False, categories=["forensics"]),
                  Check(name="gdb", tier="analysis", ok=True, categories=["pwn"])]
        degraded = degraded_categories(checks)
        self.assertEqual(degraded, {"forensics": ["tshark"]})

    def test_summary_reports_usability(self):
        from agent.doctor import probe, summary
        report = summary(probe(include_model=False))
        self.assertIn("usable", report)
        self.assertIn("hardware", report)

    def test_report_renders_with_tiers_and_remedies(self):
        from agent.doctor import render_report
        text = render_report()
        self.assertIn("Core (required)", text)
        self.assertIn("Analysis tooling", text)

    def test_hardware_detection_reports_platform(self):
        from agent.doctor import hardware
        self.assertTrue(hardware().get("os"))


if __name__ == "__main__":
    unittest.main()
