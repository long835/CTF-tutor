"""
tests/test_dataset_item20.py

The generated evaluation set (item 20).

These tests guard the three controls, not the accuracy number. An accuracy
assertion here would be self-defeating: it would make the benchmark
something to satisfy rather than something to measure against. What must not
regress is the set's honesty — that it is reproducible, that it does not
reuse corpus wording, that most of it does not hand the classifier its
answer, and that the train/test split leaks no families.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import dataset, taxonomy
from agent.retrieval_eval import family_overlap


class TestDatasetShape(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = dataset.build_dataset(per_band=25)

    def test_generation_is_deterministic(self):
        again = dataset.build_dataset(per_band=25)
        self.assertEqual([c.id for c in self.cases], [c.id for c in again])
        self.assertEqual([c.description for c in self.cases], [c.description for c in again])

    def test_a_different_seed_gives_a_different_set(self):
        other = dataset.build_dataset(seed=1, per_band=25)
        self.assertNotEqual(
            [c.description for c in self.cases], [c.description for c in other]
        )

    def test_every_band_is_populated(self):
        for band in dataset.BANDS:
            self.assertEqual(len([c for c in self.cases if c.band == band]), 25, band)

    def test_ids_are_unique(self):
        ids = [c.id for c in self.cases]
        self.assertEqual(len(ids), len(set(ids)))

    def test_labels_are_canonical(self):
        for case in self.cases:
            for technique in case.expected_techniques:
                self.assertEqual(taxonomy.canonical(technique), technique, case.id)
            self.assertEqual(case.expected_category, taxonomy.category_of(case.expected_techniques[0]))

    def test_descriptions_never_contain_rubric_patterns(self):
        # Pasting an alternation pattern into a case would hand the grader
        # its own regex back and read like machine output.
        for case in self.cases:
            self.assertNotIn("|", case.description, case.id)
            self.assertNotIn("{0,", case.description, case.id)

    def test_adversarial_cases_carry_a_trap(self):
        for case in [c for c in self.cases if c.band == "adversarial"]:
            self.assertTrue(case.trap, case.id)
            self.assertTrue(case.must_not_conclude, case.id)

    def test_multi_step_cases_need_several_stages(self):
        for case in [c for c in self.cases if c.band == "multi_step"]:
            self.assertGreaterEqual(case.expected_steps, 3, case.id)

    def test_tool_heavy_cases_name_tools(self):
        heavy = [c for c in self.cases if c.band == "tool_heavy"]
        self.assertTrue(any(c.expected_tools for c in heavy))


class TestDatasetControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = dataset.build_dataset(per_band=25)

    def test_most_cases_are_keyword_blind(self):
        report = dataset.keyword_report(self.cases)
        self.assertGreater(
            report["blind_fraction"], 0.5,
            "a set that names the technique in most cases measures re.search",
        )

    def test_keyword_detection_actually_fires(self):
        self.assertTrue(dataset.has_decisive_keyword("this is a classic SQL injection"))
        self.assertFalse(dataset.has_decisive_keyword("the query is built by concatenation"))

    def test_stripping_removes_the_name_and_keeps_the_situation(self):
        text = "The JWT header selects the algorithm used to verify it."
        stripped = dataset._strip_decisive_terms(text)
        self.assertFalse(dataset.has_decisive_keyword(stripped))
        self.assertIn("algorithm", stripped)

    def test_corpus_leakage_stays_low(self):
        report = dataset.leakage_report(self.cases[:60])
        # The Phase 3 contamination bug was a single case at 0.74.
        self.assertLess(report["mean_max_leakage"], 0.15, report["worst"][:3])
        self.assertLess(report["over_threshold"] / 60.0, 0.15)

    def test_split_leaks_no_families(self):
        train, test = dataset.split(self.cases)
        self.assertTrue(train and test)
        self.assertEqual(
            family_overlap([c.to_dict() for c in train], [c.to_dict() for c in test]),
            set(),
        )

    def test_accuracy_report_counts_only_correct_answers(self):
        # The bug this guards: `sum(1 for ... )` counted every row, so the
        # first run reported 1.000 accuracy next to 276 confusions.
        report = dataset.accuracy_report(self.cases)
        misses = sum(sum(v.values()) for v in report["confusions"].values())
        correct = round(report["accuracy"] * report["cases"])
        self.assertEqual(correct + misses, report["cases"])

    def test_blind_and_keyed_subsets_partition_the_set(self):
        report = dataset.accuracy_report(self.cases)
        self.assertEqual(report["blind_cases"] + report["keyed_cases"], report["cases"])

    def test_formal_classifier_beats_the_legacy_heuristic(self):
        # A comparison, not a target: both are measured on the same
        # out-of-sample set, which is the whole point of building it.
        formal = dataset.accuracy_report(self.cases, "formal")["accuracy"]
        heuristic = dataset.accuracy_report(self.cases, "heuristic")["accuracy"]
        self.assertGreater(formal, heuristic)


class TestDatasetPersistence(unittest.TestCase):
    def test_round_trips_through_disk(self):
        cases = dataset.build_dataset(per_band=5)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "set.json")
            dataset.save_dataset(cases, path)
            back = dataset.load_dataset(path)
        self.assertEqual(len(back), len(cases))
        self.assertEqual(back[0].to_dict(), cases[0].to_dict())

    def test_missing_file_is_empty_not_an_error(self):
        self.assertEqual(dataset.load_dataset("/nonexistent/set.json"), [])

    def test_ground_truth_export_matches_the_old_harness(self):
        rows = dataset.to_ground_truth(dataset.build_dataset(per_band=2))
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual(
                sorted(row),
                ["description", "difficulty", "expected_category",
                 "expected_techniques", "id"],
            )

    def test_shipped_set_is_present_and_large(self):
        cases = dataset.load_dataset()
        self.assertGreaterEqual(len(cases), 600)


class TestDatasetCLI(unittest.TestCase):
    def _run(self, argv):
        import contextlib
        import io
        import main

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.main(argv)
        return code, buf.getvalue()

    def test_measure_reports_the_blind_number(self):
        code, out = self._run(["dataset", "--measure"])
        self.assertEqual(code, 0)
        self.assertIn("blind", out)

    def test_split_reports_no_shared_families(self):
        code, out = self._run(["dataset", "--split"])
        self.assertEqual(code, 0)
        self.assertIn("none", out)

    def test_missing_dataset_fails_cleanly(self):
        code, out = self._run(["dataset", "--path", "/nonexistent/x.json"])
        self.assertEqual(code, 1)
        self.assertIn("--build", out)


if __name__ == "__main__":
    unittest.main()
