import sys
import os
import io
import json
import tempfile
import shutil
import contextlib
import unittest
from unittest.mock import patch
from dataclasses import dataclass, field
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import ArchiveEntry
import main
import history as history_module


def make_entry(name, category="web", techniques=None):
    return ArchiveEntry(
        challenge_name=name,
        category=category,
        techniques=techniques or ["jwt-alg-confusion"],
        source="ExampleCTF",
        description="desc",
        explanation="why it worked",
        solve_steps=["a", "b"],
    )


@dataclass
class FakeSubProblem:
    id: str
    description: str
    likely_techniques: List[str] = field(default_factory=list)
    evidence: str = ""


class TestCmdRunWarmup(unittest.TestCase):
    def test_warms_up_before_classifying_and_running(self):
        call_order = []
        with patch.object(main.llm_client, "warm_up", side_effect=lambda **k: call_order.append("warmup")) as mock_warmup, \
             patch.object(main, "classifier") as mock_classifier, \
             patch.object(main, "run") as mock_run, \
             patch.object(main, "_print_report"), \
             patch.object(main.history, "log_entry"):
            mock_classifier.classify.side_effect = lambda *a, **k: call_order.append("classify") or "web"
            mock_run.side_effect = lambda *a, **k: call_order.append("run") or {
                "sub_problems": [], "matches_by_id": {}, "synthesis": None, "explanations": [], "hints_by_id": {},
            }
            code = main.cmd_run(["some challenge", "--no-history"])

        self.assertEqual(code, 0)
        mock_warmup.assert_called_once()
        self.assertEqual(call_order, ["warmup", "classify", "run"])

    def test_no_warmup_flag_skips_the_warmup_call(self):
        with patch.object(main.llm_client, "warm_up") as mock_warmup, \
             patch.object(main, "classifier") as mock_classifier, \
             patch.object(main, "run") as mock_run, \
             patch.object(main, "_print_report"), \
             patch.object(main.history, "log_entry"):
            mock_classifier.classify.return_value = "web"
            mock_run.return_value = {
                "sub_problems": [], "matches_by_id": {}, "synthesis": None, "explanations": [], "hints_by_id": {},
            }
            code = main.cmd_run(["some challenge", "--no-warmup", "--no-history"])

        self.assertEqual(code, 0)
        mock_warmup.assert_not_called()

    def test_warmup_failure_reports_error_and_stops_before_running_pipeline(self):
        with patch.object(main.llm_client, "warm_up", side_effect=RuntimeError("Could not reach Ollama")), \
             patch.object(main, "run") as mock_run:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                code = main.cmd_run(["some challenge"])

        self.assertEqual(code, 1)
        self.assertIn("Could not reach Ollama", buf.getvalue())
        mock_run.assert_not_called()

    def test_no_history_flag_skips_logging(self):
        with patch.object(main.llm_client, "warm_up"), \
             patch.object(main, "classifier") as mock_classifier, \
             patch.object(main, "run") as mock_run, \
             patch.object(main, "_print_report"), \
             patch.object(main.history, "log_entry") as mock_log:
            mock_classifier.classify.return_value = "web"
            mock_run.return_value = {
                "sub_problems": [], "matches_by_id": {}, "synthesis": None, "explanations": [], "hints_by_id": {},
            }
            main.cmd_run(["some challenge", "--no-history"])

        mock_log.assert_not_called()


    def test_classify_failure_reports_error_cleanly(self):
        with patch.object(main.llm_client, "warm_up"), \
             patch.object(main, "classifier") as mock_classifier, \
             patch.object(main, "run") as mock_run:
            mock_classifier.classify.side_effect = RuntimeError("Could not reach Ollama")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                code = main.cmd_run(["some challenge"])

        self.assertEqual(code, 1)
        self.assertIn("Could not reach Ollama", buf.getvalue())
        mock_run.assert_not_called()

    def test_run_failure_reports_error_cleanly_instead_of_raw_traceback(self):
        with patch.object(main.llm_client, "warm_up"), \
             patch.object(main, "classifier") as mock_classifier, \
             patch.object(main, "run") as mock_run:
            mock_classifier.classify.return_value = "web"
            mock_run.side_effect = RuntimeError("Could not reach Ollama")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                code = main.cmd_run(["some challenge"])

        self.assertEqual(code, 1)
        self.assertIn("Could not reach Ollama", buf.getvalue())


class TestMainDispatch(unittest.TestCase):
    def test_defaults_to_run_subcommand_when_none_given(self):
        with patch.object(main, "cmd_run", return_value=0) as mock_run:
            code = main.main(["some challenge description"])
        mock_run.assert_called_once_with(["some challenge description"])
        self.assertEqual(code, 0)

    def test_routes_to_named_subcommand(self):
        with patch.object(main, "cmd_search", return_value=0) as mock_search:
            main.main(["search", "jwt bypass"])
        mock_search.assert_called_once_with(["jwt bypass"])

    def test_no_args_shows_help_and_returns_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.main([])
        self.assertEqual(code, 0)
        self.assertIn("run", buf.getvalue())
        self.assertIn("search", buf.getvalue())

    def test_help_flag_shows_subcommand_summary(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.main(["--help"])
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn("usage: main.py", out)
        # Every registered subcommand should be discoverable from --help,
        # regardless of how the listing is grouped.
        for name in main.SUBCOMMAND_NAMES:
            self.assertIn(name, out, f"{name} missing from --help output")


class TestCmdList(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_lists_entries_grouped_by_category(self):
        make_entry("WebOne", category="web").save(os.path.join(self.tmpdir, "one.json"))
        make_entry("PwnOne", category="pwn", techniques=["ret2libc"]).save(
            os.path.join(self.tmpdir, "two.json")
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.cmd_list(["--dir", self.tmpdir])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("WebOne", output)
        self.assertIn("PwnOne", output)
        self.assertIn("pwn (1)", output)
        self.assertIn("web (1)", output)

    def test_category_filter(self):
        make_entry("WebOne", category="web").save(os.path.join(self.tmpdir, "one.json"))
        make_entry("PwnOne", category="pwn").save(os.path.join(self.tmpdir, "two.json"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main.cmd_list(["--dir", self.tmpdir, "--category", "pwn"])
        output = buf.getvalue()
        self.assertIn("PwnOne", output)
        self.assertNotIn("WebOne", output)

    def test_empty_directory_reports_no_entries(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.cmd_list(["--dir", self.tmpdir])
        self.assertEqual(code, 0)
        self.assertIn("no archive entries found", buf.getvalue())

    def test_missing_directory_reports_gracefully(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.cmd_list(["--dir", "/no/such/directory"])
        self.assertEqual(code, 0)
        self.assertIn("no archive directory", buf.getvalue())


class TestCmdHistory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, "history.jsonl")
        self.patcher = patch.object(history_module, "DEFAULT_HISTORY_PATH", self.path)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _log(self, techniques, category="web"):
        entry = history_module.HistoryEntry(
            timestamp="2026-01-01T00:00:00+00:00", challenge_description="a challenge here",
            category=category, depth="approach", sub_problem_count=1, techniques=techniques,
        )
        history_module.log_entry(entry, path=self.path)

    def test_reports_no_history_when_empty(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main.cmd_history([])
        self.assertEqual(code, 0)
        self.assertIn("no history yet", buf.getvalue())

    def test_lists_recent_sessions(self):
        self._log(["jwt-alg-confusion"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main.cmd_history([])
        output = buf.getvalue()
        self.assertIn("a challenge here", output)
        self.assertIn("jwt-alg-confusion", output)

    def test_summary_shows_technique_counts(self):
        self._log(["jwt-alg-confusion"])
        self._log(["jwt-alg-confusion", "ssrf"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main.cmd_history(["--summary"])
        output = buf.getvalue()
        self.assertIn("jwt-alg-confusion", output)
        self.assertIn("ssrf", output)


class TestRunInteractiveHints(unittest.TestCase):
    def test_shows_hint_when_yes_then_stops_ladder_on_no(self):
        sp = FakeSubProblem(id="sp1", description="desc", likely_techniques=["jwt-alg-confusion"])
        answers = iter(["y", "n"])  # show NAME level, decline APPROACH -> stop this sub-problem
        fake_input = lambda prompt: next(answers)
        fake_hint = type("Hint", (), {"text": "it's a JWT alg confusion issue"})()

        with patch.object(main.depth_guide, "get_hint", return_value=fake_hint) as mock_get_hint:
            main.run_interactive_hints([sp], {"sp1": []}, input_func=fake_input)

        mock_get_hint.assert_called_once()  # only NAME level requested before declining

    def test_q_stops_everything_immediately(self):
        sp1 = FakeSubProblem(id="sp1", description="first")
        sp2 = FakeSubProblem(id="sp2", description="second")
        fake_input = lambda prompt: "q"

        with patch.object(main.depth_guide, "get_hint") as mock_get_hint:
            main.run_interactive_hints([sp1, sp2], {"sp1": [], "sp2": []}, input_func=fake_input)

        mock_get_hint.assert_not_called()

    def test_moves_to_next_sub_problem_after_ladder_exhausted(self):
        sp1 = FakeSubProblem(id="sp1", description="first")
        sp2 = FakeSubProblem(id="sp2", description="second")
        # sp1: decline immediately; sp2: decline immediately
        fake_input = lambda prompt: "n"

        with patch.object(main.depth_guide, "get_hint") as mock_get_hint:
            main.run_interactive_hints([sp1, sp2], {"sp1": [], "sp2": []}, input_func=fake_input)

        mock_get_hint.assert_not_called()


if __name__ == "__main__":
    unittest.main()
