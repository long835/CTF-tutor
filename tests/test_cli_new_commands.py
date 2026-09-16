"""CLI wiring tests for the subcommands added in the roadmap completion pass."""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import main


def run_cli(argv):
    """Invoke main.main(argv) and capture (exit_code, stdout)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main.main(argv)
    return code, buf.getvalue()


class TestSubcommandRegistration(unittest.TestCase):
    def test_new_subcommands_are_registered(self):
        for name in ("curriculum", "graph", "audit", "dashboard", "plugins"):
            self.assertIn(name, main.SUBCOMMAND_NAMES)
            self.assertTrue(hasattr(main, f"cmd_{name}"), f"missing handler for {name}")

    def test_help_lists_them(self):
        code, out = run_cli(["--help"])
        self.assertEqual(code, 0)
        for name in ("curriculum", "graph", "audit", "dashboard", "plugins"):
            self.assertIn(name, out)

    def test_backward_compatible_bare_description_still_routes_to_run(self):
        # A description that happens to start with a word must not be
        # swallowed by the new subcommands.
        self.assertNotIn("a login portal issues jwts", main.SUBCOMMAND_NAMES)


class TestCurriculumCommand(unittest.TestCase):
    def test_renders_text(self):
        code, out = run_cli(["curriculum", "-n", "2"])
        self.assertEqual(code, 0)
        self.assertIn("Your next steps", out)

    def test_json_output_parses(self):
        code, out = run_cli(["curriculum", "-n", "2", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertIn("lessons", payload)
        self.assertIn("target_difficulty", payload)

    def test_goal_flag_is_accepted(self):
        code, out = run_cli(["curriculum", "--goal", "ret2libc", "-n", "3", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["generated_from"]["goal"], "ret2libc")

    def test_outcome_flags_shift_difficulty(self):
        _, solved = run_cli(["curriculum", "--solved", "--json"])
        _, stuck = run_cli(["curriculum", "--stuck", "--json"])
        order = ["easy", "medium", "hard", "insane"]
        self.assertGreaterEqual(
            order.index(json.loads(solved)["target_difficulty"]),
            order.index(json.loads(stuck)["target_difficulty"]),
        )


class TestGraphCommand(unittest.TestCase):
    def test_stats(self):
        code, out = run_cli(["graph", "--stats"])
        self.assertEqual(code, 0)
        self.assertIn("nodes", json.loads(out))

    def test_query_renders_neighbourhood(self):
        code, out = run_cli(["graph", "sql-injection"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip())

    def test_unknown_query_is_graceful(self):
        code, out = run_cli(["graph", "not-a-real-technique-xyz"])
        self.assertEqual(code, 0)
        self.assertIn("No challenge", out)

    def test_path_between_endpoints(self):
        code, out = run_cli(["graph", "--path", "stack-buffer-overflow", "ret2libc"])
        self.assertIn(code, (0, 1))

    def test_dot_export(self):
        code, out = run_cli(["graph", "--dot"])
        self.assertEqual(code, 0)
        self.assertTrue(out.strip().startswith("graph challenges"))


class TestAuditCommand(unittest.TestCase):
    def test_default_report(self):
        code, out = run_cli(["audit"])
        self.assertIn(code, (0, 1))
        self.assertIn("Archive audit", out)

    def test_json_output(self):
        code, out = run_cli(["audit", "--json"])
        self.assertIn(code, (0, 1))
        self.assertIn("entries", json.loads(out))

    def test_strict_mode_returns_zero_on_a_clean_archive(self):
        code, _ = run_cli(["audit", "--sync", "--strict"])
        self.assertEqual(code, 0, "shipped archive should pass a strict audit")


class TestDashboardCommand(unittest.TestCase):
    def test_writes_html(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, "dash.html")
            code, out = run_cli(["dashboard", "--out", out_path])
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_path))
            self.assertIn("dashboard:", out)


class TestPluginsCommand(unittest.TestCase):
    def test_lists_plugins(self):
        code, out = run_cli(["plugins"])
        self.assertEqual(code, 0)
        self.assertIn("Plugins", out)

    def test_json_output(self):
        code, out = run_cli(["plugins", "--json"])
        self.assertEqual(code, 0)
        self.assertIn("discovered", json.loads(out))

    def test_missing_directory_is_handled(self):
        code, out = run_cli(["plugins", "--dir", "nope/not/here"])
        self.assertEqual(code, 0)
        self.assertIn("does not exist", out)


if __name__ == "__main__":
    unittest.main()
