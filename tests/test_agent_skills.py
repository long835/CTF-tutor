"""Tests for skill graph, tool registry, docker detect, expanded eval."""

import unittest


class TestSkillGraph(unittest.TestCase):
    def test_prereqs(self):
        from agent.skill_graph import prerequisites_for, missing_prerequisites, teaching_path, explain_concept
        pr = prerequisites_for("ret2libc")
        self.assertIn("stack-buffer-overflow", pr)
        missing = missing_prerequisites("ret2libc", mastered=set())
        self.assertTrue(len(missing) >= 2)
        path = teaching_path("jwt-none-bypass", set())
        self.assertIn("jwt-none-bypass", path)
        self.assertTrue(len(explain_concept("nx")) > 10)

    def test_mastered_skips(self):
        from agent.skill_graph import missing_prerequisites
        missing = missing_prerequisites(
            "ret2libc",
            mastered={"stack-buffer-overflow", "c-memory", "stack-layout", "calling-convention", "nx", "plt-got"},
        )
        self.assertEqual(missing, [])


class TestToolRegistry(unittest.TestCase):
    def test_builtins_registered(self):
        from agent.tools_registry import list_tools, get, run_tool
        names = {t.name for t in list_tools()}
        self.assertIn("retrieve_archive", names)
        self.assertIn("web_recon", names)
        spec = get("classify")
        self.assertIsNotNone(spec)
        ok, out, err = run_tool("classify", {"description": "JWT login portal with alg=none"})
        self.assertTrue(ok)


class TestDockerDetect(unittest.TestCase):
    def test_docker_available_bool(self):
        from agent.docker_sandbox import docker_available
        # just ensure it returns a bool without crashing
        self.assertIsInstance(docker_available(), bool)


class TestExpandedEval(unittest.TestCase):
    def test_eval_runs_and_hits(self):
        from agent.eval_agent import run_eval
        summary = run_eval(max_steps=3)
        self.assertGreaterEqual(summary["n"], 8)
        # Offline agent should stay strong on category
        self.assertGreaterEqual(summary["category_accuracy"], 0.70)
        self.assertGreaterEqual(summary["technique_hit_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
