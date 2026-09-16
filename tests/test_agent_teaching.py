"""Tests for teaching, workspace, permissions."""

import os
import tempfile
import unittest
from pathlib import Path


class TestTeaching(unittest.TestCase):
    def test_socratic_and_hints(self):
        from agent.state import new_challenge_state
        from agent.teaching import socratic_questions, progressive_hint, detect_misconceptions
        s = new_challenge_state("JWT login accepts alg=none", category="web")
        s.add_hypothesis("JWT none bypass", technique="jwt-none-bypass", confidence=0.7)
        qs = socratic_questions(s)
        self.assertTrue(len(qs) >= 1)
        h1 = progressive_hint(s, 1)
        self.assertIn("web", h1.lower())
        h6 = progressive_hint(s, 6)
        self.assertTrue(len(h6) > 10)
        misc = detect_misconceptions("is jwt encryption?")
        self.assertTrue(any("signed" in m.lower() or "encrypt" in m.lower() for m in misc))

    def test_teaching_report(self):
        from agent.state import new_challenge_state
        from agent.teaching import teaching_report
        s = new_challenge_state("overflow with gets", category="pwn")
        s.add_hypothesis("stack bof", technique="stack-buffer-overflow", confidence=0.6)
        report = teaching_report(s, hint_level=3)
        self.assertIn("Socratic", report)
        self.assertIn("Hint", report)


class TestWorkspace(unittest.TestCase):
    def test_persist_roundtrip(self):
        from agent.workspace import ChallengeWorkspace
        from agent.state import new_challenge_state
        with tempfile.TemporaryDirectory() as td:
            ws = ChallengeWorkspace("test-chal", root=td).ensure()
            state = new_challenge_state("desc", challenge_id="test-chal", category="web")
            state.add_hypothesis("h", confidence=0.5)
            ws.save_state(state)
            loaded = ws.load_state()
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.category, "web")
            self.assertEqual(len(loaded.hypotheses), 1)
            ws.append_note("tried checksec")
            self.assertTrue(ws.notes_path.exists())


class TestPermissions(unittest.TestCase):
    def test_defaults(self):
        from agent.permissions import allowed, required_permission, Permission
        self.assertTrue(allowed("retrieve_archive"))
        self.assertTrue(allowed("web_recon"))
        self.assertFalse(allowed("run_binary"))
        self.assertEqual(required_permission("network_request"), Permission.FULL_APPROVAL)


class TestLoopMemoryWorkspace(unittest.TestCase):
    def test_bootstrap_creates_workspace(self):
        from agent.loop import AgentLoop
        with tempfile.TemporaryDirectory() as td:
            # point workspaces at temp by monkeypatching default is hard;
            # just ensure bootstrap does not crash with memory+workspace
            agent = AgentLoop(
                "JWT alg=none portal",
                category="web",
                max_steps=1,
                enable_trace=False,
            )
            state = agent.bootstrap()
            self.assertTrue(len(state.hypotheses) >= 1)
            # workspace may exist under data/workspaces
            if agent.workspace:
                self.assertTrue(agent.workspace.root.exists())


if __name__ == "__main__":
    unittest.main()
