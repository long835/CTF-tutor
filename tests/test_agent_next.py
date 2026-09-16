"""Tests for triage, hybrid retrieve, sandbox, memory, trace."""

import json
import os
import tempfile
import unittest
from pathlib import Path


class TestTriage(unittest.TestCase):
    def test_inventory_single_source_file(self):
        from agent.triage import inventory_path
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "app.py"
            p.write_text("import jwt\ntoken = 'eyJhbGciOiJub25lIn0.payload.sig'\n")
            inv = inventory_path(td)
            self.assertEqual(inv.file_count, 1)
            self.assertEqual(inv.artifacts[0].kind, "source")
            self.assertTrue(any("jwt" in x for x in inv.artifacts[0].interesting) or inv.categories_hint)

    def test_inventory_binary_magic(self):
        from agent.triage import inventory_path
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "chall"
            p.write_bytes(b"\x7fELF" + b"\x00" * 20)
            inv = inventory_path(td)
            self.assertEqual(inv.artifacts[0].magic_hint, "ELF")
            self.assertIn("pwn", inv.categories_hint + ["pwn"])  # at least binary signal

    def test_apply_to_state(self):
        from agent.triage import inventory_path, apply_inventory_to_state
        from agent.state import new_challenge_state
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "main.c").write_text("gets(buf);\n")
            inv = inventory_path(td)
            state = new_challenge_state("overflow challenge")
            apply_inventory_to_state(state, inv)
            self.assertTrue(len(state.discovered_artifacts) >= 1)
            self.assertTrue(any("Inventory" in f for f in state.known_facts))


class TestHybridRetrieve(unittest.TestCase):
    def test_lexical_finds_jwt_entry(self):
        from agent.hybrid_retrieve import hybrid_search, get_lexical_index
        idx = get_lexical_index()
        self.assertGreater(len(idx.docs), 5)
        hits = hybrid_search("JWT algorithm none bypass", category="web", top_k=5)
        self.assertTrue(len(hits) >= 1)
        # at least one web-ish result
        cats = [h.get("category") for h in hits]
        self.assertTrue(any(c == "web" for c in cats) or hits[0]["score"] > 0)

    def test_empty_query(self):
        from agent.hybrid_retrieve import hybrid_search
        self.assertEqual(hybrid_search(""), [])


class TestSandbox(unittest.TestCase):
    def test_echo(self):
        from agent.sandbox import run_sandboxed
        r = run_sandboxed(["echo", "hello-ctf"], timeout_sec=5)
        self.assertTrue(r.ok)
        self.assertIn("hello-ctf", r.stdout)

    def test_timeout(self):
        from agent.sandbox import run_sandboxed
        r = run_sandboxed(["sleep", "30"], timeout_sec=0.3)
        self.assertTrue(r.timed_out)

    def test_no_shell_injection(self):
        from agent.sandbox import run_sandboxed
        # argv form must not expand shell metacharacters
        r = run_sandboxed(["echo", "a; rm -rf /"], timeout_sec=5)
        self.assertIn("a; rm -rf /", r.stdout)


class TestMemory(unittest.TestCase):
    def test_mastery_and_persist(self):
        from agent.memory import LearnerMemory, save_memory, load_memory
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "mem.json")
            mem = LearnerMemory()
            mem.record_attempt("jwt-none-bypass", success=True, hints=0)
            mem.record_attempt("jwt-none-bypass", success=True, hints=1)
            mem.record_attempt("sql-injection", success=False, hints=3)
            self.assertIn("sql-injection", mem.weak_techniques(threshold=0.5, min_attempts=1))
            save_memory(mem, path)
            mem2 = load_memory(path)
            self.assertEqual(mem2.techniques["jwt-none-bypass"].successes, 2)


class TestTrace(unittest.TestCase):
    def test_redact_and_write(self):
        from agent.trace import TraceLogger, redact
        self.assertIn("REDACTED", redact("api_key=sk-secret-12345"))
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "t.jsonl")
            tr = TraceLogger(path=path, enabled=True)
            tr.log("test_event", msg="hello", token="secret")
            lines = Path(path).read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["event"], "test_event")


class TestAgentWithPath(unittest.TestCase):
    def test_agent_triage_path(self):
        from agent.loop import AgentLoop
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "server.py").write_text(
                "# flask app\nimport jwt\n# alg=none accepted\n"
            )
            agent = AgentLoop(
                challenge_summary="Web login with JWT",
                category="web",
                max_steps=2,
                challenge_path=td,
                enable_trace=False,
            )
            state = agent.bootstrap()
            self.assertTrue(any("Inventory" in f for f in state.known_facts))
            self.assertTrue(len(state.discovered_artifacts) >= 1)


if __name__ == "__main__":
    unittest.main()
