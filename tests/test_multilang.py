import json
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from multilang import MultiLanguageSession, SUPPORTED_LANGUAGES


class TestMultiLanguageSession(unittest.TestCase):
    def test_session_state_survives_language_switch(self):
        with TemporaryDirectory() as td:
            s = MultiLanguageSession.create("polyglot", root=td)
            s.add_note("started in python")
            s.switch("rust")
            s.add_note("checked rust path")
            loaded = MultiLanguageSession.load(s.workspace)
            self.assertEqual(loaded.current_language, "rust")
            self.assertEqual(loaded.languages_used, ["python", "rust"])
            self.assertEqual(loaded.notes, ["started in python", "checked rust path"])

    def test_python_execution_is_recorded(self):
        with TemporaryDirectory() as td:
            s = MultiLanguageSession.create("exec", root=td)
            result = s.run_source("print('hello')")
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.strip(), "hello")
            loaded = MultiLanguageSession.load(s.workspace)
            self.assertEqual(len(loaded.executions), 1)
            self.assertEqual(loaded.executions[0].language, "python")
            self.assertTrue(Path(loaded.artifacts[0]).exists())

    def test_timeout_is_bounded(self):
        with TemporaryDirectory() as td:
            s = MultiLanguageSession.create("timeout", root=td)
            result = s.run_source("while True: pass", timeout=1)
            self.assertTrue(result.timed_out)
            self.assertIsNone(result.returncode)

    def test_supported_languages_are_explicit(self):
        self.assertEqual(SUPPORTED_LANGUAGES, ("python", "rust", "java", "dotnet"))

    def test_state_is_json(self):
        with TemporaryDirectory() as td:
            s = MultiLanguageSession.create("json", root=td)
            data = json.loads(Path(s.state_path).read_text())
            self.assertEqual(data["challenge_name"], "json")
            self.assertIn("languages_used", data)


if __name__ == "__main__":
    unittest.main()
