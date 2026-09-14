import sys
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch
from collections import namedtuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import ghidra_headless as gh

FakeResult = namedtuple("FakeResult", ["returncode", "stdout", "stderr"])


class TestFindAnalyzeHeadless(unittest.TestCase):
    def test_prefers_ghidra_install_dir_env_var(self):
        tmp_install = tempfile.mkdtemp()
        support_dir = os.path.join(tmp_install, "support")
        os.makedirs(support_dir)
        analyze_path = os.path.join(support_dir, "analyzeHeadless")
        open(analyze_path, "w").close()
        try:
            with patch.dict(os.environ, {"GHIDRA_INSTALL_DIR": tmp_install}):
                self.assertEqual(gh.find_analyze_headless(), analyze_path)
        finally:
            shutil.rmtree(tmp_install, ignore_errors=True)

    def test_falls_back_to_path_when_env_var_unset_or_invalid(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("shutil.which", return_value="/usr/local/bin/analyzeHeadless"):
            self.assertEqual(gh.find_analyze_headless(), "/usr/local/bin/analyzeHeadless")

    def test_returns_none_when_nothing_found(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("shutil.which", return_value=None):
            self.assertIsNone(gh.find_analyze_headless())


class TestDecompileWithGhidra(unittest.TestCase):
    def setUp(self):
        self.binary_fd, self.binary_path = tempfile.mkstemp()
        os.close(self.binary_fd)

    def tearDown(self):
        try:
            os.remove(self.binary_path)
        except OSError:
            pass

    def test_returns_helpful_message_when_ghidra_not_found(self):
        with patch.object(gh, "find_analyze_headless", return_value=None):
            result = gh.decompile_with_ghidra(self.binary_path)
        self.assertIn("Ghidra not found", result)
        self.assertIn("GHIDRA_INSTALL_DIR", result)

    def test_returns_message_when_binary_does_not_exist(self):
        with patch.object(gh, "find_analyze_headless", return_value="/fake/analyzeHeadless"):
            result = gh.decompile_with_ghidra("/no/such/binary")
        self.assertIn("binary not found", result)

    def test_reads_back_decompiled_output_on_success(self):
        decompiled_text = "// ---- main @ 00401000 ----\nint main(void) { return 0; }\n"

        def fake_run(cmd, capture_output, text, timeout):
            idx = cmd.index(gh.SCRIPT_NAME)
            output_path = cmd[idx + 1]
            with open(output_path, "w") as f:
                f.write(decompiled_text)
            return FakeResult(returncode=0, stdout="", stderr="")

        with patch.object(gh, "find_analyze_headless", return_value="/fake/analyzeHeadless"), \
             patch("subprocess.run", side_effect=fake_run):
            result = gh.decompile_with_ghidra(self.binary_path)

        self.assertEqual(result, decompiled_text)

    def test_nonzero_exit_reports_stderr(self):
        def fake_run(cmd, capture_output, text, timeout):
            return FakeResult(returncode=1, stdout="", stderr="Error: bad ELF header")

        with patch.object(gh, "find_analyze_headless", return_value="/fake/analyzeHeadless"), \
             patch("subprocess.run", side_effect=fake_run):
            result = gh.decompile_with_ghidra(self.binary_path)

        self.assertIn("exit 1", result)
        self.assertIn("bad ELF header", result)

    def test_timeout_reports_helpful_message(self):
        import subprocess as real_subprocess

        def fake_run(cmd, capture_output, text, timeout):
            raise real_subprocess.TimeoutExpired(cmd, timeout)

        with patch.object(gh, "find_analyze_headless", return_value="/fake/analyzeHeadless"), \
             patch("subprocess.run", side_effect=fake_run):
            result = gh.decompile_with_ghidra(self.binary_path, timeout=42)

        self.assertIn("timed out after 42s", result)

    def test_cleans_up_temp_output_file_after_success(self):
        captured_path = {}

        def fake_run(cmd, capture_output, text, timeout):
            idx = cmd.index(gh.SCRIPT_NAME)
            output_path = cmd[idx + 1]
            captured_path["path"] = output_path
            with open(output_path, "w") as f:
                f.write("decompiled")
            return FakeResult(returncode=0, stdout="", stderr="")

        with patch.object(gh, "find_analyze_headless", return_value="/fake/analyzeHeadless"), \
             patch("subprocess.run", side_effect=fake_run):
            gh.decompile_with_ghidra(self.binary_path)

        self.assertFalse(os.path.exists(captured_path["path"]))

    def test_cleans_up_own_project_dir_when_not_provided(self):
        captured_project_dir = {}

        def fake_run(cmd, capture_output, text, timeout):
            captured_project_dir["path"] = cmd[1]  # project_dir is 2nd positional arg
            idx = cmd.index(gh.SCRIPT_NAME)
            with open(cmd[idx + 1], "w") as f:
                f.write("decompiled")
            return FakeResult(returncode=0, stdout="", stderr="")

        with patch.object(gh, "find_analyze_headless", return_value="/fake/analyzeHeadless"), \
             patch("subprocess.run", side_effect=fake_run):
            gh.decompile_with_ghidra(self.binary_path)

        self.assertFalse(os.path.isdir(captured_project_dir["path"]))


if __name__ == "__main__":
    unittest.main()
