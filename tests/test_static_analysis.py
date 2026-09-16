import sys
import os
import unittest
from unittest.mock import patch
from collections import namedtuple

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import static_analysis as sa

FakeResult = namedtuple("FakeResult", ["stdout", "stderr"])


class TestRunHelper(unittest.TestCase):
    def test_missing_tool_returns_helpful_message_without_calling_subprocess(self):
        with patch("shutil.which", return_value=None), \
             patch("subprocess.run") as mock_run:
            result = sa._run(["not_a_real_tool", "x"])
        mock_run.assert_not_called()
        self.assertIn("not_a_real_tool not installed", result)

    def test_returns_stdout_on_success(self):
        with patch("shutil.which", return_value="/usr/bin/file"), \
             patch("subprocess.run", return_value=FakeResult(stdout="ELF 64-bit\n", stderr="")):
            result = sa._run(["file", "x"])
        self.assertEqual(result, "ELF 64-bit")

    def test_appends_stderr_when_present(self):
        with patch("shutil.which", return_value="/usr/bin/tool"), \
             patch("subprocess.run", return_value=FakeResult(stdout="out", stderr="warning: x")):
            result = sa._run(["tool", "x"])
        self.assertIn("out", result)
        self.assertIn("[stderr] warning: x", result)

    def test_timeout_returns_helpful_message(self):
        import subprocess as real_subprocess

        def raise_timeout(*a, **k):
            raise real_subprocess.TimeoutExpired(["tool"], 15)

        with patch("shutil.which", return_value="/usr/bin/tool"), \
             patch("subprocess.run", side_effect=raise_timeout):
            result = sa._run(["tool", "x"], timeout=15)
        self.assertIn("timed out after 15s", result)


class TestListSymbols(unittest.TestCase):
    def test_dynamic_only_uses_nm_dash_capital_d(self):
        with patch("shutil.which", return_value="/usr/bin/nm"), \
             patch("subprocess.run", return_value=FakeResult(stdout="system\nexecve\n", stderr="")) as mock_run:
            sa.list_symbols("/bin/x", dynamic_only=True)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd, ["nm", "-D", "/bin/x"])

    def test_full_symbol_table_omits_dash_capital_d(self):
        with patch("shutil.which", return_value="/usr/bin/nm"), \
             patch("subprocess.run", return_value=FakeResult(stdout="main\n", stderr="")) as mock_run:
            sa.list_symbols("/bin/x", dynamic_only=False)
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd, ["nm", "/bin/x"])


class TestReadElfHeaders(unittest.TestCase):
    def test_calls_readelf_with_header_and_dynamic_flags(self):
        with patch("shutil.which", return_value="/usr/bin/readelf"), \
             patch("subprocess.run", return_value=FakeResult(stdout="ELF Header:\n", stderr="")) as mock_run:
            sa.read_elf_headers("/bin/x")
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd, ["readelf", "-h", "-d", "/bin/x"])


class TestDisassemble(unittest.TestCase):
    def test_disassembles_whole_binary_by_default(self):
        with patch("shutil.which", return_value="/usr/bin/objdump"), \
             patch("subprocess.run", return_value=FakeResult(stdout="<main>:\n", stderr="")) as mock_run:
            sa.disassemble("/bin/x")
        called_cmd = mock_run.call_args[0][0]
        self.assertEqual(called_cmd, ["objdump", "-d", "-M", "intel", "/bin/x"])

    def test_targets_a_single_function_when_given(self):
        with patch("shutil.which", return_value="/usr/bin/objdump"), \
             patch("subprocess.run", return_value=FakeResult(stdout="<main>:\n", stderr="")) as mock_run:
            sa.disassemble("/bin/x", function="main")
        called_cmd = mock_run.call_args[0][0]
        self.assertIn("--disassemble=main", called_cmd)

    def test_truncates_long_output(self):
        long_output = "\n".join(f"line{i}" for i in range(500))
        with patch("shutil.which", return_value="/usr/bin/objdump"), \
             patch("subprocess.run", return_value=FakeResult(stdout=long_output, stderr="")):
            result = sa.disassemble("/bin/x", limit_lines=10)
        self.assertEqual(len(result.splitlines()), 11)  # 10 lines + truncation notice
        self.assertIn("truncated", result.splitlines()[-1])


class TestFullRecon(unittest.TestCase):
    def _patched(self, **overrides):
        defaults = dict(
            identify_file=lambda path: "file-output",
            extract_strings=lambda path, **k: "strings-output",
            check_binary_protections=lambda path: "checksec-output",
            list_symbols=lambda path, **k: "nm-output",
            read_elf_headers=lambda path: "readelf-output",
            run_binwalk=lambda path: "binwalk-output",
            extract_metadata=lambda path: "exiftool-output",
            decompile_with_ghidra=lambda path: "decompiled-output",
        )
        defaults.update(overrides)
        return defaults

    def test_pwn_category_includes_binary_checks_not_forensics_checks(self):
        with patch.multiple(sa, **self._patched()):
            evidence = sa.full_recon("/bin/x", category_hint="pwn")
        self.assertIn("binary_protections", evidence)
        self.assertIn("dynamic_symbols", evidence)
        self.assertIn("elf_headers", evidence)
        self.assertNotIn("binwalk", evidence)
        self.assertNotIn("decompiled", evidence)

    def test_forensics_category_includes_forensics_checks_not_binary_checks(self):
        with patch.multiple(sa, **self._patched()):
            evidence = sa.full_recon("/bin/x", category_hint="forensics")
        self.assertIn("binwalk", evidence)
        self.assertIn("metadata", evidence)
        self.assertNotIn("binary_protections", evidence)

    def test_none_category_includes_both(self):
        with patch.multiple(sa, **self._patched()):
            evidence = sa.full_recon("/bin/x", category_hint=None)
        self.assertIn("binary_protections", evidence)
        self.assertIn("binwalk", evidence)

    def test_decompile_only_runs_when_requested(self):
        with patch.multiple(sa, **self._patched()):
            evidence = sa.full_recon("/bin/x", category_hint="rev", include_decompile=True)
        self.assertEqual(evidence["decompiled"], "decompiled-output")


if __name__ == "__main__":
    unittest.main()
