import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tools import dotnet_decompile


class TestDotnetDecompileGracefulDegradation(unittest.TestCase):
    """Covers the paths that don't require an actual .NET SDK install --
    the same class of test tools/ghidra_headless.py and
    tools/static_analysis.py already rely on for their own optional
    dependencies."""

    def test_missing_file_reports_error_without_needing_dotnet(self):
        result = dotnet_decompile.inspect_dotnet_binary("/no/such/file.dll")
        self.assertIn("error", result)

    def test_unavailable_when_dotnet_not_installed(self):
        if dotnet_decompile.is_available():
            self.skipTest("dotnet SDK is installed in this environment")
        result = dotnet_decompile.inspect_dotnet_binary(__file__)
        self.assertIn("unavailable", result)

    def test_is_available_returns_bool(self):
        self.assertIsInstance(dotnet_decompile.is_available(), bool)


if __name__ == "__main__":
    unittest.main()
