"""Learning-outcome benchmark and pwn lab artifact."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestLearningOutcome(unittest.TestCase):
    def test_benchmark_runs(self):
        from agent.learning_outcome import run_benchmark
        report = run_benchmark(record=False)
        self.assertGreaterEqual(report["n"], 3)
        self.assertIn("pre_accuracy", report)
        self.assertIn("transfer_accuracy", report)


class TestPwnLab(unittest.TestCase):
    def test_binary_present(self):
        vuln = ROOT / "data/samples/experience/pwn_bof/vuln"
        self.assertTrue(vuln.is_file(), "teaching ELF missing — gcc build failed?")
        self.assertGreater(vuln.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()


class TestExperienceArtifacts(unittest.TestCase):
    def test_pcap_contains_flag(self):
        data = (ROOT / "data/samples/experience/forensics_pcap/capture.pcap").read_bytes()
        self.assertIn(b"flag{pcap_http_lab}", data)
        self.assertTrue(data.startswith(b"\xd4\xc3\xb2\xa1") or data[:4] == bytes.fromhex("d4c3b2a1"))

    def test_png_text(self):
        data = (ROOT / "data/samples/experience/forensics_png/hidden.png").read_bytes()
        self.assertTrue(data.startswith(b"\x89PNG"))
        self.assertIn(b"flag{png_text_lab}", data)

    def test_web_lab_script(self):
        p = ROOT / "data/samples/experience/web_ssti_lab/server.py"
        self.assertTrue(p.is_file())
        self.assertIn("format", p.read_text())

    def test_manifest_count(self):
        import json
        m = json.loads((ROOT / "data/samples/experience/manifest.json").read_text())
        self.assertGreaterEqual(len(m["items"]), 7)
