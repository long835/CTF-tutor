"""Ambiguous decoy-crypto PWN lab."""
from __future__ import annotations
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class TestDecoyLab(unittest.TestCase):
    def test_binary_and_manifest(self):
        self.assertTrue((ROOT / "data/samples/experience/pwn_decoy_crypto/vuln").is_file())
        from agent.experience_labs import get_lab
        lab = get_lab("pwn_decoy_crypto")
        self.assertEqual(lab.category, "pwn")

if __name__ == "__main__":
    unittest.main()
