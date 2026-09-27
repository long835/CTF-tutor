"""v0.5.2 labs and imported growth."""
from __future__ import annotations
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class TestV052(unittest.TestCase):
    def test_repeat_xor(self):
        p = ROOT / "data/samples/experience/crypto_repeat_xor/cipher.hex"
        self.assertTrue(p.is_file())
        self.assertGreater(len(p.read_text().strip()), 20)

    def test_path_lab(self):
        self.assertTrue((ROOT / "data/samples/experience/web_path_lab/secret.txt").is_file())
        self.assertIn(b"flag{", (ROOT / "data/samples/experience/web_path_lab/secret.txt").read_bytes())

    def test_imported_count(self):
        from agent.imported_cases import load_imported
        self.assertGreaterEqual(len(load_imported()), 6)

if __name__ == "__main__":
    unittest.main()
