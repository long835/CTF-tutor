"""v0.5.3 labs and normalize."""
from __future__ import annotations
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

class TestV053(unittest.TestCase):
    def test_rev_lab(self):
        self.assertTrue((ROOT / "data/samples/experience/rev_password/vuln").is_file())

    def test_aes_decoy(self):
        notes = (ROOT / "data/samples/experience/crypto_aes_decoy/notes.txt").read_text()
        self.assertIn("AES", notes)
        self.assertTrue((ROOT / "data/samples/experience/crypto_aes_decoy/cipher.hex").is_file())

    def test_canonical(self):
        from agent.technique_normalize import canonical_technique, canonical_list
        self.assertTrue(canonical_technique("Buffer Overflow"))
        self.assertEqual(len(canonical_list(["a", "a", "b"])), 2)

    def test_imported_ge_8(self):
        from agent.imported_cases import load_imported
        self.assertGreaterEqual(len(load_imported()), 8)

if __name__ == "__main__":
    unittest.main()
