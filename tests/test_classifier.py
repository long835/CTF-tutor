import sys
import os
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import classifier
from classifier import classify, classify_heuristic, CATEGORIES


class TestClassifyHeuristic(unittest.TestCase):
    def test_detects_web_from_jwt_and_login_terms(self):
        desc = "A login portal issues JWTs signed with RS256. The admin panel trusts the role claim."
        best, scores = classify_heuristic(desc)
        self.assertEqual(best, "web")

    def test_detects_pwn_from_buffer_overflow_terms(self):
        desc = "A binary reads a name into a fixed stack buffer with gets(), no canary, NX enabled. Get a shell with ret2libc."
        best, scores = classify_heuristic(desc)
        self.assertEqual(best, "pwn")

    def test_detects_crypto_from_cipher_terms(self):
        desc = "Messages are encrypted with RSA using a small public exponent and a shared modulus across users."
        best, scores = classify_heuristic(desc)
        self.assertEqual(best, "crypto")

    def test_detects_rev_from_decompile_terms(self):
        desc = "Reverse engineer this crackme -- disassemble it in Ghidra and find the keygen algorithm."
        best, scores = classify_heuristic(desc)
        self.assertEqual(best, "rev")

    def test_detects_forensics_from_pcap_terms(self):
        desc = "Analyze this pcap in Wireshark to find the hidden flag in the network capture."
        best, scores = classify_heuristic(desc)
        self.assertEqual(best, "forensics")

    def test_returns_none_for_generic_text_with_no_signal(self):
        best, scores = classify_heuristic("Find the flag hidden somewhere in this challenge.")
        self.assertIsNone(best)

    def test_returns_none_on_a_tie(self):
        # exactly one strong keyword for two different categories -> ambiguous
        desc = "This involves both a login page and a buffer overflow somehow."
        best, scores = classify_heuristic(desc)
        self.assertIsNone(best)

    def test_case_insensitive(self):
        best, scores = classify_heuristic("SQL INJECTION in the LOGIN form over HTTP")
        self.assertEqual(best, "web")


class TestClassify(unittest.TestCase):
    def test_uses_heuristic_without_calling_llm_when_confident(self):
        with patch.object(classifier, "call_ollama") as mock_call:
            result = classify("A classic stack buffer overflow with gets() and ret2libc, no canary")
        mock_call.assert_not_called()
        self.assertEqual(result, "pwn")

    def test_falls_back_to_llm_when_heuristic_is_ambiguous(self):
        fake_reply = '{"category": "misc", "confidence": "low"}'
        with patch.object(classifier, "call_ollama", return_value=fake_reply) as mock_call:
            result = classify("Something weird is going on with this challenge, not sure what.")
        mock_call.assert_called_once()
        self.assertEqual(result, "misc")

    def test_llm_fallback_invalid_category_defaults_to_misc(self):
        fake_reply = '{"category": "not_a_real_category"}'
        with patch.object(classifier, "call_ollama", return_value=fake_reply):
            result = classify("Something ambiguous with no clear signal at all.")
        self.assertEqual(result, "misc")

    def test_result_is_always_a_known_category(self):
        with patch.object(classifier, "call_ollama", return_value="not json at all"):
            result = classify("Totally ambiguous text with zero keyword signal.")
        self.assertIn(result, CATEGORIES)


if __name__ == "__main__":
    unittest.main()
