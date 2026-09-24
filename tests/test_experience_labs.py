"""Experience labs first-class integration."""

from __future__ import annotations

import unittest


class TestExperienceLabs(unittest.TestCase):
    def test_list(self):
        from agent.experience_labs import list_labs, labs_summary
        labs = list_labs()
        self.assertGreaterEqual(len(labs), 7)
        s = labs_summary()
        self.assertEqual(s["count"], len(labs))

    def test_get_and_classify_pwn(self):
        from agent.experience_labs import classify_lab, get_lab
        lab = get_lab("pwn_bof")
        self.assertIsNotNone(lab)
        self.assertEqual(lab.category, "pwn")
        self.assertTrue(lab.artifact_path)
        result = classify_lab("pwn_bof")
        self.assertTrue(result.get("category_match"), result)

    def test_classify_pcap(self):
        from agent.experience_labs import classify_lab
        result = classify_lab("forensics_pcap")
        self.assertIn(result.get("classification", {}).get("category"), ("forensics", "misc", "web"))


if __name__ == "__main__":
    unittest.main()
