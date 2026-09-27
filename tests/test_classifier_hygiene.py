"""Classifier hygiene: dedupe signals, full technique map, negation, unknown."""

from __future__ import annotations

import unittest


class TestClassifierHygiene(unittest.TestCase):
    def test_no_duplicate_signal_patterns(self):
        from agent.classify_challenge import SIGNALS
        seen = set()
        dups = []
        for pat, cat, _wt in SIGNALS:
            key = (pat, cat)
            if key in seen:
                dups.append(key)
            seen.add(key)
        self.assertEqual(dups, [], f"duplicate SIGNALS: {dups[:5]}")

    def test_technique_map_covers_library(self):
        import json
        from pathlib import Path
        from agent.classify_challenge import TECHNIQUE_CATEGORY
        lib = json.loads(Path("data/technique_library.json").read_text())
        techs = lib.get("techniques") or lib
        if isinstance(techs, dict):
            techs = list(techs.values())
        names = {str(t.get("technique") or "").lower() for t in techs if isinstance(t, dict)}
        names.discard("")
        covered = names & set(TECHNIQUE_CATEGORY.keys())
        self.assertGreaterEqual(len(covered) / max(len(names), 1), 0.95)

    def test_negation_does_not_prefer_web(self):
        from agent.classify_challenge import classify_challenge
        text = (
            "This is not a SQL injection challenge, there is no JWT involved, "
            "and it is definitely not web-related. The binary uses a stack "
            "buffer overflow via gets() to overwrite the return address."
        )
        r = classify_challenge(text)
        self.assertEqual(r.category, "pwn", r)

    def test_unknown_vs_misc(self):
        from agent.classify_challenge import classify_challenge
        r = classify_challenge("asdf qwer zxcv totally empty noise")
        # may be misc or unknown depending on floor — must set ambiguous/unknown flag
        self.assertTrue(
            getattr(r, "unknown", False)
            or r.category in ("misc", "unknown")
            or r.ambiguous
            or r.confidence < 0.35
        )


if __name__ == "__main__":
    unittest.main()
