import sys
import os
import json
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import ArchiveEntry, SubProblem
import synthesizer
from synthesizer import synthesize, _worth_synthesizing, build_user_prompt, Synthesis
from retriever import RetrievedMatch


def make_entry(name, category="web", techniques=None, source="ExampleCTF"):
    return ArchiveEntry(
        challenge_name=name,
        category=category,
        techniques=techniques or ["jwt-alg-confusion"],
        source=source,
        description="desc",
        explanation="why it worked",
        solve_steps=["step 1", "step 2"],
    )


def make_match(entry, score=0.9):
    return RetrievedMatch(entry=entry, score=score, distance=1.0 - score, matched_on="q")


def make_sub_problem(id, description="desc", techniques=None):
    return SubProblem(id=id, description=description, likely_techniques=techniques or [])


class TestWorthSynthesizing(unittest.TestCase):
    def test_false_when_no_matches_at_all(self):
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {"a": [], "b": []}
        self.assertFalse(_worth_synthesizing(sub_problems, matches_by_id))

    def test_false_when_only_one_sub_problem_has_matches(self):
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {"a": [make_match(make_entry("X"))], "b": []}
        self.assertFalse(_worth_synthesizing(sub_problems, matches_by_id))

    def test_false_when_both_sub_problems_match_the_same_entry(self):
        entry = make_entry("X")
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {
            "a": [make_match(entry)],
            "b": [make_match(entry)],
        }
        self.assertFalse(_worth_synthesizing(sub_problems, matches_by_id))

    def test_true_when_two_sub_problems_match_distinct_entries(self):
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {
            "a": [make_match(make_entry("X"))],
            "b": [make_match(make_entry("Y"))],
        }
        self.assertTrue(_worth_synthesizing(sub_problems, matches_by_id))


class TestBuildUserPrompt(unittest.TestCase):
    def test_includes_descriptions_and_matches(self):
        sub_problems = [make_sub_problem("sp1", description="jwt token issue", techniques=["jwt-alg-confusion"])]
        matches_by_id = {"sp1": [make_match(make_entry("AuthBreaker"))]}
        prompt = build_user_prompt("overall desc", sub_problems, matches_by_id)
        self.assertIn("overall desc", prompt)
        self.assertIn("sp1", prompt)
        self.assertIn("jwt token issue", prompt)
        self.assertIn("AuthBreaker", prompt)

    def test_notes_when_no_matches_for_a_sub_problem(self):
        sub_problems = [make_sub_problem("sp1")]
        prompt = build_user_prompt("overall", sub_problems, {"sp1": []})
        self.assertIn("No past-challenge matches found", prompt)


class TestSynthesize(unittest.TestCase):
    def test_skips_llm_call_when_not_worth_synthesizing(self):
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {"a": [], "b": []}
        with patch.object(synthesizer, "call_ollama") as mock_call:
            result = synthesize("desc", sub_problems, matches_by_id)
        mock_call.assert_not_called()
        self.assertFalse(result.combined)
        self.assertIn("Not enough distinct", result.summary)

    def test_calls_llm_and_parses_result_when_worth_synthesizing(self):
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {
            "a": [make_match(make_entry("X", techniques=["jwt-alg-confusion"]))],
            "b": [make_match(make_entry("Y", techniques=["ssrf"]))],
        }
        fake_reply = json.dumps({
            "combined": True,
            "summary": "This blends JWT confusion with SSRF.",
            "contributing_matches": ["X", "Y"],
            "shared_techniques": ["JWT Alg Confusion", "SSRF"],
        })
        with patch.object(synthesizer, "call_ollama", return_value=fake_reply) as mock_call:
            result = synthesize("desc", sub_problems, matches_by_id)

        mock_call.assert_called_once()
        self.assertTrue(result.combined)
        self.assertEqual(result.summary, "This blends JWT confusion with SSRF.")
        self.assertEqual(result.contributing_matches, ["X", "Y"])
        # technique tags get normalized (lowercase-hyphenated)
        self.assertEqual(result.shared_techniques, ["jwt-alg-confusion", "ssrf"])

    def test_gracefully_falls_back_when_llm_output_is_not_json(self):
        sub_problems = [make_sub_problem("a"), make_sub_problem("b")]
        matches_by_id = {
            "a": [make_match(make_entry("X"))],
            "b": [make_match(make_entry("Y"))],
        }
        with patch.object(synthesizer, "call_ollama", return_value="This looks unrelated to me."):
            result = synthesize("desc", sub_problems, matches_by_id)
        self.assertFalse(result.combined)
        self.assertEqual(result.summary, "This looks unrelated to me.")
        self.assertEqual(result.contributing_matches, [])


if __name__ == "__main__":
    unittest.main()