import sys
import os
import json
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import ArchiveEntry, SubProblem
import explainer
from explainer import explain, explain_all, build_user_prompt
from retriever import RetrievedMatch


def make_entry(name="AuthBreaker"):
    return ArchiveEntry(
        challenge_name=name,
        category="web",
        techniques=["jwt-alg-confusion"],
        source="ExampleCTF",
        description="desc",
        explanation="The server trusts alg=none tokens.",
        solve_steps=["a", "b"],
    )


def make_match(entry, score=0.8):
    return RetrievedMatch(entry=entry, score=score, distance=1 - score, matched_on="q")


def make_sub_problem(id="sp1", description="the token seems forgeable", techniques=None, evidence=""):
    return SubProblem(id=id, description=description, likely_techniques=techniques or [], evidence=evidence)


class TestBuildUserPrompt(unittest.TestCase):
    def test_includes_matches_when_present(self):
        sp = make_sub_problem()
        matches = [make_match(make_entry("AuthBreaker"))]
        prompt = build_user_prompt(sp, matches)
        self.assertIn("AuthBreaker", prompt)
        self.assertIn("The server trusts alg=none tokens.", prompt)

    def test_notes_absence_when_no_matches(self):
        sp = make_sub_problem()
        prompt = build_user_prompt(sp, [])
        self.assertIn("No matching past challenges were found", prompt)


class TestExplain(unittest.TestCase):
    def test_grounded_explanation_uses_grounded_system_prompt(self):
        sp = make_sub_problem()
        matches = [make_match(make_entry("AuthBreaker"))]
        fake_reply = json.dumps({
            "explanation": "This resembles AuthBreaker's alg=none bypass.",
            "cited_entries": ["AuthBreaker"],
        })
        with patch.object(explainer, "call_ollama", return_value=fake_reply) as mock_call:
            result = explain(sp, matches)

        used_system_prompt = mock_call.call_args[0][0]
        self.assertEqual(used_system_prompt, explainer.EXPLAIN_SYSTEM_PROMPT_GROUNDED)
        self.assertTrue(result.grounded)
        self.assertEqual(result.text, "This resembles AuthBreaker's alg=none bypass.")
        self.assertEqual(result.cited_entries, ["AuthBreaker"])
        self.assertEqual(result.sub_problem_id, "sp1")

    def test_ungrounded_explanation_uses_ungrounded_system_prompt(self):
        sp = make_sub_problem()
        fake_reply = json.dumps({"explanation": "General idea of JWT confusion.", "cited_entries": []})
        with patch.object(explainer, "call_ollama", return_value=fake_reply) as mock_call:
            result = explain(sp, [])

        used_system_prompt = mock_call.call_args[0][0]
        self.assertEqual(used_system_prompt, explainer.EXPLAIN_SYSTEM_PROMPT_UNGROUNDED)
        self.assertFalse(result.grounded)
        self.assertEqual(result.cited_entries, [])

    def test_falls_back_gracefully_on_non_json_reply(self):
        sp = make_sub_problem()
        with patch.object(explainer, "call_ollama", return_value="It's basically a JWT trick."):
            result = explain(sp, [])
        self.assertEqual(result.text, "It's basically a JWT trick.")
        self.assertEqual(result.cited_entries, [])


class TestExplainAll(unittest.TestCase):
    def test_maps_matches_by_sub_problem_id(self):
        sp1 = make_sub_problem(id="sp1")
        sp2 = make_sub_problem(id="sp2")
        matches_by_id = {"sp1": [make_match(make_entry("A"))]}  # sp2 intentionally missing

        with patch.object(explainer, "call_ollama", return_value='{"explanation": "x", "cited_entries": []}'):
            results = explain_all([sp1, sp2], matches_by_id)

        self.assertEqual(len(results), 2)
        by_id = {r.sub_problem_id: r for r in results}
        self.assertTrue(by_id["sp1"].grounded)
        self.assertFalse(by_id["sp2"].grounded)  # missing key defaults to no matches, no KeyError


if __name__ == "__main__":
    unittest.main()