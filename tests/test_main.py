import sys
import os
import io
import json
import contextlib
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import ArchiveEntry
import decomposer
import synthesizer
import explainer
import depth_guide
import main
from main import run, _print_report
from depth_guide import HintLevel
from retriever import Retriever
from tests.fakes import FakeCollection


DECOMPOSER_REPLY = json.dumps([
    {
        "id": "jwt-part",
        "description": "the jwt token uses alg none bypass",
        "likely_techniques": ["jwt-alg-confusion"],
        "evidence": "header shows alg none",
    },
    {
        "id": "ssrf-part",
        "description": "the server fetches an internal url causing ssrf",
        "likely_techniques": ["ssrf"],
        "evidence": "url parameter accepted unchecked",
    },
])

SYNTHESIS_REPLY = json.dumps({
    "combined": True,
    "summary": "The JWT forgery is used to reach an admin-only SSRF endpoint.",
    "contributing_matches": ["JWT None Confusion Challenge", "SSRF Internal Fetch"],
    "shared_techniques": ["jwt-alg-confusion", "ssrf"],
})

EXPLANATION_REPLY = json.dumps({
    "explanation": "This matches a known technique from the archive.",
    "cited_entries": ["JWT None Confusion Challenge"],
})

HINT_REPLY = json.dumps({"hint": "some hint text", "cited_entries": []})


def _make_entry(name, category, techniques, explanation):
    return ArchiveEntry(
        challenge_name=name,
        category=category,
        techniques=techniques,
        source="ExampleCTF",
        description="an archived challenge",
        explanation=explanation,
        solve_steps=["step one", "step two"],
    )


def _build_populated_retriever() -> Retriever:
    retriever = Retriever(collection=FakeCollection())
    retriever.index_entry(_make_entry(
        "JWT None Confusion Challenge", "web", ["jwt-alg-confusion"],
        "the jwt token uses alg none bypass technique",
    ))
    retriever.index_entry(_make_entry(
        "SSRF Internal Fetch", "web", ["ssrf"],
        "the server fetches an internal url causing ssrf issues",
    ))
    return retriever


class TestFullPipeline(unittest.TestCase):
    def test_run_wires_all_stages_together(self):
        retriever = _build_populated_retriever()

        with patch.object(decomposer, "call_ollama", return_value=DECOMPOSER_REPLY), \
             patch.object(synthesizer, "call_ollama", return_value=SYNTHESIS_REPLY), \
             patch.object(explainer, "call_ollama", return_value=EXPLANATION_REPLY):
            result = run(
                "A login portal issues JWTs signed with RS256...",
                category="web",
                retriever=retriever,
            )

        sub_problem_ids = [sp.id for sp in result["sub_problems"]]
        self.assertEqual(sub_problem_ids, ["jwt-part", "ssrf-part"])

        # retrieval actually ran and found the closest archive entry for
        # the JWT sub-problem specifically (not just "some matches")
        jwt_matches = result["matches_by_id"]["jwt-part"]
        self.assertTrue(jwt_matches)
        self.assertEqual(jwt_matches[0].entry.challenge_name, "JWT None Confusion Challenge")

        self.assertTrue(result["synthesis"].combined)
        self.assertEqual(
            result["synthesis"].summary,
            "The JWT forgery is used to reach an admin-only SSRF endpoint.",
        )

        self.assertEqual(len(result["explanations"]), 2)
        for exp in result["explanations"]:
            self.assertEqual(exp.text, "This matches a known technique from the archive.")

        # no depth requested -> no hints computed, no LLM calls for them
        self.assertEqual(result["hints_by_id"], {})

    def test_verbose_prints_stage_progress(self):
        retriever = _build_populated_retriever()

        with patch.object(decomposer, "call_ollama", return_value=DECOMPOSER_REPLY), \
             patch.object(synthesizer, "call_ollama", return_value=SYNTHESIS_REPLY), \
             patch.object(explainer, "call_ollama", return_value=EXPLANATION_REPLY):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(
                    "A login portal issues JWTs signed with RS256...",
                    category="web",
                    retriever=retriever,
                    verbose=True,
                )
        output = buf.getvalue()
        self.assertIn("Decomposing", output)
        self.assertIn("Searching", output)
        self.assertIn("Cross-referencing", output)

    def test_not_verbose_by_default_produces_no_stdout(self):
        retriever = _build_populated_retriever()

        with patch.object(decomposer, "call_ollama", return_value=DECOMPOSER_REPLY), \
             patch.object(synthesizer, "call_ollama", return_value=SYNTHESIS_REPLY), \
             patch.object(explainer, "call_ollama", return_value=EXPLANATION_REPLY):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                run(
                    "A login portal issues JWTs signed with RS256...",
                    category="web",
                    retriever=retriever,
                )
        self.assertEqual(buf.getvalue(), "")


        retriever = _build_populated_retriever()

        with patch.object(decomposer, "call_ollama", return_value=DECOMPOSER_REPLY), \
             patch.object(synthesizer, "call_ollama", return_value=SYNTHESIS_REPLY), \
             patch.object(explainer, "call_ollama", return_value=EXPLANATION_REPLY), \
             patch.object(depth_guide, "call_ollama", return_value=HINT_REPLY) as mock_hint_call:
            result = run(
                "A login portal issues JWTs signed with RS256...",
                retriever=retriever,
                depth=HintLevel.APPROACH,
            )

        # 2 sub-problems x 2 levels (NAME, APPROACH) = 4 calls
        self.assertEqual(mock_hint_call.call_count, 4)
        self.assertEqual(set(result["hints_by_id"].keys()), {"jwt-part", "ssrf-part"})
        for hints in result["hints_by_id"].values():
            self.assertEqual([h.level for h in hints], [HintLevel.NAME, HintLevel.APPROACH])

    def test_run_degrades_gracefully_when_chromadb_is_unavailable(self):
        # Simulate the sandbox-style situation: no injected retriever, and
        # the real chromadb-backed one can't even be constructed. The
        # pipeline should still produce (ungrounded) explanations rather
        # than crashing.
        with patch.dict(sys.modules, {"chromadb": None}), \
             patch.object(decomposer, "call_ollama", return_value=DECOMPOSER_REPLY), \
             patch.object(synthesizer, "call_ollama") as mock_synth_call, \
             patch.object(explainer, "call_ollama", return_value=EXPLANATION_REPLY):
            result = run("A login portal issues JWTs signed with RS256...", retriever=None)

        self.assertEqual(result["matches_by_id"], {"jwt-part": [], "ssrf-part": []})
        # nothing to cross-reference with zero matches everywhere
        mock_synth_call.assert_not_called()
        self.assertFalse(result["synthesis"].combined)
        for exp in result["explanations"]:
            self.assertFalse(exp.grounded)


class TestPrintReport(unittest.TestCase):
    def test_does_not_crash_on_a_full_result(self):
        retriever = _build_populated_retriever()
        with patch.object(decomposer, "call_ollama", return_value=DECOMPOSER_REPLY), \
             patch.object(synthesizer, "call_ollama", return_value=SYNTHESIS_REPLY), \
             patch.object(explainer, "call_ollama", return_value=EXPLANATION_REPLY), \
             patch.object(depth_guide, "call_ollama", return_value=HINT_REPLY):
            result = run(
                "A login portal issues JWTs signed with RS256...",
                retriever=retriever,
                depth=HintLevel.NAME,
            )

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            _print_report(result)
        output = buf.getvalue()
        self.assertIn("Sub-problems", output)
        self.assertIn("Explanations", output)
        self.assertIn("Cross-reference", output)
        self.assertIn("Hints", output)


if __name__ == "__main__":
    unittest.main()