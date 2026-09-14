import sys
import os
import json
import tempfile
import shutil
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import ArchiveEntry
import retriever
from retriever import (
    Retriever,
    OllamaEmbeddingFunction,
    _entry_to_metadata,
    _entry_from_metadata,
    _default_id,
    _sub_problem_query_text,
)
from tests.fakes import FakeCollection, FakeOllamaHTTP


def make_entry(name="AuthBreaker", category="web", techniques=None, source="ExampleCTF"):
    return ArchiveEntry(
        challenge_name=name,
        category=category,
        techniques=techniques or ["jwt-alg-confusion"],
        difficulty="medium",
        source=source,
        description="A login portal issues JWTs signed with RS256.",
        explanation="The server accepts alg=none tokens, so an attacker can forge one.",
        solve_steps=["Capture a token", "Set alg to none", "Replay it"],
        tools_used=["jwt_tool"],
        references=["https://example.com/writeup"],
    )


class FakeSubProblem:
    def __init__(self, id, description, likely_techniques=None, evidence=""):
        self.id = id
        self.description = description
        self.likely_techniques = likely_techniques or []
        self.evidence = evidence


class TestOllamaEmbeddingFunction(unittest.TestCase):
    def test_call_batches_documents_through_call_ollama_embed(self):
        fake = FakeOllamaHTTP(embed_dim=5)
        embed_fn = OllamaEmbeddingFunction(model="nomic-embed-text")
        with patch("requests.post", side_effect=fake):
            vectors = embed_fn(["doc a", "doc b"])
        self.assertEqual(len(vectors), 2)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(fake.calls[0]["json"]["model"], "nomic-embed-text")
        self.assertEqual(fake.calls[0]["json"]["input"], ["doc a", "doc b"])

    def test_name_reflects_model(self):
        embed_fn = OllamaEmbeddingFunction(model="my-model")
        self.assertEqual(embed_fn.name(), "ollama-my-model")


class TestMetadataRoundTrip(unittest.TestCase):
    def test_entry_round_trips_through_metadata(self):
        entry = make_entry()
        metadata = _entry_to_metadata(entry)
        # chromadb metadata values must be flat str/int/float/bool
        for value in metadata.values():
            self.assertIsInstance(value, str)
        restored = _entry_from_metadata(metadata)
        self.assertEqual(restored.to_dict(), entry.to_dict())

    def test_default_id_is_slugified(self):
        entry = make_entry(name="Web CTF 2024 - AuthBreaker!!", category="web")
        doc_id = _default_id(entry)
        self.assertEqual(doc_id, "web-web-ctf-2024-authbreaker")


class TestRetrieverIndexingAndQuery(unittest.TestCase):
    def setUp(self):
        self.collection = FakeCollection()
        self.retriever = Retriever(collection=self.collection)

    def test_index_entry_then_query_returns_match(self):
        entry = make_entry(name="AuthBreaker", techniques=["jwt-alg-confusion"])
        self.retriever.index_entry(entry)
        self.assertEqual(self.retriever.count(), 1)

        matches = self.retriever.query("jwt alg confusion login portal", n_results=5)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].entry.challenge_name, "AuthBreaker")
        self.assertGreater(matches[0].score, 0)

    def test_reindexing_same_id_upserts_not_duplicates(self):
        entry = make_entry(name="AuthBreaker")
        doc_id = self.retriever.index_entry(entry, doc_id="fixed-id")
        self.retriever.index_entry(entry, doc_id="fixed-id")
        self.assertEqual(doc_id, "fixed-id")
        self.assertEqual(self.retriever.count(), 1)

    def test_query_category_filter(self):
        self.retriever.index_entry(make_entry(name="WebOne", category="web"))
        self.retriever.index_entry(make_entry(name="PwnOne", category="pwn", techniques=["ret2libc"]))

        web_matches = self.retriever.query("some query text", n_results=5, category="web")
        self.assertEqual(len(web_matches), 1)
        self.assertEqual(web_matches[0].entry.category, "web")

    def test_reset_clears_the_collection(self):
        self.retriever.index_entry(make_entry())
        self.assertEqual(self.retriever.count(), 1)
        self.retriever.reset()
        self.assertEqual(self.retriever.count(), 0)

    def test_query_sub_problem_builds_query_from_description_and_techniques(self):
        self.retriever.index_entry(
            make_entry(name="PaddingOracleChal", techniques=["padding-oracle"])
        )
        sp = FakeSubProblem(
            id="sp1",
            description="cookie decryption looks vulnerable",
            likely_techniques=["padding-oracle"],
        )
        matches = self.retriever.query_sub_problem(sp, n_results=3)
        self.assertTrue(any(m.entry.challenge_name == "PaddingOracleChal" for m in matches))


class TestIndexDirectory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.collection = FakeCollection()
        self.retriever = Retriever(collection=self.collection)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_indexes_all_valid_entries_and_skips_bad_json(self):
        make_entry(name="One").save(os.path.join(self.tmpdir, "one.json"))
        make_entry(name="Two", category="pwn").save(os.path.join(self.tmpdir, "two.json"))
        with open(os.path.join(self.tmpdir, "broken.json"), "w") as f:
            f.write("{not valid json")

        count = self.retriever.index_directory(self.tmpdir)
        self.assertEqual(count, 2)
        self.assertEqual(self.retriever.count(), 2)

    def test_empty_directory_returns_zero(self):
        count = self.retriever.index_directory(self.tmpdir)
        self.assertEqual(count, 0)

    def test_reindexing_same_directory_does_not_duplicate(self):
        make_entry(name="One").save(os.path.join(self.tmpdir, "one.json"))
        self.retriever.index_directory(self.tmpdir)
        self.retriever.index_directory(self.tmpdir)
        self.assertEqual(self.retriever.count(), 1)


class TestSubProblemQueryText(unittest.TestCase):
    def test_includes_description_techniques_and_evidence(self):
        sp = FakeSubProblem(
            id="sp1",
            description="the token accepts alg none",
            likely_techniques=["jwt-alg-confusion", "jwt-none-bypass"],
            evidence="header shows alg: none",
        )
        text = _sub_problem_query_text(sp)
        self.assertIn("the token accepts alg none", text)
        self.assertIn("jwt-alg-confusion", text)
        self.assertIn("header shows alg: none", text)


class TestDefaultBackendRequiresChromadb(unittest.TestCase):
    def test_missing_chromadb_raises_helpful_error(self):
        # Force `import chromadb` to fail regardless of whether it's
        # actually installed in whatever environment runs this test suite
        # (it isn't, in this sandbox -- but shouldn't need to be, since
        # everything else in this file injects a collection). Setting the
        # module to None in sys.modules is the standard way to simulate
        # "not installed" for an import statement.
        with patch.dict(sys.modules, {"chromadb": None}):
            with self.assertRaises(RuntimeError) as ctx:
                Retriever(persist_dir=tempfile.mkdtemp())
        self.assertIn("pip install chromadb", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()