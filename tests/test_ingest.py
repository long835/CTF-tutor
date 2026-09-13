import sys
import os
import io
import tempfile
import shutil
import contextlib
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from schema import ArchiveEntry
import ingest
from retriever import Retriever
from tests.fakes import FakeCollection


def make_entry(name, category="web", techniques=None):
    return ArchiveEntry(
        challenge_name=name,
        category=category,
        techniques=techniques or ["jwt-alg-confusion"],
        source="ExampleCTF",
        description="desc",
        explanation="why it worked",
        solve_steps=["a", "b"],
    )


class TestIngestMain(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.retriever = Retriever(collection=FakeCollection())

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_indexes_archive_directory_and_reports_counts(self):
        make_entry("One").save(os.path.join(self.tmpdir, "one.json"))
        make_entry("Two", category="pwn", techniques=["ret2libc"]).save(
            os.path.join(self.tmpdir, "two.json")
        )

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ingest.main([self.tmpdir], retriever=self.retriever)

        self.assertEqual(code, 0)
        self.assertEqual(self.retriever.count(), 2)
        output = buf.getvalue()
        self.assertIn("indexed 2 archive entries", output)

    def test_reset_flag_clears_store_before_indexing(self):
        # pre-populate the store with an entry NOT in the archive dir --
        # --reset should wipe it rather than leaving it stranded
        self.retriever.index_entry(make_entry("Stale"))
        self.assertEqual(self.retriever.count(), 1)

        make_entry("Fresh").save(os.path.join(self.tmpdir, "fresh.json"))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = ingest.main([self.tmpdir, "--reset"], retriever=self.retriever)

        self.assertEqual(code, 0)
        self.assertEqual(self.retriever.count(), 1)
        matches = self.retriever.query("fresh", n_results=5)
        self.assertTrue(any(m.entry.challenge_name == "Fresh" for m in matches))

    def test_rerunning_does_not_duplicate(self):
        make_entry("One").save(os.path.join(self.tmpdir, "one.json"))
        with contextlib.redirect_stdout(io.StringIO()):
            ingest.main([self.tmpdir], retriever=self.retriever)
            ingest.main([self.tmpdir], retriever=self.retriever)
        self.assertEqual(self.retriever.count(), 1)

    def test_missing_chromadb_reports_error_and_nonzero_exit(self):
        from unittest.mock import patch

        with patch.dict(sys.modules, {"chromadb": None}):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                code = ingest.main([self.tmpdir])  # no retriever injected
        self.assertEqual(code, 1)
        self.assertIn("pip install chromadb", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
