"""ArchiveEntry schema accepts version/updated; audit path loads all entries."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestArchiveSchema(unittest.TestCase):
    def test_load_all_archive_entries(self):
        from schema import ArchiveEntry
        archive = ROOT / "data" / "archive"
        files = list(archive.glob("*.json"))
        self.assertGreaterEqual(len(files), 40)
        for fp in files:
            entry = ArchiveEntry.load(str(fp))
            self.assertTrue(entry.challenge_name)
            self.assertTrue(entry.category)
            self.assertIsInstance(entry.version, int)

    def test_from_dict_ignores_unknown_meta(self):
        from schema import ArchiveEntry
        e = ArchiveEntry.from_dict({
            "challenge_name": "t",
            "category": "web",
            "techniques": ["xss"],
            "version": 2,
            "updated": "2026-01-01",
            "provenance": "curated",
            "totally_unknown_field": 123,
        })
        self.assertEqual(e.version, 2)
        self.assertEqual(e.updated, "2026-01-01")


class TestCorpusProvenance(unittest.TestCase):
    def test_not_all_curated(self):
        import json
        path = ROOT / "data" / "corpus" / "challenges.jsonl"
        prov = set()
        with path.open(encoding="utf-8") as f:
            for line in f:
                prov.add(json.loads(line).get("provenance"))
        self.assertIn("curated", prov)
        self.assertIn("derived", prov)


if __name__ == "__main__":
    unittest.main()
