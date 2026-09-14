import sys
import os
import json
import tempfile
import shutil
import unittest
from dataclasses import dataclass, field
from typing import List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from history import (
    HistoryEntry,
    entry_from_run_result,
    log_entry,
    read_history,
    summarize,
)


@dataclass
class FakeSubProblem:
    id: str
    likely_techniques: List[str] = field(default_factory=list)


class TestHistoryEntryRoundTrip(unittest.TestCase):
    def test_to_dict_from_dict_round_trip(self):
        entry = HistoryEntry(
            timestamp="2026-01-01T00:00:00+00:00",
            challenge_description="a challenge",
            category="web",
            depth="approach",
            sub_problem_count=2,
            techniques=["jwt-alg-confusion", "ssrf"],
        )
        restored = HistoryEntry.from_dict(entry.to_dict())
        self.assertEqual(restored, entry)

    def test_from_dict_tolerates_missing_optional_fields(self):
        restored = HistoryEntry.from_dict({
            "timestamp": "t",
            "challenge_description": "d",
            "sub_problem_count": 0,
        })
        self.assertIsNone(restored.category)
        self.assertIsNone(restored.depth)
        self.assertEqual(restored.techniques, [])


class TestEntryFromRunResult(unittest.TestCase):
    def test_dedupes_techniques_across_sub_problems_preserving_order(self):
        result = {
            "sub_problems": [
                FakeSubProblem(id="a", likely_techniques=["jwt-alg-confusion", "ssrf"]),
                FakeSubProblem(id="b", likely_techniques=["ssrf", "idor"]),
            ]
        }
        entry = entry_from_run_result("desc", result, category="web", depth="approach")
        self.assertEqual(entry.techniques, ["jwt-alg-confusion", "ssrf", "idor"])
        self.assertEqual(entry.sub_problem_count, 2)
        self.assertEqual(entry.category, "web")
        self.assertEqual(entry.depth, "approach")

    def test_handles_sub_problems_with_no_techniques(self):
        result = {"sub_problems": [FakeSubProblem(id="a", likely_techniques=[])]}
        entry = entry_from_run_result("desc", result)
        self.assertEqual(entry.techniques, [])


class TestLogAndReadHistory(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = os.path.join(self.tmpdir, "history.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_reading_nonexistent_file_returns_empty_list(self):
        self.assertEqual(read_history(self.path), [])

    def test_log_then_read_round_trips(self):
        entry = HistoryEntry(
            timestamp="t1", challenge_description="d1", category="pwn",
            depth=None, sub_problem_count=1, techniques=["ret2libc"],
        )
        log_entry(entry, path=self.path)
        entries = read_history(self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0], entry)

    def test_creates_parent_directory_if_missing(self):
        nested_path = os.path.join(self.tmpdir, "nested", "dir", "history.jsonl")
        entry = HistoryEntry(timestamp="t", challenge_description="d", category=None,
                              depth=None, sub_problem_count=0, techniques=[])
        log_entry(entry, path=nested_path)
        self.assertTrue(os.path.exists(nested_path))

    def test_multiple_entries_preserve_order(self):
        for i in range(3):
            log_entry(
                HistoryEntry(timestamp=f"t{i}", challenge_description=f"d{i}", category=None,
                              depth=None, sub_problem_count=0, techniques=[]),
                path=self.path,
            )
        entries = read_history(self.path)
        self.assertEqual([e.timestamp for e in entries], ["t0", "t1", "t2"])

    def test_limit_returns_most_recent_entries(self):
        for i in range(5):
            log_entry(
                HistoryEntry(timestamp=f"t{i}", challenge_description=f"d{i}", category=None,
                              depth=None, sub_problem_count=0, techniques=[]),
                path=self.path,
            )
        entries = read_history(self.path, limit=2)
        self.assertEqual([e.timestamp for e in entries], ["t3", "t4"])

    def test_skips_corrupted_lines_without_failing(self):
        with open(self.path, "w") as f:
            f.write(json.dumps(HistoryEntry(
                timestamp="good", challenge_description="d", category=None,
                depth=None, sub_problem_count=0, techniques=[],
            ).to_dict()) + "\n")
            f.write("{not valid json\n")  # simulates a crash mid-write
        entries = read_history(self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].timestamp, "good")


class TestSummarize(unittest.TestCase):
    def test_counts_technique_frequency_across_entries_most_common_first(self):
        entries = [
            HistoryEntry(timestamp="t1", challenge_description="d", category=None,
                          depth=None, sub_problem_count=0, techniques=["jwt-alg-confusion", "ssrf"]),
            HistoryEntry(timestamp="t2", challenge_description="d", category=None,
                          depth=None, sub_problem_count=0, techniques=["jwt-alg-confusion"]),
        ]
        summary = summarize(entries)
        self.assertEqual(list(summary.items())[0], ("jwt-alg-confusion", 2))
        self.assertEqual(summary["ssrf"], 1)

    def test_empty_history_returns_empty_summary(self):
        self.assertEqual(summarize([]), {})


if __name__ == "__main__":
    unittest.main()
