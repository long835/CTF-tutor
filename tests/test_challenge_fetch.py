"""Tests for public challenge fetcher (mostly offline)."""

import io
import zipfile
import tempfile
import unittest
from pathlib import Path


class TestParseGithub(unittest.TestCase):
    def test_formats(self):
        from agent.challenge_fetch import parse_github_url
        p = parse_github_url("https://github.com/foo/bar")
        self.assertEqual(p["owner"], "foo")
        self.assertEqual(p["repo"], "bar")
        p2 = parse_github_url("foo/bar/challenges/web1")
        self.assertEqual(p2["path"], "challenges/web1")
        p3 = parse_github_url("https://github.com/a/b/tree/main/crypto/xor")
        self.assertEqual(p3["ref"], "main")
        self.assertEqual(p3["path"], "crypto/xor")
        self.assertIsNone(parse_github_url("not a repo"))


class TestSafeExtract(unittest.TestCase):
    def test_zip_path_traversal_blocked(self):
        from agent.challenge_fetch import _safe_extract_zip
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("safe.txt", "ok")
            # traversal attempt
            zf.writestr("../evil.txt", "bad")
            zf.writestr("nested/good.txt", "ok2")
        buf.seek(0)
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "out"
            dest.mkdir()
            with zipfile.ZipFile(buf) as zf:
                _safe_extract_zip(zf, dest)
            self.assertTrue((dest / "safe.txt").exists())
            self.assertTrue((dest / "nested" / "good.txt").exists())
            self.assertFalse((Path(td) / "evil.txt").exists())


class TestFetchAutoDispatch(unittest.TestCase):
    def test_bad_spec(self):
        from agent.challenge_fetch import fetch_auto
        r = fetch_auto("ftp://example.com/x")
        self.assertFalse(r.ok)


if __name__ == "__main__":
    unittest.main()
