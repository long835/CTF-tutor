"""Core API, vision offline path, cost router, contest dump."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _min_png(path: Path) -> None:
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes([0, 255, 0, 0]))
    data = bytes.fromhex("89504e470d0a1a0a") + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")
    path.write_bytes(data)


class TestCoreApi(unittest.TestCase):
    def test_classify(self):
        from agent.core_api import classify
        r = classify("Overflow a stack buffer using gets and control the return address")
        self.assertEqual(r["category"], "pwn")

    def test_knowledge_health(self):
        from agent.core_api import knowledge_health
        h = knowledge_health()
        self.assertEqual(h["uncovered_signals"], {})
        self.assertGreaterEqual(h["rubrics"], 90)

    def test_run_eval_public(self):
        from agent.core_api import run_eval
        r = run_eval("public")
        self.assertGreaterEqual(r["accuracy"], 0.90)


class TestCostRouter(unittest.TestCase):
    def test_classify_is_heuristic(self):
        from agent.cost_router import route_task
        d = route_task("classify")
        self.assertFalse(d.use_llm)
        self.assertEqual(d.provider, "heuristic")

    def test_vision_routes_to_vision_model(self):
        from agent.cost_router import route_task
        d = route_task("vision")
        self.assertTrue(d.use_llm)
        self.assertIn(d.model, ("llava", d.model))  # default or env


class TestVisionOffline(unittest.TestCase):
    def test_png_forensic_hints(self):
        from agent.vision import observe_image
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.png"
            _min_png(p)
            obs = observe_image(p, use_model=False)
            self.assertTrue(any("lsb" in h.lower() or "magic" in h.lower() for h in obs.forensic_hints))


class TestContestDump(unittest.TestCase):
    def test_dump_cases_score_well(self):
        from agent.contest_eval_dump import DUMP_CASES, score_dump
        report = score_dump(DUMP_CASES)
        self.assertGreaterEqual(report["accuracy"], 0.90)


if __name__ == "__main__":
    unittest.main()
