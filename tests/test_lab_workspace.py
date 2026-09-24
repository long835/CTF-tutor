"""Lab -> workspace attachment."""

from __future__ import annotations

import shutil
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestLabWorkspace(unittest.TestCase):
    def test_attach_pwn_bof(self):
        from agent.experience_labs import attach_lab_to_workspace
        cid = "test-lab-pwn-bof"
        ws_root = ROOT / "data" / "workspaces" / cid
        if ws_root.exists():
            shutil.rmtree(ws_root)
        result = attach_lab_to_workspace("pwn_bof", challenge_id=cid)
        self.assertEqual(result["lab_id"], "pwn_bof")
        self.assertTrue(result["copied"])
        inp = ws_root / "input"
        self.assertTrue(any(inp.iterdir()))
        # cleanup
        shutil.rmtree(ws_root)


if __name__ == "__main__":
    unittest.main()
