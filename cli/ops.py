"""Operational CLI commands extracted from main.py."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


def cmd_status(argv: Optional[List[str]] = None) -> int:
    from agent.project_status import format_status, project_status
    p = argparse.ArgumentParser(prog="main.py status")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if args.json:
        print(json.dumps(project_status(), indent=2, default=str))
    else:
        print(format_status())
    return 0


def cmd_gate(argv: Optional[List[str]] = None) -> int:
    root = Path(__file__).resolve().parents[1]
    gate = root / "scripts" / "release_gate.py"
    return subprocess.call([sys.executable, str(gate), *(argv or [])], cwd=str(root))


def cmd_trust(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py trust")
    p.add_argument("text", nargs="?", default="")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    try:
        from agent.trust import assess_text
        r = assess_text(args.text)
        print(json.dumps(r if isinstance(r, dict) else {"result": str(r)}, indent=2, default=str))
    except Exception as e:
        # fallback minimal
        print(json.dumps({"text_len": len(args.text or ""), "note": str(e)}))
    return 0
