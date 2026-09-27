"""Out-of-process plugin worker (optional isolation).

Run: python -m agent.plugin_worker --module path/to/plugin.py
Communicates via stdin/stdout JSON lines. Not a full seccomp sandbox —
process boundary only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--module", required=True)
    args = p.parse_args(argv)
    path = Path(args.module)
    spec = importlib.util.spec_from_file_location("plugin_mod", path)
    if not spec or not spec.loader:
        print(json.dumps({"ok": False, "error": "load failed"}))
        return 1
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Handshake
    print(json.dumps({"ok": True, "plugin": path.name}), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception:
            print(json.dumps({"ok": False, "error": "bad json"}), flush=True)
            continue
        if msg.get("cmd") == "ping":
            print(json.dumps({"ok": True, "pong": True}), flush=True)
        elif msg.get("cmd") == "quit":
            break
        else:
            print(json.dumps({"ok": False, "error": "unknown cmd"}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
