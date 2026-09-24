"""
agent/telemetry.py — local opt-in telemetry policy (item 74).

Default: OFF. When enabled, appends redacted event lines to a local JSONL
file. Never phones home. No challenge text or secrets are stored — only
event names, durations, and coarse categories.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

_ENABLED = os.getenv("CTF_TUTOR_TELEMETRY", "0").lower() in ("1", "true", "yes")
_PATH = Path(os.getenv("CTF_TUTOR_TELEMETRY_PATH", "data/telemetry.jsonl"))


def telemetry_enabled() -> bool:
    return _ENABLED


def record(event: str, **fields: Any) -> None:
    if not _ENABLED:
        return
    # Drop anything that looks like content
    safe = {k: v for k, v in fields.items() if k not in ("description", "prompt", "text", "flag", "token")}
    row = {"ts": time.time(), "event": event, **safe}
    try:
        _PATH.parent.mkdir(parents=True, exist_ok=True)
        with _PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def policy() -> Dict[str, Any]:
    return {
        "enabled": _ENABLED,
        "path": str(_PATH),
        "phones_home": False,
        "stores_challenge_text": False,
        "opt_in_env": "CTF_TUTOR_TELEMETRY=1",
    }
