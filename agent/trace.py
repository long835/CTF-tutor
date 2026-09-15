"""
agent/trace.py

Append-only JSONL action log for debugging, teaching, and evaluation.
Never stores secrets (best-effort redaction).
"""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[a-z0-9\-._~+/]+=*"),
]


def redact(text: str) -> str:
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


class TraceLogger:
    def __init__(self, path: Optional[str] = None, enabled: bool = True):
        self.enabled = enabled
        if path is None:
            path = os.path.join("data", "traces", f"trace_{int(time.time())}.jsonl")
        self.path = Path(path)
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, **payload: Any) -> None:
        if not self.enabled:
            return
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
        }
        for k, v in payload.items():
            if isinstance(v, str):
                record[k] = redact(v)[:4000]
            else:
                try:
                    json.dumps(v)  # ensure serializable
                    record[k] = v
                except (TypeError, ValueError):
                    record[k] = redact(str(v))[:2000]
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def log_state_snapshot(self, state) -> None:
        self.log(
            "state_snapshot",
            challenge_id=state.challenge_id,
            status=state.status,
            step=state.step_count,
            confidence=state.overall_confidence,
            hypotheses=[
                {"id": h.id, "conf": h.confidence, "tech": h.technique, "stmt": h.statement[:120]}
                for h in state.hypotheses[:8]
            ],
            evidence_count=len(state.evidence),
            facts_count=len(state.known_facts),
        )
