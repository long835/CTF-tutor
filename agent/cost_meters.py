"""
agent/cost_meters.py — estimated cost meters for local vs frontier usage.

Local models are scored in relative *units* (CPU/GPU time proxy).
Frontier / OpenAI-compatible endpoints can report rough USD estimates when
token counts are known. Never bills anyone — display and budgeting only.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.cost_router import TaskKind, route_task

LEDGER = Path(os.getenv("CTF_TUTOR_COST_LEDGER", "data/cost_ledger.jsonl"))

# Very rough public list-price anchors (USD per 1M tokens). Override via env JSON.
_DEFAULT_FRONTIER_RATES = {
    "input_per_mtok": float(os.getenv("CTF_TUTOR_USD_INPUT_PER_MTOK", "0.15")),
    "output_per_mtok": float(os.getenv("CTF_TUTOR_USD_OUTPUT_PER_MTOK", "0.60")),
}


@dataclass
class CostEvent:
    ts: float
    task: str
    provider: str
    model: str
    local_units: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    usd_estimate: float = 0.0
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def estimate_usd(
    prompt_tokens: int,
    completion_tokens: int,
    rates: Optional[Dict[str, float]] = None,
) -> float:
    rates = rates or _DEFAULT_FRONTIER_RATES
    return (
        prompt_tokens * rates["input_per_mtok"] / 1_000_000.0
        + completion_tokens * rates["output_per_mtok"] / 1_000_000.0
    )


def record_usage(
    task: str,
    *,
    provider: str = "ollama",
    model: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    note: str = "",
) -> CostEvent:
    decision = route_task(task, force_model=model or None)
    local_units = decision.estimated_cost
    usd = 0.0
    if provider not in ("ollama", "heuristic", "local-skip") or os.getenv("CTF_TUTOR_ALLOW_FRONTIER") == "1":
        if provider not in ("ollama", "heuristic", "local-skip"):
            usd = estimate_usd(prompt_tokens, completion_tokens)
    event = CostEvent(
        ts=time.time(),
        task=task,
        provider=provider or decision.provider,
        model=model or decision.model,
        local_units=local_units,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        usd_estimate=round(usd, 6),
        note=note,
    )
    if os.getenv("CTF_TUTOR_COST_LEDGER_ENABLE", "1").lower() not in ("0", "false", "no"):
        try:
            LEDGER.parent.mkdir(parents=True, exist_ok=True)
            with LEDGER.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
        except OSError:
            pass
    return event


def ledger_summary(path: Path = LEDGER) -> Dict[str, Any]:
    if not path.exists():
        return {"events": 0, "local_units": 0.0, "usd_estimate": 0.0, "by_task": {}}
    events = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    by_task: Dict[str, Dict[str, float]] = {}
    total_units = total_usd = 0.0
    for e in events:
        total_units += float(e.get("local_units") or 0)
        total_usd += float(e.get("usd_estimate") or 0)
        t = e.get("task") or "unknown"
        bucket = by_task.setdefault(t, {"local_units": 0.0, "usd_estimate": 0.0, "n": 0})
        bucket["local_units"] += float(e.get("local_units") or 0)
        bucket["usd_estimate"] += float(e.get("usd_estimate") or 0)
        bucket["n"] += 1
    return {
        "events": len(events),
        "local_units": round(total_units, 3),
        "usd_estimate": round(total_usd, 6),
        "by_task": by_task,
        "path": str(path),
    }
