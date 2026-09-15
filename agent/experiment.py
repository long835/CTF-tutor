"""
agent/experiment.py

Lightweight experiment harness for reproducible agent runs.

One JSON/YAML-like config drives model, steps, tools, benchmark.
Each run gets an experiment id and writes a trace summary under data/experiments/.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


EXP_DIR = os.path.join("data", "experiments")


@dataclass
class ExperimentConfig:
    name: str = "default"
    max_steps: int = 6
    hint_level: int = 2
    category: Optional[str] = None
    online_research: bool = False
    enable_trace: bool = True
    challenge_path: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExperimentConfig":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ExperimentResult:
    experiment_id: str
    config: Dict[str, Any]
    challenge: str
    status: str
    confidence: float
    steps: int
    category: Optional[str]
    flag_candidate: str
    techniques: List[str] = field(default_factory=list)
    duration_sec: float = 0.0
    ts: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_experiment(
    challenge: str,
    config: Optional[ExperimentConfig] = None,
) -> ExperimentResult:
    from agent.loop import AgentLoop

    config = config or ExperimentConfig()
    if config.online_research:
        os.environ["CTF_TUTOR_ONLINE_RESEARCH"] = "1"

    exp_id = f"exp_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    t0 = time.time()
    agent = AgentLoop(
        challenge_summary=challenge,
        category=config.category,
        max_steps=config.max_steps,
        challenge_path=config.challenge_path,
        enable_trace=config.enable_trace,
    )
    agent.hint_level = config.hint_level
    state = agent.run(verify_at_end=True)
    duration = time.time() - t0

    techs = [h.technique for h in state.hypotheses if h.technique]
    result = ExperimentResult(
        experiment_id=exp_id,
        config=config.to_dict(),
        challenge=challenge[:500],
        status=state.status,
        confidence=state.overall_confidence,
        steps=state.step_count,
        category=state.category,
        flag_candidate=state.flag_candidate or "",
        techniques=techs,
        duration_sec=round(duration, 3),
        ts=datetime.now(timezone.utc).isoformat(),
    )

    out_dir = Path(EXP_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{exp_id}.json"
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    # also append to leaderboard index
    lb = out_dir / "leaderboard.jsonl"
    with open(lb, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "id": exp_id,
            "status": result.status,
            "confidence": result.confidence,
            "steps": result.steps,
            "duration_sec": result.duration_sec,
            "category": result.category,
            "flag": bool(result.flag_candidate),
        }) + "\n")
    return result


def run_benchmark(config: Optional[ExperimentConfig] = None) -> Dict[str, Any]:
    """Run all ground_truth cases and summarize."""
    from agent.eval_agent import load_ground_truth

    config = config or ExperimentConfig(max_steps=4, enable_trace=False)
    cases = load_ground_truth()
    rows = []
    for case in cases:
        r = run_experiment(case["description"], config)
        rows.append({
            "id": case.get("id"),
            "expected_category": case.get("expected_category"),
            "got_category": r.category,
            "status": r.status,
            "confidence": r.confidence,
            "flag": r.flag_candidate,
            "techniques": r.techniques,
            "duration_sec": r.duration_sec,
        })
    n = max(1, len(rows))
    summary = {
        "n": len(rows),
        "solved_or_verified": sum(1 for r in rows if r["status"] in ("solved", "verified")) / n,
        "category_match": sum(
            1 for r in rows
            if r["expected_category"] and r["got_category"] == r["expected_category"]
        ) / n,
        "avg_confidence": sum(r["confidence"] for r in rows) / n,
        "avg_duration_sec": sum(r["duration_sec"] for r in rows) / n,
        "rows": rows,
    }
    Path(EXP_DIR).mkdir(parents=True, exist_ok=True)
    Path(EXP_DIR, "last_benchmark.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
