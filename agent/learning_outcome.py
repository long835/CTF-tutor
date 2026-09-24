"""
Learning-outcome benchmark scaffold (Phase 6.5).

Measures a minimal pre → teach → post → transfer cycle for one technique.
This is *not* a full RCT; it is a local, deterministic harness the project
can grow into CTF-TUTOR-LEARN.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.classify_challenge import classify_challenge
from agent.learner_view import record_learning, unified_technique


@dataclass
class OutcomeCase:
    id: str
    technique: str
    category: str
    pre_prompt: str          # ask learner/agent to name the technique/category
    post_prompt: str         # same idea, different wording after teaching
    transfer_prompt: str     # different surface, same technique
    expected_category: str


DEFAULT_CASES: List[OutcomeCase] = [
    OutcomeCase(
        id="lo-jwt",
        technique="jwt-none-bypass",
        category="web",
        pre_prompt="A web app stores a browser cookie that looks like three base64 segments. Changing the middle segment changes the role field. What category is this?",
        post_prompt="The token header allows algorithm none and the server skips signature checks. Name the category and core issue.",
        transfer_prompt="An API accepts a bearer token; setting alg to none elevates privileges without the secret. Category?",
        expected_category="web",
    ),
    OutcomeCase(
        id="lo-bof",
        technique="stack-buffer-overflow",
        category="pwn",
        pre_prompt="A local binary reads input with gets into a fixed stack buffer and crashes on long input. Category?",
        post_prompt="Overflowing a stack buffer lets you overwrite the saved return address. Category?",
        transfer_prompt="NX is off; long input to a stack buffer redirects execution to a win function. Category?",
        expected_category="pwn",
    ),
    OutcomeCase(
        id="lo-xor",
        technique="xor-single-byte",
        category="crypto",
        pre_prompt="Ciphertext is hex; frequency suggests a single repeating XOR key byte. Category?",
        post_prompt="Recover a one-byte XOR key by scoring English plaintext. Category?",
        transfer_prompt="A short flag was XOR-encrypted with one constant byte and given as hex. Category?",
        expected_category="crypto",
    ),
]


@dataclass
class StageResult:
    stage: str
    predicted_category: str
    expected_category: str
    correct: bool
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OutcomeReport:
    case_id: str
    technique: str
    stages: List[StageResult] = field(default_factory=list)
    improved: bool = False
    transfer_ok: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "technique": self.technique,
            "stages": [s.to_dict() for s in self.stages],
            "improved": self.improved,
            "transfer_ok": self.transfer_ok,
            "timestamp": self.timestamp,
        }


def _predict(prompt: str, expected: str) -> StageResult:
    r = classify_challenge(prompt)
    return StageResult(
        stage="",
        predicted_category=r.category,
        expected_category=expected,
        correct=r.category == expected,
        confidence=float(r.confidence or 0.0),
    )


def run_case(case: OutcomeCase, record: bool = False) -> OutcomeReport:
    """
    pre → (optional record as taught) → post → transfer.

    For agent-side evaluation we use the formal classifier as a stand-in
    sensor; a human learner study would replace _predict with user answers.
    """
    pre = _predict(case.pre_prompt, case.expected_category)
    pre.stage = "pre"
    post = _predict(case.post_prompt, case.expected_category)
    post.stage = "post"
    transfer = _predict(case.transfer_prompt, case.expected_category)
    transfer.stage = "transfer"

    if record:
        # Simulate a successful independent solve after teaching
        record_learning(case.technique, success=True, hint_level=1, scenario=case.id, verified=False)

    report = OutcomeReport(
        case_id=case.id,
        technique=case.technique,
        stages=[pre, post, transfer],
        improved=(not pre.correct and post.correct) or (pre.correct and post.correct),
        transfer_ok=transfer.correct,
    )
    return report


def run_benchmark(cases: Optional[List[OutcomeCase]] = None, record: bool = False) -> Dict[str, Any]:
    cases = cases or list(DEFAULT_CASES)
    reports = [run_case(c, record=record) for c in cases]
    pre_ok = sum(1 for r in reports if r.stages[0].correct)
    post_ok = sum(1 for r in reports if r.stages[1].correct)
    transfer_ok = sum(1 for r in reports if r.transfer_ok)
    n = len(reports)
    return {
        "n": n,
        "pre_accuracy": pre_ok / n if n else 0.0,
        "post_accuracy": post_ok / n if n else 0.0,
        "transfer_accuracy": transfer_ok / n if n else 0.0,
        "reports": [r.to_dict() for r in reports],
    }
