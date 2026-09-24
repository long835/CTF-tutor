"""
Verification level hierarchy (Phase 6.5).

Separates "model assertion" from "independently verified" so confidence
numbers are not mistaken for proof.

Levels
------
0  assertion     — model/plan claims without external support
1  evidence      — observations support the hypothesis
2  tool          — tool output supports the hypothesis
3  reproduction  — candidate action reproduces expected behavior
4  challenge     — challenge behavior matches prediction (e.g. crash, leak)
5  independent   — flag/answer verified by independent checker
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Dict, List, Optional


class VerificationLevel(IntEnum):
    ASSERTION = 0
    EVIDENCE = 1
    TOOL = 2
    REPRODUCTION = 3
    CHALLENGE = 4
    INDEPENDENT = 5


LEVEL_LABELS = {
    VerificationLevel.ASSERTION: "assertion",
    VerificationLevel.EVIDENCE: "evidence",
    VerificationLevel.TOOL: "tool",
    VerificationLevel.REPRODUCTION: "reproduction",
    VerificationLevel.CHALLENGE: "challenge-behavior",
    VerificationLevel.INDEPENDENT: "independent-check",
}


@dataclass
class VerificationReport:
    level: int = 0
    label: str = "assertion"
    belief_score: float = 0.0  # internal score, not a calibrated probability
    reasons: List[str] = field(default_factory=list)
    blockers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["level_name"] = LEVEL_LABELS.get(VerificationLevel(self.level), self.label)
        return d

    def as_tutor_line(self) -> str:
        return (
            f"verification level {self.level}/5 ({self.label}); "
            f"belief_score={self.belief_score:.2f} (not a calibrated probability)"
        )


def assess_verification(
    *,
    has_hypothesis: bool = False,
    evidence_count: int = 0,
    tool_support: bool = False,
    reproduction_ok: bool = False,
    challenge_behavior_ok: bool = False,
    flag_verified: bool = False,
    contradictions: int = 0,
    belief_score: float = 0.0,
) -> VerificationReport:
    """Map investigation state to a verification level."""
    reasons: List[str] = []
    blockers: List[str] = []
    level = VerificationLevel.ASSERTION

    if not has_hypothesis:
        blockers.append("no hypothesis yet")
        return VerificationReport(0, LEVEL_LABELS[0], belief_score, reasons, blockers)

    reasons.append("hypothesis stated")
    if evidence_count > 0:
        level = VerificationLevel.EVIDENCE
        reasons.append(f"{evidence_count} evidence item(s)")
    else:
        blockers.append("no evidence linked to hypothesis")

    if tool_support:
        level = max(level, VerificationLevel.TOOL)
        reasons.append("tool output supports hypothesis")
    elif level >= VerificationLevel.EVIDENCE:
        blockers.append("no confirming tool output")

    if reproduction_ok:
        level = max(level, VerificationLevel.REPRODUCTION)
        reasons.append("reproduction succeeded")

    if challenge_behavior_ok:
        level = max(level, VerificationLevel.CHALLENGE)
        reasons.append("challenge behavior matched prediction")

    if flag_verified:
        level = VerificationLevel.INDEPENDENT
        reasons.append("flag independently verified")

    if contradictions > 0:
        blockers.append(f"{contradictions} contradiction(s) present")
        # contradictions cannot raise level; may reduce belief presentation
        belief_score = min(belief_score, 0.4)

    return VerificationReport(
        level=int(level),
        label=LEVEL_LABELS[VerificationLevel(level)],
        belief_score=round(belief_score, 3),
        reasons=reasons,
        blockers=blockers,
    )
