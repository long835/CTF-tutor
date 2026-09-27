"""
Confidence / belief_score policy (P0).

belief_score is an *internal* evidence score in [0, 1].
It is NOT a calibrated probability of correctness unless a calibration
study has been run and recorded.

Always pair belief_score with verification_level (0–5).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agent.verification_levels import VerificationLevel, assess_verification, LEVEL_LABELS


def present_confidence(
    belief_score: float,
    *,
    has_hypothesis: bool = False,
    evidence_count: int = 0,
    tool_support: bool = False,
    reproduction_ok: bool = False,
    challenge_behavior_ok: bool = False,
    flag_verified: bool = False,
    contradictions: int = 0,
) -> Dict[str, Any]:
    """Canonical confidence payload for APIs and CLI."""
    report = assess_verification(
        has_hypothesis=has_hypothesis,
        evidence_count=evidence_count,
        tool_support=tool_support,
        reproduction_ok=reproduction_ok,
        challenge_behavior_ok=challenge_behavior_ok,
        flag_verified=flag_verified,
        contradictions=contradictions,
        belief_score=belief_score,
    )
    return {
        "belief_score": round(float(belief_score), 3),
        "belief_score_is_probability": False,
        "verification_level": report.level,
        "verification_label": report.label,
        "verification": report.to_dict(),
        **{k: v for k, v in __import__("agent.calibration_fit", fromlist=["present_with_calibration"]).present_with_calibration(belief_score).items() if k != "belief_score"},
        "disclaimer": (
            "belief_score is an internal evidence score, not a calibrated "
            "probability of being correct."
        ),
    }


def present_with_calibration(belief_score: float):
    from agent.calibration_fit import present_with_calibration as _p
    return _p(belief_score)
