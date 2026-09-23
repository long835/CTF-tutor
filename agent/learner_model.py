"""
agent/learner_model.py

Did they learn it, or did we tell them? (items 14 and 15)

The existing learner memory records attempts, successes and a hint count, and
`TechniqueStats.mastery` subtracts a flat 0.05 per hint. That treats all
hints as equal, which they are not: "look at how authentication works" and
"compare the declared algorithm with what the server verifies" are four
levels apart, and only one of them leaves any discovery to the learner.

It also cannot distinguish the two outcomes that matter most:

    solved this challenge          vs      learned this technique

A learner who solves one JWT challenge after a level-4 hint, and a learner
who solves two structurally different JWT challenges unaided, both show up
as "attempted jwt-none-bypass, succeeded" in the old model.

So this module measures two things the review asked for:

*   **independence** (item 17's data, item 14's model) -- what fraction of
    successes came without being handed the answer, weighted by how deep the
    hint went.
*   **transfer** (item 15's "can solve a variation") -- whether the technique
    has been solved across *distinct scenarios* from the technique library,
    not the same framing twice.

Both are deliberately conservative. Independence with two attempts is noise;
transfer claimed from one scenario is just the instance again. Where there
is not enough evidence, these return `None` and say so, for the same reason
`INSUFFICIENT_EVIDENCE` exists in the evidence module: a tutor that
overstates what a learner knows schedules them into work they will fail.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from agent import taxonomy

DEFAULT_PATH = os.path.join("data", "learner_attempts.json")

# A hint at or below this level still leaves the discovery to the learner.
INDEPENDENT_HINT_CEILING = 1

# Below this many attempts, any rate is noise.
MIN_ATTEMPTS_FOR_RATE = 3

# Distinct scenarios needed before we call it transfer rather than recall.
MIN_SCENARIOS_FOR_TRANSFER = 2


@dataclass
class Attempt:
    """One recorded go at one technique."""

    technique: str
    success: bool = False
    hint_level: int = 0          # deepest hint reached (0 = none)
    hints_requested: int = 0
    scenario: str = ""           # which framing of the technique
    difficulty: str = "medium"
    verified: bool = False       # the answer was checked, not just asserted
    steps_before_hint: int = 0
    timestamp: str = ""

    def __post_init__(self) -> None:
        self.technique = taxonomy.canonical(self.technique)
        self.hint_level = max(0, int(self.hint_level or 0))
        self.hints_requested = max(0, int(self.hints_requested or 0))
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    @property
    def independent(self) -> bool:
        """A success that was not handed over."""
        return bool(self.success) and self.hint_level <= INDEPENDENT_HINT_CEILING

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Attempt":
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in (data or {}).items() if k in fields})


@dataclass
class TechniqueIndependence:
    """What the record supports saying about one technique."""

    technique: str
    attempts: int = 0
    successes: int = 0
    independent_successes: int = 0
    scenarios_seen: List[str] = field(default_factory=list)
    scenarios_solved_independently: List[str] = field(default_factory=list)
    mean_hint_level: float = 0.0
    deepest_hint: int = 0
    verified_successes: int = 0

    @property
    def independent_solve_rate(self) -> Optional[float]:
        """
        Fraction of attempts solved without being handed the answer.

        `None` below MIN_ATTEMPTS_FOR_RATE: one lucky solve is not a rate,
        and reporting 1.00 from a single attempt is how a curriculum talks
        itself into promoting someone.
        """
        if self.attempts < MIN_ATTEMPTS_FOR_RATE:
            return None
        return self.independent_successes / self.attempts

    @property
    def hint_dependency(self) -> Optional[float]:
        """0.0 = solves unaided, 1.0 = needs the answer spelled out."""
        if self.attempts < MIN_ATTEMPTS_FOR_RATE:
            return None
        return min(1.0, self.mean_hint_level / 4.0)

    @property
    def transfer(self) -> Optional[bool]:
        """
        Solved across distinct framings, not the same one twice.

        This is item 15's "can solve a variation", and it is the difference
        between knowing the technique and remembering the challenge.
        """
        if len(self.scenarios_seen) < MIN_SCENARIOS_FOR_TRANSFER:
            return None
        return len(self.scenarios_solved_independently) >= MIN_SCENARIOS_FOR_TRANSFER

    @property
    def status(self) -> str:
        """A single word the curriculum can branch on."""
        if self.attempts == 0:
            return "unseen"
        rate = self.independent_solve_rate
        if rate is None:
            return "insufficient_evidence"
        if self.transfer is True and rate >= 0.6:
            return "transferred"
        if rate >= 0.6:
            return "solves_unaided"
        if self.successes and rate < 0.3:
            return "hint_dependent"
        return "developing"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "attempts": self.attempts,
            "successes": self.successes,
            "independent_successes": self.independent_successes,
            "independent_solve_rate": (
                None if self.independent_solve_rate is None
                else round(self.independent_solve_rate, 3)
            ),
            "hint_dependency": (
                None if self.hint_dependency is None else round(self.hint_dependency, 3)
            ),
            "mean_hint_level": round(self.mean_hint_level, 2),
            "deepest_hint": self.deepest_hint,
            "scenarios_seen": list(self.scenarios_seen),
            "scenarios_solved_independently": list(self.scenarios_solved_independently),
            "transfer": self.transfer,
            "verified_successes": self.verified_successes,
            "status": self.status,
        }

    def explain(self) -> str:
        lines = [f"{self.technique}: {self.status}"]
        rate = self.independent_solve_rate
        if rate is None:
            lines.append(f"  only {self.attempts} attempt(s) -- not enough to state a rate")
        else:
            lines.append(
                f"  independent solves {self.independent_successes}/{self.attempts} "
                f"({rate:.0%}), mean hint level {self.mean_hint_level:.1f}"
            )
        if self.transfer is None:
            lines.append(
                f"  seen in {len(self.scenarios_seen)} framing(s) -- "
                f"needs {MIN_SCENARIOS_FOR_TRANSFER} to tell recall from transfer"
            )
        elif self.transfer:
            lines.append(
                f"  solved unaided across {len(self.scenarios_solved_independently)} "
                f"distinct framings"
            )
        else:
            lines.append("  has not yet solved a second framing unaided")
        return "\n".join(lines)


class LearnerRecord:
    """The attempt log, plus the questions worth asking of it."""

    def __init__(self, attempts: Optional[Sequence[Attempt]] = None):
        self.attempts: List[Attempt] = list(attempts or [])

    # -- recording ---------------------------------------------------------

    def record(self, attempt: Attempt) -> Attempt:
        if attempt.technique:
            self.attempts.append(attempt)
        return attempt

    def record_attempt(
        self,
        technique: str,
        success: bool = False,
        hint_level: int = 0,
        scenario: str = "",
        difficulty: str = "medium",
        verified: bool = False,
        hints_requested: int = 0,
        steps_before_hint: int = 0,
    ) -> Attempt:
        return self.record(Attempt(
            technique=technique, success=success, hint_level=hint_level,
            scenario=scenario, difficulty=difficulty, verified=verified,
            hints_requested=hints_requested, steps_before_hint=steps_before_hint,
        ))

    # -- questions ---------------------------------------------------------

    def for_technique(self, technique: str) -> TechniqueIndependence:
        canon = taxonomy.canonical(technique)
        rows = [a for a in self.attempts if a.technique == canon]
        out = TechniqueIndependence(technique=canon, attempts=len(rows))
        if not rows:
            return out

        total_hint = 0
        for a in rows:
            total_hint += a.hint_level
            out.deepest_hint = max(out.deepest_hint, a.hint_level)
            if a.scenario and a.scenario not in out.scenarios_seen:
                out.scenarios_seen.append(a.scenario)
            if a.success:
                out.successes += 1
                if a.verified:
                    out.verified_successes += 1
            if a.independent:
                out.independent_successes += 1
                if a.scenario and a.scenario not in out.scenarios_solved_independently:
                    out.scenarios_solved_independently.append(a.scenario)
        out.mean_hint_level = total_hint / len(rows)
        return out

    def techniques(self) -> List[str]:
        seen: List[str] = []
        for a in self.attempts:
            if a.technique not in seen:
                seen.append(a.technique)
        return sorted(seen)

    def profile(self) -> Dict[str, TechniqueIndependence]:
        return {t: self.for_technique(t) for t in self.techniques()}

    def overall_independent_solve_rate(self) -> Optional[float]:
        """
        The single number the review asked for in item 17.

        Computed over attempts, not techniques, so a technique practised ten
        times does not count the same as one practised once.
        """
        if len(self.attempts) < MIN_ATTEMPTS_FOR_RATE:
            return None
        independent = sum(1 for a in self.attempts if a.independent)
        return independent / len(self.attempts)

    def hint_dependent_techniques(self) -> List[str]:
        return sorted(
            t for t, p in self.profile().items() if p.status == "hint_dependent"
        )

    def transferred_techniques(self) -> List[str]:
        return sorted(t for t, p in self.profile().items() if p.status == "transferred")

    def summary(self) -> Dict[str, Any]:
        prof = self.profile()
        by_status: Dict[str, int] = {}
        for p in prof.values():
            by_status[p.status] = by_status.get(p.status, 0) + 1
        rate = self.overall_independent_solve_rate()
        return {
            "attempts": len(self.attempts),
            "techniques": len(prof),
            "independent_solve_rate": None if rate is None else round(rate, 3),
            "by_status": dict(sorted(by_status.items())),
            "hint_dependent": self.hint_dependent_techniques(),
            "transferred": self.transferred_techniques(),
        }

    def render(self) -> str:
        s = self.summary()
        rate = s["independent_solve_rate"]
        head = (
            "not enough attempts to state one"
            if rate is None else f"{rate:.0%}"
        )
        lines = [
            f"Learner record: {s['attempts']} attempt(s) across {s['techniques']} technique(s)",
            f"Independent solve rate: {head}",
            "",
        ]
        for _, p in sorted(self.profile().items()):
            lines.append(p.explain())
        if s["hint_dependent"]:
            lines += ["", "Needs repair before advancing: " + ", ".join(s["hint_dependent"])]
        return "\n".join(lines)

    # -- persistence -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {"attempts": [a.to_dict() for a in self.attempts]}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearnerRecord":
        rows = (data or {}).get("attempts") or []
        return cls([Attempt.from_dict(r) for r in rows if isinstance(r, dict)])


def load_record(path: str = DEFAULT_PATH) -> LearnerRecord:
    p = Path(path)
    if not p.is_file():
        return LearnerRecord()
    try:
        with open(p, "r", encoding="utf-8") as f:
            return LearnerRecord.from_dict(json.load(f))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        # A corrupt log is a missing log, not a crash mid-lesson.
        return LearnerRecord()


def save_record(record: LearnerRecord, path: str = DEFAULT_PATH) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(record.to_dict(), f, indent=2)


# ---------------------------------------------------------------------------
# Variations (item 15: "can solve a variation")
# ---------------------------------------------------------------------------


def variations_for(technique: str) -> List[str]:
    """
    The distinct framings the technique library holds for one technique.

    These are the scenarios the corpus was built from -- deliberately
    different contexts rather than v1/v2 clones of one challenge -- which
    makes them the right unit for testing transfer.
    """
    from agent import knowledge_graph

    node = knowledge_graph.get_graph().node(technique)
    return list(node.scenarios) if node else []


def next_variation(technique: str, record: Optional[LearnerRecord] = None) -> Optional[str]:
    """
    A framing of this technique the learner has not solved unaided yet.

    Returns `None` when every known framing has been solved independently --
    at which point the honest next step is a different technique, not another
    rerun of the same idea in new clothes.
    """
    scenarios = variations_for(technique)
    if not scenarios:
        return None
    if record is None:
        return scenarios[0]
    solved = set(record.for_technique(technique).scenarios_solved_independently)
    for s in scenarios:
        if s not in solved:
            return s
    return None


def transfer_check(technique: str, record: LearnerRecord) -> Dict[str, Any]:
    """
    Whether to claim the learner knows the technique, and what to set next.

    The `verdict` is the part the curriculum should read:
      `transferred`  -- move on
      `retest`       -- solved once unaided; try another framing
      `repair`       -- solves only with deep hints
      `unknown`      -- not enough evidence either way
    """
    prof = record.for_technique(technique)
    remaining = next_variation(technique, record)
    if prof.status == "transferred":
        verdict = "transferred"
    elif prof.status == "hint_dependent":
        verdict = "repair"
    elif prof.independent_successes >= 1 and remaining:
        verdict = "retest"
    else:
        verdict = "unknown"
    return {
        "technique": prof.technique,
        "verdict": verdict,
        "status": prof.status,
        "independent_solve_rate": prof.independent_solve_rate,
        "scenarios_solved_independently": list(prof.scenarios_solved_independently),
        "next_variation": remaining,
        "variations_available": len(variations_for(technique)),
    }


# ---------------------------------------------------------------------------
# Hooks the rest of the tutor uses
# ---------------------------------------------------------------------------


def recommended_hint_level(technique: str, record: LearnerRecord, default: int = 2) -> int:
    """
    How much to give away, based on measured independence rather than mastery.

    The asymmetry is deliberate: a learner who has shown they can get there
    alone is dropped to a nudge, but someone with no record gets the caller's
    default rather than being assumed helpless.
    """
    prof = record.for_technique(technique)
    if prof.attempts == 0:
        return default
    if prof.status == "transferred":
        return 0
    if prof.status == "solves_unaided":
        return 1
    if prof.status == "hint_dependent":
        return min(4, max(default, prof.deepest_hint))
    return default


def independence_axis(record: LearnerRecord) -> Dict[str, Any]:
    """
    An education-side score for the metrics scorecard (item 15).

    Solving is not the only thing worth measuring, and an agent that hands
    over answers scores perfectly on correctness while teaching nothing.
    """
    rate = record.overall_independent_solve_rate()
    transferred = record.transferred_techniques()
    dependent = record.hint_dependent_techniques()
    if rate is None:
        return {"score": None, "reason": "fewer than "
                f"{MIN_ATTEMPTS_FOR_RATE} attempts recorded"}
    score = rate
    if transferred:
        score = min(1.0, score + 0.1 * len(transferred) / max(1, len(record.techniques())))
    if dependent:
        score = max(0.0, score - 0.1 * len(dependent) / max(1, len(record.techniques())))
    return {
        "score": round(score, 3),
        "independent_solve_rate": round(rate, 3),
        "transferred": transferred,
        "hint_dependent": dependent,
    }
