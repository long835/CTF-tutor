"""
agent/metrics.py

What to measure besides "did it get the flag" (items 21, 59, 60).

A single correct/incorrect bit tells you almost nothing useful about an
agent. Two runs can both solve a challenge while one spent three tool calls
and the other spent twenty, and two runs can both fail while one failed
honestly and the other asserted a vulnerability it had no evidence for. The
second difference matters far more than the first, and neither shows up in
an accuracy number.

Three things are measured here.

**Efficiency (item 59).** Steps, tool calls, failure rate, estimated
tokens, and the derived ratios — tokens per piece of evidence, evidence per
step. For a local-first project this is not a footnote: a configuration that
is two points more accurate and ten times slower is worse on the hardware
this is meant to run on.

**Hallucination (item 60).** Five specific failures, each checked against
the record rather than judged by a model: a flag that appears in no tool
output, a claim attributed to a tool that never ran, a technique asserted
without its required observations, a conclusion citing no evidence at all,
and confidence out of proportion to the evidence behind it. An invented flag
is the worst of these, because it looks exactly like success.

**Dimensions (item 21).** The twelve-axis scorecard, so a failure can be
attributed. "Retrieval was fine, tool selection was fine, verification let a
bad claim through" is actionable; "42% accuracy" is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

CHARS_PER_TOKEN = 3.6


def _text_of(state: Any) -> str:
    """All observed text: tool output, findings, facts. Not hypotheses."""
    parts: List[str] = []
    for ev in getattr(state, "evidence", None) or []:
        parts.append(str(getattr(ev, "content", "") or ""))
        parts.append(str(getattr(ev, "finding", "") or ""))
    for action in getattr(state, "actions", None) or []:
        parts.append(str(getattr(action, "raw_output", "") or ""))
    for fact in getattr(state, "known_facts", None) or []:
        parts.append(str(fact))
    return "\n".join(parts)


# --------------------------------------------------------------- efficiency


@dataclass
class EfficiencyMetrics:
    """Resource cost of one investigation."""

    steps: int = 0
    tool_calls: int = 0
    failed_calls: int = 0
    repeated_calls: int = 0
    wall_ms: int = 0
    estimated_tokens: int = 0
    evidence_items: int = 0
    hypotheses: int = 0

    @property
    def failure_rate(self) -> float:
        return (self.failed_calls / self.tool_calls) if self.tool_calls else 0.0

    @property
    def evidence_per_step(self) -> float:
        return (self.evidence_items / self.steps) if self.steps else 0.0

    @property
    def tokens_per_evidence(self) -> float:
        """
        Cost of each thing actually learned.

        The most useful single efficiency number: it rises both when the
        agent is verbose and when it is unproductive, which are the two ways
        a local run becomes unpleasant to use.
        """
        return (self.estimated_tokens / self.evidence_items) if self.evidence_items else 0.0

    @property
    def wasted_steps(self) -> int:
        return self.failed_calls + self.repeated_calls

    def to_dict(self) -> Dict[str, Any]:
        return {
            "steps": self.steps,
            "tool_calls": self.tool_calls,
            "failed_calls": self.failed_calls,
            "repeated_calls": self.repeated_calls,
            "wasted_steps": self.wasted_steps,
            "failure_rate": round(self.failure_rate, 3),
            "wall_ms": self.wall_ms,
            "estimated_tokens": self.estimated_tokens,
            "evidence_items": self.evidence_items,
            "evidence_per_step": round(self.evidence_per_step, 3),
            "tokens_per_evidence": round(self.tokens_per_evidence, 1),
        }

    def render(self) -> str:
        return (
            f"steps={self.steps} calls={self.tool_calls} "
            f"failed={self.failed_calls} repeated={self.repeated_calls} "
            f"evidence={self.evidence_items} "
            f"tokens≈{self.estimated_tokens} ({self.tokens_per_evidence:.0f}/evidence) "
            f"wall={self.wall_ms}ms"
        )


def efficiency(state: Any) -> EfficiencyMetrics:
    """Compute efficiency metrics from the action record."""
    actions = list(getattr(state, "actions", None) or [])
    seen: Dict[str, int] = {}
    repeated = 0
    failed = 0
    wall = 0
    for action in actions:
        key = f"{getattr(action, 'tool', '')}|{sorted((getattr(action, 'arguments', None) or {}).items())}"
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            repeated += 1
        if str(getattr(action, "status", "")) in ("failed", "timeout"):
            failed += 1
        wall += int(getattr(action, "duration_ms", 0) or 0)

    chars = len(_text_of(state)) + len(str(getattr(state, "challenge_summary", "") or ""))
    return EfficiencyMetrics(
        steps=int(getattr(state, "step_count", 0) or 0),
        tool_calls=len(actions),
        failed_calls=failed,
        repeated_calls=repeated,
        wall_ms=wall,
        estimated_tokens=int(chars / CHARS_PER_TOKEN),
        evidence_items=len(getattr(state, "evidence", None) or []),
        hypotheses=len(getattr(state, "hypotheses", None) or []),
    )


# ------------------------------------------------------------ hallucination


@dataclass
class Finding:
    """One unsupported claim."""

    kind: str
    detail: str
    severity: str = "warn"   # warn | serious | severe

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "detail": self.detail, "severity": self.severity}

    def __str__(self) -> str:
        return f"[{self.severity}] {self.kind}: {self.detail}"


@dataclass
class HallucinationReport:
    findings: List[Finding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.findings

    @property
    def score(self) -> float:
        """1.0 is clean. Severe findings dominate, as they should."""
        weights = {"warn": 0.1, "serious": 0.3, "severe": 0.6}
        penalty = sum(weights.get(f.severity, 0.2) for f in self.findings)
        return max(0.0, 1.0 - penalty)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clean": self.clean,
            "score": round(self.score, 3),
            "findings": [f.to_dict() for f in self.findings],
        }

    def render(self) -> str:
        if self.clean:
            return "No unsupported claims detected."
        return "Unsupported claims:\n" + "\n".join(f"  {f}" for f in self.findings)


def detect_hallucinations(state: Any, graph: Any = None) -> HallucinationReport:
    """
    Check the agent's conclusions against what was actually observed.

    Every check compares a claim to the record. Nothing here asks a model
    whether it made something up, because a model that invents a flag will
    also confirm that it did not.
    """
    report = HallucinationReport()
    observed = _text_of(state)
    observed_lower = observed.lower()

    # 1. A flag that appears in no tool output. The most damaging failure:
    #    a fabricated flag is indistinguishable from a solved challenge.
    flag = str(getattr(state, "flag_candidate", "") or "").strip()
    if flag and flag not in observed:
        report.findings.append(Finding(
            kind="invented_flag",
            detail=f"flag {flag!r} does not appear in any recorded tool output",
            severity="severe",
        ))

    # 2. A conclusion attributed to a tool that never ran successfully.
    ran = {str(getattr(a, "tool", "")).lower()
           for a in (getattr(state, "actions", None) or [])
           if str(getattr(a, "status", "")) == "succeeded"}
    # Only the conclusion counts. `lessons` holds teaching advice — a skill
    # pack saying "run checksec first" is guidance, not a claim that checksec
    # ran, and scanning it here produced false positives on every pwn run.
    conclusion = str(getattr(state, "solution_summary", "") or "").lower()
    for tool in ("ghidra", "gdb", "readelf", "strings", "tshark", "exiftool",
                 "objdump", "checksec", "binwalk"):
        if tool in conclusion and tool not in ran and not any(tool in r for r in ran):
            report.findings.append(Finding(
                kind="invented_tool_output",
                detail=f"conclusion refers to {tool}, which never ran successfully",
                severity="serious",
            ))

    # 3. An asserted technique whose required observations are missing.
    for h in getattr(state, "hypotheses", None) or []:
        if str(getattr(h, "status", "")) != "confirmed":
            continue
        technique = str(getattr(h, "technique", "") or "")
        if not technique:
            continue
        try:
            from agent.evidence import SupportLevel, assess
            level = assess(technique, observed_lower).level
        except Exception:
            continue
        if level in (SupportLevel.INSUFFICIENT_EVIDENCE, SupportLevel.REFUTED):
            report.findings.append(Finding(
                kind="unsupported_technique",
                detail=f"{h.id} is marked confirmed but evidence for {technique} "
                       f"is only '{level.value}'",
                severity="serious",
            ))

    # 4. A conclusion with no evidence behind it at all.
    if str(getattr(state, "status", "")) in ("verified", "solved"):
        if not (getattr(state, "evidence", None) or []):
            report.findings.append(Finding(
                kind="conclusion_without_evidence",
                detail="run concluded successfully with no evidence records",
                severity="severe",
            ))

    # 5. Confidence out of proportion to the evidence behind it.
    confidence = float(getattr(state, "overall_confidence", 0.0) or 0.0)
    evidence_count = len(getattr(state, "evidence", None) or [])
    if confidence >= 0.85 and evidence_count <= 1 and not flag:
        report.findings.append(Finding(
            kind="overconfidence",
            detail=f"confidence {confidence:.2f} on {evidence_count} evidence item(s)",
            severity="warn",
        ))

    # 6. Support that rests only on reference material (graph-aware).
    if graph is not None:
        try:
            best = graph.best_technique()
            if best is not None and best.gaps and confidence >= 0.8:
                report.findings.append(Finding(
                    kind="unsupported_technique",
                    detail=f"confidence {confidence:.2f} while {len(best.gaps)} required "
                           f"signal(s) for {best.technique} are unobserved",
                    severity="serious",
                ))
        except Exception:
            pass
    return report


# --------------------------------------------------------------- dimensions

DIMENSIONS = (
    "challenge_classification",
    "technique_identification",
    "evidence_quality",
    "hypothesis_quality",
    "tool_selection",
    "tool_execution",
    "verification",
    "final_correctness",
    "hallucination",
    "explanation",
    "hint_quality",
    "efficiency",
)


@dataclass
class DimensionScores:
    """Per-axis scores in [0, 1], plus the reason each was given."""

    scores: Dict[str, float] = field(default_factory=dict)
    notes: Dict[str, str] = field(default_factory=dict)

    def set(self, dimension: str, score: float, note: str = "") -> None:
        self.scores[dimension] = max(0.0, min(1.0, float(score)))
        if note:
            self.notes[dimension] = note

    @property
    def overall(self) -> float:
        if not self.scores:
            return 0.0
        return sum(self.scores.values()) / len(self.scores)

    def weakest(self, count: int = 3) -> List[Tuple[str, float]]:
        """Where the system is actually failing."""
        return sorted(self.scores.items(), key=lambda kv: kv[1])[:count]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scores": {k: round(v, 3) for k, v in self.scores.items()},
            "notes": dict(self.notes),
            "overall": round(self.overall, 3),
            "weakest": [k for k, _ in self.weakest()],
        }

    def render(self) -> str:
        lines = [f"Overall: {self.overall:.2f}"]
        for dimension in DIMENSIONS:
            if dimension not in self.scores:
                continue
            bar = "█" * int(round(self.scores[dimension] * 10))
            note = self.notes.get(dimension, "")
            lines.append(f"  {dimension:26s} {self.scores[dimension]:.2f} {bar:10s} {note}")
        return "\n".join(lines)


def score_run(
    state: Any,
    expected: Optional[Dict[str, Any]] = None,
    graph: Any = None,
) -> DimensionScores:
    """
    Score one run on every axis the record can support.

    Axes needing ground truth are skipped rather than guessed when
    `expected` is absent, so an unlabelled run still yields the process
    axes — which are the ones that say *why* something failed.
    """
    expected = expected or {}
    out = DimensionScores()
    eff = efficiency(state)

    if expected.get("expected_category"):
        got = str(getattr(state, "category", "") or "").lower()
        want = str(expected["expected_category"]).lower()
        out.set("challenge_classification", 1.0 if got == want else 0.0,
                f"got {got or 'none'}, wanted {want}")

    if expected.get("expected_techniques"):
        want = {str(t).lower() for t in expected["expected_techniques"]}
        got = {str(getattr(h, "technique", "")).lower()
               for h in (getattr(state, "hypotheses", None) or [])
               if getattr(h, "technique", "")}
        hit = want & got
        out.set("technique_identification", len(hit) / len(want) if want else 0.0,
                f"{len(hit)}/{len(want)} identified")

    # Evidence quality: corroboration and provenance, not volume.
    if graph is not None:
        try:
            stats = graph.stats()
            observations = max(1, stats.get("observations", 0))
            corroborated = stats.get("corroborated", 0)
            out.set("evidence_quality", min(1.0, 0.4 + 0.6 * (corroborated / observations)),
                    f"{corroborated}/{observations} corroborated by 2+ tools")
        except Exception:
            pass
    else:
        count = len(getattr(state, "evidence", None) or [])
        out.set("evidence_quality", min(1.0, count / 5.0), f"{count} evidence items")

    # Hypothesis quality: did the agent keep real alternatives and resolve them?
    hypotheses = list(getattr(state, "hypotheses", None) or [])
    resolved = [h for h in hypotheses if str(getattr(h, "status", "")) in ("confirmed", "rejected")]
    if hypotheses:
        breadth = min(1.0, len(hypotheses) / 3.0)
        resolution = len(resolved) / len(hypotheses)
        out.set("hypothesis_quality", 0.5 * breadth + 0.5 * resolution,
                f"{len(hypotheses)} considered, {len(resolved)} resolved")

    # Tool selection: were chosen tools capable of closing an open gap?
    actions = list(getattr(state, "actions", None) or [])
    if actions:
        useful = 0
        try:
            from agent.tool_capabilities import capability
            for action in actions:
                cap = capability(str(getattr(action, "tool", "")))
                if cap is not None and cap.produces:
                    useful += 1
        except Exception:
            useful = len(actions)
        out.set("tool_selection", useful / len(actions),
                f"{useful}/{len(actions)} could produce observations")
        out.set("tool_execution", 1.0 - eff.failure_rate,
                f"{eff.failed_calls} failure(s)")

    # Verification: an honest "insufficient" scores better than a lucky pass.
    status = str(getattr(state, "status", "") or "")
    verified = status == "verified"
    solved_truth = expected.get("solvable", None)
    if verified and (solved_truth is not False):
        out.set("verification", 1.0, "verified with evidence")
    elif status in ("stuck", "investigating"):
        out.set("verification", 0.6, "declined to conclude — honest under-claiming")
    elif verified and solved_truth is False:
        out.set("verification", 0.0, "verified something that is not the answer")
    else:
        out.set("verification", 0.3, f"status {status}")

    if "expected_flag" in expected:
        got_flag = str(getattr(state, "flag_candidate", "") or "")
        out.set("final_correctness", 1.0 if got_flag == str(expected["expected_flag"]) else 0.0,
                "flag match" if got_flag else "no flag recovered")
    elif solved_truth is not None:
        out.set("final_correctness", 1.0 if verified == bool(solved_truth) else 0.0)

    report = detect_hallucinations(state, graph=graph)
    out.set("hallucination", report.score,
            "clean" if report.clean else f"{len(report.findings)} finding(s)")

    # Explanation: can the run be read back as reasoning, with provenance?
    explanation_bits = [
        bool(getattr(state, "lessons", None)),
        bool(getattr(state, "solution_summary", "")),
        bool(getattr(state, "belief_updates", None)),
        bool(getattr(state, "phase_history", None)),
    ]
    out.set("explanation", sum(explanation_bits) / len(explanation_bits),
            f"{sum(explanation_bits)}/4 narrative components present")

    # Hint quality: solving unaided beats solving after the answer.
    hint_level = int(getattr(state, "hint_level_reached", 0) or 0)
    out.set("hint_quality", max(0.0, 1.0 - 0.2 * hint_level),
            f"reached hint level {hint_level}")

    budget = max(1, int(getattr(state, "max_steps", 1) or 1))
    thrift = 1.0 - (eff.wasted_steps / budget)
    out.set("efficiency", max(0.0, min(1.0, thrift)),
            f"{eff.wasted_steps} wasted of {budget} budget")
    return out


def scorecard(state: Any, expected: Optional[Dict[str, Any]] = None, graph: Any = None) -> str:
    """Full report for one run."""
    dims = score_run(state, expected=expected, graph=graph)
    report = detect_hallucinations(state, graph=graph)
    return "\n".join([
        "=== Run scorecard ===",
        dims.render(),
        "",
        efficiency(state).render(),
        "",
        report.render(),
    ])


def aggregate(runs: Sequence[DimensionScores]) -> Dict[str, Any]:
    """Mean per dimension across runs, with the weakest axes named."""
    if not runs:
        return {"runs": 0}
    totals: Dict[str, List[float]] = {}
    for run in runs:
        for dimension, value in run.scores.items():
            totals.setdefault(dimension, []).append(value)
    means = {k: round(sum(v) / len(v), 3) for k, v in totals.items()}
    return {
        "runs": len(runs),
        "means": means,
        "overall": round(sum(means.values()) / len(means), 3) if means else 0.0,
        "weakest": sorted(means.items(), key=lambda kv: kv[1])[:3],
    }
