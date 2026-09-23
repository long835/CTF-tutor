"""
agent/recovery.py

Noticing that the current line of attack has failed (item 23).

The failure mode this exists to prevent is not a crash. It is the agent
spending its whole step budget politely re-confirming its first guess:
re-running the tool that already failed, re-reading the file that had
nothing in it, and testing the leading hypothesis with actions that could
not have discriminated against the runner-up in the first place.

Detection is deliberately based on the record rather than on asking a model
whether it feels stuck — a small model asked that question says no.

Six patterns are recognised, each with a remedy that changes what happens
next rather than merely logging a complaint:

    repeated_action     → ban the action, force a different one
    failing_tool        → stop retrying; record the coverage gap
    refuted_leader      → retire it, promote the best survivor
    no_discrimination   → seek a signal that separates the top two
    evidence_plateau    → broaden, using the lookalikes as seeds
    all_rejected        → reopen with the innocent explanations as candidates

`no_discrimination` is the one that most changes behaviour. When two
hypotheses are both plausible, the useful next action is not "test the
leader again" but "find an observation the two disagree about", which
`discriminating_signals` computes straight from their rubrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from agent.belief import belief_spread, rank_by_belief
from agent.evidence import SupportLevel, _matches, requirements_for

# Thresholds. Low enough to react inside a 12-step budget, high enough not
# to fire on ordinary iteration.
REPEAT_LIMIT = 3            # identical action attempts before it is banned
FAILURE_LIMIT = 2           # failures of one tool before it is abandoned
PLATEAU_STEPS = 3           # steps without confidence movement
DISCRIMINATION_FLOOR = 0.08  # gap below which the leaders are not separated
MIN_STEPS_BEFORE_PLATEAU = 3


@dataclass
class Diagnosis:
    """One recognised failure pattern and what to do about it."""

    pattern: str
    detail: str
    remedy: str
    severity: str = "warn"            # warn | serious | fatal
    targets: List[str] = field(default_factory=list)   # tools or hypothesis ids
    suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "detail": self.detail,
            "remedy": self.remedy,
            "severity": self.severity,
            "targets": list(self.targets),
            "suggestions": list(self.suggestions),
        }

    def __str__(self) -> str:
        return f"[{self.severity}] {self.pattern}: {self.detail} → {self.remedy}"


def _action_key(action: Any) -> str:
    tool = str(getattr(action, "tool", "") or "")
    args = getattr(action, "arguments", None) or {}
    try:
        rendered = ",".join(f"{k}={str(v)[:40]}" for k, v in sorted(args.items()))
    except Exception:
        rendered = str(args)[:80]
    return f"{tool}({rendered})"


def discriminating_signals(technique_a: str, technique_b: str, limit: int = 4) -> List[str]:
    """
    Observations that would tell two techniques apart.

    A signal both rubrics list is useless for choosing between them however
    strongly it is present; what helps is a signal one requires and the
    other does not, or one that outright contradicts the rival.
    """
    req_a = requirements_for(technique_a)
    req_b = requirements_for(technique_b)
    if req_a is None or req_b is None:
        return []

    # Overlap has to be judged semantically. "jwt" and "jwt|json web token"
    # are not equal as strings but describe the same observation, and
    # offering it as a discriminator would send the agent to look for
    # something both hypotheses predict.
    other = list(req_b.required) + list(req_b.supporting)

    def _shared(signal: str) -> bool:
        return any(_matches(signal, o) or _matches(o, signal) for o in other)

    out: List[str] = []
    for signal in req_a.required + req_a.supporting:
        if not _shared(signal) and signal not in out:
            out.append(signal)
    for signal in req_b.contradicting:
        marker = f"absence of: {signal}"
        if signal not in out and marker not in out:
            out.append(marker)
    return out[:limit]


def diagnose(state: Any, graph: Any = None) -> List[Diagnosis]:
    """Inspect the record and report every pattern that currently holds."""
    found: List[Diagnosis] = []
    actions = list(getattr(state, "actions", None) or [])
    step_count = int(getattr(state, "step_count", 0) or 0)

    # --- repeated identical action -------------------------------------
    counts: Dict[str, int] = {}
    for action in actions:
        key = _action_key(action)
        counts[key] = counts.get(key, 0) + 1
    for key, count in counts.items():
        if count >= REPEAT_LIMIT:
            tool = key.split("(")[0]
            found.append(Diagnosis(
                pattern="repeated_action",
                detail=f"{key} attempted {count}× with no new evidence",
                remedy="ban this exact action and plan a different one",
                severity="serious",
                targets=[tool],
            ))

    # --- a tool that keeps failing --------------------------------------
    failures: Dict[str, List[str]] = {}
    for action in actions:
        if str(getattr(action, "status", "")) in ("failed", "timeout"):
            tool = str(getattr(action, "tool", "") or "")
            failures.setdefault(tool, []).append(str(getattr(action, "error", ""))[:120])
    for tool, errors in failures.items():
        if len(errors) >= FAILURE_LIMIT:
            found.append(Diagnosis(
                pattern="failing_tool",
                detail=f"{tool} failed {len(errors)}× ({errors[-1] or 'no detail'})",
                remedy="abandon the tool and record a coverage gap — this is missing "
                       "evidence, not evidence of absence",
                severity="serious",
                targets=[tool],
            ))

    # --- the leader has been refuted ------------------------------------
    ranked = rank_by_belief(state)
    rejected = [h for h in (getattr(state, "hypotheses", None) or [])
                if getattr(h, "status", "") == "rejected"]
    if graph is not None and ranked:
        try:
            support = graph.assess_technique(getattr(ranked[0], "technique", "") or "")
            if support.level is SupportLevel.REFUTED:
                found.append(Diagnosis(
                    pattern="refuted_leader",
                    detail=f"{ranked[0].id} is contradicted by collected evidence",
                    remedy="retire it and promote the best surviving hypothesis",
                    severity="serious",
                    targets=[str(ranked[0].id)],
                ))
        except Exception:
            pass

    if not ranked and rejected:
        techniques = [getattr(h, "technique", "") for h in rejected if getattr(h, "technique", "")]
        alternatives: List[str] = []
        for technique in techniques:
            req = requirements_for(technique)
            if req:
                alternatives.extend(req.alternatives)
        found.append(Diagnosis(
            pattern="all_rejected",
            detail=f"every hypothesis has been rejected ({len(rejected)} of them)",
            remedy="reopen the investigation using the innocent explanations as candidates",
            severity="fatal",
            targets=[str(h.id) for h in rejected],
            suggestions=alternatives[:4] or ["re-triage the artifacts from scratch"],
        ))

    # --- the leaders are not separated ----------------------------------
    if len(ranked) >= 2 and step_count >= MIN_STEPS_BEFORE_PLATEAU:
        spread = belief_spread(state)
        if spread < DISCRIMINATION_FLOOR:
            a = getattr(ranked[0], "technique", "") or ""
            b = getattr(ranked[1], "technique", "") or ""
            found.append(Diagnosis(
                pattern="no_discrimination",
                detail=f"{ranked[0].id} and {ranked[1].id} differ by only {spread:.2f} "
                       f"after {step_count} steps",
                remedy="stop testing the leader; look for an observation the two disagree about",
                severity="warn",
                targets=[str(ranked[0].id), str(ranked[1].id)],
                suggestions=discriminating_signals(a, b) or
                            [f"an observation that {a or 'the leader'} predicts and "
                             f"{b or 'the rival'} does not"],
            ))

    # --- nothing is moving ----------------------------------------------
    updates = list(getattr(state, "belief_updates", None) or [])
    if step_count >= MIN_STEPS_BEFORE_PLATEAU:
        recent_moves = [u for u in updates[-8:] if abs(float(u.get("delta", 0.0))) > 0.02]
        productive = [a for a in actions[-PLATEAU_STEPS:]
                      if str(getattr(a, "status", "")) == "succeeded"
                      and str(getattr(a, "result_summary", "")).strip()]
        if not recent_moves and not productive:
            leader = ranked[0] if ranked else None
            technique = getattr(leader, "technique", "") if leader else ""
            req = requirements_for(technique)
            found.append(Diagnosis(
                pattern="evidence_plateau",
                detail=f"no belief movement and no productive action in the last "
                       f"{PLATEAU_STEPS} steps",
                remedy="broaden: the current framing is not producing evidence",
                severity="warn",
                targets=[str(getattr(leader, "id", ""))] if leader else [],
                suggestions=(list(req.alternatives)[:3] if req else
                             ["ask the user for the artifact or output the agent cannot obtain"]),
            ))
    return found


def banned_actions(state: Any) -> Set[str]:
    """Actions the planner must not choose again this investigation."""
    return {str(x) for x in (getattr(state, "abandoned_actions", None) or [])}


def is_stuck(state: Any, graph: Any = None) -> bool:
    """True when at least one serious pattern holds."""
    return any(d.severity in ("serious", "fatal") for d in diagnose(state, graph=graph))


def apply_recovery(state: Any, graph: Any = None,
                   diagnoses: Optional[Sequence[Diagnosis]] = None) -> List[str]:
    """
    Act on the diagnosis. Returns the changes made, for the trace.

    Every branch changes something the planner reads on the next step;
    recording a diagnosis without acting on it would leave the agent free to
    repeat exactly what triggered it.
    """
    diagnoses = list(diagnoses if diagnoses is not None else diagnose(state, graph=graph))
    if not diagnoses:
        return []

    actions_taken: List[str] = []
    abandoned = getattr(state, "abandoned_actions", None)
    if not isinstance(abandoned, list):
        abandoned = []
        try:
            state.abandoned_actions = abandoned
        except Exception:
            pass

    for diag in diagnoses:
        if diag.pattern in ("repeated_action", "failing_tool"):
            for tool in diag.targets:
                if tool and tool not in abandoned:
                    abandoned.append(tool)
                    actions_taken.append(f"banned tool: {tool}")
            if diag.pattern == "failing_tool":
                _add_fact(state, f"Coverage gap: {diag.detail}. Absence of evidence, "
                                 f"not evidence of absence.")

        elif diag.pattern == "refuted_leader":
            for hid in diag.targets:
                for h in getattr(state, "hypotheses", None) or []:
                    if str(getattr(h, "id", "")) == hid and getattr(h, "status", "") == "active":
                        h.status = "superseded"
                        actions_taken.append(f"retired {hid} (refuted)")
            survivors = rank_by_belief(state)
            if survivors:
                actions_taken.append(f"promoted {survivors[0].id} as the line to test")

        elif diag.pattern == "no_discrimination":
            for signal in diag.suggestions[:3]:
                _add_fact(state, f"Need a discriminating observation: {signal}")
            actions_taken.append("requested a discriminating observation")

        elif diag.pattern in ("evidence_plateau", "all_rejected"):
            added = _seed_alternatives(state, diag.suggestions)
            actions_taken.extend(added)
            if diag.pattern == "all_rejected" and not added:
                _add_fact(state, "All hypotheses rejected and no alternatives available — "
                                 "re-triage or ask the user for more material.")

    # A diagnosis whose remedy is already applied is not a new event. Without
    # this, a banned tool re-reports itself on every remaining step and the
    # trace fills with recoveries that changed nothing.
    if not actions_taken:
        return []

    events = getattr(state, "recovery_events", None)
    if isinstance(events, list):
        events.append({
            "step": int(getattr(state, "step_count", 0) or 0),
            "diagnoses": [d.to_dict() for d in diagnoses],
            "actions": list(actions_taken),
        })
    lessons = getattr(state, "lessons", None)
    if isinstance(lessons, list):
        for diag in diagnoses:
            if diag.severity in ("serious", "fatal"):
                lessons.append(f"Recovery — {diag.pattern}: {diag.remedy}")
    return actions_taken


def _add_fact(state: Any, text: str) -> None:
    try:
        state.add_fact(text)
    except Exception:
        pass


def _seed_alternatives(state: Any, suggestions: Sequence[str]) -> List[str]:
    """
    Turn the lookalikes into live hypotheses.

    This is where the negative knowledge from item 12 earns its keep: the
    list of things that produce the same signal is exactly the list of
    candidates worth opening once the obvious reading has failed.
    """
    added: List[str] = []
    existing = {str(getattr(h, "statement", "")).strip().lower()
                for h in (getattr(state, "hypotheses", None) or [])}
    for suggestion in suggestions[:3]:
        text = str(suggestion).strip()
        if not text:
            continue
        # Compare the stored form, not the raw suggestion: the prefix is part
        # of what gets written, so comparing without it never matches and
        # every plateau re-opens the same alternatives.
        statement = f"Alternative explanation: {text}"
        if statement.strip().lower() in existing:
            continue
        try:
            state.add_hypothesis(
                statement=statement,
                technique="",
                category=str(getattr(state, "category", "") or ""),
                confidence=0.3,
            )
            existing.add(statement.strip().lower())
            added.append(f"opened alternative: {text[:60]}")
        except Exception:
            continue
    return added


def recovery_report(state: Any, graph: Any = None) -> str:
    """Readable diagnosis for traces and the teaching summary."""
    diagnoses = diagnose(state, graph=graph)
    if not diagnoses:
        return "No stall patterns detected."
    lines = ["Stall diagnosis:"]
    for diag in diagnoses:
        lines.append(f"  {diag}")
        for suggestion in diag.suggestions[:3]:
            lines.append(f"      → {suggestion}")
    return "\n".join(lines)
