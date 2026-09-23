"""
agent/writeup.py

The investigation written up so it can be checked (item 64).

The previous version dumped the state's fields under headings. It read like
a log, which meant it was useless for the two purposes a writeup actually
has: teaching someone the reasoning, and letting a developer see where the
reasoning went wrong.

The structure now follows the review's outline -- challenge, objective,
initial observations, hypotheses, evidence, technique, steps, verification,
result, lessons, related techniques -- with three additions that make it
checkable rather than merely readable:

*   **Provenance per claim.** Each observation says which tool produced it,
    and the evidence graph section shows what supports the conclusion. A
    reader can disagree with a specific step instead of with the whole
    thing.
*   **What was ruled out, and why.** Rejected hypotheses and the lookalikes
    that were considered are part of the reasoning, not clutter. A writeup
    that only lists the winning path teaches guessing.
*   **Honest verification.** If the required observations were never made,
    the writeup says so under its own heading rather than presenting the
    leading guess as the answer.

`render_writeup(state)` keeps its old signature; the graph is optional so
existing callers work unchanged.
"""

from __future__ import annotations

from typing import Any, List, Optional

from agent.hypothesis import rank_hypotheses
from agent.state import AgentState
from agent.teaching import progressive_hint


def _section(lines: List[str], title: str) -> None:
    lines.extend(["", f"## {title}"])


def render_writeup(state: AgentState, graph: Any = None, hint_level: int = 3) -> str:
    """Render the full structured writeup."""
    lines: List[str] = [
        f"# Writeup: {state.challenge_summary[:120]}",
        "",
    ]

    # ---- header -------------------------------------------------------
    try:
        from agent.difficulty import estimate

        difficulty = estimate(state)
        difficulty_line = (f"**Difficulty:** {difficulty.band} ({difficulty.score:.2f} measured)"
                           + (f", stated {difficulty.stated}" if difficulty.stated else "") + "  ")
    except Exception:
        difficulty_line = f"**Difficulty:** {state.difficulty or 'unrated'}  "

    lines += [
        f"**Category:** {state.category or 'unknown'}  ",
        f"**Status:** {state.status}  ",
        f"**Confidence:** {state.overall_confidence:.2f}  ",
        difficulty_line,
    ]

    _section(lines, "Objective")
    lines.append(state.challenge_summary or "(no description recorded)")

    # ---- observations, attributed --------------------------------------
    _section(lines, "Initial observations")
    if state.discovered_artifacts:
        lines.append(f"Artifacts: {', '.join(str(a) for a in state.discovered_artifacts[:6])}")
    if state.known_facts:
        for fact in state.known_facts[:10]:
            lines.append(f"- {fact}")
    else:
        lines.append("- none recorded before the first action")

    # ---- hypotheses, including the discarded ones ----------------------
    _section(lines, "Hypotheses considered")
    ranked = rank_hypotheses(state)
    if ranked:
        for h in ranked:
            lines.append(f"- **[{h.confidence:.2f}] {h.technique or '-'}:** {h.statement}")
    else:
        lines.append("- none survived")

    discarded = [h for h in state.hypotheses if h.status in ("rejected", "superseded")]
    if discarded:
        lines += ["", "### Ruled out"]
        for h in discarded:
            reason = (h.contradicting_evidence or ["no reason recorded"])[-1]
            lines.append(f"- ~~{h.technique or h.statement[:50]}~~ - {reason}")

    # ---- evidence with its source --------------------------------------
    _section(lines, "Evidence")
    if state.evidence:
        for e in state.evidence[-12:]:
            lines.append(f"- `{e.source}`: {e.finding or e.content[:160]}")
    else:
        lines.append("- no evidence was collected")

    if graph is not None:
        try:
            if len(graph):
                lines += ["", "### How it fits together", "```", graph.render(), "```"]
                for gap in graph.coverage_gaps[:4]:
                    lines.append(f"- Coverage gap: {gap}")
        except Exception:
            pass

    # ---- technique and the alternatives that were live -----------------
    top = ranked[0] if ranked else None
    _section(lines, "Technique")
    if top is not None and top.technique:
        lines.append(f"**{top.technique}** - {top.statement}")
        try:
            from agent.evidence import requirements_for

            req = requirements_for(top.technique)
            if req:
                lines += ["", "Required observations:"]
                for signal in req.required:
                    lines.append(f"- {signal}")
                if req.alternatives:
                    lines += ["", "Considered and not ruled out:"]
                    for alt in req.alternatives[:3]:
                        lines.append(f"- {alt}")
                if req.verification:
                    lines += ["", f"How this is confirmed: {req.verification}"]
        except Exception:
            pass
    else:
        lines.append("No technique was established.")

    # ---- the steps actually taken --------------------------------------
    _section(lines, "Steps")
    if state.actions:
        for index, a in enumerate(state.actions, start=1):
            outcome = a.result_summary[:90] or a.error[:90] or "no output"
            lines.append(f"{index}. `{a.tool}` - {a.reason[:90]}")
            lines.append(f"   -> {a.status}: {outcome}")
    else:
        lines.append("No actions were executed.")

    # ---- verification, honestly ----------------------------------------
    _section(lines, "Verification")
    if state.status == "verified":
        lines.append("Verified: the observations this technique requires were collected.")
    else:
        lines.append(f"**Not verified** (status: {state.status}).")
    if graph is not None and top is not None and top.technique:
        try:
            support = graph.assess_technique(top.technique)
            lines.append(f"Graph assessment: **{support.level.value}** ({support.score:.2f}), "
                         f"{support.independent_sources} independent source(s).")
            for gap in support.gaps[:4]:
                lines.append(f"- Still unobserved: {gap}")
            if support.caveat:
                lines.append(f"- Caveat: {support.caveat}")
        except Exception:
            pass

    try:
        from agent.metrics import detect_hallucinations

        report = detect_hallucinations(state, graph=graph)
        if not report.clean:
            lines += ["", "### Claims not backed by the record"]
            for finding in report.findings:
                lines.append(f"- {finding}")
    except Exception:
        pass

    # ---- result --------------------------------------------------------
    _section(lines, "Result")
    if state.flag_candidate:
        lines.append(f"Flag candidate: `{state.flag_candidate}`")
    if state.solution_summary:
        lines.append(state.solution_summary)
    if not (state.flag_candidate or state.solution_summary):
        lines.append("No result was reached.")

    # ---- what to take away ---------------------------------------------
    _section(lines, "Lessons learned")
    if state.lessons:
        for lesson in state.lessons[:10]:
            lines.append(f"- {lesson}")
    else:
        lines.append("- none recorded")

    _section(lines, "Related techniques")
    related: List[str] = []
    if top is not None and top.technique:
        try:
            from agent.skill_graph import prerequisites_for

            related = list(prerequisites_for(top.technique) or [])
        except Exception:
            related = []
    if related:
        lines.append("Prerequisites: " + ", ".join(related[:6]))
    try:
        lines.append(progressive_hint(state, hint_level))
    except Exception:
        pass

    # ---- cost ----------------------------------------------------------
    try:
        from agent.metrics import efficiency

        _section(lines, "Cost")
        lines.append("```")
        lines.append(efficiency(state).render())
        lines.append("```")
    except Exception:
        pass

    return "\n".join(lines)


def render_brief(state: AgentState, graph: Any = None) -> str:
    """
    One-paragraph version for a list view or a commit message.

    Deliberately states the verification status: a summary that reads like
    success when nothing was verified is the thing this module exists to
    avoid.
    """
    ranked = rank_hypotheses(state)
    top = ranked[0] if ranked else None
    technique = (top.technique or "unclassified") if top else "unclassified"
    verdict = "verified" if state.status == "verified" else f"unverified ({state.status})"
    return (
        f"{state.challenge_summary[:80]} - {state.category or 'uncategorised'}, "
        f"leading technique {technique} at {state.overall_confidence:.2f}, {verdict}; "
        f"{len(state.evidence)} evidence item(s) over {state.step_count} step(s)."
    )
