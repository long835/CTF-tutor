"""
agent/writeup.py

Structured CTF writeup generator from AgentState.
"""

from __future__ import annotations

from agent.state import AgentState
from agent.hypothesis import rank_hypotheses
from agent.teaching import progressive_hint


def render_writeup(state: AgentState) -> str:
    lines = [
        f"# Writeup: {state.challenge_summary[:120]}",
        "",
        f"**Category:** {state.category or "unknown"}  ",
        f"**Status:** {state.status}  ",
        f"**Confidence:** {state.overall_confidence:.2f}  ",
        "",
        "## Objective",
        state.challenge_summary,
        "",
        "## Initial observations",
    ]
    for f in state.known_facts[:10]:
        lines.append(f"- {f}")
    lines += ["", "## Hypotheses"]
    for h in rank_hypotheses(state):
        lines.append(f"- **[{h.confidence:.2f}] {h.technique or "—"}:** {h.statement}")
    lines += ["", "## Evidence"]
    for e in state.evidence[-12:]:
        lines.append(f"- `{e.source}`: {e.finding or e.content[:160]}")
    lines += ["", "## Exploitation / resolution"]
    if state.flag_candidate:
        lines.append(f"Flag candidate: `{state.flag_candidate}`")
    if state.solution_summary:
        lines.append(state.solution_summary)
    lines += ["", "## Lessons learned"]
    for L in state.lessons:
        lines.append(f"- {L}")
    lines += ["", "## Related concepts", progressive_hint(state, 3)]
    lines += ["", "## Commands / tools used"]
    for a in state.actions:
        lines.append(f"- `{a.tool}` → {a.status}: {a.reason[:100]}")
    return "\n".join(lines)
