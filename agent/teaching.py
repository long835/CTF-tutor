"""
agent/teaching.py

Progressive / Socratic teaching layer on top of AgentState.

Produces questions and staged hints from hypotheses + evidence
without dumping the full solution early.
"""

from __future__ import annotations

from typing import List, Optional

from agent.state import AgentState, Hypothesis


HINT_LEVELS = (
    "concept",      # 1 — what class of problem is this?
    "direction",    # 2 — where to look
    "tool",         # 3 — which tool / command class
    "partial",      # 4 — partial technique
    "walkthrough",  # 5 — ordered steps
    "solution",     # 6 — full answer (only on request)
)


def socratic_questions(state: AgentState, n: int = 3) -> List[str]:
    """Generate guiding questions from current state (no spoilers)."""
    questions: List[str] = []
    top = state.top_hypothesis()
    cat = state.category or "this"

    if not state.known_facts:
        questions.append("What is the first concrete observation you can make about the challenge artifacts?")
    if top:
        tech = top.technique or "the suspected technique"
        questions.append(f"What evidence would confirm or rule out: “{top.statement}”?")
        questions.append(f"If {tech} is involved, which input or state would you inspect first?")
    else:
        questions.append(f"Which category does this most resemble, and why ({cat})?")

    if state.evidence:
        questions.append("Which piece of evidence is strongest, and what does it imply for the next action?")
    else:
        questions.append("What safe local analysis (strings, headers, file type) have you not run yet?")

    if state.contradictions:
        questions.append("You have contradictions — which hypothesis should be demoted first?")

    # unique preserve order
    seen = set()
    out = []
    for q in questions:
        if q not in seen:
            seen.add(q)
            out.append(q)
    return out[:n]


def progressive_hint(state: AgentState, level: int = 1) -> str:
    """
    Return a hint at the requested level (1–6).
    Higher levels reveal more; level 6 is full solution summary only.
    """
    level = max(1, min(6, int(level)))
    top = state.top_hypothesis()
    cat = state.category or "unknown"

    if level == 1:
        return (
            f"Concept: This looks like a **{cat}** problem. "
            f"Focus on the core property of that category before jumping to exploits."
        )
    if level == 2:
        if top:
            extra = ""
            try:
                from agent.skill_graph import teaching_path, explain_concept
                path = teaching_path(top.technique, set()) if top.technique else []
                if path and len(path) > 1:
                    extra = " Prerequisites to review: " + ", ".join(path[:-1][:4]) + "."
            except Exception:
                pass
            return f"Direction: Investigate whether “{top.statement}” is true. Gather evidence for or against it." + extra
        return "Direction: Inventory the files, identify formats, and note anything unusual (crypto constants, unsafe APIs, auth logic)."
    if level == 3:
        tools = []
        if cat == "web":
            tools = ["inspect source for JWT/auth patterns", "check cookie/header handling"]
        elif cat in ("pwn", "rev"):
            tools = ["file/checksec", "strings", "disassemble interesting functions"]
        elif cat == "crypto":
            tools = ["identify encoding/hash/cipher", "check key sizes and modes"]
        elif cat == "forensics":
            tools = ["file magic", "metadata", "carving / pcap follow-stream"]
        else:
            tools = ["static inspection", "archive search for similar cases"]
        return "Tool class: " + "; ".join(tools) + "."
    if level == 4:
        if top and top.technique:
            return (
                f"Partial: The leading technique tag is **{top.technique}** "
                f"(confidence {top.confidence:.2f}). Validate it with a concrete check."
            )
        return "Partial: Narrow to one testable claim and run a single analysis that would falsify it."
    if level == 5:
        steps = [
            "1. Inventory artifacts and classify the challenge.",
            "2. Form 2–3 ranked hypotheses.",
            "3. Run one analysis per hypothesis; record evidence.",
            "4. Update confidences; drop falsified claims.",
            "5. Only then assemble a candidate solution and verify.",
        ]
        if top:
            steps.insert(2, f"   Focus check: {top.statement}")
        return "Walkthrough:\n" + "\n".join(steps)
    # level 6
    if state.solution_summary:
        return f"Solution summary:\n{state.solution_summary}"
    if top:
        return (
            f"Best current conclusion ({top.confidence:.2f}): {top.statement}\n"
            f"Technique: {top.technique or 'n/a'}\n"
            f"Supporting evidence: {len(top.supporting_evidence)} note(s), "
            f"{len(state.evidence)} observation(s) total."
        )
    return "No strong conclusion yet — collect more evidence."


def teaching_report(state: AgentState, hint_level: int = 2) -> str:
    """Full teaching block: questions + hint + misconceptions guardrails."""
    lines = [
        "## Teach mode",
        "",
        "### Socratic prompts",
    ]
    for q in socratic_questions(state):
        lines.append(f"- {q}")
    lines.append("")
    lines.append(f"### Hint (level {hint_level}/{len(HINT_LEVELS)} — {HINT_LEVELS[hint_level-1]})")
    lines.append(progressive_hint(state, hint_level))
    if state.lessons:
        lines.append("")
        lines.append("### Lessons so far")
        for L in state.lessons:
            lines.append(f"- {L}")

    # Scan what the learner and the tools have said for wrong-but-common
    # beliefs, and correct them before they calcify.
    scan_text = " ".join(
        [state.challenge_summary or ""]
        + list(state.known_facts or [])
        + [e.finding or e.content or "" for e in (state.evidence or [])][:8]
    )
    block = misconception_block(scan_text, category=state.category)
    if block:
        lines.append("")
        lines.append(block)

    return "\n".join(lines)


# Legacy keyword pairs, kept so existing callers and tests keep working.
# The real detection now lives in agent.misconception, which understands
# negations ("base64 is *not* encryption") and returns graded confidence.
MISCONCEPTION_GUARDS = [
    ("jwt", "encryption", "JWT is signed (integrity), not encrypted by default (confidentiality)."),
    ("base64", "encryption", "Base64 is encoding, not encryption — anyone can decode it."),
    ("hash", "encryption", "Hashes are one-way; they do not decrypt."),
    ("aslr", "canary", "ASLR randomizes addresses; canaries detect stack smashing — different mitigations."),
    ("authentication", "authorization", "Authentication answers who you are; authorization answers what you may do."),
]


def detect_misconceptions(text: str) -> List[str]:
    """
    Return plain-language corrections for misconceptions found in `text`.

    Prefers the full engine; falls back to the keyword pairs above if that
    module is unavailable, so the teaching layer never hard-fails.
    """
    hits: List[str] = []
    try:
        from agent.misconception import detect as _detect

        for d in _detect(text):
            hits.append(d.misconception.correction)
    except Exception:
        pass

    lower = (text or "").lower()
    for a, b, msg in MISCONCEPTION_GUARDS:
        if a in lower and b in lower and msg not in hits:
            hits.append(msg)
    return hits


def misconception_block(text: str, category: Optional[str] = None) -> str:
    """Rendered correction block, or an empty string when nothing fires."""
    try:
        from agent.misconception import remediation_report

        return remediation_report(text, category=category)
    except Exception:
        return ""
