"""
agent/observer.py

Turns raw tool output into structured Evidence and drives hypothesis updates.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from agent.state import AgentState, Evidence
from agent.hypothesis import update_hypotheses_from_observation


def observe(
    state: AgentState,
    tool: str,
    raw_output: str,
    success: bool = True,
    error: str = "",
    meta: Optional[Dict[str, Any]] = None,
) -> Evidence:
    """
    Create an Evidence record from a tool result and update hypotheses.
    """
    finding = _extract_finding(tool, raw_output, success, error)
    content = raw_output if success else f"ERROR: {error}\n{raw_output}"
    conf = 0.75 if success and raw_output.strip() else 0.3

    related = []
    top = state.top_hypothesis()
    if top:
        related = [top.id]

    evidence = state.add_evidence(
        source=tool,
        content=content[:3500],
        finding=finding,
        confidence=conf,
        related_hypothesis_ids=related,
        raw=meta,
    )

    # Feed observation back into hypothesis engine
    obs_text = finding if finding else content[:1500]
    if obs_text.strip():
        update_hypotheses_from_observation(state, obs_text, source=tool)

    # Promote interesting strings into known facts
    if success and finding:
        state.add_fact(f"[{tool}] {finding[:200]}")

    # Flag auto-capture (high-signal CTF outcome)
    try:
        from agent.auto_decode import scan_for_flags
        import json
        flags = []
        raw = raw_output or ""
        # Prefer structured auto_decode JSON
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for fl in data.get("flags") or []:
                    if isinstance(fl, str) and fl not in flags:
                        flags.append(fl)
                if data.get("final_text"):
                    for fl in scan_for_flags(str(data["final_text"])):
                        if fl not in flags:
                            flags.append(fl)
        except Exception:
            pass
        if not flags:
            flags = scan_for_flags(raw + "\n" + (finding or ""))
        # de-dupe preserve order
        seen = set()
        clean = []
        for fl in flags:
            fl = fl.strip().rstrip('",')
            if fl and fl not in seen and len(fl) < 200:
                seen.add(fl)
                clean.append(fl)
        flags = clean
        if flags:
            # Grade before accepting (items 62/63). The previous behaviour took
            # flags[0] on sight, which is exactly how a planted decoy wins: it
            # is usually placed where the first tool will hit it.
            accepted = list(flags)
            try:
                from agent.flag_check import FlagVerdict, check_flag

                graded = [(fl, check_flag(fl, state=state)) for fl in flags]
                rejected = [(fl, c) for fl, c in graded
                            if c.verdict in (FlagVerdict.DECOY, FlagVerdict.REJECTED)]
                for fl, check in rejected:
                    state.add_fact(f"Rejected flag-shaped string {fl}: "
                                   f"{check.verdict.value} — {'; '.join(check.reasons[:2])}")
                    state.lessons.append(
                        f"{fl} looks like a flag but is {check.verdict.value}. A "
                        f"flag-shaped string is not a flag."
                    )
                accepted = [fl for fl, c in graded
                            if c.verdict not in (FlagVerdict.DECOY, FlagVerdict.REJECTED)]
            except Exception:
                accepted = list(flags)
            if not accepted:
                return evidence
            flags = accepted
            for fl in flags:
                state.add_fact(f"FLAG_CANDIDATE: {fl}")
            state.flag_candidate = flags[0]
            state.solution_summary = f"Flag candidate(s): {', '.join(flags)}"
            top = state.top_hypothesis()
            if top:
                top.update_confidence(+0.35, reason=f"flag pattern observed: {flags[0]}")
                top.status = "confirmed"
            else:
                state.add_hypothesis(
                    statement=f"Recovered flag material: {flags[0]}",
                    technique="flag-recovery",
                    category=state.category or "misc",
                    confidence=0.95,
                )
                state.hypotheses[-1].status = "confirmed"
            state.overall_confidence = max(state.overall_confidence, 0.9)
            state.status = "solved"
            state.lessons.append(f"Recovered flag-like token via {tool}")
    except Exception:
        pass

    return evidence


def _extract_finding(tool: str, raw: str, success: bool, error: str) -> str:
    if not success:
        return f"{tool} failed: {error[:200]}" if error else f"{tool} failed"
    text = (raw or "").strip()
    if not text:
        return f"{tool} returned empty output"

    # Prefer the first informative line / JSON-ish summary
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return f"{tool}: no content"

    # Heuristic: look for high-signal keywords
    interesting = []
    keywords = (
        "jwt", "alg", "hs256", "rs256", "none", "sql", "union", "xss",
        "nx", "canary", "pie", "relro", "gets", "strcpy", "format",
        "md5", "sha", "rsa", "aes", "xor", "ecb", "padding",
        "elf", "pe32", "mach-o", "pcap", "exif", "steg",
        "flag", "ctf{", "htb{",
    )
    lower = text.lower()
    for kw in keywords:
        if kw in lower:
            interesting.append(kw)

    head = lines[0][:180]
    if interesting:
        return f"{head} | signals: {', '.join(interesting[:8])}"
    return head
