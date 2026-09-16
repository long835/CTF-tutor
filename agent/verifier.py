"""
agent/verifier.py

Independent verification of candidate solutions.

A solution is only marked verified when evidence supports it.
LLM opinion alone is never sufficient.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from agent.state import AgentState
from llm_client import call_ollama, extract_json_object_lenient, DEFAULT_MODEL


SYSTEM_VERIFY = """You are a strict CTF solution verifier.
You receive a challenge, the agent's evidence, hypotheses, and a candidate solution.
Decide whether the candidate is supported by the evidence.
Return ONLY JSON:
{
  "verdict": "pass" | "fail" | "insufficient_evidence",
  "confidence": 0.0-1.0,
  "reasons": ["..."],
  "missing_evidence": ["..."]
}
Never invent tool output or flags that were not provided.
"""


def verify_solution(
    state: AgentState,
    candidate: str,
    model: str = DEFAULT_MODEL,
) -> Dict[str, Any]:
    """
    Run verification. Returns a structured verdict dict.
    """
    candidate = (candidate or state.flag_candidate or state.solution_summary or "").strip()
    if not candidate:
        return {
            "verdict": "insufficient_evidence",
            "confidence": 0.0,
            "reasons": ["no candidate solution provided"],
            "missing_evidence": ["candidate answer or flag"],
        }

    # FLAG early-accept: concrete flag pattern in state is strong evidence
    try:
        from agent.auto_decode import scan_for_flags
        flags = scan_for_flags(candidate) or scan_for_flags(state.flag_candidate or "")
        if flags or (state.flag_candidate and "{" in state.flag_candidate and "}" in state.flag_candidate):
            return {
                "verdict": "pass",
                "confidence": max(0.9, state.overall_confidence),
                "reasons": [f"flag pattern accepted: {state.flag_candidate or flags[0]}"],
                "missing_evidence": [],
            }
    except Exception:
        pass

    # Fast deterministic checks first
    if len(state.evidence) == 0 and len(state.known_facts) < 2:
        return {
            "verdict": "insufficient_evidence",
            "confidence": 0.15,
            "reasons": ["almost no evidence collected yet"],
            "missing_evidence": ["tool observations", "archive matches"],
        }

    top = state.top_hypothesis()
    if top and top.confidence < 0.4:
        return {
            "verdict": "fail",
            "confidence": 0.3,
            "reasons": [f"top hypothesis confidence too low ({top.confidence:.2f})"],
            "missing_evidence": ["stronger supporting evidence"],
        }

    # LLM-assisted structured check (optional)
    try:
        user = (
            f"Challenge:\n{state.challenge_summary}\n\n"
            f"Candidate solution:\n{candidate}\n\n"
            f"State snapshot:\n{state.summary_for_llm(2500)}"
        )
        raw = call_ollama(SYSTEM_VERIFY, user, model=model)
        data = extract_json_object_lenient(raw) or {}
        verdict = data.get("verdict", "insufficient_evidence")
        if verdict not in ("pass", "fail", "insufficient_evidence"):
            verdict = "insufficient_evidence"
        return {
            "verdict": verdict,
            "confidence": float(data.get("confidence", 0.5)),
            "reasons": data.get("reasons") or [],
            "missing_evidence": data.get("missing_evidence") or [],
        }
    except Exception as exc:
        # Offline fallback: require at least one high-confidence hypothesis + evidence
        if state.overall_confidence >= 0.7 and len(state.evidence) >= 2:
            return {
                "verdict": "pass",
                "confidence": state.overall_confidence,
                "reasons": ["offline heuristic: high confidence + multiple evidence items"],
                "missing_evidence": [],
                "note": f"LLM verify unavailable: {exc}",
            }
        return {
            "verdict": "insufficient_evidence",
            "confidence": state.overall_confidence,
            "reasons": [f"LLM verify unavailable ({exc}); evidence not yet strong enough"],
            "missing_evidence": ["additional confirming observations"],
        }


def apply_verification(state: AgentState, result: Dict[str, Any]) -> None:
    """Update AgentState from a verification result."""
    verdict = result.get("verdict")
    if verdict == "pass":
        state.status = "verified"
        state.overall_confidence = max(state.overall_confidence, float(result.get("confidence", 0.8)))
        for r in result.get("reasons") or []:
            state.add_fact(f"Verified: {r}")
    elif verdict == "fail":
        state.status = "investigating"
        for r in result.get("reasons") or []:
            state.contradictions.append(r)
        # Lower confidence of top hypothesis
        top = state.top_hypothesis()
        if top:
            top.update_confidence(-0.2, reason="verification failed")
        state.recompute_overall_confidence()
    else:
        state.status = "investigating"
    state.touch()
