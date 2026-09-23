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
    graph: Any = None,
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

    # FLAG gate (items 62/63). This used to be an early-accept: anything
    # flag-shaped returned pass at 0.9. A CTF is full of flag-shaped strings
    # that are not the flag — the README example, the decoy in .git, the
    # format hint in the description, a retrieved writeup. The candidate now
    # has to have come out of a tool that looked at *this* challenge, survive
    # the decoy checks, and satisfy any format the challenge stated.
    try:
        from agent.flag_check import FlagVerdict, best_candidate, check_flag

        check = check_flag(candidate, state=state)
        if check.verdict is FlagVerdict.REJECTED and not check.sources:
            # Not flag-shaped at all: fall through to the normal solution path.
            check = None
        if check is None:
            pass
        elif check.acceptable:
            return {
                "verdict": "pass",
                "confidence": check.confidence,
                "reasons": check.reasons,
                "missing_evidence": [],
                "flag_check": check.to_dict(),
            }
        elif check.verdict is FlagVerdict.DECOY:
            alternative = best_candidate(state)
            reasons = [f"candidate looks planted: {'; '.join(check.reasons)}"]
            if alternative is not None and alternative.candidate != check.candidate:
                reasons.append(f"a better candidate exists: {alternative.candidate} "
                               f"({alternative.verdict.value})")
            return {
                "verdict": "fail",
                "confidence": 0.1,
                "reasons": reasons,
                "missing_evidence": ["the real flag, observed by a tool"],
                "flag_check": check.to_dict(),
            }
        elif check.verdict in (FlagVerdict.FORMAT_ONLY, FlagVerdict.PLAUSIBLE):
            return {
                "verdict": "insufficient_evidence",
                "confidence": check.confidence,
                "reasons": check.reasons + check.warnings,
                "missing_evidence": (
                    ["a tool observation containing this string"]
                    if check.verdict is FlagVerdict.FORMAT_ONLY
                    else ["independent reproduction, or elimination of the competing "
                          "candidates"]
                ),
                "flag_check": check.to_dict(),
            }
    except Exception:
        pass

    # Evidence-requirement gate (item 5): before asking any model, check
    # whether the observations a claim of this kind REQUIRES are present.
    # A model that sounds sure is not a substitute for the signal itself.
    assessment = None
    try:
        from agent.evidence import SupportLevel, assess_state, next_evidence_to_seek

        assessment = assess_state(state)
        if assessment.level is SupportLevel.REFUTED:
            return {
                "verdict": "fail",
                "confidence": 0.1,
                "reasons": [
                    f"evidence contradicts {assessment.technique}: "
                    f"{', '.join(assessment.matched_contradicting)}"
                ],
                "missing_evidence": [],
                "evidence_assessment": assessment.to_dict(),
            }
        if assessment.level is SupportLevel.INSUFFICIENT_EVIDENCE and assessment.missing_required:
            return {
                "verdict": "insufficient_evidence",
                "confidence": assessment.confidence,
                "reasons": [f"required observations for {assessment.technique} not collected"],
                "missing_evidence": next_evidence_to_seek(assessment),
                "evidence_assessment": assessment.to_dict(),
            }
    except Exception:
        assessment = None

    # Graph gate. The graph knows which observation supports the claim and
    # which tool produced it, so it catches two things the text rubric
    # cannot: a required signal that is only "present" because a retrieval
    # card mentioned it, and support that rests entirely on one tool.
    graph_support = None
    if graph is not None:
        try:
            from agent.evidence import SupportLevel as _SL

            top_h = state.top_hypothesis()
            technique = (getattr(top_h, "technique", "") or "") if top_h else ""
            if technique:
                graph_support = graph.assess_technique(technique)
                if graph_support.level is _SL.REFUTED:
                    return {
                        "verdict": "fail",
                        "confidence": 0.1,
                        "reasons": [f"evidence graph refutes {technique}"],
                        "missing_evidence": [],
                        "graph_support": graph_support.to_dict(),
                    }
                if graph_support.gaps:
                    return {
                        "verdict": "insufficient_evidence",
                        "confidence": min(0.4, graph_support.score),
                        "reasons": [
                            f"no observation yet supports {len(graph_support.gaps)} "
                            f"signal(s) that {technique} requires"
                        ],
                        "missing_evidence": list(graph_support.gaps),
                        "graph_support": graph_support.to_dict(),
                    }
        except Exception:
            graph_support = None

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

        # Small local models rarely return clean JSON; repair rather than
        # discard, and fall back to the lenient extractor if that fails.
        try:
            from agent.structured import VERIFY_SCHEMA, parse_structured

            parsed = parse_structured(raw, VERIFY_SCHEMA)
            data = parsed.data if parsed.ok else (extract_json_object_lenient(raw) or {})
            parse_method = parsed.method
        except Exception:
            data = extract_json_object_lenient(raw) or {}
            parse_method = "lenient"

        verdict = data.get("verdict", "insufficient_evidence")
        if verdict not in ("pass", "fail", "insufficient_evidence"):
            verdict = "insufficient_evidence"
        confidence = float(data.get("confidence", 0.5) or 0.5)

        # The model may lower a verdict but never raise one above what the
        # evidence supports. This is the difference between a verifier and
        # a second opinion.
        if verdict == "pass" and assessment is not None:
            from agent.evidence import SupportLevel

            if assessment.level in (SupportLevel.INSUFFICIENT_EVIDENCE, SupportLevel.UNCERTAIN):
                return {
                    "verdict": "insufficient_evidence",
                    "confidence": min(confidence, assessment.confidence),
                    "reasons": [
                        "model reported pass, but the required observations for "
                        f"{assessment.technique} are not all present"
                    ],
                    "missing_evidence": assessment.missing_required,
                    "evidence_assessment": assessment.to_dict(),
                    "parse_method": parse_method,
                }
            confidence = min(confidence, assessment.confidence + 0.2)

        result = {
            "verdict": verdict,
            "confidence": confidence,
            "reasons": data.get("reasons") or [],
            "missing_evidence": data.get("missing_evidence") or [],
            "parse_method": parse_method,
        }
        if assessment is not None:
            result["evidence_assessment"] = assessment.to_dict()
        return result
    except Exception as exc:
        # Offline fallback. This is the default path for a local-first
        # install, so it gets the same evidence gate as the model path: a
        # high confidence number and a pile of evidence items are not a
        # verification, and treating them as one is how the agent ends up
        # asserting a technique whose required observations it never made.
        from agent.evidence import SupportLevel as _SupportLevel

        supported = assessment is not None and assessment.level in (
            _SupportLevel.SUPPORTED, _SupportLevel.LIKELY,
        )
        graph_ok = graph_support is None or not graph_support.gaps
        if supported and graph_ok and state.overall_confidence >= 0.7 and len(state.evidence) >= 2:
            result = {
                "verdict": "pass",
                "confidence": min(state.overall_confidence, assessment.confidence + 0.2),
                "reasons": [
                    f"offline: required observations for {assessment.technique} are present "
                    f"({', '.join(assessment.matched_required[:3])})"
                ],
                "missing_evidence": [],
                "note": f"LLM verify unavailable: {exc}",
                "evidence_assessment": assessment.to_dict(),
            }
            if graph_support is not None:
                result["graph_support"] = graph_support.to_dict()
                if graph_support.caveat:
                    result["reasons"].append(graph_support.caveat)
            return result
        if assessment is not None and not supported:
            return {
                "verdict": "insufficient_evidence",
                "confidence": min(state.overall_confidence, assessment.confidence),
                "reasons": [
                    f"LLM verify unavailable ({exc}); evidence for "
                    f"{assessment.technique} is only '{assessment.level.value}'"
                ],
                "missing_evidence": list(assessment.missing_required)
                                    or ["additional confirming observations"],
                "evidence_assessment": assessment.to_dict(),
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
