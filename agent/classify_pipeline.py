"""Single classification entry: evidence → heuristic → optional LLM → arbitration → calibrate.

LLM is an *additional evidence source*, never a silent replacement for deterministic signals.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _artifact_strong(profile: Any) -> bool:
    kinds = list(getattr(profile, "artifact_kinds", None) or [])
    if not kinds:
        return False
    # Binary/pcap/image etc. are stronger than prose alone
    strong_kinds = {"elf", "pe", "binary", "pcap", "image", "apk", "solidity"}
    return any(str(k).lower() in strong_kinds for k in kinds)


def _signal_sources(profile: Any) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for s in getattr(profile, "signals", None) or []:
        src = getattr(s, "source", None) or (s.get("source") if isinstance(s, dict) else "unknown")
        counts[str(src)] = counts.get(str(src), 0) + 1
    return counts


def arbitrate(
    heuristic: Any,
    llm: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Combine heuristic profile + optional LLM opinion without erasing artifacts."""
    h_cat = getattr(heuristic, "category", "misc")
    h_conf = float(getattr(heuristic, "confidence", 0.0) or 0.0)
    decision = getattr(heuristic, "decision", "commit")
    unknown = bool(getattr(heuristic, "unknown", False))
    artifact_strong = _artifact_strong(heuristic)
    sources = _signal_sources(heuristic)

    result = {
        "category": h_cat,
        "belief_score": h_conf,
        "decision": decision,
        "unknown": unknown,
        "artifact_strong": artifact_strong,
        "sources": sources,
        "llm_used": False,
        "llm_opinion": None,
        "arbitration": "heuristic_only",
        "reasoning_source": "heuristic",
    }

    # Strong artifact evidence: LLM may annotate but not override category
    if artifact_strong and h_conf >= 0.45 and decision == "commit":
        result["arbitration"] = "artifact_authoritative"
        if llm and llm.get("ok"):
            result["llm_used"] = True
            result["llm_opinion"] = {
                "category": llm.get("category"),
                "confidence": llm.get("confidence"),
            }
            if llm.get("category") != h_cat:
                result["notes"] = [
                    f"LLM suggested {llm.get('category')} but artifacts keep {h_cat}"
                ]
        return result

    # Weak / abstain / unknown: allow LLM as secondary evidence
    if llm and llm.get("ok"):
        result["llm_used"] = True
        result["llm_opinion"] = {
            "category": llm.get("category"),
            "confidence": llm.get("confidence"),
            "evidence": llm.get("evidence"),
        }
        l_cat = llm.get("category")
        l_conf = float(llm.get("confidence") or 0.0)
        if decision in ("abstain", "unknown") or h_conf < 0.45 or unknown:
            if l_cat and l_conf >= 0.55 and (l_conf > h_conf + 0.1):
                result["category"] = l_cat
                result["belief_score"] = min(0.75, (h_conf + l_conf) / 2)
                result["decision"] = "commit" if l_conf >= 0.6 else "abstain"
                result["unknown"] = False
                result["arbitration"] = "llm_secondary_promoted"
                result["reasoning_source"] = "heuristic+llm"
            else:
                result["arbitration"] = "llm_consulted_no_override"
                result["reasoning_source"] = "heuristic+llm"
        else:
            result["arbitration"] = "heuristic_preferred"
            result["reasoning_source"] = "heuristic+llm"
    return result


def classify_pipeline(
    description: str = "",
    artifacts=None,
    inventory=None,
    content_sample: str = "",
    *,
    use_llm: bool | None = None,
) -> Dict[str, Any]:
    """Full pipeline returning a dict suitable for agent state + teaching."""
    import os

    from agent.classify_challenge import classify_challenge
    from agent.active_classify import suggest_discriminators
    from agent.calibration_fit import present_with_calibration

    profile = classify_challenge(
        description,
        artifacts=artifacts,
        inventory=inventory,
        content_sample=content_sample,
    )

    llm = None
    enabled = (
        os.getenv("CTF_TUTOR_LLM_CLASSIFY", "0").lower() in {"1", "true", "yes", "on"}
        if use_llm is None
        else use_llm
    )
    if enabled and (
        getattr(profile, "unknown", False)
        or getattr(profile, "ambiguous", False)
        or float(getattr(profile, "confidence", 0) or 0) < 0.45
        or getattr(profile, "decision", "commit") in ("abstain", "unknown")
    ):
        try:
            from agent.ensemble import _ask_llm

            llm = _ask_llm(description)
        except Exception as e:
            llm = {"ok": False, "error": str(e)}

    arb = arbitrate(profile, llm)
    cal = present_with_calibration(arb["belief_score"])
    arb.update(cal)
    arb["profile"] = profile.to_dict() if hasattr(profile, "to_dict") else {}
    arb["discriminators"] = suggest_discriminators(profile)
    arb["secondary_categories"] = list(
        getattr(profile, "secondary_categories", None) or []
    )
    return arb
