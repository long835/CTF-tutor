"""Hybrid CTF classifier: deterministic evidence first, optional local LLM second opinion.

The LLM is never allowed to erase artifact evidence or manufacture verification.
It is used only as a bounded semantic second opinion for ambiguous/low-confidence
cases. Enable with CTF_TUTOR_LLM_CLASSIFY=1; Ollama remains local by design.
"""
from __future__ import annotations
import json, os, re
from typing import Any, Dict

CATEGORIES = {"web","pwn","crypto","rev","forensics","osint","blockchain","mobile","misc"}

def _ask_llm(description: str, model: str | None = None) -> Dict[str, Any]:
    from llm_client import call_ollama, DEFAULT_MODEL
    prompt = """Classify this CTF challenge. Return JSON only:
{"category":"web|pwn|crypto|rev|forensics|osint|blockchain|mobile|misc",
 "confidence":0.0,
 "alternatives":["..."],
 "evidence":["short observable clues"]}.
Do not invent artifacts. If evidence is insufficient, use misc with low confidence.
Challenge:
""" + description[:4000]
    raw = call_ollama("You are a cautious CTF taxonomy classifier.", prompt, model=model or DEFAULT_MODEL)
    try:
        start, end = raw.find("{"), raw.rfind("}")
        obj = json.loads(raw[start:end+1])
        cat = str(obj.get("category","")).lower().strip()
        if cat not in CATEGORIES:
            raise ValueError("invalid category")
        conf = max(0.0, min(1.0, float(obj.get("confidence", 0.0))))
        return {"ok": True, "category": cat, "confidence": conf,
                "alternatives": [x for x in obj.get("alternatives",[]) if str(x) in CATEGORIES][:3],
                "evidence": [str(x)[:240] for x in obj.get("evidence",[])][:5],
                "raw": raw[:1000]}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "raw": raw[:1000]}

def classify_enhanced(
    description: str = "",
    artifacts=None,
    inventory=None,
    content_sample: str = "",
    *,
    use_llm: bool | None = None,
    model: str | None = None,
) -> Any:
    from agent.classify_challenge import classify_challenge
    profile = classify_challenge(description, artifacts=artifacts, inventory=inventory, content_sample=content_sample)
    enabled = (os.getenv("CTF_TUTOR_LLM_CLASSIFY","0").lower() in {"1","true","yes","on"}) if use_llm is None else use_llm
    if not enabled or not (profile.unknown or profile.ambiguous or profile.confidence < 0.45):
        return profile
    try:
        llm = _ask_llm(description, model=model)
    except Exception as exc:
        profile.notes.append(f"LLM second opinion unavailable: {type(exc).__name__}")
        return profile
    profile.llm_opinion = llm
    # Strong artifact evidence remains authoritative. Otherwise a high-quality
    # semantic opinion can replace a weak guess, but ambiguity is retained.
    artifact_sources = [s for s in profile.signals if s.source == "artifact" and s.weight >= 2.5]
    if llm.get("ok") and llm["confidence"] >= 0.75 and not artifact_sources:
        old = profile.category
        profile.category = profile.primary_category = llm["category"]
        profile.confidence = min(0.85, max(profile.confidence, 0.5 + 0.35 * llm["confidence"]))
        profile.ambiguous = profile.confidence < 0.70
        profile.notes.append(f"local LLM second opinion selected {llm['category']} over weak heuristic {old}")
    else:
        profile.notes.append("local LLM second opinion retained as supporting evidence only")
    return profile
