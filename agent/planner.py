"""
agent/planner.py

Selects the next concrete action given AgentState.

Actions are drawn from a small, safe, local toolkit catalogue.
Dangerous operations (network, unrestricted shell, binary execution)
are never chosen automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from agent.state import AgentState, ActionRecord
from agent.hypothesis import best_next_hypothesis_to_test


@dataclass
class PlannedAction:
    tool: str
    arguments: Dict[str, Any]
    reason: str
    expected_observation: str
    priority: float = 0.5


# Safe, local-only tools the agent is allowed to propose.
# Execution is still gated by the loop / sandbox layer.
SAFE_TOOLS = {
    "static_analysis": {
        "desc": "Run category-aware static analysis on a local file or source",
        "args": ["path", "category_hint"],
    },
    "web_recon": {
        "desc": "Passive web pattern scan (JWT, frameworks, auth markers) on local source",
        "args": ["path"],
    },
    "crypto_toolkit": {
        "desc": "Hash/cipher/RSA pattern detection on local file or text",
        "args": ["path_or_text"],
    },
    "forensics_toolkit": {
        "desc": "Basic forensics signals (magic, strings, metadata hints)",
        "args": ["path"],
    },
    "decode_toolkit": {
        "desc": "Identify and decode common encodings / nested archives safely",
        "args": ["path_or_text"],
    },
    "xor_crack": {
        "desc": "Single/repeating-key XOR recovery on ciphertext bytes/hex",
        "args": ["data", "max_keysize"],
    },
    "auto_decode": {
        "desc": "Ciphey-style layered encoding peel with timeout",
        "args": ["data", "max_depth", "timeout"],
    },
    "gdb_inspect": {
        "desc": "Sandboxed GDB batch inspect/disassemble",
        "args": ["path", "function"],
    },
    "retrieve_archive": {
        "desc": "Query local CTF archive for similar challenges / techniques",
        "args": ["query", "category", "top_k"],
    },
    "classify": {
        "desc": "Re-classify the challenge description",
        "args": ["description"],
    },
    "decompose": {
        "desc": "Break the challenge into sub-problems",
        "args": ["description", "category"],
    },
    "research": {
        "desc": "Search local archive + concepts (+ optional online docs)",
        "args": ["query", "category", "online"],
    },
    "ask_user": {
        "desc": "Request missing file, command output, or clarification from the user",
        "args": ["question"],
    },
    "verify_candidate": {
        "desc": "Check a candidate solution or flag format against known constraints",
        "args": ["candidate", "constraints"],
    },
}


def plan_next_action(state: AgentState) -> Optional[PlannedAction]:
    """
    Deterministic + heuristic planner.
    Prefer tools that can produce evidence for the current top hypothesis.
    """
    if state.step_count >= state.max_steps:
        return None

    # 0. If we have artifacts but have not run static/web/crypto yet, prioritize analysis
    if state.discovered_artifacts:
        ran = {a.tool for a in state.actions}
        src = _guess_source_path(state)
        binary = _guess_binary_path(state)
        cat = (state.category or "").lower()
        if src and "web_recon" not in ran and cat in ("web", ""):
            return PlannedAction(
                tool="web_recon",
                arguments={"path": src},
                reason="Source artifact available — run passive web recon first",
                expected_observation="JWT/framework/auth findings",
                priority=0.92,
            )
        if binary and "static_analysis" not in ran and cat in ("pwn", "rev", ""):
            return PlannedAction(
                tool="static_analysis",
                arguments={"path": binary, "category_hint": cat or "pwn"},
                reason="Binary artifact available — static analysis first",
                expected_observation="checksec/symbols/interesting strings",
                priority=0.92,
            )
        if src and "auto_decode" not in ran and cat in ("crypto", "misc", ""):
            return PlannedAction(
                tool="auto_decode",
                arguments={"path": src, "timeout": 2.0},
                reason="Text/cipher artifact available — layered auto_decode first",
                expected_observation="peeled layers and possible flags",
                priority=0.93,
            )
        if src and "crypto_toolkit" not in ran and cat == "crypto":
            return PlannedAction(
                tool="crypto_toolkit",
                arguments={"path_or_text": src},
                reason="Crypto challenge with file — run crypto toolkit",
                expected_observation="hash/cipher/RSA hints",
                priority=0.9,
            )

    # 1. If we have almost no facts, start with classification / decomposition
    if not state.known_facts and not state.hypotheses:
        return PlannedAction(
            tool="classify",
            arguments={"description": state.challenge_summary},
            reason="No classification yet; establish category first",
            expected_observation="category label and confidence",
            priority=0.95,
        )

    if len(state.hypotheses) == 0:
        return PlannedAction(
            tool="decompose",
            arguments={
                "description": state.challenge_summary,
                "category": state.category or "",
            },
            reason="Need sub-problems and technique seeds before deeper analysis",
            expected_observation="list of sub-problems with likely techniques",
            priority=0.9,
        )

    top = best_next_hypothesis_to_test(state)
    if top is None:
        return PlannedAction(
            tool="retrieve_archive",
            arguments={
                "query": state.challenge_summary[:300],
                "category": state.category or "",
                "top_k": 5,
            },
            reason="No strong hypothesis; look for similar past challenges",
            expected_observation="matching archive entries and techniques",
            priority=0.7,
        )

    tech = (top.technique or "").lower()
    cat = (top.category or state.category or "").lower()

    # Technique / category driven tool selection
    if any(k in tech for k in ("jwt", "sqli", "xss", "ssrf", "ssti", "path-traversal")) or cat == "web":
        path = _guess_source_path(state)
        if path:
            return PlannedAction(
                tool="web_recon",
                arguments={"path": path},
                reason=f"Top hypothesis '{top.statement[:80]}' suggests web patterns",
                expected_observation="JWT/header/auth/framework findings",
                priority=0.85,
            )
        # No file yet — retrieve similar cases or ask user
        if not any(a.tool == "retrieve_archive" for a in state.actions[-3:]):
            return PlannedAction(
                tool="retrieve_archive",
                arguments={"query": top.statement or state.challenge_summary[:200], "category": "web", "top_k": 5},
                reason="Web hypothesis but no source file; search archive for similar JWT/web cases",
                expected_observation="matching archive entries and techniques",
                priority=0.8,
            )

    if any(k in tech for k in ("xor", "rsa", "aes", "hash", "padding", "ecb", "encod")) or cat in ("crypto", "misc"):
        if not any(a.tool == "auto_decode" for a in state.actions[-3:]):
            src = _guess_source_path(state)
            args = {"timeout": 2.0}
            if src:
                args["path"] = src
            else:
                args["data"] = state.challenge_summary
            return PlannedAction(
                tool="auto_decode",
                arguments=args,
                reason="Try fast layered decode before heavier crypto analysis",
                expected_observation="peeled layers and possible flags",
                priority=0.88,
            )
        return PlannedAction(
            tool="crypto_toolkit",
            arguments={"path_or_text": state.challenge_summary},
            reason=f"Crypto-related hypothesis: {top.technique or top.statement[:60]}",
            expected_observation="hash type, cipher mode, key size hints",
            priority=0.85,
        )

    if any(k in tech for k in ("stack", "rop", "format-string", "ret2", "heap")) or cat in ("pwn", "rev"):
        path = _guess_binary_path(state)
        if path:
            return PlannedAction(
                tool="static_analysis",
                arguments={"path": path, "category_hint": cat or "pwn"},
                reason=f"Binary/pwn hypothesis: {top.technique or top.statement[:60]}",
                expected_observation="checksec, symbols, interesting strings or gadgets",
                priority=0.85,
            )
        if not any(a.tool == "retrieve_archive" for a in state.actions[-3:]):
            return PlannedAction(
                tool="retrieve_archive",
                arguments={"query": top.statement or state.challenge_summary[:200], "category": cat or "pwn", "top_k": 5},
                reason="Pwn/rev hypothesis but no binary; search archive",
                expected_observation="matching archive entries",
                priority=0.8,
            )

    if cat in ("forensics", "osint") or "steg" in tech or "pcap" in tech:
        tool = "forensics_toolkit" if cat == "forensics" or "pcap" in tech else "retrieve_archive"
        return PlannedAction(
            tool=tool,
            arguments={"path": _guess_source_path(state)} if tool == "forensics_toolkit"
            else {"query": top.statement, "category": cat, "top_k": 5},
            reason=f"Forensics/OSINT hypothesis: {top.statement[:80]}",
            expected_observation="file magic, metadata, or similar cases",
            priority=0.8,
        )

    # Default: retrieve similar cases then ask user if still stuck
    if not any(a.tool == "retrieve_archive" for a in state.actions[-4:]):
        return PlannedAction(
            tool="retrieve_archive",
            arguments={
                "query": f"{top.statement} {top.technique}".strip(),
                "category": cat,
                "top_k": 5,
            },
            reason="Seek supporting examples from local archive",
            expected_observation="similar challenges and recommended tools",
            priority=0.65,
        )

    binary = _guess_binary_path(state)
    if binary and not any(a.tool == "gdb_inspect" for a in state.actions[-4:]) and cat in ("pwn", "rev"):
        return PlannedAction(
            tool="gdb_inspect",
            arguments={"path": binary},
            reason="Binary present — sandboxed GDB inspection",
            expected_observation="disassembly / symbols",
            priority=0.55,
        )

    if not any(a.tool == "research" for a in state.actions[-5:]):
        return PlannedAction(
            tool="research",
            arguments={
                "query": top.statement or state.challenge_summary[:200],
                "category": cat,
                "online": False,
            },
            reason="Local research on current hypothesis before asking the user",
            expected_observation="archive matches and concept cards",
            priority=0.5,
        )

    return PlannedAction(
        tool="ask_user",
        arguments={
            "question": (
                f"I am investigating: {top.statement}\n"
                f"Please provide the challenge files, relevant command output, "
                f"or any additional observation that would help test this hypothesis."
            )
        },
        reason="Need external evidence the agent cannot produce itself",
        expected_observation="user-supplied file path or tool output",
        priority=0.4,
    )


def _guess_source_path(state: AgentState) -> str:
    for art in state.discovered_artifacts:
        if any(art.endswith(ext) for ext in (".py", ".js", ".php", ".java", ".go", ".rb", ".txt", ".src")):
            return art
    return state.discovered_artifacts[0] if state.discovered_artifacts else ""


def _guess_binary_path(state: AgentState) -> str:
    for art in state.discovered_artifacts:
        if not any(art.endswith(ext) for ext in (".py", ".js", ".php", ".txt", ".md", ".json")):
            return art
    return state.discovered_artifacts[0] if state.discovered_artifacts else ""


def action_to_record(plan: PlannedAction, state: AgentState) -> ActionRecord:
    return state.record_action(
        tool=plan.tool,
        arguments=plan.arguments,
        reason=plan.reason,
        expected=plan.expected_observation,
    )
