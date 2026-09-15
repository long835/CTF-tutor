"""
agent/tools_registry.py

Plugin-style registry of agent tools.

New toolkits register here instead of hardcoding every branch in the executor.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from agent.permissions import Permission, TOOL_PERMISSIONS


@dataclass
class ToolSpec:
    name: str
    description: str
    permission: Permission
    handler: Callable[[Dict[str, Any]], tuple]  # returns (ok, output, error)
    category_tags: List[str]


_REGISTRY: Dict[str, ToolSpec] = {}


def register(
    name: str,
    handler: Callable[[Dict[str, Any]], tuple],
    description: str = "",
    permission: Optional[Permission] = None,
    category_tags: Optional[List[str]] = None,
) -> None:
    perm = permission or TOOL_PERMISSIONS.get(name, Permission.FULL_APPROVAL)
    _REGISTRY[name] = ToolSpec(
        name=name,
        description=description,
        permission=perm,
        handler=handler,
        category_tags=category_tags or [],
    )


def get(name: str) -> Optional[ToolSpec]:
    return _REGISTRY.get(name)


def list_tools() -> List[ToolSpec]:
    return list(_REGISTRY.values())


def run_tool(name: str, args: Dict[str, Any]) -> tuple:
    spec = _REGISTRY.get(name)
    if not spec:
        return False, "", f"tool not registered: {name}"
    return spec.handler(args)


def _register_builtins() -> None:
    """Bind existing executor helpers into the registry once."""
    if _REGISTRY:
        return
    from agent import executor as ex

    mapping = {
        "classify": (ex._run_classify, "Heuristic/LLM category classification", ["all"]),
        "decompose": (ex._run_decompose, "Break challenge into sub-problems", ["all"]),
        "retrieve_archive": (ex._run_retrieve, "Hybrid archive search", ["all"]),
        "static_analysis": (ex._run_static, "Binary/source static analysis", ["pwn", "rev"]),
        "web_recon": (ex._run_web_recon, "Passive web pattern scan", ["web"]),
        "crypto_toolkit": (ex._run_crypto, "Crypto pattern detection", ["crypto"]),
        "forensics_toolkit": (ex._run_forensics, "Forensics signals", ["forensics"]),
        "decode_toolkit": (ex._run_decode, "Encoding/archive decode", ["misc", "forensics"]),
        "xor_crack": (ex._run_xor, "XOR key recovery", ["crypto"]),
        "verify_candidate": (ex._run_verify, "Candidate solution checks", ["all"]),
    }
    for name, (fn, desc, tags) in mapping.items():
        register(name, fn, description=desc, category_tags=tags)

    def _ask_user(args: Dict[str, Any]) -> tuple:
        q = args.get("question", "Please provide more information.")
        return True, f"USER_QUESTION: {q}", ""

    register("ask_user", _ask_user, description="Ask the learner for input", category_tags=["all"])


_register_builtins()
