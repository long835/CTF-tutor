"""
agent/permissions.py

Capability levels for tools.

READ_ONLY       — inspect local files / archive only
ANALYSIS        — run passive local analysis toolkits
SANDBOX_EXEC    — subprocess under resource limits (still no network)
FULL_APPROVAL   — requires explicit user confirmation (not auto-run)
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class Permission(str, Enum):
    READ_ONLY = "read_only"
    ANALYSIS = "analysis"
    SANDBOX_EXEC = "sandbox_exec"
    FULL_APPROVAL = "full_approval"


# Default capability required per tool
TOOL_PERMISSIONS: Dict[str, Permission] = {
    "classify": Permission.READ_ONLY,
    "decompose": Permission.READ_ONLY,
    "retrieve_archive": Permission.READ_ONLY,
    "web_recon": Permission.ANALYSIS,
    "crypto_toolkit": Permission.ANALYSIS,
    "forensics_toolkit": Permission.ANALYSIS,
    "decode_toolkit": Permission.ANALYSIS,
    "static_analysis": Permission.ANALYSIS,
    "xor_crack": Permission.ANALYSIS,
    "verify_candidate": Permission.READ_ONLY,
    "ask_user": Permission.READ_ONLY,
    "research": Permission.READ_ONLY,
    "auto_decode": Permission.ANALYSIS,
    "gdb_inspect": Permission.SANDBOX_EXEC,
    "platform_ctfd": Permission.READ_ONLY,
    "platform_htb": Permission.READ_ONLY,
    # Future dynamic tools would be SANDBOX_EXEC or FULL_APPROVAL
    "run_binary": Permission.FULL_APPROVAL,
    "network_request": Permission.FULL_APPROVAL,
}


# Session policy: maximum permission the agent may exercise without prompting
def _default_max():
    import os
    raw = os.getenv("CTF_TUTOR_MAX_PERMISSION", "sandbox_exec").lower()
    for p in Permission:
        if p.value == raw:
            return p
    return Permission.SANDBOX_EXEC

DEFAULT_MAX_PERMISSION = _default_max()

_ORDER = [
    Permission.READ_ONLY,
    Permission.ANALYSIS,
    Permission.SANDBOX_EXEC,
    Permission.FULL_APPROVAL,
]


def allowed(tool: str, max_permission: Permission = DEFAULT_MAX_PERMISSION) -> bool:
    need = TOOL_PERMISSIONS.get(tool, Permission.FULL_APPROVAL)
    return _ORDER.index(need) <= _ORDER.index(max_permission)


def required_permission(tool: str) -> Permission:
    return TOOL_PERMISSIONS.get(tool, Permission.FULL_APPROVAL)
