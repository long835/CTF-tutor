"""
agent/offline_ingest.py — offline-first ingestion policy (item 71).

All ingestion paths should call `assert_offline_ok` or respect
`CTF_TUTOR_NETWORK`. This module documents and enforces the policy.
"""

from __future__ import annotations

import os
from typing import Any, Dict


def network_allowed() -> bool:
    return os.getenv("CTF_TUTOR_NETWORK", "0").lower() in ("1", "true", "yes")


def assert_offline_ok(action: str = "ingest") -> None:
    if not network_allowed() and action in ("web_fetch", "online_research"):
        raise RuntimeError(
            f"{action} blocked: set CTF_TUTOR_NETWORK=1 to allow outbound network "
            "(offline-first default)."
        )


def policy() -> Dict[str, Any]:
    return {
        "network_allowed": network_allowed(),
        "online_research": os.getenv("CTF_TUTOR_ONLINE_RESEARCH", "0"),
        "default": "offline",
        "local_sources": ["data/archive", "data/corpus", "skill_graph"],
    }
