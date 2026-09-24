"""
agent/external_provenance.py — external knowledge provenance (item 70).

Records source tier and licence hints for material brought in from outside
the curated archive. Integrates with agent.provenance when available.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

STORE = Path("data/external_provenance.jsonl")

TIERS = {
    "curated": 5,
    "official-writeup": 4,
    "community-writeup": 3,
    "generated": 2,
    "unknown": 1,
}


def record_external(
    *,
    source_url: str = "",
    source_name: str = "",
    tier: str = "unknown",
    licence: str = "unknown",
    content_hash: str = "",
    note: str = "",
) -> Dict[str, Any]:
    row = {
        "ts": time.time(),
        "source_url": source_url,
        "source_name": source_name,
        "tier": tier,
        "tier_rank": TIERS.get(tier, 1),
        "licence": licence,
        "content_hash": content_hash,
        "note": note,
    }
    STORE.parent.mkdir(parents=True, exist_ok=True)
    with STORE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    return row


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def list_records(limit: int = 50) -> List[Dict[str, Any]]:
    if not STORE.exists():
        return []
    rows: List[Dict[str, Any]] = []
    with STORE.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows[-limit:]
