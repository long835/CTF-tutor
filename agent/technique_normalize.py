"""Canonical technique IDs at input boundaries."""

from __future__ import annotations

from typing import List

try:
    from agent import taxonomy
except Exception:
    taxonomy = None  # type: ignore


def canonical_technique(name: str) -> str:
    name = (name or "").strip().lower().replace(" ", "-")
    if not name:
        return name
    if taxonomy is not None:
        try:
            return taxonomy.canonical(name)
        except Exception:
            pass
    return name


def canonical_list(names: List[str]) -> List[str]:
    out = []
    seen = set()
    for n in names or []:
        c = canonical_technique(n)
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out
