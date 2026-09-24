"""
agent/resource_concurrency.py — resource-aware concurrency (item 28).

Caps worker count by model tier / RAM hints so a tiny laptop does not
spawn more parallel Ollama calls than it can feed.
"""

from __future__ import annotations

import os
from typing import Callable, List, Optional, TypeVar

from agent.model_profile import ModelTier, get_profile

T = TypeVar("T")
R = TypeVar("R")


def recommended_workers(model: Optional[str] = None, requested: Optional[int] = None) -> int:
    env_cap = int(os.getenv("CTF_TUTOR_MAX_WORKERS", "4"))
    profile = get_profile(model)
    tier_cap = {
        ModelTier.TINY: 1,
        ModelTier.SMALL: 2,
        ModelTier.MEDIUM: 3,
        ModelTier.LARGE: 4,
        ModelTier.FRONTIER: 6,
    }.get(profile.tier, 2)
    hard = min(env_cap, tier_cap)
    if requested is not None:
        return max(1, min(requested, hard))
    return max(1, hard)


def map_concurrent(
    func: Callable[[T], R],
    items: List[T],
    *,
    model: Optional[str] = None,
    max_workers: Optional[int] = None,
) -> List[R]:
    from concurrent.futures import ThreadPoolExecutor

    if len(items) <= 1:
        return [func(x) for x in items]
    workers = recommended_workers(model, max_workers)
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(func, items))
