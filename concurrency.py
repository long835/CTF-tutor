"""
concurrency.py

One tiny helper used by main.py/explainer.py/depth_guide.py to run
independent, blocking, I/O-bound calls (each sub-problem's Ollama request)
concurrently instead of one-at-a-time in a for loop.

Why threads and not asyncio: every call in this codebase goes through
`requests`, which is synchronous. `requests` releases the GIL while
waiting on the socket, so a thread pool genuinely overlaps the waiting
time for multiple in-flight HTTP requests -- no need to rewrite the whole
call chain onto an async HTTP client for that benefit.

Honest caveat: the actual speedup on a single local Ollama instance
depends on OLLAMA_NUM_PARALLEL (Ollama's own concurrent-request setting,
not this codebase's). If your Ollama server processes one request at a
time, these calls still queue there -- concurrency here mainly removes
Python-side serialization overhead and lets them queue immediately rather
than waiting for the full round trip (network + generation) of the
previous one before even being sent. It also helps a lot for calls to
different services (e.g. embeddings hitting chromadb while a chat call is
in flight to Ollama).
"""

from config import MAX_WORKERS
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, List, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def map_concurrent(func: Callable[[T], R], items: List[T], max_workers: int = None) -> List[R]:
    """
    Apply func to every item concurrently, returning results in the same
    order as `items`. Default worker count is CTF_TUTOR_MAX_WORKERS (env).
    """
    workers = MAX_WORKERS if max_workers is None else max_workers
    if len(items) <= 1:
        return [func(item) for item in items]

    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as executor:
        return list(executor.map(func, items))
