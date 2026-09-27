"""Cheap local cost/latency micro-benchmark (no network required)."""

from __future__ import annotations

import time
from typing import Any, Dict


def run_microbench(iterations: int = 50) -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge
    from agent.environment_snapshot import environment_snapshot

    samples = [
        "JWT alg none bypass on login API",
        "ELF crashes after 80 bytes of input",
        "PCAP with HTTP response body",
        "RSA small public exponent",
        "Android apk hardcoded key",
    ]
    t0 = time.perf_counter()
    for i in range(iterations):
        classify_challenge(samples[i % len(samples)])
    dt = time.perf_counter() - t0
    env = environment_snapshot()
    return {
        "classify_iterations": iterations,
        "total_seconds": round(dt, 4),
        "per_call_ms": round(1000 * dt / max(iterations, 1), 3),
        "environment": env,
        "note": "Classifier-only microbench; LLM latency not included unless Ollama is timed separately.",
    }
