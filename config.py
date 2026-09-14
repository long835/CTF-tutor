"""
Shared runtime knobs loaded from the environment / .env.

OLLAMA_* stays in llm_client.py (that's the network client). Everything else
that used to be a magic number scattered across call sites lives here so a
single CTF_TUTOR_MAX_WORKERS setting actually applies everywhere.
"""

import os

from dotenv import load_dotenv

load_dotenv()


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


MAX_WORKERS = _int_env("CTF_TUTOR_MAX_WORKERS", 4)
HISTORY_MAX_ENTRIES = _int_env("CTF_TUTOR_HISTORY_MAX_ENTRIES", 400, minimum=20)
MAX_DECOMPRESSED_SIZE = _int_env("CTF_TUTOR_MAX_DECOMPRESSED_BYTES", 50 * 1024 * 1024, minimum=1024)
EVIDENCE_CHAR_LIMIT = _int_env("CTF_TUTOR_EVIDENCE_CHAR_LIMIT", 1500, minimum=200)
HEURISTIC_MIN_SCORE = _int_env("CTF_TUTOR_HEURISTIC_MIN_SCORE", 2, minimum=1)
