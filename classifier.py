"""
classifier.py

Guesses a challenge's category (web / pwn / crypto / rev / forensics / misc)
from its description text when the user doesn't specify one with
--category. Used by main.py to fill in `category` before it's passed to
decomposer.decompose() and retriever.query_sub_problem() -- both use it to
narrow static analysis and archive retrieval, so an unclassified challenge
currently gets the least helpful, most generic treatment (no checksec, no
category filter). Better classification means more of the archive/tooling
actually kicks in automatically.

Two-tier approach:
1. A fast, free, deterministic keyword-overlap heuristic (classify_heuristic)
   -- no LLM call, no network, works offline, and is what the tests exercise
   directly since it's deterministic.
2. classify() calls the heuristic first; if it's confident (a clear
   category has meaningfully more keyword hits than the runner-up), that's
   used directly with zero LLM cost. Only genuinely ambiguous descriptions
   fall through to an LLM call for a second opinion -- cheap in the common
   case, still gets model judgment for the hard cases.
"""

import re
from typing import Dict, List, Optional, Tuple

from llm_client import call_ollama, extract_json_object_lenient, DEFAULT_MODEL

CATEGORIES = ["web", "pwn", "crypto", "rev", "forensics", "misc"]

# Keyword -> category. Deliberately biased toward terms that are strong,
# near-unambiguous signals rather than broad/generic words, to keep false
# positives low.
_KEYWORDS: Dict[str, List[str]] = {
    "web": [
        "http", "https", "cookie", "session", "jwt", "sql injection", "sqli",
        "xss", "csrf", "ssrf", "login", "website", "web app", "endpoint",
        "api", "flask", "django", "php", "html", "browser", "url", "request",
        "response header", "burp", "cors", "admin panel",
    ],
    "pwn": [
        "buffer overflow", "stack overflow", "shellcode", "rop", "ret2libc",
        "ret2win", "canary", "nx", "aslr", "gets(", "strcpy", "format string",
        "segfault", "heap overflow", "use-after-free", "double free", "gdb",
        "pwntools", "libc", "exploit the binary", "got overwrite",
    ],
    "crypto": [
        "cipher", "encrypt", "decrypt", "rsa", "aes", "xor cipher", "hash",
        "md5", "sha", "public key", "private key", "modulus", "prime",
        "padding oracle", "ecb", "cbc", "nonce", "signature forgery",
        "elliptic curve",
    ],
    "rev": [
        "reverse engineer", "disassemble", "decompile", "ida", "ghidra",
        "crackme", "keygen", "license key", "obfuscat", "binary analysis",
        "assembly", "opcodes", "control flow", ".apk", "firmware",
    ],
    "forensics": [
        "pcap", "wireshark", "memory dump", "disk image", "steganography",
        "stego", "exif", "hidden file", "file carving", "volatility",
        "network capture", "log file", "artifact", "metadata",
    ],
}


def classify_heuristic(description: str) -> Tuple[Optional[str], Dict[str, int]]:
    """
    Score each category by counting keyword occurrences in the description
    (case-insensitive). Returns (best_category_or_None, scores). Returns
    None for best_category when there are no hits at all, or when the top
    two categories are tied -- an ambiguous heuristic result should defer
    to the LLM rather than confidently guess wrong.
    """
    text = description.lower()
    scores = {cat: 0 for cat in CATEGORIES if cat != "misc"}
    for cat, keywords in _KEYWORDS.items():
        for kw in keywords:
            scores[cat] += len(re.findall(re.escape(kw), text))

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_cat, top_score = ranked[0]
    runner_up_score = ranked[1][1] if len(ranked) > 1 else 0

    if top_score == 0 or top_score == runner_up_score:
        return None, scores
    return top_cat, scores


CLASSIFY_SYSTEM_PROMPT = """You are classifying a CTF challenge description \
into exactly one category. Respond ONLY with a JSON object with keys:
category (one of: web, pwn, crypto, rev, forensics, misc -- use misc only \
if truly none of the others fit), confidence (one of: low, medium, high)
"""


def classify(description: str, model: str = DEFAULT_MODEL) -> str:
    """
    Best-effort category guess: try the free heuristic first, only fall
    back to an LLM call when the heuristic is ambiguous (no clear winner).
    Always returns one of CATEGORIES -- never raises, since a wrong guess
    just means slightly less-targeted retrieval/static-analysis, not a
    broken run, so "misc" is a safe fallback for a genuinely-unclear case.
    """
    heuristic_result, _scores = classify_heuristic(description)
    if heuristic_result is not None:
        return heuristic_result

    raw = call_ollama(CLASSIFY_SYSTEM_PROMPT, f"Challenge description:\n{description}", model=model)
    parsed = extract_json_object_lenient(raw, fallback_key="category")
    category = str(parsed.get("category", "misc")).strip().lower()
    return category if category in CATEGORIES else "misc"
