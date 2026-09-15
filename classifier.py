"""
classifier.py

Guesses a challenge's category from its description when the user doesn't
specify one with --category.

Two-tier approach:
1. classify_heuristic -- keyword overlap, no LLM.
2. classify() uses the heuristic only when it is clearly ahead of the
   runner-up AND has at least HEURISTIC_MIN_SCORE hits (default 2). A
   one-keyword coincidence is not treated as confident.
"""

import re
from typing import Dict, List, Optional, Tuple

from config import HEURISTIC_MIN_SCORE
from llm_client import call_ollama, extract_json_object_lenient, DEFAULT_MODEL

CATEGORIES = [
    "web", "pwn", "crypto", "rev", "forensics", "osint",
    "blockchain", "mobile", "misc",
]

_KEYWORDS: Dict[str, List[str]] = {
    "web": [
        "http", "https", "cookie", "session", "jwt", "sql injection", "sqli",
        "xss", "csrf", "ssrf", "login", "website", "web app", "endpoint",
        "api", "flask", "django", "php", "html", "browser", "url", "request",
        "response header", "burp", "cors", "admin panel",
    ],
    "pwn": [
        "buffer overflow", "stack overflow", "shellcode", "rop", "ret2libc",
        "ret2win", "canary", "nx", "aslr", "gets(", "strcpy", "format string", "format-string", "printf(user)",
        "segfault", "heap overflow", "use-after-free", "double free", "gdb",
        "pwntools", "libc", "exploit the binary", "got overwrite",
        "unsafe rust", "rust binary",
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
        "assembly", "opcodes", "control flow", "ilspy", "dnspy", "javap",
    ],
    "forensics": [
        "pcap", "wireshark", "memory dump", "disk image", "steganography", "stego", "lsb",
        "stego", "exif", "hidden file", "file carving", "volatility",
        "network capture", "log file", "artifact",
    ],
    "osint": [
        "geolocate", "geolocation", "reverse image", "social media",
        "username", "public record", "whois", "shodan", "google dork",
        "open source intelligence",
    ],
    "blockchain": [
        "smart contract", "solidity", "wallet", "gas", "web3", "ethereum",
        "reentrancy", "erc20", "blockchain", "ether",
    ],
    "mobile": [
        "android", "apk", "ios", "ipa", "mobile app", "frida", "jadx",
        "exported activity", "shared preferences", "keystore",
    ],
}


def classify_heuristic(description: str) -> Tuple[Optional[str], Dict[str, int]]:
    """
    Score each category by counting keyword occurrences. Returns
    (best_category_or_None, scores). None when there are no hits, the top
    two categories are tied, or the winning score is below the confidence
    floor (a single coincidental keyword is not enough).
    """
    text = description.lower()
    scores = {cat: 0 for cat in CATEGORIES if cat != "misc"}
    for cat, keywords in _KEYWORDS.items():
        for kw in keywords:
            scores[cat] += len(re.findall(re.escape(kw), text))

    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    top_cat, top_score = ranked[0]
    runner_up_score = ranked[1][1] if len(ranked) > 1 else 0

    if top_score < HEURISTIC_MIN_SCORE or top_score == runner_up_score:
        return None, scores
    return top_cat, scores


CLASSIFY_SYSTEM_PROMPT = """You are classifying a CTF challenge description \
into exactly one category. Respond ONLY with a JSON object with keys:
category (one of: web, pwn, crypto, rev, forensics, osint, blockchain, \
mobile, misc -- use misc only if truly none of the others fit), \
confidence (one of: low, medium, high)
"""


def classify(description: str, model: str = DEFAULT_MODEL) -> str:
    heuristic_result, _scores = classify_heuristic(description)
    if heuristic_result is not None:
        return heuristic_result

    raw = call_ollama(CLASSIFY_SYSTEM_PROMPT, f"Challenge description:\n{description}", model=model)
    parsed = extract_json_object_lenient(raw, fallback_key="category")
    category = str(parsed.get("category", "misc")).strip().lower()
    return category if category in CATEGORIES else "misc"
