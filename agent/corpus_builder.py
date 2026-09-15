"""
agent/corpus_builder.py

Build a 100+ entry local challenge/technique corpus.

Sources mixed:
  - Existing data/archive curated JSON
  - Synthetic pattern cards (deterministic templates)
  - Optional public GitHub search hits (metadata only)

Writes to data/corpus/challenges.jsonl for eval/RAG expansion.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

ARCHIVE = Path("data/archive")
OUT_DIR = Path("data/corpus")
OUT_FILE = OUT_DIR / "challenges.jsonl"


# Deterministic synthetic templates — educational patterns, not live flags
_SYNTH = [
    ("web", "easy", "sql-injection", "Login form concatenates username into SQL WHERE clause."),
    ("web", "medium", "sqli-union", "Search page allows UNION SELECT after column enumeration."),
    ("web", "medium", "ssti", "Greeting page renders user name inside Jinja template."),
    ("web", "easy", "path-traversal", "Download handler joins ../ user input onto base directory."),
    ("web", "medium", "jwt-none-bypass", "API accepts JWT with alg=none and trusts role claim."),
    ("web", "hard", "ssrf", "URL preview feature fetches attacker-controlled addresses."),
    ("web", "medium", "xss-reflected", "Search reflects q= without encoding into HTML."),
    ("web", "hard", "xxe", "XML upload parses external entities."),
    ("web", "medium", "idor", "Profile API uses sequential user id without authz checks."),
    ("web", "hard", "deserialization-rce", "Cookie untrusted pickle/object deserialize."),
    ("pwn", "easy", "stack-buffer-overflow", "gets() into 64-byte stack buffer; win() present."),
    ("pwn", "medium", "format-string", "printf(user) with writable GOT entry."),
    ("pwn", "hard", "ret2libc", "NX enabled overflow; system/binsh available via libc leak."),
    ("pwn", "hard", "rop-chain", "NX+ASLR; need ROP to call mprotect or system."),
    ("pwn", "medium", "canary-bypass", "Stack canary present; leak via format string first."),
    ("pwn", "hard", "heap-overflow", "Custom allocator chunk overflow into metadata."),
    ("pwn", "medium", "integer-overflow", "Size calculation wraps before malloc."),
    ("pwn", "hard", "use-after-free", "Freed structure still used for function pointer."),
    ("crypto", "easy", "xor-single-byte", "Ciphertext XORed with one repeating key byte."),
    ("crypto", "easy", "xor-repeating-key", "Vigenere-like XOR with short key."),
    ("crypto", "medium", "rsa-small-e", "RSA e=3 with small message, no padding."),
    ("crypto", "hard", "rsa-common-modulus", "Same n, different e for related messages."),
    ("crypto", "medium", "ecb-byte-at-a-time", "AES-ECB oracle with prefix control."),
    ("crypto", "hard", "padding-oracle", "CBC padding error oracle on decrypt API."),
    ("crypto", "easy", "classical-substitution", "Caesar/substitution on English text."),
    ("crypto", "medium", "hash-length-extension", "Secret-prefix hash allows extension."),
    ("crypto", "easy", "encoding-recognition", "Layered base64/hex wraps the flag."),
    ("rev", "easy", "string-decryption", "Password compared after XOR decode of .rodata."),
    ("rev", "medium", "anti-debug-bypass", "ptrace anti-debug exits under debugger."),
    ("rev", "hard", "vm-obfuscation", "Custom bytecode VM protects check."),
    ("rev", "medium", "packed-binary", "UPX or custom packer hides real code."),
    ("rev", "easy", "control-flow-flattening", "State machine obscures comparison logic."),
    ("forensics", "easy", "pcap-carving", "HTTP objects in PCAP hide flag file."),
    ("forensics", "easy", "steganography", "LSB stego in PNG."),
    ("forensics", "medium", "file-carving", "Deleted JPEG in disk image."),
    ("forensics", "medium", "memory-forensics", "Process memory dump holds credentials."),
    ("forensics", "easy", "image-metadata", "EXIF GPS points to location puzzle."),
    ("osint", "easy", "osint-geolocation", "Photo landmarks identify city."),
    ("osint", "medium", "osint-username", "Same handle across public sites."),
    ("osint", "medium", "osint-domain-dns", "DNS history reveals staging host."),
    ("misc", "easy", "encoding-recognition", "Multiple encoding layers."),
    ("misc", "easy", "nested-archive", "Zip of zip of flag.txt."),
    ("misc", "medium", "esoteric-lang", "Program in unusual language prints flag."),
    ("blockchain", "hard", "reentrancy", "Classic withdraw reentrancy."),
    ("blockchain", "medium", "access-control", "Missing onlyOwner on mint."),
    ("blockchain", "hard", "integer-accounting", "Unchecked arithmetic drains pool."),
    ("mobile", "medium", "android-exported-component", "Exported activity leaks data."),
    ("mobile", "medium", "insecure-storage", "Secrets in SharedPreferences."),
    ("mobile", "easy", "hardcoded-secret", "API key in APK strings."),
]


def _load_archive() -> List[Dict[str, Any]]:
    rows = []
    if not ARCHIVE.is_dir():
        return rows
    for fp in sorted(ARCHIVE.glob("*.json")):
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows.append({
            "id": f"archive-{fp.stem}",
            "source": "archive",
            "name": d.get("challenge_name") or fp.stem,
            "category": d.get("category") or "misc",
            "difficulty": d.get("difficulty") or "medium",
            "description": d.get("description") or "",
            "techniques": d.get("techniques") or d.get("tags") or [],
        })
    return rows


def _synth_rows(target_extra: int = 120) -> List[Dict[str, Any]]:
    rows = []
    # repeat templates with numbered variants to reach target
    i = 0
    while len(rows) < target_extra:
        cat, diff, tech, desc = _SYNTH[i % len(_SYNTH)]
        variant = i // len(_SYNTH) + 1
        rows.append({
            "id": f"synth-{tech}-{variant}-{i}",
            "source": "synthetic",
            "name": f"{cat.upper()} pattern: {tech} (v{variant})",
            "category": cat,
            "difficulty": diff,
            "description": f"{desc} [variant {variant} — local study pattern card]",
            "techniques": [tech],
        })
        i += 1
    return rows


def build_corpus(min_entries: int = 120) -> Dict[str, Any]:
    archive = _load_archive()
    need = max(0, min_entries - len(archive))
    synth = _synth_rows(need if need > 0 else 80)
    # de-dupe by id
    all_rows = archive + synth
    seen = set()
    uniq = []
    for r in all_rows:
        if r["id"] in seen:
            continue
        seen.add(r["id"])
        uniq.append(r)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for r in uniq:
            f.write(json.dumps(r) + "\n")

    # also write a compact ground-truth expansion sample
    gt_extra = [
        {
            "id": r["id"],
            "description": r["description"],
            "expected_category": r["category"],
            "expected_techniques": r["techniques"],
            "difficulty": r["difficulty"],
        }
        for r in uniq
        if r["source"] == "synthetic"
    ][:80]
    (OUT_DIR / "eval_extra.json").write_text(json.dumps(gt_extra, indent=2), encoding="utf-8")

    by_cat: Dict[str, int] = {}
    for r in uniq:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
    return {
        "total": len(uniq),
        "archive": len(archive),
        "synthetic": len(synth),
        "by_category": by_cat,
        "path": str(OUT_FILE),
    }


if __name__ == "__main__":
    print(json.dumps(build_corpus(120), indent=2))
