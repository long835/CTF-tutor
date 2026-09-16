"""
agent/skill_packs.py

Category skill packs inspired by community CTF skill repos (e.g. ctf-skills).

Each pack is a lightweight playbook the planner/teacher can surface:
  indicators → first checks → common tools → pitfalls.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


PACKS: Dict[str, Dict[str, Any]] = {
    "web": {
        "indicators": ["http", "cookie", "jwt", "login", "flask", "php", "sql", "xss"],
        "first_checks": [
            "Read source for auth/JWT/SQL sinks",
            "Map routes and parameters",
            "Check cookie flags and JWT alg handling",
        ],
        "tools": ["web_recon", "retrieve_archive", "research"],
        "pitfalls": [
            "JWT is signed, not encrypted by default",
            "Authentication ≠ authorization",
        ],
    },
    "pwn": {
        "indicators": ["buffer", "overflow", "gets", "ROP", "canary", "NX", "ELF"],
        "first_checks": [
            "file + checksec",
            "Identify overflow offset",
            "List protections (NX/canary/PIE/ASLR)",
        ],
        "tools": ["static_analysis", "retrieve_archive"],
        "pitfalls": [
            "NX forces ret2libc/ROP, not shellcode on stack",
            "Canary and ASLR are different mitigations",
        ],
    },
    "crypto": {
        "indicators": ["xor", "rsa", "aes", "cipher", "ecb", "hash", "encrypt"],
        "first_checks": [
            "Identify encoding vs encryption",
            "Check key sizes / modes",
            "Try layered decode before heavy crypto",
        ],
        "tools": ["crypto_toolkit", "auto_decode", "xor_crack", "retrieve_archive"],
        "pitfalls": [
            "Base64/hex are encodings, not encryption",
            "ECB leaks structure via repeated blocks",
        ],
    },
    "rev": {
        "indicators": ["crackme", "disassemble", "ghidra", "keygen", "packed"],
        "first_checks": [
            "file/strings",
            "Find comparison / password check",
            "Look for runtime string decryption",
        ],
        "tools": ["static_analysis", "auto_decode", "retrieve_archive"],
        "pitfalls": ["Packed binaries need unpacking before real analysis"],
    },
    "forensics": {
        "indicators": ["pcap", "memory", "steg", "exif", "disk", "carving"],
        "first_checks": [
            "file magic",
            "Metadata / EXIF",
            "Carve by magic bytes",
        ],
        "tools": ["forensics_toolkit", "decode_toolkit", "auto_decode"],
        "pitfalls": [" stego ≠ encryption; start with metadata and LSB"],
    },
    "osint": {
        "indicators": ["geolocat", "username", "whois", "social", "exif"],
        "first_checks": [
            "Normalize identifiers",
            "Cross-reference public sources",
            "Verify with a second source",
        ],
        "tools": ["research", "retrieve_archive"],
        "pitfalls": ["Do not dox; stay on public educational data"],
    },
    "misc": {
        "indicators": ["encoding", "base64", "layered", "puzzle"],
        "first_checks": ["Run auto_decode", "Identify charset/alphabet"],
        "tools": ["auto_decode", "decode_toolkit"],
        "pitfalls": ["Peel one layer at a time; verify each step"],
    },
}


def get_pack(category: Optional[str]) -> Optional[Dict[str, Any]]:
    if not category:
        return None
    return PACKS.get(category.lower())


def pack_summary(category: Optional[str]) -> str:
    pack = get_pack(category)
    if not pack:
        return ""
    lines = [
        f"Skill pack [{category}]:",
        "  First checks: " + "; ".join(pack["first_checks"][:3]),
        "  Tools: " + ", ".join(pack["tools"]),
        "  Pitfalls: " + "; ".join(pack["pitfalls"][:2]),
    ]
    return "\n".join(lines)


def suggest_tools_for_category(category: Optional[str]) -> List[str]:
    pack = get_pack(category)
    return list(pack["tools"]) if pack else []
