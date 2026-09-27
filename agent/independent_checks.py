"""Independent checks that do NOT use agent.evidence.REQUIREMENTS.

Used as a second channel so classifier/rubric loops cannot self-certify alone.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


def independent_static_checks(description: str = "", artifact_paths: List[str] | None = None) -> Dict[str, Any]:
    text = description or ""
    findings = []
    # File magic independent of taxonomy keywords
    for path in artifact_paths or []:
        try:
            data = open(path, "rb").read(16)
        except Exception:
            continue
        if data.startswith(b"\x7fELF"):
            findings.append({"check": "magic_elf", "result": True})
        if data.startswith(b"\x89PNG"):
            findings.append({"check": "magic_png", "result": True})
        if data[:4] == bytes.fromhex("d4c3b2a1") or data[:4] == bytes.fromhex("a1b2c3d4"):
            findings.append({"check": "magic_pcap", "result": True})
        if b"flag{" in data or b"CTF{" in data:
            findings.append({"check": "flag_bytes_in_file", "result": True})

    # Behavioral language without technique names
    if re.search(r"crashes|segfault|terminates after", text, re.I):
        findings.append({"check": "crash_language", "result": True})
    if re.search(r"http://|https://|cookie|endpoint", text, re.I):
        findings.append({"check": "http_language", "result": True})

    return {
        "channel": "independent_static",
        "findings": findings,
        "count": len(findings),
        "uses_rubrics": False,
    }
