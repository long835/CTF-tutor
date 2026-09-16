"""
tools/osint_toolkit.py

Local-first OSINT evidence: image GPS/metadata (exiftool), whois/dig for a
domain the learner supplied. Reverse image search is listed as a *manual*
step only -- scraping Google/Yandex would violate their terms.
"""

import shutil
import subprocess
from typing import Optional


def _run(cmd: list, timeout: int = 15) -> str:
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"[{exe} not installed -- skip this check]"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout or "").strip()
        if result.stderr and result.stderr.strip():
            output += f"\n[stderr] {result.stderr.strip()[:1500]}"
        return output or "[no output]"
    except subprocess.TimeoutExpired:
        return f"[{exe} timed out after {timeout}s]"
    except Exception as e:
        return f"[{exe} failed: {e}]"


def extract_gps(path: str) -> str:
    return _run(["exiftool", "-GPS*", "-n", path])


def whois_lookup(domain: str) -> str:
    domain = domain.strip().split("/")[0]
    if not domain or " " in domain:
        return "[invalid domain]"
    return _run(["whois", domain])


def dig_lookup(domain: str) -> str:
    domain = domain.strip().split("/")[0]
    if not domain or " " in domain:
        return "[invalid domain]"
    return _run(["dig", domain, "ANY", "+noall", "+answer"])


def manual_osint_steps() -> str:
    return (
        "Manual next steps (not automated): reverse image search in a browser "
        "(Google/Yandex/Lens) -- do not scrape those services; username checks "
        "on public profiles the challenge actually names."
    )


def gather_osint_evidence(path: Optional[str], domain: Optional[str] = None) -> dict:
    evidence = {"manual_osint": manual_osint_steps()}
    if path:
        evidence["gps_metadata"] = extract_gps(path)
        evidence["metadata"] = _run(["exiftool", path])
    if domain:
        evidence["whois"] = whois_lookup(domain)
        evidence["dns"] = dig_lookup(domain)
    return evidence
