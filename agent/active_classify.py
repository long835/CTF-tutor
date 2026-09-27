"""Active classification: cheapest discriminating observation.

Instead of only regex → category, propose what to look at next when
two categories are close.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


DISCRIMINATORS = {
    ("pwn", "rev"): [
        "Run `file` / check if interactive crash-on-long-input vs offline password check",
        "Look for win()/system()/execve gadgets vs strcmp/password prompts",
        "checksec: NX/canary/PIE presence suggests exploit path (pwn) vs analysis (rev)",
    ],
    ("web", "crypto"): [
        "Is there an HTTP service / URL, or only ciphertext files?",
        "Does error text mention SQL/JWT/HTTP, or padding/oracle/modulus?",
    ],
    ("web", "misc"): [
        "Is there an HTTP endpoint or only an encoding puzzle file?",
    ],
    ("forensics", "misc"): [
        "Is the primary artifact a capture/image/disk image?",
    ],
    ("pwn", "web"): [
        "Local binary/crash vs remote HTTP application?",
    ],
    ("crypto", "rev"): [
        "Ciphertext/parameters file vs executable that implements crypto?",
    ],
    ("blockchain", "web"): [
        "Solidity/EVM contract vs HTTP API?",
    ],
    ("mobile", "rev"): [
        "APK/IPA package vs generic native binary?",
    ],
}


def suggest_discriminators(profile: Any) -> List[str]:
    """Return cheapest observations to separate top categories."""
    primary = getattr(profile, "category", None) or getattr(profile, "primary_category", "")
    runner = getattr(profile, "runner_up", "") or ""
    secondaries = list(getattr(profile, "secondary_categories", None) or [])
    pairs = []
    if runner:
        pairs.append(tuple(sorted([primary, runner])))
    for s in secondaries[:2]:
        pairs.append(tuple(sorted([primary, s])))
    out: List[str] = []
    for a, b in pairs:
        key = (a, b) if (a, b) in DISCRIMINATORS else (b, a)
        for tip in DISCRIMINATORS.get(key, []):
            if tip not in out:
                out.append(tip)
    if getattr(profile, "unknown", False) or getattr(profile, "ambiguous", False):
        out.insert(0, "Inspect artifacts first (file/magic/strings) before trusting the description")
    return out[:5]


def active_classify(description: str, artifacts=None) -> Dict[str, Any]:
    try:
        from agent.ensemble import classify_enhanced as classify_challenge
    except Exception:
        from agent.classify_challenge import classify_challenge

    profile = classify_challenge(description, artifacts=artifacts)
    return {
        "profile": profile.to_dict(),
        "discriminators": suggest_discriminators(profile),
        "mode": "active",
    }
