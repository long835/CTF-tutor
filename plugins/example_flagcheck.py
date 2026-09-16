"""Example plugin: flag-format sanity checks for local challenge text.

Copy this file, rename it, and edit `register()` to add your own tools.
A plugin is a single .py file (or a package with __init__.py) in this
directory that exports `register(api)`.

Tools you register are namespaced automatically, so this file's `check`
tool becomes `example_flagcheck.check` and cannot collide with a built-in.
Permissions are clamped to the plugin ceiling (analysis at most), and any
exception you raise is caught and reported rather than ending the run.

Plugins only load when CTF_TUTOR_ENABLE_PLUGINS=1.
"""

from __future__ import annotations

import re

__version__ = "1.0.0"

# Flag shapes commonly used by public CTF platforms.
_FLAG_PATTERNS = [
    re.compile(r"\b[A-Za-z0-9_]{2,16}\{[^}\n]{1,120}\}"),
    re.compile(r"\bFLAG-[A-Za-z0-9\-]{4,64}\b", re.IGNORECASE),
]

# Things that look like a flag but almost never are.
_DECOY_HINTS = ("example", "sample", "test", "dummy", "placeholder", "your_flag_here", "redacted")


def _check(args):
    """
    Scan text for flag-shaped strings and rank how plausible each one is.

    Returns the (ok, output, error) triple every agent tool returns.
    """
    text = str(args.get("text") or args.get("content") or "")
    if not text.strip():
        return False, "", "no text supplied (pass text=...)"

    found = []
    seen = set()
    for pattern in _FLAG_PATTERNS:
        for match in pattern.findall(text):
            if match in seen:
                continue
            seen.add(match)
            lowered = match.lower()
            decoy = any(hint in lowered for hint in _DECOY_HINTS)
            found.append(
                {
                    "candidate": match,
                    "likely_decoy": decoy,
                    "note": "matches a known placeholder word" if decoy else "shape looks plausible",
                }
            )

    if not found:
        return True, "No flag-shaped strings in this text.", ""

    lines = [f"{len(found)} flag-shaped candidate(s):"]
    for item in found:
        mark = "decoy?" if item["likely_decoy"] else "check "
        lines.append(f"  [{mark}] {item['candidate']} — {item['note']}")
    lines.append("")
    lines.append("A matching shape is a candidate, not an answer. Confirm it came from the intended path.")
    return True, "\n".join(lines), ""


def register(api):
    """Called once at load time. `api` is an agent.plugins.PluginAPI."""
    api.describe(
        version=__version__,
        description="Flags shaped like flags, and which of them are probably decoys.",
    )
    api.register_tool(
        "check",
        _check,
        description="Scan text for flag-shaped candidates and flag likely decoys.",
        category_tags=["misc", "all"],
    )
