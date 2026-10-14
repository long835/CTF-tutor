#!/usr/bin/env python3
"""
scripts/verify_env.py

A local developer helper that reports which optional integrations are
available and prints actionable installation hints.
Does NOT modify any files or the system.
"""
import importlib
import shutil
import sys
from textwrap import indent

CHECKS = [
    ("python", lambda: sys.version_info >= (3, 10)),
    ("requests", lambda: importlib.util.find_spec("requests") is not None),
    ("python-dotenv", lambda: importlib.util.find_spec("dotenv") is not None),
    ("pytest (dev)", lambda: importlib.util.find_spec("pytest") is not None),
    ("chromadb (optional)", lambda: importlib.util.find_spec("chromadb") is not None),
    ("ollama CLI (optional)", lambda: shutil.which("ollama") is not None),
    ("gdb (optional)", lambda: shutil.which("gdb") is not None),
    ("ghidra headless (optional)", lambda: shutil.which("analyzeHeadless") is not None or shutil.which("ghidra") is not None),
    ("pwntools (optional)", lambda: importlib.util.find_spec("pwn") is not None or importlib.util.find_spec("pwnlib") is not None),
]

REQUIRED = {"python", "requests", "python-dotenv"}


def main() -> int:
    ok = True
    out = []
    for name, checker in CHECKS:
        try:
            res = checker()
        except Exception:
            res = False
        status = "OK" if res else "MISSING"
        out.append(f"{name:35} : {status}")
        if not res and name.split()[0] in REQUIRED:
            ok = False

    print("Environment quick-check:")
    print(indent("\n".join(out), "  "))

    if not ok:
        print()
        print("Notes:")
        print("  - The project requires Python 3.10+ and a small core set of packages (requests, python-dotenv).")
        print("  - Optional features (vector search, Ghidra, gdb, local LLMs) are detected above and are not required for basic tests.")
        print("  - To run the full CI you may need to install optional extras (see pyproject.toml extras).")
        return 2

    print()
    print("All core checks passed.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
