"""
tools/web_recon.py

Passive recon for web challenges: local file fingerprints, JWT *decode*
(header/payload only), and optional header fetch for a user-supplied URL.
Never forges tokens or attacks a remote host beyond a single GET/HEAD that
the learner explicitly opted into with --url.
"""

import base64
import json
import re
import shutil
import subprocess
from typing import Optional
from urllib.parse import urlparse


def _run(cmd: list, timeout: int = 15) -> str:
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"[{exe} not installed -- skip this check]"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout or "").strip()
        if result.stderr and result.stderr.strip():
            output += f"\n[stderr] {result.stderr.strip()}"
        return output or "[no output]"
    except subprocess.TimeoutExpired:
        return f"[{exe} timed out after {timeout}s]"
    except Exception as e:
        return f"[{exe} failed: {e}]"


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    padded = padded.replace("-", "+").replace("_", "/")
    return base64.b64decode(padded)


def decode_jwt(token: str) -> str:
    """Decode JWT header and payload only. Does not verify or forge a signature."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return "[not a three-part JWT]"
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as e:
        return f"[jwt decode failed: {e}]"
    return json.dumps({"header": header, "payload": payload, "signature_present": len(parts) >= 3}, indent=2)


def fingerprint_source(text: str) -> str:
    hits = []
    mapping = {
        "flask": "Flask",
        "django": "Django",
        "express": "Express/Node",
        "laravel": "Laravel",
        "wordpress": "WordPress",
        "jquery": "jQuery",
        "react": "React",
        "next.js": "Next.js",
        "php": "PHP",
    }
    lower = text.lower()
    for needle, label in mapping.items():
        if needle in lower:
            hits.append(label)
    return ", ".join(hits) or "[no obvious framework markers in file]"


def get_headers(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return f"[refusing to fetch URL with scheme {parsed.scheme!r}]"
    if shutil.which("curl"):
        return _run(["curl", "-sI", "-L", "--max-time", "10", url])
    if shutil.which("httpx"):
        return _run(["httpx", "-silent", "-title", "-tech-detect", "-status-code", url])
    return "[curl/httpx not installed -- skip header recon]"


def whatweb(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "[whatweb skipped -- URL is not http(s)]"
    return _run(["whatweb", url])


def wafw00f(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "[wafw00f skipped -- URL is not http(s)]"
    return _run(["wafw00f", url])


def gather_web_evidence(path: Optional[str], target_url: Optional[str] = None) -> dict:
    evidence = {}
    blob = ""
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                blob = f.read(200_000)
        except OSError as e:
            evidence["web_file"] = f"[could not read {path}: {e}]"
            blob = ""
        if blob:
            evidence["framework_fingerprint"] = fingerprint_source(blob)
            jwt_match = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", blob)
            if jwt_match:
                evidence["jwt_decoded"] = decode_jwt(jwt_match.group(0))
    if target_url:
        evidence["response_headers"] = get_headers(target_url)
        evidence["whatweb"] = whatweb(target_url)
        evidence["waf"] = wafw00f(target_url)
    return evidence
