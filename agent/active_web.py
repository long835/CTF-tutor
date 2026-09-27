"""Active-safe Web: HTTP only to an explicit user-approved target host.

Default remains passive. Enable with approve_target('http://127.0.0.1:8000').
"""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Dict, Optional
import ipaddress
import socket

_approved: Optional[str] = None


def approve_target(base_url: str) -> Dict[str, Any]:
    global _approved
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        return {"ok": False, "error": "only http(s)"}
    host = parsed.hostname or ""
    # Allow localhost for labs; block cloud metadata
    if host.lower() in {"metadata.google.internal"}:
        return {"ok": False, "error": "metadata blocked"}
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip in ipaddress.ip_network("169.254.0.0/16"):
                return {"ok": False, "error": "link-local blocked"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    _approved = f"{parsed.scheme}://{parsed.netloc}"
    return {"ok": True, "approved": _approved}


def clear_target() -> None:
    global _approved
    _approved = None


def approved_target() -> Optional[str]:
    return _approved


def safe_get(path: str = "/", timeout: float = 5.0) -> Dict[str, Any]:
    """GET path on approved target only."""
    if not _approved:
        return {"ok": False, "error": "no approved target — call approve_target first"}
    from urllib.parse import urljoin
    import urllib.request
    url = urljoin(_approved.rstrip("/") + "/", path.lstrip("/"))
    # Re-validate host still matches approved netloc
    if urlparse(url).netloc != urlparse(_approved).netloc:
        return {"ok": False, "error": "host escape blocked"}
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "CTF-Tutor-active-safe/0.8"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(50_000)
            return {
                "ok": True,
                "status": getattr(resp, "status", None),
                "url": url,
                "body_preview": body[:2000].decode("utf-8", errors="replace"),
                "reasoning_source": "tool",
            }
    except Exception as e:
        return {"ok": False, "error": str(e), "url": url}
