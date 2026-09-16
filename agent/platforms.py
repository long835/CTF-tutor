"""
agent/platforms.py

Optional CTF platform clients.

- CTFd: public/self-hosted API (no auth required for public challenges list if open)
- HTB: requires user API token in HTB_TOKEN env — never hardcoded

Does NOT bypass private contests, paywalls, or ToS.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import requests

USER_AGENT = "CTF-Tutor/1.0 (local educational agent)"


def _sess(extra: Optional[Dict[str, str]] = None) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    if extra:
        s.headers.update(extra)
    return s


def ctfd_list_challenges(base_url: str, *, token: Optional[str] = None) -> Dict[str, Any]:
    """
    List challenges from a CTFd instance.
    base_url example: https://ctfd.example.com
    """
    base = base_url.rstrip("/")
    headers = {}
    tok = token or os.getenv("CTFD_TOKEN")
    if tok:
        headers["Authorization"] = f"Token {tok}"
    try:
        r = _sess(headers).get(f"{base}/api/v1/challenges", timeout=20)
        if r.status_code == 403:
            return {"ok": False, "error": "forbidden — need CTFD_TOKEN or public access"}
        r.raise_for_status()
        data = r.json()
        challenges = data.get("data") or data.get("challenges") or []
        out = []
        for c in challenges[:100]:
            out.append({
                "id": c.get("id"),
                "name": c.get("name"),
                "category": c.get("category"),
                "value": c.get("value"),
                "solved": c.get("solved_by_me"),
            })
        return {"ok": True, "count": len(out), "challenges": out, "source": base}
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}


def ctfd_challenge_detail(base_url: str, challenge_id: int, *, token: Optional[str] = None) -> Dict[str, Any]:
    base = base_url.rstrip("/")
    headers = {}
    tok = token or os.getenv("CTFD_TOKEN")
    if tok:
        headers["Authorization"] = f"Token {tok}"
    try:
        r = _sess(headers).get(f"{base}/api/v1/challenges/{challenge_id}", timeout=20)
        r.raise_for_status()
        data = r.json().get("data") or r.json()
        return {
            "ok": True,
            "id": data.get("id"),
            "name": data.get("name"),
            "category": data.get("category"),
            "description": (data.get("description") or "")[:2000],
            "files": data.get("files") or [],
        }
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}


def htb_profile() -> Dict[str, Any]:
    """Hack The Box profile — requires HTB_TOKEN."""
    token = os.getenv("HTB_TOKEN") or os.getenv("HACKTHEBOX_TOKEN")
    if not token:
        return {"ok": False, "error": "Set HTB_TOKEN in environment (account API token)"}
    try:
        r = _sess({"Authorization": f"Bearer {token}"}).get(
            "https://labs.hackthebox.com/api/v4/user/info",
            timeout=20,
        )
        if r.status_code in (401, 403):
            return {"ok": False, "error": "HTB token rejected"}
        r.raise_for_status()
        return {"ok": True, "data": r.json()}
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}


def htb_list_machines(limit: int = 20) -> Dict[str, Any]:
    """List HTB machines (token required). Educational metadata only."""
    token = os.getenv("HTB_TOKEN") or os.getenv("HACKTHEBOX_TOKEN")
    if not token:
        return {"ok": False, "error": "Set HTB_TOKEN in environment"}
    try:
        r = _sess({"Authorization": f"Bearer {token}"}).get(
            "https://labs.hackthebox.com/api/v4/machine/list",
            timeout=25,
        )
        if r.status_code in (401, 403):
            return {"ok": False, "error": "HTB token rejected or endpoint restricted"}
        r.raise_for_status()
        data = r.json()
        machines = data.get("info") or data.get("data") or data.get("machines") or []
        if isinstance(machines, dict):
            machines = list(machines.values()) if machines else []
        out = []
        for m in (machines if isinstance(machines, list) else [])[:limit]:
            if not isinstance(m, dict):
                continue
            out.append({
                "id": m.get("id"),
                "name": m.get("name"),
                "os": m.get("os"),
                "difficulty": m.get("difficultyText") or m.get("difficulty"),
            })
        return {"ok": True, "count": len(out), "machines": out}
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}
