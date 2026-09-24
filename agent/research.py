"""
agent/research.py

Optional research agent — offline-first.

When Internet is disabled or requests fail, falls back to:
  - local archive (hybrid_retrieve)
  - local skill_graph concept cards
  - installed man-page style hints (static)

When Internet is enabled (explicit), may fetch public documentation
with rate limiting, caching, and source tier labels. Never required
for core tutoring.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

from agent.hybrid_retrieve import hybrid_search
from agent.skill_graph import explain_concept, prerequisites_for


CACHE_DIR = os.path.join("data", "research_cache")
DEFAULT_ONLINE = os.getenv("CTF_TUTOR_ONLINE_RESEARCH", "0") in ("1", "true", "True")


@dataclass
class ResearchHit:
    title: str
    url: str
    snippet: str
    tier: int  # 1=official docs ... 5=unverified
    source: str  # local_archive | concept | web | cache
    retrieved_at: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _cache_path(key: str) -> Path:
    h = hashlib.sha256(key.encode()).hexdigest()[:24]
    return Path(CACHE_DIR) / f"{h}.json"


def _load_cache(key: str, max_age_sec: int = 7 * 86400) -> Optional[List[Dict[str, Any]]]:
    p = _cache_path(key)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if time.time() - data.get("ts", 0) > max_age_sec:
            return None
        return data.get("hits")
    except (OSError, json.JSONDecodeError):
        return None


def _save_cache(key: str, hits: List[ResearchHit]) -> None:
    Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)
    payload = {"ts": time.time(), "hits": [h.to_dict() for h in hits]}
    _cache_path(key).write_text(json.dumps(payload), encoding="utf-8")


def research(
    query: str,
    *,
    category: Optional[str] = None,
    online: Optional[bool] = None,
    top_k: int = 5,
) -> List[ResearchHit]:
    """
    Multi-source research. Local sources always run; web only if online=True.
    """
    online = DEFAULT_ONLINE if online is None else online
    hits: List[ResearchHit] = []

    # 1. Local archive
    for m in hybrid_search(query, category=category, top_k=top_k):
        hits.append(ResearchHit(
            title=m.get("name") or "archive",
            url=f"local://archive/{m.get('name')}",
            snippet=(m.get("snippet") or str(m.get("techniques")))[:300],
            tier=2,
            source="local_archive",
            retrieved_at=time.time(),
        ))

    # 2. Concept cards from skill graph
    tokens = re.findall(r"[a-z0-9\-]+", query.lower())
    for tok in tokens:
        blurb = explain_concept(tok)
        if "No concept card" not in blurb:
            hits.append(ResearchHit(
                title=f"concept:{tok}",
                url=f"local://concept/{tok}",
                snippet=blurb,
                tier=1,
                source="concept",
                retrieved_at=time.time(),
            ))
        for pre in prerequisites_for(tok)[:3]:
            hits.append(ResearchHit(
                title=f"prereq:{pre}",
                url=f"local://concept/{pre}",
                snippet=explain_concept(pre),
                tier=1,
                source="concept",
                retrieved_at=time.time(),
            ))

    # 3. Optional online (cached)
    if online:
        cache_key = f"web:{query}:{category}"
        cached = _load_cache(cache_key)
        if cached:
            for h in cached[:top_k]:
                hits.append(ResearchHit(**{**h, "source": "cache"}))
        else:
            web_hits = _web_search_safe(query, top_k=top_k)
            if web_hits:
                _save_cache(cache_key, web_hits)
                hits.extend(web_hits)

    # Dedup by title, prefer lower tier number
    seen = set()
    out: List[ResearchHit] = []
    for h in rank_hits(hits):
        if h.title in seen:
            continue
        seen.add(h.title)
        out.append(h)
    return out[: top_k + 3]


# Domain → tier (1 best … 5 unverified). Used when online hits are admitted.
_DOMAIN_TIERS = {
    "docs.python.org": 1,
    "man7.org": 1,
    "kernel.org": 1,
    "openssl.org": 1,
    "developer.mozilla.org": 1,
    "portswigger.net": 2,
    "owasp.org": 2,
    "ctftime.org": 2,
    "picoctf.org": 2,
    "github.com": 3,
    "wikipedia.org": 3,
    "medium.com": 4,
    "stackoverflow.com": 3,
}


def rank_source_tier(url: str, default: int = 4) -> int:
    """Map a URL host to a research trust tier (lower is better)."""
    try:
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return default
    if not host:
        return default
    for domain, tier in _DOMAIN_TIERS.items():
        if host == domain or host.endswith("." + domain):
            return tier
    return default


def rank_hits(hits: List[ResearchHit]) -> List[ResearchHit]:
    """Stable sort: tier ascending, then recency."""
    return sorted(hits, key=lambda h: (h.tier, -h.retrieved_at))


def _web_search_safe(query: str, top_k: int = 5) -> List[ResearchHit]:
    """
    Best-effort DuckDuckGo HTML-lite search. Failures return [].
    Respects a hard timeout; never raises to the agent loop.
    """
    try:
        import requests
        url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query + " CTF")
        resp = requests.get(
            url,
            timeout=8,
            headers={"User-Agent": "CTF-Tutor-Research/1.0 (local educational agent)"},
        )
        if resp.status_code != 200:
            return []
        text = resp.text
        # very light extract of result titles/urls
        titles = re.findall(r'class="result__a"[^>]*>([^<]+)</a>', text)
        urls = re.findall(r'class="result__url"[^>]*>([^<]+)</a>', text)
        snippets = re.findall(r'class="result__snippet"[^>]*>([^<]+)</a>?', text)
        hits = []
        for i, title in enumerate(titles[:top_k]):
            _url = (urls[i].strip() if i < len(urls) else "")
            hits.append(ResearchHit(
                title=re.sub(r"\s+", " ", title).strip()[:120],
                url=_url,
                snippet=(snippets[i].strip()[:240] if i < len(snippets) else ""),
                tier=rank_source_tier(_url, default=4),
                source="web",
                retrieved_at=time.time(),
            ))
        return hits
    except Exception:
        return []


def format_citations(hits: List[ResearchHit]) -> str:
    if not hits:
        return "Sources: (none — local knowledge only)"
    lines = ["Sources:"]
    for h in hits:
        lines.append(f"- [tier {h.tier} | {h.source}] {h.title}: {h.snippet[:120]}")
    return "\n".join(lines)



def research_safe(
    query: str,
    *,
    category: Optional[str] = None,
    online: Optional[bool] = None,
    top_k: int = 5,
) -> List[ResearchHit]:
    """Hardened wrapper: never raises; always returns local hits on failure."""
    try:
        return research(query, category=category, online=online, top_k=top_k)
    except Exception as e:
        # Fall back to pure local archive / concepts
        hits: List[ResearchHit] = []
        try:
            from agent.hybrid_retrieve import hybrid_search
            for m in hybrid_search(query, top_k=top_k) or []:
                hits.append(ResearchHit(
                    title=str(m.get("title") or m.get("id") or "local"),
                    url="",
                    snippet=str(m.get("snippet") or m.get("text") or "")[:500],
                    tier=2,
                    source="local_archive_fallback",
                    retrieved_at=time.time(),
                ))
        except Exception:
            pass
        if not hits:
            hits.append(ResearchHit(
                title="research unavailable",
                url="",
                snippet=f"offline research failed: {e}",
                tier=5,
                source="error",
                retrieved_at=time.time(),
            ))
        return hits[:top_k]
