"""
agent/challenge_fetch.py

Fetch *public* CTF challenge material for local study.

Supported sources:
  - GitHub public repository or subdirectory (via API + zipball)
  - Direct public .zip / .tar.gz URL
  - CTFtime public event metadata (no private tasks)

Safety rules:
  - HTTPS preferred; no auth / no private repos
  - Size and file-count limits
  - Downloaded bytes treated as untrusted (see agent.security)
  - Rate-limit friendly; caches metadata
  - Does NOT attack live CTF infra or bypass paywalls

This is for authorized education / public writeup material only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import zipfile
import tarfile
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from agent.security import redact_secrets, is_safe_path
from agent.triage import inventory_path
from agent.workspace import ChallengeWorkspace, DEFAULT_ROOT


MAX_DOWNLOAD_BYTES = int(os.getenv("CTF_TUTOR_MAX_FETCH_BYTES", str(40 * 1024 * 1024)))
MAX_FILES = int(os.getenv("CTF_TUTOR_MAX_FETCH_FILES", "400"))
USER_AGENT = "CTF-Tutor-Fetcher/1.0 (local educational agent; +https://github.com)"
GITHUB_API = "https://api.github.com"


@dataclass
class FetchResult:
    ok: bool
    source: str
    local_path: str = ""
    challenge_id: str = ""
    files: int = 0
    bytes: int = 0
    inventory: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json, application/json, */*",
    })
    # Optional unauthenticated GitHub is fine; token only if user sets it for higher rate limit
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    return s


def _safe_slug(text: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", text.strip())[:80]
    return text.strip("-") or "challenge"


def parse_github_url(url: str) -> Optional[Dict[str, str]]:
    """
    Accept:
      https://github.com/owner/repo
      https://github.com/owner/repo/tree/branch/path/to/dir
      https://github.com/owner/repo/blob/branch/file
      owner/repo
      owner/repo/path
    """
    url = url.strip().rstrip("/")
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", url) and "://" not in url:
        parts = url.split("/")
        return {
            "owner": parts[0],
            "repo": parts[1],
            "ref": "HEAD",
            "path": "/".join(parts[2:]) if len(parts) > 2 else "",
        }
    m = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)(?:/(tree|blob)/([^/]+)/(.*))?",
        url,
    )
    if not m:
        return None
    owner, repo, kind, ref, path = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    repo = repo.removesuffix(".git")
    return {
        "owner": owner,
        "repo": repo,
        "ref": ref or "HEAD",
        "path": path or "",
    }


def fetch_github(
    url_or_spec: str,
    *,
    dest_root: str = DEFAULT_ROOT,
    challenge_id: Optional[str] = None,
) -> FetchResult:
    """Download a public GitHub repo (or subfolder) into a workspace."""
    parsed = parse_github_url(url_or_spec)
    if not parsed:
        return FetchResult(ok=False, source="github", error=f"unrecognized GitHub spec: {url_or_spec}")

    owner, repo, ref, subpath = parsed["owner"], parsed["repo"], parsed["ref"], parsed["path"]
    cid = challenge_id or _safe_slug(f"gh-{owner}-{repo}-{subpath or 'root'}")
    ws = ChallengeWorkspace(cid, root=dest_root).ensure()
    sess = _session()

    # Resolve default branch if HEAD
    if ref == "HEAD":
        try:
            r = sess.get(f"{GITHUB_API}/repos/{owner}/{repo}", timeout=20)
            if r.status_code == 404:
                return FetchResult(ok=False, source="github", error="repo not found or private")
            r.raise_for_status()
            ref = r.json().get("default_branch") or "main"
        except requests.RequestException as e:
            return FetchResult(ok=False, source="github", error=f"github api: {e}")

    # Prefer zipball of whole repo then extract subpath (simple + reliable)
    zip_url = f"{GITHUB_API}/repos/{owner}/{repo}/zipball/{ref}"
    try:
        with sess.get(zip_url, timeout=60, stream=True) as resp:
            if resp.status_code == 404:
                return FetchResult(ok=False, source="github", error="ref or repo not found")
            resp.raise_for_status()
            total = 0
            tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
            try:
                for chunk in resp.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        tmp.close()
                        os.unlink(tmp.name)
                        return FetchResult(ok=False, source="github", error="download exceeds size limit")
                    tmp.write(chunk)
                tmp.close()
                extract_dir = ws.input_dir / "_github_extract"
                if extract_dir.exists():
                    shutil.rmtree(extract_dir)
                extract_dir.mkdir(parents=True)
                with zipfile.ZipFile(tmp.name, "r") as zf:
                    _safe_extract_zip(zf, extract_dir)
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
    except requests.RequestException as e:
        return FetchResult(ok=False, source="github", error=str(e))

    # zipball root is owner-repo-<hash>/
    roots = [p for p in extract_dir.iterdir() if p.is_dir()]
    repo_root = roots[0] if roots else extract_dir
    src = repo_root / subpath if subpath else repo_root
    if not src.exists():
        return FetchResult(
            ok=False,
            source="github",
            error=f"path not found in repo: {subpath}",
            meta={"owner": owner, "repo": repo, "ref": ref},
        )

    # Move selected content to input/ (flatten one level)
    final = ws.input_dir / "challenge"
    if final.exists():
        shutil.rmtree(final)
    if src.is_dir():
        shutil.copytree(src, final)
    else:
        final.mkdir(parents=True)
        shutil.copy2(src, final / src.name)

    # cleanup extract
    shutil.rmtree(extract_dir, ignore_errors=True)

    inv = inventory_path(str(final))
    ws.save_inventory(inv.to_dict())
    return FetchResult(
        ok=True,
        source="github",
        local_path=str(final),
        challenge_id=cid,
        files=inv.file_count,
        bytes=inv.total_bytes,
        inventory=inv.to_dict(),
        meta={"owner": owner, "repo": repo, "ref": ref, "path": subpath},
    )


def fetch_url_archive(
    url: str,
    *,
    dest_root: str = DEFAULT_ROOT,
    challenge_id: Optional[str] = None,
) -> FetchResult:
    """Download a public zip/tar.gz challenge package."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return FetchResult(ok=False, source="url", error="only http(s) URLs allowed")

    cid = challenge_id or _safe_slug(f"url-{Path(parsed.path).stem or 'pack'}")
    ws = ChallengeWorkspace(cid, root=dest_root).ensure()
    sess = _session()
    try:
        with sess.get(url, timeout=60, stream=True) as resp:
            resp.raise_for_status()
            total = 0
            suffix = ".zip"
            if url.endswith(".tar.gz") or url.endswith(".tgz"):
                suffix = ".tar.gz"
            elif url.endswith(".tar"):
                suffix = ".tar"
            tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            try:
                for chunk in resp.iter_content(65536):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        tmp.close()
                        os.unlink(tmp.name)
                        return FetchResult(ok=False, source="url", error="download exceeds size limit")
                    tmp.write(chunk)
                tmp.close()
                final = ws.input_dir / "challenge"
                if final.exists():
                    shutil.rmtree(final)
                final.mkdir(parents=True)
                if suffix == ".zip":
                    with zipfile.ZipFile(tmp.name, "r") as zf:
                        _safe_extract_zip(zf, final)
                else:
                    with tarfile.open(tmp.name, "r:*") as tf:
                        _safe_extract_tar(tf, final)
            finally:
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass
    except requests.RequestException as e:
        return FetchResult(ok=False, source="url", error=str(e))

    inv = inventory_path(str(final))
    ws.save_inventory(inv.to_dict())
    return FetchResult(
        ok=True,
        source="url",
        local_path=str(final),
        challenge_id=cid,
        files=inv.file_count,
        bytes=inv.total_bytes,
        inventory=inv.to_dict(),
        meta={"url": url},
    )


def search_github_challenges(
    query: str,
    *,
    max_results: int = 8,
) -> List[Dict[str, Any]]:
    """
    Search public GitHub repositories for CTF challenge material.
    Uses GitHub search API (rate-limited when unauthenticated).
    """
    sess = _session()
    q = f"{query} CTF challenge in:name,description,readme"
    try:
        r = sess.get(
            f"{GITHUB_API}/search/repositories",
            params={"q": q, "sort": "stars", "order": "desc", "per_page": max_results},
            timeout=25,
        )
        if r.status_code == 403:
            return [{"error": "GitHub rate limit — set GITHUB_TOKEN for higher limits"}]
        r.raise_for_status()
        items = r.json().get("items") or []
        out = []
        for it in items:
            out.append({
                "full_name": it.get("full_name"),
                "url": it.get("html_url"),
                "description": (it.get("description") or "")[:200],
                "stars": it.get("stargazers_count"),
                "topics": it.get("topics") or [],
            })
        return out
    except requests.RequestException as e:
        return [{"error": str(e)}]


def fetch_ctftime_event(event_id: int) -> Dict[str, Any]:
    """Public CTFtime event metadata (not private challenge files)."""
    sess = _session()
    try:
        r = sess.get(f"https://ctftime.org/api/v1/events/{event_id}/", timeout=20)
        r.raise_for_status()
        data = r.json()
        return {
            "id": data.get("id"),
            "title": data.get("title"),
            "url": data.get("url"),
            "description": (data.get("description") or "")[:500],
            "weight": data.get("weight"),
            "start": data.get("start"),
            "finish": data.get("finish"),
        }
    except requests.RequestException as e:
        return {"error": str(e)}


def fetch_auto(
    spec: str,
    *,
    dest_root: str = DEFAULT_ROOT,
    challenge_id: Optional[str] = None,
) -> FetchResult:
    """
    Dispatch by spec:
      - github URL or owner/repo[/path]
      - http(s) archive URL
    """
    spec = spec.strip()
    if "github.com" in spec or re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", spec):
        return fetch_github(spec, dest_root=dest_root, challenge_id=challenge_id)
    if spec.startswith("http://") or spec.startswith("https://"):
        if any(spec.endswith(ext) for ext in (".zip", ".tar.gz", ".tgz", ".tar")):
            return fetch_url_archive(spec, dest_root=dest_root, challenge_id=challenge_id)
        # treat as github if it looks like it
        if "github.com" in spec:
            return fetch_github(spec, dest_root=dest_root, challenge_id=challenge_id)
        return FetchResult(
            ok=False,
            source="auto",
            error="URL must be a GitHub repo/path or a direct .zip/.tar.gz archive",
        )
    return FetchResult(ok=False, source="auto", error=f"unrecognized source: {spec}")


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    count = 0
    total = 0
    for info in zf.infolist():
        name = info.filename
        if name.endswith("/"):
            continue
        # path traversal guard
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest.resolve())):
            continue
        if info.file_size > MAX_DOWNLOAD_BYTES:
            continue
        count += 1
        total += info.file_size
        if count > MAX_FILES or total > MAX_DOWNLOAD_BYTES:
            break
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    count = 0
    total = 0
    for m in tf.getmembers():
        if not m.isfile():
            continue
        name = m.name
        target = (dest / name).resolve()
        if not str(target).startswith(str(dest.resolve())):
            continue
        if m.size > MAX_DOWNLOAD_BYTES:
            continue
        count += 1
        total += m.size
        if count > MAX_FILES or total > MAX_DOWNLOAD_BYTES:
            break
        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(m)
        if src is None:
            continue
        with src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
