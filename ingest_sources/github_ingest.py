"""
ingest_sources/github_ingest.py

Pulls write-up content from a public GitHub repo (via the GitHub REST API --
no git clone needed) and summarizes each write-up into an ArchiveEntry using
your local LLM. Stores the ORIGINAL repo/file URL in `references` so you can
always go read the full thing -- we don't keep a verbatim copy of someone
else's write-up sitting in your archive.

Requires internet access (this only touches GitHub's public API, no auth
token needed for public repos, but you'll hit GitHub's unauthenticated rate
limit fast -- ~60 requests/hour. Set GITHUB_TOKEN env var for 5000/hour.)

Usage:
    python -m ingest_sources.github_ingest https://github.com/user/ctf-writeups
"""

import os
import re
import base64
import requests
from typing import List, Optional

from schema import ArchiveEntry
from llm_client import call_ollama, extract_json_object, DEFAULT_MODEL


GITHUB_API = "https://api.github.com"


SUMMARIZE_SYSTEM_PROMPT = """You are helping build a CTF learning archive. \
You will be given the text of someone else's CTF write-up. Summarize it into \
YOUR OWN WORDS -- do not copy sentences verbatim -- capturing: the challenge \
category, the underlying technique(s) used (as lowercase-hyphenated tags), \
a plain-language explanation of WHY the vulnerability/technique works, and \
the high-level solve steps (general approach, not necessarily every exact \
command).

Respond ONLY with a JSON object with keys:
challenge_name, category, techniques (array), difficulty (guess if unstated:
easy/medium/hard/insane), description, explanation, solve_steps (array),
tools_used (array, guess from context if not explicit)
"""


def _headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _parse_repo_url(url: str) -> tuple:
    """https://github.com/user/repo -> (user, repo)"""
    match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url.strip())
    if not match:
        raise ValueError(f"Doesn't look like a GitHub repo URL: {url}")
    return match.group(1), match.group(2)


def list_markdown_files(
    owner: str, repo: str, path: str = "", max_depth: int = 4, _depth: int = 0
) -> List[str]:
    """
    Recursively find .md file paths in a repo via the contents API, up to
    max_depth subdirectory levels. Each subdirectory costs one API call, and
    unauthenticated calls are capped at ~60/hour -- a large repo with deep
    nesting and no GITHUB_TOKEN set can burn through that quota fast, so this
    stops descending past max_depth rather than recursing without limit.
    """
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=_headers(), timeout=20)
    resp.raise_for_status()
    items = resp.json()

    md_files = []
    for item in items:
        if item["type"] == "file" and item["name"].lower().endswith(".md"):
            md_files.append(item["path"])
        elif item["type"] == "dir" and _depth < max_depth:
            md_files.extend(
                list_markdown_files(
                    owner, repo, item["path"], max_depth=max_depth, _depth=_depth + 1
                )
            )
    return md_files


def fetch_file_text(owner: str, repo: str, path: str) -> str:
    url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    resp = requests.get(url, headers=_headers(), timeout=20)
    resp.raise_for_status()
    data = resp.json()
    content = base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    return content


def summarize_writeup(
    text: str, source_url: str, model: str = DEFAULT_MODEL
) -> ArchiveEntry:
    # keep the prompt a reasonable size for local models with smaller context
    truncated = text if len(text) < 8000 else text[:8000] + "\n...[truncated]"
    raw = call_ollama(SUMMARIZE_SYSTEM_PROMPT, truncated, model=model)
    parsed = extract_json_object(raw)

    return ArchiveEntry(
        challenge_name=parsed.get("challenge_name", "Unknown"),
        category=parsed.get("category", "misc"),
        techniques=parsed.get("techniques", []),
        difficulty=parsed.get("difficulty"),
        source="GitHub write-up (auto-summarized)",
        description=parsed.get("description", ""),
        explanation=parsed.get("explanation", ""),
        solve_steps=parsed.get("solve_steps", []),
        tools_used=parsed.get("tools_used", []),
        references=[source_url],
        notes="Auto-summarized from an external write-up -- verify against the source link before relying on details.",
    )


def ingest_repo(
    repo_url: str, output_dir: str = "data/archive", model: str = DEFAULT_MODEL
) -> List[ArchiveEntry]:
    owner, repo = _parse_repo_url(repo_url)
    md_paths = list_markdown_files(owner, repo)
    print(f"Found {len(md_paths)} markdown files in {owner}/{repo}")

    entries = []
    for path in md_paths:
        file_url = f"https://github.com/{owner}/{repo}/blob/main/{path}"
        try:
            text = fetch_file_text(owner, repo, path)
            if len(text.strip()) < 200:
                continue  # skip near-empty files (READMEs, stubs)
            entry = summarize_writeup(text, file_url, model=model)
            entries.append(entry)

            safe_name = re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-")
            out_path = os.path.join(output_dir, f"github-{safe_name}.json")
            entry.save(out_path)
            print(f"  saved: {out_path}  ({entry.challenge_name})")
        except Exception as e:
            print(f"  skipped {path}: {e}")

    return entries


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m ingest_sources.github_ingest <github-repo-url>")
        sys.exit(1)

    ingest_repo(sys.argv[1])
