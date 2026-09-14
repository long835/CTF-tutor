"""
ingest_sources/youtube_ingest.py

Pulls the TRANSCRIPT/captions of a YouTube CTF walkthrough (not the video
itself -- we can't have the LLM watch video) and summarizes it into an
ArchiveEntry the same way github_ingest.py does for write-ups.

Only works for videos that HAVE captions (auto-generated captions are
usually fine, just noisier). If a video has no captions at all, this will
fail loudly rather than silently producing garbage -- that's intentional.

Requires:
    pip install youtube-transcript-api

Usage:
    python -m ingest_sources.youtube_ingest https://www.youtube.com/watch?v=XXXXXXXXXXX
"""

import re
import os
from typing import List, Optional

from schema import ArchiveEntry
from llm_client import call_ollama, extract_json_object, DEFAULT_MODEL

try:
    from youtube_transcript_api import YouTubeTranscriptApi
except ImportError:
    YouTubeTranscriptApi = None


SUMMARIZE_SYSTEM_PROMPT = """You are helping build a CTF learning archive. \
You will be given the auto-generated transcript of a YouTube CTF walkthrough \
video. Transcripts from spoken video are messy (no punctuation structure, \
filler words, occasional misheard words) -- read past that noise and \
summarize into YOUR OWN WORDS: the challenge category, the underlying \
technique(s) used (as lowercase-hyphenated tags), a plain-language \
explanation of WHY the vulnerability/technique works, and the high-level \
solve steps (general approach, not necessarily every exact command spoken).

If the transcript doesn't seem to be about a CTF challenge at all, or you
can't confidently identify a technique, say so honestly in the "notes" field
rather than inventing details.

Respond ONLY with a JSON object with keys:
challenge_name, category, techniques (array), difficulty (guess if unstated:
easy/medium/hard/insane), description, explanation, solve_steps (array),
tools_used (array), notes (string -- any uncertainty or caveats)
"""


def _extract_video_id(url: str) -> str:
    patterns = [
        r"(?:v=|/)([0-9A-Za-z_-]{11}).*",
        r"youtu\.be/([0-9A-Za-z_-]{11})",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)
    raise ValueError(f"Couldn't extract a video ID from: {url}")


def fetch_transcript(video_url: str) -> str:
    if YouTubeTranscriptApi is None:
        raise RuntimeError(
            "youtube-transcript-api isn't installed. Run:\n"
            "    pip install youtube-transcript-api"
        )
    video_id = _extract_video_id(video_url)
    try:
        # get_transcript()/get_transcripts() were removed as of
        # youtube-transcript-api v1.x -- you now instantiate the class and
        # call .fetch(), which returns a FetchedTranscript object (iterable
        # of snippets with .text), not a plain list of dicts.
        ytt_api = YouTubeTranscriptApi()
        fetched_transcript = ytt_api.fetch(video_id)
    except Exception as e:
        raise RuntimeError(
            f"Couldn't fetch a transcript for {video_url}: {e}\n"
            "This usually means the video has no captions available at all."
        )
    return " ".join(snippet.text for snippet in fetched_transcript)


def summarize_video(
    video_url: str, model: str = DEFAULT_MODEL
) -> ArchiveEntry:
    transcript_text = fetch_transcript(video_url)
    truncated = (
        transcript_text
        if len(transcript_text) < 10000
        else transcript_text[:10000] + " ...[truncated]"
    )
    raw = call_ollama(SUMMARIZE_SYSTEM_PROMPT, truncated, model=model)
    parsed = extract_json_object(raw)

    return ArchiveEntry(
        challenge_name=parsed.get("challenge_name", "Unknown (from video)"),
        category=parsed.get("category", "misc"),
        techniques=parsed.get("techniques", []),
        difficulty=parsed.get("difficulty"),
        source="YouTube walkthrough (auto-summarized from transcript)",
        description=parsed.get("description", ""),
        explanation=parsed.get("explanation", ""),
        solve_steps=parsed.get("solve_steps", []),
        tools_used=parsed.get("tools_used", []),
        references=[video_url],
        notes=parsed.get("notes")
        or "Auto-summarized from a video transcript -- transcripts can be noisy; verify against the video before relying on details.",
    )


def ingest_video(
    video_url: str, output_dir: str = "data/archive", model: str = DEFAULT_MODEL
) -> ArchiveEntry:
    entry = summarize_video(video_url, model=model)
    video_id = _extract_video_id(video_url)
    out_path = os.path.join(output_dir, f"youtube-{video_id}.json")
    entry.save(out_path)
    print(f"saved: {out_path}  ({entry.challenge_name})")
    return entry


def list_playlist_video_urls(playlist_url: str) -> List[str]:
    """Return video URLs from a playlist using optional yt-dlp metadata only."""
    try:
        from yt_dlp import YoutubeDL
    except ImportError as e:
        raise RuntimeError("playlist mode requires yt-dlp: pip install yt-dlp") from e
    opts = {"quiet": True, "skip_download": True, "extract_flat": True}
    with YoutubeDL(opts) as ydl:
        info = ydl.extract_info(playlist_url, download=False)
    entries = info.get("entries") or []
    return [
        f"https://www.youtube.com/watch?v={item['id']}"
        for item in entries
        if item and item.get("id")
    ]


def ingest_playlist(playlist_url: str, output_dir: str = "data/archive",
                    model: str = DEFAULT_MODEL, dry_run: bool = False) -> List[ArchiveEntry]:
    import json
    urls = list_playlist_video_urls(playlist_url)
    print(f"Found {len(urls)} videos in playlist")
    entries = []
    os.makedirs(output_dir, exist_ok=True)
    for url in urls:
        try:
            entry = summarize_video(url, model=model)
            entries.append(entry)
            video_id = _extract_video_id(url)
            out_path = os.path.join(output_dir, f"youtube-{video_id}.json")
            if dry_run:
                print(f"  DRY-RUN {out_path}:\n{json.dumps(entry.to_dict(), indent=2, ensure_ascii=False)}")
            else:
                entry.save(out_path)
                print(f"  saved: {out_path}  ({entry.challenge_name})")
        except Exception as e:
            print(f"  skipped {url}: {e}")
    return entries


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m ingest_sources.youtube_ingest <youtube-video-url> | --playlist <playlist-url> [--dry-run]")
        sys.exit(1)

    if sys.argv[1] == "--playlist":
        if len(sys.argv) < 3:
            print("error: --playlist requires a playlist URL", file=sys.stderr)
            sys.exit(1)
        ingest_playlist(sys.argv[2], dry_run="--dry-run" in sys.argv[3:])
    else:
        ingest_video(sys.argv[1])
