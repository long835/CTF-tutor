# CTF Tutor

> **Layout note:** `tools/` and `ingest_sources/` are real packages now (each
> with an `__init__.py`), matching the `python -m ingest_sources.github_ingest`
> style commands below. Also fixed since the first draft: the YouTube ingest
> script now uses the current `youtube-transcript-api` v1.x instance-based
> `.fetch()` call (the old static `get_transcript()` method was removed
> upstream), `checksec` invocation now matches real `checksec.py`/`checksec.sh`
> syntax instead of a flag neither tool uses, and the Ollama JSON extraction
> strips `<think>...</think>` reasoning blocks before parsing so qwen3's
> chain-of-thought stops corrupting the JSON extraction.
>
> **Second fix pass:** the six roadmap files below (`retriever.py`,
> `synthesizer.py`, `explainer.py`, `depth_guide.py` -- note the underscore,
> the old `depth guide.py` with a space was never importable -- `main.py`,
> and `llm client.py`) had each been saved with their *test suite* as the
> file content instead of an implementation, so e.g. `retriever.py` did
> `from retriever import Retriever`, importing itself. Those test files are
> now at `tests/test_*.py` (plus `tests/fakes.py`, moved from the stray
> root-level `Fakes.py`) where they belong, and every module now has a real
> implementation behind it. `ingest.py` had no test yet, so one was written
> alongside it (`tests/test_ingest.py`). `requirements.txt` was also missing
> `chromadb`, which `retriever.py` needs. All 58 tests pass against
> `tests/fakes.py`'s fake Ollama HTTP layer and fake Chroma collection, with
> no live Ollama/chromadb required:
>
> ```bash
> python -m unittest discover -s tests
> ```

A free, local, learning-focused CTF assistant. It does **not** auto-solve
challenges or submit flags. Instead it:

1. **Decomposes** a challenge into sub-problems (this part is built)
2. Retrieves similar past challenges from your own solved-challenge archive,
   matched by *technique*, not just category (next step)
3. Cross-references multiple matches to suggest combined approaches when a
   challenge blends techniques from more than one past challenge (next step)
4. Explains each piece in plain language, citing the precedent it drew from
   (next step)
5. Offers a tiered hint ladder -- name the technique, explain the approach,
   suggest specific commands, full walkthrough -- only as deep as you ask for
   (next step)

## Status

- [x] `schema.py` -- archive entry + sub-problem data structures
- [x] `tools/static_analysis.py` -- free CLI tool wrappers (file, strings,
      checksec, binwalk, exiftool)
- [x] `llm_client.py` -- shared local-Ollama calling logic
- [x] `decomposer.py` -- breaks a challenge into sub-problems via a local LLM
- [x] `ingest_sources/github_ingest.py` -- pulls write-ups from a GitHub repo,
      summarizes into the archive format, keeps the source link
- [x] `ingest_sources/youtube_ingest.py` -- pulls a video's transcript,
      summarizes into the archive format, keeps the source link
- [x] `retriever.py` -- ChromaDB-backed semantic search over your archive
- [x] `synthesizer.py` -- cross-references multiple retrieved matches
- [x] `explainer.py` -- plain-language explanation generation
- [x] `depth_guide.py` -- tiered hint escalation
- [x] `main.py` -- CLI entrypoint tying it all together
- [x] `ingest.py` -- one-time script to embed everything in `data/archive/`
      into the vector store

## Pulling in external write-ups (GitHub repos, YouTube videos)

We deliberately do NOT store a verbatim copy of someone else's write-up or
video transcript. Instead, each source is summarized into your own archive
format by the local LLM, and the original URL is kept in `references` so
you can always go read the full thing. This keeps the archive dense and
searchable, and avoids just hoarding other people's copyrighted prose.

### From a GitHub write-up repo

```bash
pip install -r requirements.txt   # picks up requests
python -m ingest_sources.github_ingest https://github.com/someuser/ctf-writeups
```

This walks the repo's markdown files via the GitHub API (no `git clone`
needed), summarizes each one, and saves a new archive entry per write-up
under `data/archive/github-*.json`.

Unauthenticated GitHub API calls are capped at ~60/hour. For bigger repos,
set a personal access token first:

```bash
export GITHUB_TOKEN=ghp_your_token_here
```

### From a YouTube walkthrough

```bash
pip install youtube-transcript-api
python -m ingest_sources.youtube_ingest https://www.youtube.com/watch?v=XXXXXXXXXXX
```

This only works if the video has captions (auto-generated captions are
fine, just noisier) -- it pulls the transcript text, not the video itself,
since the LLM can't watch video. If a video has no captions, this fails
loudly rather than guessing.

## Setup

### 1. Install Ollama (free, local LLM runner)

Download from https://ollama.com, then:

```bash
ollama pull qwen3:8b
```

Use a bigger model (`qwen3:14b`, `devstral:24b`) if your hardware can
handle it -- more parameters generally means better reasoning about
unfamiliar challenges. `devstral:24b` is specifically tuned for
agentic/tool-use tasks and is a strong pick if you have 24-32GB RAM.

Make sure the server is running:

```bash
ollama serve
```

### 2. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional but recommended) Install CTF recon CLI tools

These make the decomposer's evidence real instead of guessed:

```bash
# Debian/Ubuntu
sudo apt install file binutils binwalk exiftool
pip install checksec.py    # or install the standalone checksec.sh script
```

Everything in `static_analysis.py` degrades gracefully if a tool isn't
installed -- it just reports the check as skipped rather than crashing.

## Usage

### 1. Index your archive (once, and again whenever you add entries)

```bash
python ingest.py                # indexes data/archive/*.json into ./data/chroma
python ingest.py --reset        # wipe and rebuild the vector store first
```

Requires `ollama pull nomic-embed-text` (or your own `--persist-dir`/embedding
setup) since indexing embeds each entry with a local Ollama model, same as
everything else in this project.

### 2. Run the full pipeline

```bash
python main.py "A login portal issues JWTs signed with RS256. \
The admin panel trusts the role claim in the token." \
    --category web --file ./challenge_files/app.js --depth approach
```

`--depth` is optional and tiered: `name` -> `approach` -> `commands` ->
`walkthrough`. Omit it to get decomposition, retrieval, cross-referencing,
and explanations without any hints at all.

Or from Python:

```python
from main import run, _print_report
from depth_guide import HintLevel

result = run(
    "A login portal issues JWTs signed with RS256...",
    category="web",
    file_path="./challenge.bin",   # optional
    depth=HintLevel.APPROACH,       # optional
)
_print_report(result)
```

`run()` degrades gracefully if chromadb/Ollama embeddings aren't set up --
you still get decomposition and general-knowledge (ungrounded) explanations,
just no archive matches.

Just the decomposer, standalone:

```bash
python decomposer.py "A login portal issues JWTs signed with RS256. \
The admin panel trusts the role claim in the token." ./challenge_files/app.js web
```

## Archive format

Past solved challenges live in `data/archive/*.json`, one file per
challenge, following the `ArchiveEntry` schema in `schema.py`. See
`data/archive/example_web_jwt.json` and `example_pwn_ret2libc.json` for
real examples.

The most important field is `techniques` -- a list of normalized,
lowercase-hyphenated tags (e.g. `jwt-alg-confusion`, `stack-buffer-overflow`,
`padding-oracle`). Keep this vocabulary consistent across entries (see the
guide comment at the top of `schema.py`) -- this is what lets the retriever
(next step) match challenges by *underlying technique* rather than surface
category, which is what powers the "this challenge combines technique X
from past-challenge-A with technique Y from past-challenge-B" behavior.

## Design principle: tutor, not solver

Every prompt in this codebase is written to explain and guide, not to hand
over flags. The decomposer's system prompt explicitly instructs the model
not to produce a full solution. Keep that principle when you extend
`explainer.py` and `depth_guide.py` -- the value of this tool is building
your own skill, not skipping the challenge.
