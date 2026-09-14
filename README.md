# CTF-Tutor

> Learn the vulnerability. Understand the exploit. Capture the flag.

CTF-Tutor is a **local-first, learning-focused CTF assistant**. It helps a learner decompose a challenge, retrieve relevant examples from a local archive, explain the underlying concepts, and optionally reveal hints progressively.

It is designed for **authorized CTFs, security labs, education, and research**. It does not submit flags, target third-party systems, or attempt to automatically solve challenges.

## Highlights

- Local Ollama models for chat, classification, decomposition, explanations, and challenge generation.
- A **32-entry curated archive** spanning PWN, reverse engineering, web, crypto, forensics, OSINT, misc, blockchain, and mobile.
- Semantic archive retrieval with optional **category and difficulty filters**.
- `suggest_tools()` recommendations grounded in retrieved archive entries; recommendations are not executed automatically.
- Tiered and interactive hints: `name` → `approach` → `commands` → `walkthrough`.
- Local history with rotation and average recorded hint depth by technique.
- A deterministic evaluation runner backed by `data/eval/ground_truth.json`.
- Passive web, crypto, forensics, OSINT, and binary-analysis toolkits.
- Optional Ghidra headless decompilation.
- Multi-language challenge sessions for **Python, Rust, Java, and .NET** with shared notes/artifacts/execution history.
- Safe local challenge-spec generation and a local chat command.
- Archive validation and duplicate detection through `archive_quality.py`.
- 186 automated tests in the supplied development snapshot.

---

## Architecture

```text
                         CTF challenge
                              │
                              ▼
                    ┌──────────────────┐
                    │ Classifier       │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Decomposer       │
                    │ + local evidence │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Retriever        │◄──── data/archive/*.json
                    │ Chroma + Ollama  │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Synthesizer      │
                    │ Explainer        │
                    └────────┬─────────┘
                             ▼
                    ┌──────────────────┐
                    │ Optional hints   │
                    │ + history        │
                    └──────────────────┘
```

The default workflow is intentionally educational: understand the evidence and technique before moving toward implementation.

---

## Requirements

- Python 3.10+ recommended.
- [Ollama](https://ollama.com/) for the local LLM and embedding model.
- `chromadb` for persistent semantic retrieval.
- Optional analysis tools such as Ghidra, `binutils`, `file`, `binwalk`, and `exiftool` depending on the challenge type.
- Rust (`rustc`), Java (`javac`/`java`), or .NET (`dotnet`) only when using that language in a multi-language session.

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Pull the default local models:

```bash
ollama pull qwen3:8b
ollama pull nomic-embed-text
```

Copy the configuration template if you need to change defaults:

```bash
cp .env.example .env
```

`.env.example` contains the Ollama settings plus runtime controls for concurrency, history size, decompression limits, evidence size, and heuristic classification confidence.

---

## Quick start

### 1. Index the 32-entry archive

The archive is stored in `data/archive/`. Index it into the local Chroma store:

```bash
python ingest.py
```

Re-run the command after adding or changing archive entries. IDs are deterministic, so existing entries are upserted rather than duplicated.

### 2. Run the tutor

```bash
python main.py "A login portal issues JWTs signed with RS256. The admin panel trusts the role claim in the token." --category web
```

Or use the backward-compatible form without the `run` subcommand:

```bash
python main.py "A login portal issues JWTs signed with RS256. The admin panel trusts the role claim in the token." --category web
```

With a local challenge file:

```bash
python main.py "Analyze this binary for a stack overflow" --category pwn --file ./chall
```

Optional hint depth:

```bash
python main.py "Analyze this binary for a stack overflow" --category pwn --depth approach
```

Interactive hints:

```bash
python main.py "Analyze this binary for a stack overflow" --category pwn --interactive
```

Use `--no-warmup` when Ollama is already loaded. Use `--no-history` when a run should not be recorded.

---

## CLI commands

Show all commands:

```bash
python main.py --help
```

### `run`

Runs classification (when needed), decomposition, retrieval, synthesis, explanations, and optional hints.

```bash
python main.py run "JWT authentication challenge" --category web
python main.py run "binary overflow" --category pwn --file ./chall --decompile
```

Supported categories include `web`, `pwn`, `crypto`, `rev`, `forensics`, and `misc`; the archive also contains `osint`, `blockchain`, and `mobile` material.

### `search`

Search the archive without running the full tutor pipeline:

```bash
python main.py search "jwt alg none bypass"
python main.py search "rsa small e" --category crypto -n 3
python main.py search "stack overflow" --category pwn --difficulty easy
```

The `--difficulty` filter accepts `easy`, `medium`, `hard`, or `insane`.

### `list`

List archive entries grouped by category:

```bash
python main.py list
python main.py list --category crypto
```

The supplied archive contains **32 JSON entries** across nine categories.

### `history`

Every normal `run` is recorded in `data/history.jsonl` unless `--no-history` is used.

```bash
python main.py history
python main.py history -n 20
python main.py history --summary
```

The summary reports technique frequency and, when hint-depth data exists, average recorded hint depth by technique. History is rotated according to `CTF_TUTOR_HISTORY_MAX_ENTRIES` (400 by default).

### `chat`

Talk directly to the local Ollama tutor:

```bash
python main.py chat "Explain why JWT algorithm confusion can happen."
```

Use `--model` to select another locally available Ollama model.

### `generate`

Generate a **safe local CTF challenge specification** as JSON:

```bash
python main.py generate "Create a beginner JWT validation challenge"
python main.py generate "Create a crypto challenge about weak RSA parameters" --output challenge.json
```

The generator is constrained to local educational fixtures and does not generate real credentials, third-party targets, or real flags.

### `session`

Manage a shared stateful multi-language session:

```bash
python main.py session create polyglot --language python
python main.py session list
python main.py session switch data/sessions/<session-id> rust
python main.py session note data/sessions/<session-id> "Check integer parsing next"
python main.py session run data/sessions/<session-id> ./snippet.py --language python
```

Supported languages:

```text
python
rust
java
dotnet
```

Session state is stored in `.ctf-session.json` inside the workspace and tracks the current language, languages used, notes, artifacts, and execution records. Execution uses argument arrays rather than a shell, bounded timeouts, capped output, and OS resource limits where available.

---

## Archive quality and ingestion

`archive_quality.py` contains reusable validation and duplicate-detection helpers for `ArchiveEntry` records:

- validates supported categories and difficulty values;
- requires a specific challenge name, techniques, description, explanation, solve steps, and references;
- computes a stable fingerprint from challenge name, category, and references;
- detects duplicates before saving an entry.

The archive-quality checks are covered by `tests/test_archive_quality.py`.

The normal ingestion command is:

```bash
python ingest.py
```

Source ingestion helpers are available under `ingest_sources/` for GitHub and YouTube material, including dry-run/rate-limit-aware workflows where supported by those modules.

---

## Evaluation

The repository includes a local evaluation dataset at:

```text
data/eval/ground_truth.json
```

Run the evaluator with:

```bash
python eval.py
```

Or specify another ground-truth JSON file:

```bash
python eval.py --data path/to/ground_truth.json
```

The evaluator reports category accuracy and deterministic technique precision/recall/F1 metrics. The supplied ground truth contains **8 cases**. This runner is a lightweight local regression/evaluation tool; it is not a claim that an Ollama model achieves those scores.

---

## Analysis toolkits

The `tools/` directory contains passive/local analysis helpers:

- `static_analysis.py` — dispatches analysis based on challenge category.
- `web_recon.py` — framework, JWT, security-header, and authentication-pattern inspection without making HTTP requests.
- `crypto_toolkit.py` — hash/algorithm/RSA/ciphertext structure analysis.
- `forensics_toolkit.py` — local forensic-file inspection helpers.
- `osint_toolkit.py` — local/manual OSINT-oriented guidance and metadata inspection.
- `decode_toolkit.py` — CTF-relevant Base64, hex, URL, ROT/Caesar, XOR, gzip/zlib, recipe chaining, and magic decoding.
- `ghidra_headless.py` — optional Ghidra decompilation for local binaries.

For example:

```bash
python -m tools.decode_toolkit "ZmxhZ3t0ZXN0fQ=="
python -m tools.web_recon ./app.py
python -m tools.crypto_toolkit ./ciphertext.txt
```

These tools are intended for challenge/lab artifacts. They do not perform network exploitation.

### Optional Ghidra

Set `GHIDRA_INSTALL_DIR` to a local Ghidra installation and use:

```bash
python main.py "Analyze this binary" --category rev --file ./chall --decompile
```

Without Ghidra, the feature degrades gracefully instead of making decompilation mandatory.

---

## Archive contents

`data/archive/` contains 32 curated/example entries covering:

| Category | Coverage |
|---|---|
| PWN | stack overflow, ret2libc, format strings |
| Reverse engineering | crackmes, XOR obfuscation, packed binaries |
| Web | JWT validation, SQL injection, path traversal, SSTI |
| Crypto | encoding layers, substitution, single-byte XOR, weak RSA |
| Forensics | PCAP/HTTP, file carving, PNG steganography, image metadata |
| OSINT | DNS pivots, EXIF geolocation, username correlation |
| Misc | encoding recognition, nested archives |
| Blockchain | Solidity access control, integer accounting |
| Mobile | Android manifest review, hardcoded-secret discovery |

`data/technique_vocab.json` provides the controlled vocabulary used to normalize technique tags.

---

## Project structure

```text
CTF-tutor/
├── data/
│   ├── archive/                 # 32 curated/example ArchiveEntry JSON files
│   ├── eval/ground_truth.json   # local evaluation cases
│   └── technique_vocab.json     # canonical technique tags
├── ingest_sources/              # GitHub / YouTube source ingestion helpers
├── tools/                       # passive analysis and CTF utility modules
├── tests/                       # automated regression suite
├── archive_quality.py           # archive validation + fingerprints
├── classifier.py                # category classification
├── decomposer.py                # challenge decomposition
├── retriever.py                 # local Chroma/Ollama archive retrieval
├── synthesizer.py               # cross-reference synthesis
├── explainer.py                 # grounded explanations
├── depth_guide.py               # tiered hints
├── history.py                   # local learning/session history
├── eval.py                      # ground-truth evaluator
├── chat_generate.py             # local chat + safe challenge generation
├── multilang.py                 # Python/Rust/Java/.NET sessions
├── main.py                      # CLI entrypoint
├── ingest.py                    # archive indexing
├── config.py                    # environment-driven runtime controls
├── .env.example                 # local configuration template
└── README.md
```

Generated/local state is intentionally not part of the shared archive:

```text
data/chroma/       # local vector store, gitignored
 data/history.jsonl # local history, gitignored
 data/sessions/     # local multi-language session workspaces
.env                # local environment configuration, gitignored
```

---

## Development and verification

Run the full test suite:

```bash
pytest -q
```

Run focused tests:

```bash
pytest tests/test_archive_quality.py
pytest tests/test_retriever.py
pytest tests/test_history.py
pytest tests/test_chat_generate.py
pytest tests/test_multilang.py
```

Run a syntax check:

```bash
python -m compileall -q .
```

The supplied development snapshot was verified with **186 passing tests**. Optional external toolchains (Ghidra, Rust, Java, .NET) may not be installed in every environment, so their runtime paths should be tested separately when available.

---

## Safety

CTF challenge files are untrusted input. Analysis may invoke third-party local tools such as `binwalk`, `exiftool`, `objdump`, Ghidra, `tshark`, or Volatility when available. For untrusted samples, use a disposable VM/container or other appropriate isolation, keep tools patched, and avoid unnecessary network access.

The tutor's subprocess timeouts, output limits, decompression limits, and resource limits are **defense in depth**, not a replacement for proper sandboxing.

Use exploitation techniques only against systems you own or are explicitly authorized to test.

---

## Roadmap

The current implementation covers the core local-first tutor, archive retrieval, evaluation, history, tool recommendation, multi-language sessions, and safe local chat/generation workflows.

Potential future work:

- Personalized difficulty based on observed learner performance.
- Integration with a specific CTF platform once a concrete platform and authorization model are chosen.
- More structured multi-challenge learning paths/curricula.
- Additional language/toolchain adapters where they materially improve CTF learning.

---

## Philosophy

> **Don't just solve the challenge. Understand why the solution works.**

A good CTF tutor should help the learner become less dependent on the tutor over time.

---

## Disclaimer

This project is intended for **education, CTF competitions, security research, and authorized testing**. Only use exploitation techniques against systems you own or have explicit permission to test.

## Status

Active development. Interfaces may evolve as the project grows.
