# CTF-Tutor

**Learn the vulnerability. Understand the exploit. Capture the flag.**

Most CTF tools are built to hand you an answer. This one is built to make you
not need it next time.

CTF-Tutor is a local-first CTF assistant that runs entirely on your machine. It
reads a challenge, works out what kind of problem it is, digs through a library
of patterns it already knows, forms ranked guesses, tests them with local
analysis tools, and then — the important part — explains what it found and asks
you the questions that would have gotten you there yourself.

It will not solve challenges for you. It will not submit flags. It will not
touch a system you haven't pointed it at. That's a deliberate design choice, not
a missing feature.

```bash
python main.py agent "A login portal issues JWTs and the admin panel trusts the role claim."
```

---

## Why this exists

The fastest way to get worse at CTFs is to read a writeup the moment you're
stuck. You get the flag and you learn nothing, because the insight arrived
fully formed instead of being something you built.

But sitting stuck for six hours isn't learning either. It's just being stuck.

CTF-Tutor tries to sit in the gap. It'll tell you *which class of problem*
you're staring at before it tells you *where to look*, and it'll tell you that
before it tells you *what to run*. Six levels of hint, and you choose how far
down you go. It tracks what you've genuinely understood versus what you needed
hand-holding for, and it plans your next session around the difference.

> **Don't just solve the challenge. Understand why the solution works.**
>
> A good tutor makes itself less necessary over time.

---

## What you get

**A real agent, not a prompt wrapper.** It holds state, ranks competing
hypotheses with confidence scores, plans which tool to reach for, observes the
result, updates its beliefs, and verifies before concluding. Every step lands in
a JSONL trace you can read back.

**It works with the network off.** Ollama makes it smarter, but nothing
*requires* it. No API key, no account, no telemetry. If the model is down the
agent falls back to heuristics and keeps going.

**Knowledge it can actually search.** 45 curated archive entries plus a
560-card study corpus covering 118 techniques, across pwn, reverse engineering,
web, crypto, forensics, OSINT, misc, blockchain, and mobile. Hybrid retrieval
(lexical BM25 always, vectors when available) with a reranking stage that
diversifies results so you get three different ideas rather than three
paraphrases of one.

**A tutor that adapts.** A skill graph of technique prerequisites, six hint
levels, Socratic prompts, a misconception engine that catches the beliefs
quietly costing you hours, and a curriculum that schedules repairs before new
material.

**Safety that's actually load-bearing.** Tool permission tiers, no-shell
subprocesses with timeouts and resource limits, prompt-injection filtering on
untrusted challenge text, secret redaction in logs, optional Docker isolation,
and online research off by default.

---

## Getting started

You need Python 3.10+. Everything else is optional.

```bash
pip install -r requirements.txt
```

For the smarter path, install [Ollama](https://ollama.com/) and pull two models:

```bash
ollama pull qwen3:8b
ollama pull nomic-embed-text
```

Then index the archive and take it for a spin:

```bash
python ingest.py
python main.py agent "A binary reads input with gets() into a 64-byte buffer and there's a win() function."
```

Want to change defaults? `cp .env.example .env`. Every setting has a sane
default, so an empty file works fine.

---

## The commands you'll actually use

### Investigate a challenge

```bash
python main.py agent "JWT login accepts alg=none"
python main.py agent --path ./challenge_files --hint-level 3 "Something's hidden in this image"
python main.py agent --fetch owner/repo/path "Analyse this"
```

The agent triages any files you point it at, forms hypotheses, runs safe local
analysis, and finishes with a teaching block. `--hint-level` (1–6) controls how
much it gives away:

| Level | What you get |
|---|---|
| 1 | Concept — what *class* of problem this is |
| 2 | Direction — where to look |
| 3 | Tool class — what kind of thing to run |
| 4 | Partial technique |
| 5 | Ordered walkthrough |
| 6 | Full conclusion (only when you ask) |

### Find out what to study next

```bash
python main.py curriculum
python main.py curriculum --goal ret2libc
python main.py curriculum --stuck        # last attempt went badly, ease off
```

Reads your actual history and builds a plan. If you ask for `ret2libc` and
haven't got `stack-buffer-overflow` down yet, it'll schedule that first — plus
`c-memory` and `stack-layout` underneath it. Misconceptions get repaired before
anything new gets introduced, because building on a broken foundation is worse
than building slowly.

### See how challenges relate

```bash
python main.py graph "ret2libc"
python main.py graph --path stack-buffer-overflow ret2libc
python main.py graph --stats
```

Answers the two questions you actually have when you're stuck: *what's an easier
version of this?* and *what should I try now that I've got it?*

### Search the archive

```bash
python main.py search "jwt alg none bypass"
python main.py search "rsa small e" --category crypto -n 3
python main.py search "stack overflow" --category pwn --difficulty easy
```

### Check your progress

```bash
python main.py history --summary
```

Technique frequency and average hint depth per technique — a decent proxy for
which things you're leaning on help for.

### Everything else

```bash
python main.py chat "Why does JWT algorithm confusion happen?"
python main.py generate "A beginner JWT validation challenge"
python main.py list --category crypto
python main.py fetch --search "picoctf"
python main.py session create polyglot --language rust
python main.py webui                     # http://127.0.0.1:8765
```

`python main.py --help` has the full list.

---

## Keeping it honest

A tutor that quietly teaches you wrong things is worse than no tutor. Three
commands exist purely to keep that from happening.

### Audit the archive

```bash
python main.py audit --sync
python main.py audit --strict     # non-zero exit if anything's wrong (for CI)
```

Validates every entry, tracks where each piece of knowledge came from and how
trustworthy that source is, versions entries by content hash so edits are
visible instead of silent, and flags **contradictions** — two entries that make
opposing claims about the same technique. When two entries disagree, source
trust decides which one wins.

### Rebuild the corpus

```bash
python main.py corpus --min 500
```

Generates the study corpus from `data/technique_library.json`. Five kinds of
card, each doing a different job:

| Card kind | Count | What it's for |
|---|---:|---|
| scenario | 251 | The same idea wearing a different disguise |
| discrimination | 111 | Telling two easily-confused techniques apart |
| concept | 61 | What this technique *is* |
| triage | 61 | Given these signals, what do you check first |
| prerequisite | 31 | The foundations underneath |
| archive | 45 | Hand-written curated entries |

It's deterministic, so evaluation stays comparable across machines and commits.

### Look at the results

```bash
python main.py dashboard --eval --trace
```

Writes two self-contained HTML files to `data/reports/` — no server, no CDN,
just open them. One is a benchmark dashboard (accuracy, difficulty × category
matrix, corpus health, archive issues). The other is a trace viewer that walks
you through an agent run step by step, so when it goes somewhere strange you can
see exactly where it turned.

---

## Evaluation

```bash
python -m agent.eval_agent
python main.py experiment --benchmark
python main.py experiment --ablation
```

The offline evaluator runs 20 ground-truth cases with no Ollama and no vector
store, using heuristic seeding and lexical retrieval. On the shipped set it gets
**90% category accuracy** and a **95% technique hit rate**.

Read that number for what it is: a regression check on a small local set, not a
claim about solving real contest challenges. It exists to tell you when a change
broke something. The ablation harness compares the full agent against
`no_tools`, `no_retrieve`, and `classify_only` variants so you can see which
parts are pulling weight.

---

## Extending it

Drop a `.py` file in `plugins/` that exports `register(api)`:

```python
def _check(args):
    text = args.get("text", "")
    return True, f"saw {len(text)} characters", ""   # (ok, output, error)

def register(api):
    api.describe(version="1.0.0", description="What this plugin does")
    api.register_tool("check", _check, description="...", category_tags=["web"])
```

```bash
CTF_TUTOR_ENABLE_PLUGINS=1 python main.py plugins
```

Tools get namespaced (`yourplugin.check`) so nothing can shadow a built-in,
permissions are clamped to ANALYSIS at most no matter what a plugin asks for,
and a handler that raises gets caught and reported rather than ending your run.
Plugins are off by default because "drop a file in a folder and it executes"
should never be silent. See `plugins/example_flagcheck.py` for a working one.

---

## How it fits together

```
                    Challenge (+ optional files)
                              │
                              ▼
                   ┌──────────────────────┐
                   │ Triage               │  inventory, magic bytes,
                   │                      │  category hints
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ AgentState           │  facts + ranked hypotheses
                   └──────────┬───────────┘
                              ▼
        ┌─────────────────────────────────────────────┐
        │  Loop (budgeted)                            │
        │    plan  →  execute  →  observe  →  update   │
        │    permission-gated, sandboxed, traced      │
        └─────────────────────┬───────────────────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Verify               │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Teach                │  Socratic prompts,
                   │                      │  staged hints,
                   │                      │  prerequisites,
                   │                      │  misconception repair
                   └──────────┬───────────┘
                              ▼
              workspace + learner memory + trace
```

`ARCHITECTURE.md` has the full module table and safety model.

---

## Project layout

```text
CTF-tutor/
├── agent/                    # the agent and tutor
│   ├── loop.py               #   closed-loop orchestration
│   ├── state.py              #   working memory
│   ├── hypothesis.py         #   ranked claims with confidence
│   ├── planner.py            #   which tool next
│   ├── executor.py           #   local tool runners
│   ├── observer.py           #   evidence extraction
│   ├── verifier.py           #   independent check
│   ├── triage.py             #   artifact inventory
│   ├── hybrid_retrieve.py    #   lexical + vector search
│   ├── rerank.py             #   second-stage scoring + diversity
│   ├── challenge_graph.py    #   how challenges relate
│   ├── skill_graph.py        #   technique prerequisites
│   ├── curriculum.py         #   personalised plans, adaptive difficulty
│   ├── misconception.py      #   detect and repair wrong beliefs
│   ├── teaching.py           #   Socratic prompts + hint levels
│   ├── memory.py             #   learner mastery stats
│   ├── provenance.py         #   sources, versions, contradictions
│   ├── corpus_builder.py     #   builds the 560-card corpus
│   ├── dashboard.py          #   HTML reports + trace viewer
│   ├── plugins.py            #   third-party toolkit loading
│   ├── providers.py          #   Ollama / OpenAI-compatible + failover
│   ├── permissions.py        #   tool capability tiers
│   ├── security.py           #   injection filtering, redaction
│   ├── sandbox.py            #   resource-limited subprocesses
│   └── eval_agent.py         #   offline metrics
├── tools/                    # passive analysis toolkits
├── data/
│   ├── archive/              #   45 curated entries
│   ├── corpus/               #   560 generated study cards
│   ├── technique_library.json#   61 techniques, 251 scenarios
│   ├── technique_vocab.json  #   canonical technique tags
│   ├── eval/ground_truth.json#   20 evaluation cases
│   └── provenance.json       #   where each entry came from
├── plugins/                  # your extensions
├── tests/                    # 355 tests
├── webui/                    # local web UI
└── main.py                   # CLI
```

Your personal state — history, learner memory, sessions, traces, reports, the
vector store — stays local and gitignored. It's yours.

---

## Analysis toolkits

All passive, all local. They read files; they don't attack anything.

| Module | What it inspects |
|---|---|
| `static_analysis.py` | Dispatches by challenge category |
| `web_recon.py` | Frameworks, JWTs, headers, auth patterns — no HTTP requests |
| `crypto_toolkit.py` | Hashes, algorithms, RSA parameters, ciphertext structure |
| `forensics_toolkit.py` | Local forensic file inspection |
| `osint_toolkit.py` | Metadata and manual-OSINT guidance |
| `decode_toolkit.py` | Base64, hex, URL, ROT, XOR, gzip, recipe chaining |
| `xor_crack.py` | XOR key recovery (with an optional Rust backend) |
| `ghidra_headless.py` | Ghidra decompilation, if you have it installed |

```bash
python -m tools.decode_toolkit "ZmxhZ3t0ZXN0fQ=="
python -m tools.web_recon ./app.py
python -m tools.crypto_toolkit ./ciphertext.txt
```

Set `GHIDRA_INSTALL_DIR` and pass `--decompile` to use Ghidra. Without it, that
feature degrades quietly rather than becoming mandatory.

---

## Development

```bash
python -m pytest -q              # 355 tests
python -m compileall -q .        # syntax check
python main.py audit --strict    # archive quality gate
```

CI runs all four of those plus a corpus build and the offline evaluator, and
uploads the dashboard as an artifact.

Optional toolchains (Ghidra, Rust, Java, .NET) aren't installed everywhere, so
their paths need testing separately when you have them.

---

## Where it stands

Honest status: this is a **working local agent and tutor**, with the seven-phase
roadmap now substantially complete.

| Phase | Focus | Status |
|---|---|---|
| 1 | Agent core — state, hypotheses, planning, tools, verification | Done |
| 2 | Measurable — benchmark, ablation, difficulty matrix, CI, dashboard | Done |
| 3 | CTF strength — triage, hybrid retrieval, reranking, challenge graph | Done |
| 4 | Tutor — skill graph, hints, Socratic, curriculum, misconceptions | Done |
| 5 | Robust — sandbox, permissions, injection defence, provider failover | Done |
| 6 | Knowledge scale — 500+ cards, provenance, versioning, contradictions | Done |
| 7 | Professionalize — plugins, web UI, experiments, dashboard, trace viewer | Mostly |

**Still open, and worth being clear about:**

- The corpus is high-quality *pattern* knowledge, not 500 real contest
  writeups. Those are a different and much harder acquisition problem.
- No public benchmark integration or multi-model comparison yet.
- Deep language-specific reverse engineering and fully dynamic web/crypto
  interaction remain shallow.
- No research paper.

The highest-value next step is a locked regression benchmark on real tasks. The
offline numbers above measure consistency, not capability, and it'd be
dishonest to pretend otherwise.

---

## Safety

CTF challenge files are untrusted input. Analysis may invoke local third-party
tools (`binwalk`, `exiftool`, `objdump`, Ghidra, `tshark`, Volatility) when
they're present. For genuinely untrusted samples, use a disposable VM or
container, keep your tools patched, and cut network access.

The built-in timeouts, output caps, decompression limits, and resource limits
are defence in depth. They are not a substitute for real isolation.

Only use exploitation techniques against systems you own or have explicit
written permission to test.

---

## License and intent

Built for education, CTF competitions, security research, and authorized
testing. If you're using it for anything else, you're using the wrong tool.

Contributions welcome — especially archive entries with real provenance, new
technique library scenarios, and plugins. Run `python main.py audit --strict`
before you open a PR.
