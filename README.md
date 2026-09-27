# CTF-Tutor

## CURRENT (v0.9.2)

| **Item**               | **Value**                                   |
| ---------------------- | ------------------------------------------- |
| Version                | 0.9.2                                       |
| Techniques             | 97                                          |
| External hard (honest) | ~69.6%                                      |
| Evaluation             | `python main.py experiment --benchmark`     |
| Gate                   | `python main.py gate`                       |
| Full CI                | `bash scripts/ci_full.sh`                   |
| Calibration            | `python main.py calibrate`                  |
| Calibration fitting    | `python main.py fit_calibration`            |
| Model comparison       | `python main.py compare_models`             |
| Knowledge audit        | `python main.py knowledge --audit --strict` |
| Web API                | `python main.py serve --port 8765`          |

**Confidence is a heuristic `belief_score`, not a calibrated probability.** Calibration tooling exists, but confidence should not be interpreted as a statistical probability unless a calibrated model and validation set are explicitly being used.

**UNKNOWN / abstain is intentional.** The agent can refuse to make a classification when evidence is insufficient rather than forcing a confident-looking answer.

**Prefer external_hard / held_out over generated benchmarks.** Offline evaluation is a regression signal, not evidence that the system can solve arbitrary real-world CTF challenges.

---

**Learn the vulnerability. Understand the exploit. Capture the flag.**

Most CTF tools are built to hand you an answer. This one is built to make you not need it next time.

CTF-Tutor is a local-first CTF assistant that runs primarily on your machine. It reads a challenge, works out what kind of problem it is, searches a local knowledge base, forms competing hypotheses, tests them with local analysis tools, and then — the important part — explains what it found and asks the questions that would have gotten you there yourself.

It will not submit flags. It will not silently attack arbitrary systems. It does not treat an uncertain classification as a fact. Those are deliberate design choices, not missing features.

```bash
python main.py agent "A login portal issues JWTs and the admin panel trusts the role claim."
```

---

## Why this exists

The fastest way to get worse at CTFs is to read a writeup the moment you're stuck. You get the flag and you learn nothing, because the insight arrived fully formed instead of being something you built.

But sitting stuck for six hours isn't learning either. It's just being stuck.

CTF-Tutor tries to sit in the gap. It'll tell you *which class of problem* you're staring at before it tells you *where to look*, and it'll tell you that before it tells you *what to run*. Six levels of hint, and you choose how far down you go.

The current agent also tracks uncertainty explicitly. It can retrieve evidence, compare competing techniques, ask active discriminating questions, abstain from retrieval or classification when evidence is weak, and run independent checks before accepting a conclusion.

> **Don't just solve the challenge. Understand why the solution works.**
>
> A good tutor makes itself less necessary over time.

---

## What you get

**A real agent, not a prompt wrapper.** It holds state, ranks competing hypotheses with `belief_score`, plans which tool to reach for, observes the result, updates its beliefs, and verifies before concluding. Agent activity can be recorded into structured traces so you can inspect what happened instead of treating the model as a black box.

**It works with the network off.** Ollama makes it smarter, but nothing *requires* a paid API. The core system can fall back to deterministic heuristics and local analysis when a model is unavailable.

**Knowledge it can actually search.** The project maintains a canonical technique taxonomy, a local technique library, curated knowledge, derived study material, provenance metadata, and retrieval controls. Lexical retrieval is available locally, while vector retrieval is optional.

**A tutor that adapts.** A skill graph of technique prerequisites, six hint levels, Socratic prompts, learner history, misconception repair, curriculum planning, and transfer-oriented evaluation are all part of the learning layer.

**It knows when not to guess.** UNKNOWN / abstain paths are used when evidence is insufficient. Retrieval can abstain, classification can abstain, and active discriminators can be selected when two techniques remain difficult to distinguish.

**Independent verification.** The agent is designed to separate a hypothesis from verification. Independent checks, evidence requirements, and verification levels help prevent a plausible-looking model answer from becoming an unquestioned conclusion.

**Safety is part of the architecture.** Tool permission tiers, subprocess timeouts, resource limits, archive extraction limits, SSRF restrictions, prompt-injection filtering, secret redaction, optional Docker isolation, and online research controls are treated as load-bearing components rather than documentation-only promises.

---

## Getting started

You need Python 3.10+. Everything else is optional.

```bash
pip install -e .
```

For the smarter local path, install [Ollama](https://ollama.com/) and pull a model:

```bash
ollama pull qwen3:8b
```

For local embeddings, install an embedding model:

```bash
ollama pull nomic-embed-text
```

Then take it for a spin:

```bash
python main.py agent "A binary reads input with gets() into a 64-byte buffer and there's a win() function."
```

Want to change defaults? Copy `.env.example` to `.env`.

```bash
cp .env.example .env
```

The project is designed so the core workflow remains usable without requiring a hosted API.

---

## The commands you'll actually use

### Investigate a challenge

```bash
python main.py agent "JWT login accepts alg=none"
python main.py agent --path ./challenge_files --hint-level 3 "Something's hidden in this image"
python main.py agent --fetch owner/repo/path "Analyse this"
```

The agent triages any files you point it at, forms hypotheses, runs safe local analysis, and finishes with a teaching block. `--hint-level` controls how much it gives away:

| **Level** | **What you get**                          |
| --------- | ----------------------------------------- |
| 1         | Concept — what *class* of problem this is |
| 2         | Direction — where to look                 |
| 3         | Tool class — what kind of thing to run    |
| 4         | Partial technique                         |
| 5         | Ordered walkthrough                       |
| 6         | Full conclusion (only when you ask)       |

### Find out what to study next

```bash
python main.py curriculum
python main.py curriculum --goal ret2libc
python main.py curriculum --stuck
```

Reads your recorded history and builds a study plan around what you've actually done.

If you ask for `ret2libc` and haven't got `stack-buffer-overflow` down yet, the curriculum can put the prerequisite first instead of pretending the missing foundation does not matter.

### See how challenges relate

```bash
python main.py graph "ret2libc"
python main.py graph --path stack-buffer-overflow ret2libc
python main.py graph --stats
```

The graph connects techniques through prerequisites, related techniques, and learning routes.

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

Use the learner and history commands to inspect technique frequency, previous attempts, and hint dependency.

### Compare configured models

```bash
python main.py compare_models
```

This compares model capability profiles without requiring every model to be installed or reachable.

### Inspect confidence and calibration

```bash
python main.py calibrate
python main.py fit_calibration
python main.py diagnose
```

Calibration machinery exists to measure and improve confidence behavior. It does **not** make an arbitrary `belief_score` equivalent to a probability.

### Run performance diagnostics

```bash
python main.py perf
```

### Everything else

```bash
python main.py chat "Why does JWT algorithm confusion happen?"
python main.py generate "A beginner JWT validation challenge"
python main.py list --category crypto
python main.py fetch --search "picoctf"
python main.py session create polyglot --language rust
python main.py serve --port 8765
```

`python main.py --help` has the current command list.

---

## Multi-language sessions

Challenge sessions can execute supported source languages through the sandboxed runner.

Current explicit language support:

| **Language** | **Runtime**      |
| ------------ | ---------------- |
| Python       | `python3`        |
| Rust         | `rustc`          |
| Java         | `javac` / `java` |
| .NET         | `dotnet`         |
| C            | `gcc`            |
| C++          | `g++`            |
| Go           | `go`             |

Example:

```bash
python main.py session create polyglot --language rust
```

Execution is subject to timeouts, output limits, resource limits, and the configured sandbox policy.

---

## Keeping it honest

A tutor that quietly teaches you wrong things is worse than no tutor.

The current system has several mechanisms specifically intended to make that failure visible.

### Audit the knowledge base

```bash
python main.py knowledge --audit
python main.py knowledge --audit --strict
```

The audit checks the relationship between the canonical taxonomy, technique library, corpus metadata, and knowledge graph.

Strict mode is intended to fail CI when the knowledge base contains blocking inconsistencies.

### Rebuild the corpus

```bash
python main.py corpus
```

Study material is derived from the technique library and taxonomy rather than being treated as an unquestionable collection of generated facts.

The system distinguishes between different learning-card purposes, including:

| **Card kind**  | **What it's for**                            |
| -------------- | -------------------------------------------- |
| scenario       | The same idea wearing a different disguise   |
| discrimination | Telling two easily-confused techniques apart |
| concept        | What this technique *is*                     |
| triage         | Given these signals, what do you check first |
| prerequisite   | The foundations underneath                   |
| archive        | Curated knowledge with provenance            |

The exact corpus size is data-dependent and should be checked from the current generated corpus rather than hard-coded into this README.

### Look at the results

```bash
python main.py dashboard --eval --trace
```

The dashboard produces local reports for evaluation and trace inspection. They are intended to make regressions and strange agent behavior easier to inspect.

---

## Evaluation

```bash
python -m agent.eval_agent
python main.py experiment --benchmark
python main.py experiment --ablation
```

The offline evaluator provides a deterministic regression signal for the shipped evaluation set. It does not require Ollama or a hosted model.

For broader capability measurement, the project distinguishes between local evaluation and harder external / held-out evaluation.

The current release reports approximately **69.6% on the external-hard evaluation**.

Read that number for what it is: a measurement on a defined evaluation population, not a claim about solving arbitrary real contest challenges.

The system also supports:

* category classification
* technique classification
* retrieval evaluation
* active discrimination
* abstention / UNKNOWN behavior
* independent verification
* calibration analysis
* model capability comparison
* ablation experiments

The important goal is not to maximize a single benchmark number. It is to make regressions visible and make unsupported confidence harder to hide.

---

## Extending it

Drop a `.py` file in `plugins/` that exports `register(api)`:

```python
def _check(args):
    text = args.get("text", "")
    return True, f"saw {len(text)} characters", ""


def register(api):
    api.describe(
        version="1.0.0",
        description="What this plugin does",
    )
    api.register_tool(
        "check",
        _check,
        description="...",
        category_tags=["web"],
    )
```

Enable plugins explicitly:

```bash
CTF_TUTOR_ENABLE_PLUGINS=1 python main.py plugins
```

Plugins are treated as trusted local Python code. They are not an untrusted plugin sandbox.

Tool names are namespaced so a plugin cannot silently shadow a built-in tool. Plugin failures are reported rather than silently terminating the whole agent run.

Plugins are disabled by default because "drop a file in a folder and execute it" should never be an implicit behavior.

---

## Web interface

The current web architecture is intentionally small:

```text
python main.py serve
        │
        ▼
 agent.http_api
        │
        ├── /health
        ├── /v1/classify
        ├── /v1/route
        ├── /v1/eval
        ├── /v1/triage
        ├── /v1/vision
        ├── /v1/research
        ├── /v1/config
        ├── /v1/models/compare
        ├── /v1/cost
        ├── /v1/languages
        └── /v1/embeddings/info
        │
        ▼
 frontend/index.html
```

Start it with:

```bash
python main.py serve --port 8765
```

By default the server binds to `127.0.0.1`, so it is not exposed to the network unless you explicitly configure it otherwise.

The old `webui/` package is no longer the primary web architecture.

---

## How it fits together

```text
                    Challenge (+ optional files)
                              │
                              ▼
                   ┌──────────────────────┐
                   │ Triage               │
                   │ inventory, metadata, │
                   │ category signals     │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Classification       │
                   │ hypotheses +         │
                   │ belief_score         │
                   └──────────┬───────────┘
                              ▼
        ┌─────────────────────────────────────────────┐
        │ Investigation Loop                          │
        │                                             │
        │ plan → execute → observe → update → verify  │
        │                                             │
        │ permission-gated, sandboxed, traced         │
        └─────────────────────┬───────────────────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Active discrimination│
                   │ or abstain when      │
                   │ evidence is weak     │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Independent Verify   │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │ Teach                │
                   │ Socratic prompts,    │
                   │ staged hints,        │
                   │ prerequisites,       │
                   │ misconception repair │
                   └──────────┬───────────┘
                              ▼
              workspace + learner memory + trace
```

`ARCHITECTURE.md` has the fuller module table and safety model.

---

## Project layout

```text
CTF-tutor/
├── agent/                       # agent, tutor, retrieval, evaluation
│   ├── http_api.py              #   local HTTP API + web handler
│   ├── model_compare.py         #   model capability comparison
│   ├── model_profile.py         #   model capability profiles
│   ├── active_classify.py       #   active classification
│   ├── active_web.py             #   active web discrimination
│   ├── calibration.py            #   calibration machinery
│   ├── calibration_fit.py        #   calibration fitting
│   ├── capability_plan.py        #   capability planning
│   ├── challenge_fetch.py        #   public challenge fetching + archive safety
│   ├── classify_challenge.py     #   challenge classification
│   ├── classify_ensemble.py      #   ensemble classification
│   ├── classify_pipeline.py      #   classification pipeline
│   ├── confidence_policy.py      #   confidence / abstention policy
│   ├── ensemble.py               #   model / heuristic ensemble
│   ├── retrieval_abstain.py      #   retrieval abstention
│   ├── sandbox.py                #   resource-limited execution
│   ├── rev_dynamic_loop.py       #   reverse-engineering loop
│   ├── pwn_exploit_loop.py       #   pwn investigation loop
│   ├── taxonomy.py               #   canonical technique taxonomy
│   ├── tool_result_schema.py     #   structured tool results
│   └── unified_learner_store.py  #   learner state
├── cli/                          # extracted CLI quality / ops commands
├── frontend/
│   └── index.html                # local web interface
├── tools/                        # passive analysis toolkits
├── data/
│   ├── archive/                  # curated knowledge
│   ├── corpus/                   # generated study corpus
│   ├── technique_library.json    # technique definitions
│   ├── technique_vocab.json      # canonical technique tags
│   └── ...                       # local evaluation / runtime data
├── plugins/                      # optional local extensions
├── tests/                        # automated tests
├── scripts/
│   └── release_gate.py           # release / gate checks
├── CHANGELOG.md
├── ARCHITECTURE.md
└── main.py                       # CLI entry point
```

Your personal state — history, learner memory, sessions, traces, reports, and local vector data — stays local and is intended to remain outside the committed source tree.

---

## Analysis toolkits

All passive by default, all local. They read files and artifacts rather than automatically attacking remote systems.

| **Module**             | **What it inspects**                                     |
| ---------------------- | -------------------------------------------------------- |
| `static_analysis.py`   | Dispatches analysis by challenge category                |
| `web_recon.py`         | Frameworks, JWTs, headers, auth patterns                 |
| `crypto_toolkit.py`    | Hashes, algorithms, RSA parameters, ciphertext structure |
| `forensics_toolkit.py` | Local forensic file inspection                           |
| `osint_toolkit.py`     | Metadata and manual-OSINT guidance                       |
| `decode_toolkit.py`    | Base64, hex, URL, ROT, XOR, gzip, chaining               |
| `xor_crack.py`         | XOR key recovery                                         |
| `ghidra_headless.py`   | Ghidra decompilation when installed                      |

Examples:

```bash
python -m tools.decode_toolkit "ZmxhZ3t0ZXN0fQ=="
python -m tools.web_recon ./app.py
python -m tools.crypto_toolkit ./ciphertext.txt
```

Set `GHIDRA_INSTALL_DIR` and pass the relevant decompilation options to use Ghidra. Without it, the rest of the system remains usable.

---

## Security hardening

CTF challenge files and remote resources are untrusted input.

The current release includes several explicit controls:

* archive path traversal protection
* archive member count and extraction-size limits
* compression-ratio checks
* symlink rejection during archive extraction
* SSRF restrictions for network-aware features
* bounded subprocess execution
* CPU and memory limits where supported
* output-size limits
* Docker-backed sandbox execution where available
* prompt-injection filtering for untrusted challenge text
* secret redaction in logs
* plugin permission restrictions
* UNKNOWN / abstain behavior instead of forced classification

These controls are defence in depth. They are not a replacement for a disposable VM or properly isolated environment when analysing genuinely malicious samples.

---

## Development

```bash
python -m pytest -q
python -m compileall -q .
python main.py knowledge --audit --strict
python main.py gate
```

CI runs the automated test suite and release-quality checks.

Optional toolchains such as Ghidra, Rust, Java, .NET, and Docker are not guaranteed to be available on every development machine, so those execution paths should be tested separately when available.

---

## Where it stands

Honest status: this is a **working local CTF agent and tutor**, with the major reliability, knowledge, evaluation, and hardening work substantially implemented.

| **Area**       | **Focus**                                                  | **Status**  |
| -------------- | ---------------------------------------------------------- | ----------- |
| Agent core     | state, hypotheses, planning, tools, verification           | Done        |
| Evaluation     | benchmarks, ablations, regression checks                   | Done        |
| CTF capability | triage, retrieval, classification, challenge relationships | Done        |
| Tutor          | hints, Socratic teaching, curriculum, misconceptions       | Done        |
| Reliability    | abstention, independent checks, retrieval controls         | Done        |
| Security       | sandboxing, SSRF, archive safety, plugin boundaries        | Done        |
| Knowledge      | taxonomy, corpus, provenance, contradiction checks         | Done        |
| Model layer    | profiles, comparison, calibration machinery                | Implemented |
| Web interface  | local HTTP API + frontend                                  | Implemented |
| Multilanguage  | Python, Rust, Java, .NET, C, C++, Go                       | Implemented |

**Still open, and worth being clear about:**

* The corpus is pattern-oriented study knowledge, not a replacement for hundreds of real contest writeups.
* External-hard evaluation is still a bounded benchmark, not a universal measure of CTF-solving ability.
* Deep language-specific reverse engineering remains less mature than the core classification / teaching pipeline.
* Fully dynamic exploitation workflows remain intentionally constrained.
* Calibration machinery exists, but `belief_score` should not be presented as a probability without proper calibration evidence.
* The project still needs broader real-task evaluation before making stronger capability claims.

The highest-value next step is continued evaluation on held-out real tasks and growing the experience-lab layer without turning the project into a flag-solving black box.

---

## Safety

CTF challenge files are untrusted input. Analysis may invoke local third-party tools such as `binwalk`, `exiftool`, `objdump`, Ghidra, `tshark`, or Volatility when they are installed.

For genuinely untrusted samples, use a disposable VM or container, keep your tools patched, and cut network access.

The built-in timeouts, output caps, decompression limits, SSRF restrictions, and resource limits are defence in depth. They are not a substitute for real isolation.

Only use exploitation techniques against systems you own or have explicit written permission to test.

---

## License and intent

Built for education, CTF competitions, security research, and authorized testing.

If you're using it for anything else, you're using the wrong tool.

Contributions welcome — especially:

* archive entries with real provenance
* new technique-library scenarios
* real experience labs
* evaluation cases
* retrieval / classification improvements
* safe plugins
* documentation improvements

Run the relevant quality gates before opening a PR.

© 2026 CTF-Tutor
