# CTF-Tutor Architecture

## Goal
Local-first CTF tutoring agent: investigate, hypothesize, use tools, verify, teach.
No paid APIs required. Ollama (or OpenAI-compatible local server) optional for richer LLM steps.

## Pipeline

```
Challenge (+ optional --path)
    → Triage (inventory, magic, category hints)
    → AgentState bootstrap (facts, offline/LLM hypotheses)
    → Loop (budgeted steps):
         plan tool (permission-gated)
         → execute (local toolkits / hybrid retrieve + rerank / research)
         → observe → update hypotheses
    → Verify
    → Teach (Socratic + progressive hints + skill-graph prereqs
             + misconception repair)
    → Persist workspace + learner memory + trace
```

## Packages (`agent/`)
| Module | Role |
|--------|------|
| state | Working memory |
| hypothesis | Generate/update ranked claims |
| planner | Next safe tool |
| executor | Local tool runners |
| observer | Evidence extraction |
| verifier | Independent check |
| loop | Closed loop orchestration |
| triage | Artifact inventory |
| sandbox / docker_sandbox | Resource limits / optional containers |
| hybrid_retrieve | Lexical (+ vector) archive search |
| rerank | Second-stage scoring + MMR diversity |
| challenge_graph | How challenges relate: warm-ups, next steps, routes |
| research | Local archive/concepts + optional web |
| teaching | Socratic + hint levels 1–6 |
| skill_graph | Technique prerequisites |
| curriculum | Personalised plans + adaptive difficulty |
| misconception | Detects and repairs wrong-but-common beliefs |
| memory | Learner mastery stats |
| workspace | Per-challenge files/state |
| permissions | Tool capability levels |
| security | Injection filter + secret redaction |
| providers | Ollama / OpenAI-compatible local, with failover chain |
| tools_registry | Tool specs |
| plugins | Third-party toolkit loading (sandboxed permissions) |
| provenance | Source tracking, versioning, contradiction detection |
| corpus_builder | Generates the 500+ card study corpus |
| trace | JSONL audit log |
| eval_agent | Offline category/technique metrics |
| dashboard | Self-contained HTML reports + trace viewer |

## Safety
- Challenge/tool text is untrusted; sanitized before LLM prompts.
- Default max permission = ANALYSIS (no arbitrary binary exec).
- Subprocess: no shell, timeouts, rlimits; Docker helper is network=none.
- Online research off by default (`CTF_TUTOR_ONLINE_RESEARCH=0`).

## CLI
```bash
python main.py agent "challenge text"
python main.py agent --path ./chal --hint-level 3 "..."
python main.py curriculum --goal ret2libc
python main.py graph "ret2libc"
python main.py audit --sync --strict
python main.py dashboard --eval --trace
python -m agent.eval_agent
python -m pytest -q
```

## Config
```
OLLAMA_BASE_URL / OLLAMA_MODEL / OLLAMA_EMBED_MODEL
LLM_PROVIDER=ollama|openai_compatible
LLM_BASE_URL=http://localhost:8080/v1
LLM_PROVIDER_FALLBACK=openai_compatible,offline
CTF_TUTOR_ONLINE_RESEARCH=0
CTF_TUTOR_MAX_WORKERS=4
CTF_TUTOR_ENABLE_PLUGINS=0
```
See `.env.example` for the full list.

## Knowledge pipeline
```
data/technique_library.json  (61 techniques, 251 scenarios)
          │
          ├─► corpus_builder ─► data/corpus/challenges.jsonl  (560 cards,
          │                      5 card kinds, 118 techniques)
          │
data/archive/*.json  (45 curated entries)
          │
          ├─► provenance ─► data/provenance.json  (source, version, history)
          │                 + contradiction detection across shared techniques
          │
          └─► ingest.py ─► data/chroma/  (vector store, optional)
```

## Plugins
A plugin is a `.py` file in `plugins/` exporting `register(api)`. Tools are
namespaced (`myplugin.mytool`), permission-clamped to ANALYSIS at most, and
wrapped so a raising handler cannot end a run. Off unless
`CTF_TUTOR_ENABLE_PLUGINS=1`.

## Public challenge import
`agent/challenge_fetch.py` downloads public GitHub trees or zip archives into `data/workspaces/<id>/input/` with size/file limits and zip-slip protection. Use only public educational material.
