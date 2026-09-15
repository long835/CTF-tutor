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
         → execute (local toolkits / hybrid retrieve / research)
         → observe → update hypotheses
    → Verify
    → Teach (Socratic + progressive hints + skill-graph prereqs)
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
| research | Local archive/concepts + optional web |
| teaching | Socratic + hint levels 1–6 |
| skill_graph | Technique prerequisites |
| memory | Learner mastery stats |
| workspace | Per-challenge files/state |
| permissions | Tool capability levels |
| security | Injection filter + secret redaction |
| providers | Ollama / OpenAI-compatible local |
| tools_registry | Plugin tool specs |
| trace | JSONL audit log |
| eval_agent | Offline category/technique metrics |

## Safety
- Challenge/tool text is untrusted; sanitized before LLM prompts.
- Default max permission = ANALYSIS (no arbitrary binary exec).
- Subprocess: no shell, timeouts, rlimits; Docker helper is network=none.
- Online research off by default (`CTF_TUTOR_ONLINE_RESEARCH=0`).

## CLI
```bash
python main.py agent "challenge text"
python main.py agent --path ./chal --hint-level 3 "..."
python -m agent.eval_agent
python -m pytest -q
```

## Config
```
OLLAMA_BASE_URL / OLLAMA_MODEL / OLLAMA_EMBED_MODEL
LLM_PROVIDER=ollama|openai_compatible
LLM_BASE_URL=http://localhost:8080/v1
CTF_TUTOR_ONLINE_RESEARCH=0
CTF_TUTOR_MAX_WORKERS=4
```

## Public challenge import
`agent/challenge_fetch.py` downloads public GitHub trees or zip archives into `data/workspaces/<id>/input/` with size/file limits and zip-slip protection. Use only public educational material.
