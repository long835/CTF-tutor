# Data layout (P0)

## Package resources (shipped with the code)
- `data/technique_library.json`
- `data/technique_vocab.json`
- `data/provenance.json`
- `data/archive/*.json` (curated patterns)
- `data/corpus/challenges.jsonl` (derived study cards)
- `data/eval/*.json`
- `data/samples/experience/**` (labs)

These should be read-only from the package perspective.

## Runtime mutable data (created on the machine)
- `data/workspaces/` — per-challenge agent workspaces
- `data/sessions/`
- `data/learner_memory.json` / `data/learner_attempts.json`
- `data/spaced_repetition.json`
- `data/cost_ledger.jsonl` / telemetry

## Install modes
| Mode | Behavior |
|------|----------|
| Source checkout | All paths relative to repo root |
| `pip install -e .` | Same; PYTHONPATH/repo root |
| `pip install .` wheel | Package data via importlib.resources where declared in pyproject; runtime dirs created under CWD or XDG later |

**Current rule:** prefer running from the repo root with `PYTHONPATH=.`.
