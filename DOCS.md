# CTF-Tutor documentation set (item 72)

## Quick start
```bash
pip install -e .
python main.py doctor
python main.py eval --public
python main.py serve --port 8765
```

## Core concepts
- **Local-first**: classification and most tutoring work without a network.
- **Tutor not solver**: hints and evidence, not automatic flag submission.
- **Knowledge graph**: techniques, rubrics, corpus cards under `data/`.

## CLI map
| Command | Purpose |
|---------|---------|
| `agent` | Interactive tutoring loop |
| `eval` | Offline classification accuracy |
| `vision` | Image forensic / optional VL model |
| `route` | Cost-aware model routing |
| `dump_eval` | Public contest-text eval dump |
| `serve` | Local HTTP API (`127.0.0.1`) |
| `knowledge` | Graph audit / taxonomy |
| `doctor` | Tooling capability check |

## HTTP API
See `agent/http_api.py`. Default bind: `127.0.0.1:8765`.

## Configuration
Environment variables are summarised by `GET /v1/config` and `agent/app_config.py`.
Important:
- `CTF_TUTOR_NETWORK=0` (default) — offline
- `CTF_TUTOR_TELEMETRY=0` (default) — no local event log
- `CTF_TUTOR_EMBED_BACKEND=ollama|hash|none`

## Safety
- No paid API required for core operation.
- Telemetry never phones home.
- Fetches respect size limits and treat downloads as untrusted.

## Architecture
See `ARCHITECTURE.md`.
