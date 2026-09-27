# Plugin trust model

## Default
Plugins load **in-process** via `exec_module` with host privileges.
Permission clamps apply only to **registered tool capabilities**.

## Optional process boundary
```bash
python -m agent.plugin_worker --module plugins/foo.py
```
Sends JSON-lines handshake. This is a **process boundary**, not a full OS sandbox.
Prefer Docker for untrusted code.

## Recommendation
Treat third-party plugins as trusted local code, or run under Docker + network off.
