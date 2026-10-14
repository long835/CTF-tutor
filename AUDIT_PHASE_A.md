# CTF-Tutor Phase A Audit Report

This file records the initial Phase A audit actions, findings, and immediate next steps.

What I did so far (evidence-backed):
- Created branch: `improve/audit-phaseA` (branch created from default `main`).
- Enumerated top-level repository contents and inspected core files: README.md, ARCHITECTURE.md, main.py, pyproject.toml, requirements.txt, and GitHub Actions workflows.
- Listed and sampled `agent/` and `tools/` packages to understand runtime structure and available toolkits.
- Read `.github/workflows/agent-ci.yml` to determine CI expectations (syntax check, tests, quality gates, corpus build, offline eval, dashboard generation).

High-level findings (Phase A):
1. Project scope and architecture
   - Local-first CTF tutoring agent with closed-loop agent (triage → plan → execute → observe → verify → teach).
   - Substantial agent code in `agent/` (~100+ modules) and local analysis toolkits in `tools/`.
   - Knowledge corpus and archive under `data/` with provenance and evaluation assets.

2. Safety & trust boundaries
   - Plugins: `plugins/` loads arbitrary local Python files by `agent.plugins` and are off by default (`CTF_TUTOR_ENABLE_PLUGINS=0`) — current model trusts local files when enabled. This is a security boundary requiring hardening (sandboxing, signing, capability limits, or running untrusted plugins in subprocesses/containers).
   - Tool execution: agent has sandboxing helpers (`agent/sandbox.py`, `agent/docker_sandbox.py`) and claims "no shell, timeouts, rlimits", but this must be verified; any subprocess wrappers must ensure no accidental shell=True, safe argument handling, and strict resource limits.

3. Reproducibility & CI
   - CI requires tests, archive audits, a corpus build min of 500 cards, offline eval and dashboard generation. These heavy gates may fail in many contributor environments (lack of optional deps like chromadb, Ollama models, Ghidra). The repo already accounts for graceful degradation in code, but CI may still be brittle for external-dependency-free runs.

4. Dependencies & optional features
   - `requirements.txt` lists core runtime deps (requests, python-dotenv) and comments optional packages; `pyproject.toml` declares optional extras for `vector`, `ingest`, and `full`.
   - Tests may assume additional optional packages; CI currently installs only `requirements.txt` (no optional extras).

5. Immediate high-risk issues to address first (prioritised):
   A. Plugin sandbox & execution safety (security risk — high)
   B. CI brittleness: heavy gates that require optional external tools or network (moderate-high)
   C. Missing quick local developer checks and documented minimal setup (low-medium)
   D. Verification & provenance enforcement: ensure retrieved content can't claim verification without independent checks (medium)

Reproducible blockers identified now:
- I cannot run the test suite or CI from this environment (no shell to execute the code, limited environment). That _is_ a blocker for dynamic validation — recorded as external to this audit.

Immediate, safe changes committed in this branch:
- Added a developer helper script `scripts/verify_env.py` that checks the local environment for required and optional tools and prints actionable guidance. This is a non-invasive dev tool (no runtime change) to help contributors reproduce the CI environment locally.
- Added this audit report file (`AUDIT_PHASE_A.md`) in the branch.

Next high-value actions (short list):
1. Harden plugin loading paths and implement optional sandboxing via subprocess/container or import-time capability clamp. Produce a minimal POC that loads plugins in a restricted subprocess and communicates via JSON over STDIN/STDOUT.
2. Make CI gates more contributor-friendly: split CI into "fast" and "full" pipelines. Fast pipeline: syntax check + unit tests where possible, audit only a lightweight check, skip corpus build/dashboard. Full pipeline run on schedule or when explicitly requested.
3. Add targeted regression tests for sandboxing, plugin loading, and a small set of agent loop unit tests that do not require optional external tools.
4. Implement provenance and verification hardening: mark retrieved materials as "untrusted" until verified by `agent.verifier` and ensure LLM-generated text cannot be treated as verified evidence.
5. Incrementally add adapters for pwn tooling (detect gdb/pwntools availability, add wrapper modules that run in sandboxed subprocesses, and add test fixtures for pwn cases under `tests/fixtures/pwn/`).

Files added in branch `improve/audit-phaseA`:
- scripts/verify_env.py
- AUDIT_PHASE_A.md

If you want me to continue now I will:
- Implement a safe plugin loader POC (sandbox subprocess) and tests, or
- Split CI into fast/full pipelines and update `.github/workflows/agent-ci.yml` to be less brittle, or
- Create a small, runnable pwn test fixture and a minimal harness that exercises `agent.triage` and `agent.loop` without optional deps.

I will proceed with 