## 0.3.2 — multilang runners, cost meters, research tiers, richer UI

- Multilang: C, C++, Go compile-and-run with resource limits.
- Cost meters + ledger (`main.py cost`, `GET /v1/cost`).
- Research: domain-based source tier ranking.
- WebUI: eval, model compare, cost, languages, embeddings.

## 0.3.1 — HTTP API, embeddings, compare, config, telemetry

- Local HTTP API on 127.0.0.1 (`main.py serve`) wrapping core_api.
- Embedding backend separation (`ollama` | `hash` | `none`).
- Model comparison harness (`main.py compare`).
- Central `app_config`, opt-in local telemetry, resource-aware concurrency.
- research_safe, external provenance, offline ingest policy, DOCS.md.
- Web UI talks to API; multilang list includes c/cpp/go.

## 0.3.0 — contest dump, vision, cost routing, core API

- `agent/contest_eval_dump.py`: 30 public-contest-style cases; public eval 50/50.
- `agent/vision.py`: offline PNG LSB / magic hints; optional Ollama vision models.
- `agent/cost_router.py`: local-first task routing (classify stays heuristic).
- `agent/core_api.py`: library surface for classify / route / eval / triage.
- CLI: `main.py vision`, `route`, `dump_eval`.

## 0.2.1 — knowledge depth, blind eval, packaging

- Technique library and evidence rubrics expanded to 97 (taxonomy gap closed).
- Corpus rebuilt to 857 cards; freshness fields on cards and archive entries.
- Blind eval sets: independent (30) and public-contest-grounded (20); both 100% on formal classifier.
- `main.py eval` / `eval.py --independent` / `--public`.
- Packaging: `pyproject.toml` v0.2.1 with optional `[vector]`, `[ingest]`, `[full]`.
- Offline PNG LSB stego hint when zsteg/steghide absent.

# Changelog

## Phase 4 — Hardening

Items 8, 13, 22, 45, 46, 62, 63. The hardest remaining items, chosen because
each is a place where a confident wrong answer is worse than no answer.

### New modules
- `agent/classify_challenge.py` — weighted-signal classification producing a
  full `ChallengeProfile` (category + confidence + the signals behind it,
  runner-up, artifact kinds, candidate techniques, tool shortlist). Artifact
  kinds outrank prose; an evidence floor keeps scattered weak matches from
  naming a specialised category. **11/20 → 20/20** on the eval set (in-sample).
- `agent/trust.py` — ordered trust levels (SYSTEM > DEVELOPER > USER > TOOL >
  CHALLENGE > RETRIEVED > WEB) enforced in `PromptBuilder`: content below USER
  cannot occupy instruction position, data is fenced with a per-prompt nonce,
  and injection attempts are recorded rather than silently filtered. Plus the
  artifact threat model — traversal, symlink escape, decompression bombs,
  oversized files, unsafe tool arguments.
- `agent/flag_check.py` — flag grading by provenance, decoy markers, stated
  format and optional reproduction, returning REPRODUCED / VERIFIED /
  PLAUSIBLE / FORMAT_ONLY / DECOY / REJECTED. `verify_solution_steps` requires
  technique support, a verified flag and reproducible steps together.
- `agent/adversarial.py` + `data/eval/adversarial.json` — 15 cases across 9
  trap types, scored on trap avoidance and overclaim rate rather than solve
  rate. **10/15 → 15/15 avoided**, overclaim rate 27% → 0%.

### Changed
- `agent/sandbox.py` — `SandboxPolicy` with four tiers (inspect / analyse /
  debug / hostile) separating filesystem, network, process and resource
  limits. Fails closed on an unresolvable command, a working directory outside
  the allowed roots, a network tool under a DENY policy, and a null byte in
  arguments. `network=DENY` unshares the network namespace where the kernel
  allows it, and says which enforcement you got. An unknown tier gets the
  tightest policy, not the default.
- `agent/verifier.py` — the flag early-accept path is gone. Anything
  flag-shaped used to return `pass` at 0.9 confidence.
- `agent/observer.py` — grades a flag before adopting it.
- `agent/loop.py` — formal classification at bootstrap, trust gate on tool
  arguments before launch, injection attempts surfaced as a lesson.
- `agent/evidence.py` — contradicting signals for `format-string` and
  `stack-buffer-overflow` rephrased as patterns.
- `eval.py` — `--classifier {formal,heuristic}` so the difference stays
  measurable.
- `main.py` — new `adversarial` and `trust` subcommands.

### Fixed
Three defects the adversarial suite found on its first run, and two of my own:
- The observer adopted the first flag-shaped string it saw, so a planted decoy
  won every time.
- `invented_tool_output` scanned `state.lessons`, reading "run checksec first"
  as a claim that checksec had run.
- A contradicting signal was a literal sentence, so natural rephrasing slipped
  past and a refuted hypothesis stayed live at 0.98 confidence.
- The trust gate rejected the user's own challenge directory (root was
  hardcoded to the workspace).
- The argument check rejected shell metacharacters in free-text payloads,
  where no shell is involved.

### Tests
- `tests/test_hardening_phase4.py` — 62 tests. Suite total: 530 → 592.


## Phase 3 — Evaluation, replay and diagnostics

Items 18, 19, 21, 26, 27, 42, 43, 44, 54, 55, 56, 59, 60, 64, 65.

### New modules
- `agent/replay.py` — `RunRecord`, `Recorder`, `ReplayExecutor`, `diff_records`.
  A run is captured completely enough to re-run offline with no tools, no
  network and no model; `diff_records` reports whether a code change altered
  the reasoning and whether it regressed.
- `agent/metrics.py` — efficiency metrics, hallucination detection (invented
  flags, invented tool output, unsupported techniques, overconfidence), and the
  12-axis dimension scorecard.
- `agent/retrieval_eval.py` — Recall@K, Precision@K, MRR, nDCG@K, plus
  `leakage`, `check_contamination`, `split_by_family` for keeping evaluation
  answers out of the corpus.
- `agent/doctor.py` — tiered environment probe (core / model / analysis / dev /
  gpu) that reports missing tooling as degraded challenge *categories*.
- `agent/difficulty.py` — difficulty measured from six observable factors
  instead of taken from a label.

### Changed
- `agent/writeup.py` rewritten: provenance per claim, what was ruled out and
  why, honest verification section, unsupported-claim section, cost.
- `agent/loop.py` — the executor is now injectable, which is what makes both
  deterministic replay and end-to-end testing possible.
- `main.py` — new `doctor`, `replay` and `metrics` subcommands.
- `data/eval/ground_truth.json` — two contaminated cases rewritten.

### Fixed
- Plateau recovery re-opened the same alternative hypotheses every step:
  the dedupe compared the raw suggestion against the stored statement, which
  carries a prefix, so it never matched.
- The shipped evaluation set was contaminated by its own corpus (`web-jwt` 74%,
  `pwn-bof` 41% shingle overlap with archive cards they were copied from).
  Both rewritten independently with labels unchanged. Both now fail
  classification, so the previous score was partly measuring memorisation.

### Tests
- `tests/test_reasoning_phase2.py` — 58 tests for the Phase 2 reasoning layer.
- `tests/test_e2e_agent.py` — 19 end-to-end, replay and regression tests, with
  `FIXED_CASES` as a permanent record of every bug found so far.
- `tests/test_eval_infra.py` — 47 tests for the evaluation layer, including one
  that fails if the shipped evaluation set becomes contaminated again.
- Suite total: 406 → 530.


## Roadmap completion pass

Closed out the remaining items from the seven-phase roadmap in the README, and
fixed one real bug found along the way.

### Fixed

**13 of 45 archive entries were never being indexed.** Those entries used an
older field shape (`approach` / `tools` instead of `explanation` /
`solve_steps` / `tools_used`). `ArchiveEntry.load()` raised a `TypeError` on
each of them, and `Retriever.index_directory()` caught the exception and moved
on — so roughly a third of the archive was silently absent from the vector
store, with only a `skipped ...` line in the output to show for it.

Two-part fix: `ArchiveEntry.from_dict()` now maps legacy field aliases and
preserves unrecognised keys in `notes` instead of raising, and the 13 affected
files were migrated to the canonical shape. All 45 entries now load and pass
validation. `python main.py audit --strict` is the regression guard.

### Added

**Retrieval reranking** (`agent/rerank.py`) — Phase 3. A second stage over
first-stage results scoring seven explainable features (technique overlap,
category agreement, difficulty proximity, vocabulary expansion, unmet
prerequisites, novelty, base score) followed by MMR diversification. Wired into
`hybrid_search()`, which now retrieves a wider pool to give the reranker room.
Personalised when a `LearnerMemory` is passed. Falls back silently on any error.

**Challenge graph** (`agent/challenge_graph.py`) — Phase 3. Weighted graph over
archive plus corpus, with edges from shared techniques, shared category,
adjacent difficulty, and skill-graph prerequisites. Answers "what's an easier
version of this?", "what should I try next?", and shortest path between two
challenges. Exports JSON and Graphviz DOT.

**Misconception engine** (`agent/misconception.py`) — Phase 4. Replaces five
keyword pairs with a catalogue of 12 misconceptions, each carrying triggers,
strong phrases, negations, a correction, a Socratic probe, and linked review
concepts. Detection is graded by confidence and suppressed by negation, so
"base64 is just encoding, not encryption" correctly fires nothing. Surfaced
through `teaching_report()`; the old `detect_misconceptions()` still works.

**Personalised curriculum** (`agent/curriculum.py`) — Phase 4. Reads learner
memory, skill graph, challenge graph, and open misconceptions into an ordered
plan with adaptive difficulty. Repairs before advancing, never schedules a
technique whose prerequisites are unmet, and states its reasoning per lesson.

**Provider failover** (`agent/providers.py`) — Phase 5. `FailoverProvider` tries
providers in order with per-provider cooldowns and a health report, terminating
in an `OfflineProvider` that returns empty rather than raising — which drops the
agent back to its heuristic path instead of ending the session. Configured via
`LLM_PROVIDER_FALLBACK`. Unchanged behaviour when unset.

**Provenance, versioning, contradiction detection** (`agent/provenance.py`) —
Phase 6. Source tiers with trust ranking, content-hash versioning with history
(bookkeeping fields excluded so re-saves don't create phantom versions), and
detection of opposing claims between entries sharing a technique. Sidecar index
at `data/provenance.json` keeps archive JSON clean.

**Corpus rebuild** (`agent/corpus_builder.py`, `data/technique_library.json`) —
Phase 6. The old builder padded to its target by appending "(v2)", "(v3)" to the
same template. Replaced with a 61-technique, 251-scenario library generating
**560 distinct cards** across five kinds — concept, scenario, triage,
discrimination, prerequisite — covering 118 techniques. Deterministic, so
evaluation stays comparable across machines. `min_entries` is now a floor to
report against rather than a target to pad toward.

**Dashboard and trace viewer** (`agent/dashboard.py`) — Phase 7. Two
self-contained HTML files, no CDN and no server. The dashboard shows accuracy,
the difficulty × category matrix, corpus composition, archive issues, and recent
runs. The trace viewer walks an agent run step by step with hypotheses and
confidences promoted out of the raw payload.

**Plugin system** (`agent/plugins.py`, `plugins/example_flagcheck.py`) — Phase
7. A plugin is a `.py` file exporting `register(api)`. Tools are namespaced so
nothing can shadow a built-in, permissions are clamped to `ANALYSIS` at most
regardless of what a plugin requests, and handler exceptions are caught and
reported rather than ending a run. Off unless `CTF_TUTOR_ENABLE_PLUGINS=1`.

**Five CLI subcommands** — `curriculum`, `graph`, `audit`, `dashboard`,
`plugins`. Help output regrouped into learning / knowledge / workflow.

### Changed

- CI now runs the full suite, a syntax check, a strict archive audit, a corpus
  build gated at 500 cards, the offline evaluator, and uploads reports as an
  artifact.
- `.env.example` documents every setting with comments.
- `.gitignore` covers learner memory, traces, experiments, reports, and
  workspaces — personal state stays local.
- README rewritten: plainer voice, corrected counts (the old one variously
  claimed 32 and 45 archive entries, and 8 and 20 eval cases), and a roadmap
  table that reflects reality, including what is still open.
- `IMPLEMENTATION_SUMMARY.md` marked historical.

### Tests

248 → **355**, all passing. New coverage for reranking, challenge graph,
misconceptions, curriculum, provenance, contradictions, schema aliases, corpus
generation, dashboard rendering and escaping, plugin isolation and permission
clamping, provider failover, and the new CLI commands.

One existing assertion was updated: `test_help_flag_shows_subcommand_summary`
checked for the literal string `"subcommands:"`, which the regrouped help no
longer uses. It now asserts that every registered subcommand appears in the help
output, which is what the test was actually trying to establish.
