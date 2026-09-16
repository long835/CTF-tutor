# Changelog

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
