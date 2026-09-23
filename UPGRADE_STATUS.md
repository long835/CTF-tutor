# Upgrade backlog status

Tracking the 75-item consolidated review. Status is per-item and honest:
"done" means implemented, tested, and wired in — not stubbed.

Test suite: **592 tests, all passing** (`python3 -m unittest discover -s tests -t .`).
The suite runs under plain `unittest`; pytest is optional.

---

## Done (41 items)

### Phase 1 — Reliability

| # | Item | Module |
|---|---|---|
| 1 | Model profiles | `agent/model_profile.py` |
| 2 | Context management | `agent/context.py` |
| 5 | Verification (evidence gate) | `agent/verifier.py`, `agent/evidence.py` |
| 7 | Tool result normalization | `agent/tool_result.py` |
| 9 | Error handling (failure ≠ emptiness) | `agent/tool_result.py`, `agent/executor.py` |
| 12 | Negative knowledge | `agent/evidence.py` |
| 29 | Hardware awareness | `agent/model_profile.py` |
| 30 | Quantization awareness | `agent/model_profile.py` |
| 36 | Memory architecture (5 scopes) | `agent/context.py` |
| 37 | Long-term memory decay | `agent/context.py` |
| 47 | Structured output repair | `agent/structured.py` |
| 61 | "Unknown" as a first-class state | `agent/evidence.py` |

### Phase 2 — Reasoning

| # | Item | Module |
|---|---|---|
| 3 | Reasoning loop as a state machine | `agent/reasoning.py` |
| 4 | Hypothesis management (log-odds Bayes) | `agent/belief.py` |
| 6 | Tool selection via capability registry | `agent/tool_capabilities.py` |
| 23 | Recovery from wrong reasoning | `agent/recovery.py` |
| 34 | Unified tool-finding fusion | `agent/evidence_graph.py` |
| 35 | Evidence graph | `agent/evidence_graph.py` |

### Phase 3 — Evaluation, replay and diagnostics

| # | Item | Module |
|---|---|---|
| 18 | Retrieval metrics (Recall@K, P@K, MRR, nDCG) | `agent/retrieval_eval.py` |
| 19 | Train/eval contamination split | `agent/retrieval_eval.py` |
| 21 | 12-axis evaluation dimensions | `agent/metrics.py` |
| 26 | Full run trace | `agent/replay.py` |
| 27 | Deterministic replay | `agent/replay.py` |
| 42 | Cross-platform capability detection | `agent/doctor.py` |
| 43 | `doctor` command | `agent/doctor.py`, `main.py doctor` |
| 44 | Dependency tiers | `agent/doctor.py` |
| 54 | Integration tests | `tests/test_e2e_agent.py` |
| 55 | End-to-end challenge tests | `tests/test_e2e_agent.py` |
| 56 | Regression suite | `tests/test_e2e_agent.py` (`FIXED_CASES`) |
| 59 | Efficiency metrics | `agent/metrics.py` |
| 60 | Hallucination measurement | `agent/metrics.py` |
| 64 | Writeup structure | `agent/writeup.py` |
| 65 | Dynamic difficulty estimation | `agent/difficulty.py` |

### Done in the earlier roadmap pass

16 (hint levels), 17 (hint dependency tracking), 25 (provenance), 38 (plugins),
48 (model fallback), 57 (ablation), 66 (challenge graph), 68 (corpus versioning).

### No action needed

50 (Rust strategy — keep as-is), 51 (TypeScript — later), 52 (C/C++ — bindings
only), 53 (Go — not needed). The review's own conclusion; recorded so they
stop appearing as open work.

---

### Phase 4 — Hardening (the hard items)

| # | Item | Module |
|---|---|---|
| 13 | CTF challenge classifier, formalized | `agent/classify_challenge.py` |
| 8 | Sandbox policy tiers, fail-closed | `agent/sandbox.py` |
| 22 | Adversarial evaluation suite | `agent/adversarial.py`, `data/eval/adversarial.json` |
| 45 | Security threat model | `agent/trust.py` |
| 46 | Prompt-injection defence by trust level | `agent/trust.py` |
| 62 | Solution verification | `agent/flag_check.py` |
| 63 | Flag verification | `agent/flag_check.py` |

Measured effects:

* **Classification: 11/20 → 20/20** on the project's own evaluation set
  (`python main.py ... eval.py --classifier heuristic` still reports the old
  number for comparison). The legacy heuristic returned `None` for 45% of
  cases; the formal classifier always answers and attaches its uncertainty.
  Caveat: the signal table was tuned against these 20 cases, so this is
  in-sample. The adversarial suite is the out-of-sample check.
* **Adversarial suite: 10/15 → 15/15 traps avoided**, overclaim rate 27% → 0%,
  after fixing the three defects it found (below).

## Partially done (3 items)

| # | Item | What exists | What is missing |
|---|---|---|---|
| 10 | Knowledge depth | 560 cards / 118 techniques | Advanced heap, lattice, kernel topics |
| 11 | Knowledge representation | Skill graph, challenge graph, evidence graph | Not unified into one technique-relationship graph |
| 14/15 | Learner model + teaching metrics | Mastery, misconceptions, hint depth, `explanation` and `hint_quality` axes | Independence metric in the learner model; "can solve a variation" |

---

## Not started (16 items)

20 (600-case dataset), 24 (research module hardening), 28 (resource-aware
concurrency), 31 (embedding separation), 32 (vision), 33 (multi-language
expansion), 39 (core/CLI/API split), 40 (web UI), 41 (config management),
49 (cost-aware routing), 58 (model comparison harness), 67 (corpus taxonomy
dedup), 69 (knowledge quality scoring), 70 (external knowledge provenance),
71 (offline-first ingestion), 72 (doc set), 73 (packaging), 74 (telemetry
policy).

75 (target architecture) is a tracking item, satisfied incrementally as the
rest lands.

---

## Bugs found by this work

Kept as permanent regression cases in `tests/test_e2e_agent.py`.

1. **Retrieval unavailability read as absence** (Phase 1) — `_run_retrieve`
   returned `(True, {"matches": []})` when the vector store was down.
2. **Knowledge cards supported claims about the challenge** (Phase 2) — an
   archive card matched the technique rubric and raised confidence.
3. **Offline verifier passed on a confidence number** (Phase 2) — the default
   local-first path granted `pass` from `overall_confidence >= 0.7` plus two
   evidence items, with no rubric check.
4. **Hypotheses supplied their own evidence** (Phase 2) — `collect_evidence_text`
   included hypothesis statements.
5. **Repeated tool runs compounded confidence** (Phase 2) — re-delivering the
   same signals raised belief again.
6. **Plateau recovery re-opened the same alternatives** (Phase 3) — dedupe
   compared the raw suggestion against the prefixed stored statement.
7. **The observer adopted the first flag-shaped string it saw** (Phase 4) —
   `observe()` set `state.flag_candidate = flags[0]` with no grading, and the
   verifier then early-accepted anything flag-shaped at 0.9 confidence. A
   planted decoy won every time, because decoys are placed where the first
   tool will hit them.
8. **`invented_tool_output` fired on teaching advice** (Phase 4) — the
   hallucination detector scanned `state.lessons`, so a skill pack saying
   "run checksec first" was read as a claim that checksec had run. False
   positive on every pwn run.
9. **A contradicting signal was phrased as one exact sentence** (Phase 4) —
   the rubric looked for the literal string "format string is a literal", so
   "printf is called with a literal format string" slipped past and a refuted
   hypothesis stayed live at 0.98 confidence.
10. **The trust gate initially rejected the user's own challenge directory**
    (Phase 4, mine) — the allowed root was hardcoded to the workspace.
    Naming a directory is USER-level consent to read it.
11. **The argument check rejected punctuation in payloads** (Phase 4, mine) —
    `|` and `$` in a base64 blob are harmless when no shell is involved;
    scoping the check to path-like keys fixed it.
12. **The shipped evaluation set was contaminated** (Phase 3) — `web-jwt`
   overlapped `example_web_jwt.json` by 74% and `pwn-bof` by 41%; both were
   near-verbatim copies. Rewritten independently, same labels. Classification
   accuracy on those two cases dropped to 0 afterwards, which means the
   previous score was partly measuring recall of corpus wording.

---

## Known limitation of the current adversarial result

Every adversarial case ends in `stuck`. That is the correct outcome for
fourteen of them — there is no verifiable answer to find — but it means the
suite measures *trap avoidance* and not *capability*, and an agent that
never concludes anything would also score 15/15. The counterweight is the
end-to-end suite, where a legitimately observed flag still reaches
`verified`. Both numbers have to be read together, and the honest summary is
"avoids every trap, and still solves the clean cases it can".

## Suggested next pass

1. **11** — unify skill graph, challenge graph and evidence rubrics into one
   technique-relationship graph. Now the highest-leverage structural item:
   four modules hold overlapping technique knowledge in different shapes.
2. **20** — grow the evaluation set. Every harness it needs now exists
   (items 21, 22, 54–56, 59, 60), so unused capacity is the binding
   constraint on knowing whether any of this generalises.
3. **14 + 15** — independence metric in the learner model.
4. **41 + 39** — configuration, then the core/CLI/API split.
5. **58 + 49 + 31** — model comparison, cost routing, embedding separation.
