# Upgrade backlog status

Tracking the 75-item consolidated review. Status is per-item and honest:
"done" means implemented, tested, and wired in — not stubbed.

Test suite: **663 tests, all passing** (`python3 -m unittest discover -s tests -t .`).
The suite runs under plain `unittest`; pytest is optional.

---

## Done (53 items)

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

### Phase 5 — Knowledge layer

| # | Item | Module |
|---|---|---|
| 11 | Unified technique knowledge graph | `agent/knowledge_graph.py` |
| 67 | Canonical taxonomy, aliases, duplicate report | `agent/taxonomy.py` |
| 14 | Learner independence model | `agent/learner_model.py` |
| 15 | Transfer: "can solve a variation" | `agent/learner_model.py` |
| 69 | Knowledge quality scoring | `agent/knowledge_quality.py` |
| 10 | Knowledge depth (rubrics and prerequisites) | `agent/evidence.py`, `agent/skill_graph.py` |

CLI: `main.py knowledge` (describe a technique, audit the base, taxonomy
report, card-quality report, `--strict` for CI) and `main.py learner`
(independent-solve rate, hint dependency, next untried variation).

Measured effects:

* **Evidence rubrics 12 → 61.** The graph's first audit found 51 techniques
  the corpus actively teaches with no rubric behind them, which meant any
  claim about roughly two thirds of the syllabus could only ever grade as
  `insufficient_evidence`.
* **Prerequisites 29 → 97.** 34 corpus-taught techniques had nothing the
  curriculum could schedule before them.
* **Corpus tags 121 spellings → 100 canonical ids**, with no unknown tags and
  no alias/canonical collisions.
* **Knowledge-graph audit: clean at error and warning severity**, asserted by
  `tests/test_knowledge_phase5.py` and by `main.py knowledge --strict`.

Design note: the knowledge graph is a resolved *view* over the existing
tables, not a replacement for them. Each table stays in the shape its owner
wants to edit; the graph joins them and fails loudly when they drift apart.


### Phase 6 — The evaluation set

| # | Item | Module |
|---|---|---|
| 20 | Generated 600-case evaluation set | `agent/dataset.py`, `data/eval/generated.json` |

600 cases across six bands (basic, intermediate, advanced, adversarial,
multi-step, tool-heavy), generated deterministically from a seed so the set
is reproducible and reviewable rather than a frozen blob. CLI:
`main.py dataset --build | --measure | --leakage | --split | --show ID`.

Three controls, because a bigger number is only worth having if it means
something:

* **No corpus wording.** Descriptions are composed from structured fields
  through templates written for the generator, never from card prose. Mean
  maximum overlap with any knowledge card is **0.040**, with 7 of 600 cases
  above 0.25. The Phase 3 contamination bug was a single case at **0.74**.
* **Keyword echo reported separately.** 81% of cases contain none of the
  classifier's own decisive signal patterns. Accuracy is split into the
  keyed subset and the **blind** subset, and only the blind number is quoted.
* **Family-wise split**, using `retrieval_eval.family_of` so there is one
  definition of "family" in the project rather than two.

**The result, and it is not a good one:**

| | accuracy |
|---|---|
| formal classifier, overall | 0.555 |
| formal classifier, keyed subset (115 cases) | 0.826 |
| **formal classifier, blind subset (485 cases)** | **0.491** |
| legacy heuristic, overall | 0.140 |

The classifier that scored 20/20 on the hand-written set scores **0.49 on
blind out-of-sample cases**. The dominant failure is falling back to `misc`
when no technique is named: 53 pwn cases, 44 rev, 43 web. The in-sample
caveat recorded in Phase 4 was correct, and this is the size of it. The
formal classifier is still a real improvement — 3.9x the legacy heuristic on
the same set — but it is doing much less well than the old number suggested.

**A limitation that has to be stated before anyone acts on this.** The
descriptions are built from the knowledge graph's own indicator phrases.
Grounding the classifier in those same phrases would push this number toward
1.0 and mean nothing at all. This set can measure the current classifier; it
cannot validate a classifier that reads the table it was generated from. A
genuinely independent set needs descriptions from outside the project —
public challenge text, or cases written by someone who has not seen the
signal table.


## Partially done (2 items)

| # | Item | What exists | What is missing |
|---|---|---|---|
| 10 | Knowledge depth | 61 rubrics, 97 prerequisite chains, 564 corpus cards | 30 advanced techniques are named in the taxonomy but have no library entry or corpus card: heap tcache/fastbin/unsorted-bin, ret2csu/SROP/seccomp, lattice/Wiener/Franklin-Reiter/ECDSA nonce reuse, request smuggling/OAuth/GraphQL/NoSQL, Go/Rust/.NET binaries |
| 67 | Corpus taxonomy | Aliases resolve at read time everywhere | Ingest still writes the variant spellings; `main.py knowledge --taxonomy` lists the 19 that remain |

---

## Not started (13 items)

24 (research module hardening), 28 (resource-aware
concurrency), 31 (embedding separation), 32 (vision), 33 (multi-language
expansion), 39 (core/CLI/API split), 40 (web UI), 41 (config management),
49 (cost-aware routing), 58 (model comparison harness), 70 (external
knowledge provenance), 71 (offline-first ingestion), 72 (doc set), 73
(packaging), 74 (telemetry policy).

Note on 68 (corpus versioning, previously marked done): the quality scorer
found that no shipped card carries a date or a version, so `freshness` is
unmeasurable across the entire corpus. The schema supports it; the data does
not use it. Reported as `unmeasurable` rather than scored zero.

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

## Bugs found in Phase 5

10. **Two authoritative answers to one question** (mine) — the knowledge
    graph matched rubric signals to tools with its own looser matcher and
    reported six fewer gaps than `tool_capabilities.uncovered_signals()`.
    Exactly the drift item 11 exists to stop. The graph now delegates to the
    registry, and a test asserts the two agree.
11. **Quality scoring judged two schemas against one checklist** (mine) —
    corpus index entries were marked down for missing `solve_steps`, a field
    their schema never had, which called 86% of the shipped corpus "poor".
    Coverage is now judged against the schema the card actually uses.
12. **An unmeasurable axis was scored zero** (mine) — freshness dragged every
    card down by a tenth for a property none of them records. Absent and bad
    are different; the total now renormalises over measurable axes only.
13. **The curriculum could schedule an alias and a concept as lessons** —
    `_candidate_techniques` offered both `android` and `android-basics`, and
    offered concepts such as `stack-layout` as though they were solvable
    challenges. Candidates now resolve through the taxonomy.

## Bugs found in Phase 6

14. **Accuracy counted every row as correct** (mine) — `sum(1 for _, _, ok
    in subset)` ignores `ok`. The first run reported 1.000 accuracy printed
    directly above 276 confusions, which is the only reason it was caught.
    The real number was 0.537.
15. **A node's category and its signals came from different sources** — the
    generator produced a `web` case describing Solidity modifiers, because
    `access-control` was categorised by the taxonomy and described by a
    blockchain library entry, and nothing compared the two. `category_conflict`
    is now an audit check; four library disagreements and two corpus ones
    were resolved in favour of the data.
16. **Two definitions of "family"** — this module split on its own
    per-technique field and looked clean, while
    `retrieval_eval.family_overlap` still reported sixteen shared families.
    The split now uses `retrieval_eval.family_of`, the same principle as
    item 11: one question, one answer.

## Suggested next pass

1. **An independent evaluation set.** The generated set cannot validate
   anything that reads the knowledge graph's indicator table, and the
   classifier's blind accuracy of 0.49 is the most actionable number the
   project has. Public challenge descriptions would give a set with no
   shared ancestry.
2. **10, remaining half** — library entries and corpus cards for the 30
   advanced techniques the taxonomy now names but nothing teaches.
3. **41 + 39** — configuration, then the core/CLI/API split.
4. **58 + 49 + 31** — model comparison, cost routing, embedding separation.
5. **70 + 71 + 68** — external provenance, offline ingestion, and putting a
   date and version on every card so freshness becomes measurable.
