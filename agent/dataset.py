"""
agent/dataset.py

The evaluation set (item 20).

Twenty hand-written cases were enough to find bugs and not nearly enough to
tell whether anything generalises. Worse, the classifier's signal table was
tuned against those twenty, so 20/20 measured fit to the sample rather than
skill. This module builds a much larger set, and — more importantly — builds
in the three controls that make a bigger number mean something.

Control 1: **no corpus wording.**
The Phase 3 contamination bug was a case description that shared a sentence
with the card meant to teach it, so classification was partly measuring
recall of corpus phrasing. Descriptions here are composed from structured
fields (artifact kind, observed conditions, the ask) through templates
written for this module, never from card prose. `leakage_report()` measures
the overlap that remains and the tests fail above a threshold.

Control 2: **keyword echo is reported separately.**
A generator that writes "SQL injection" into a description and then scores
the classifier for answering "web" measures string matching. Every case is
labelled with whether it contains one of the classifier's own decisive
signal patterns, and `accuracy_report()` splits the score into the easy
subset and the **blind subset** — cases with no decisive keyword, where the
category has to come from the situation. The blind number is the honest one.

Control 3: **family split.**
Cases carry a family (category plus technique root). `split()` keeps whole
families on one side, so a model cannot see one framing of a technique in
training and be scored on its sibling.

The set is generated deterministically from a seed, so it is reproducible
and reviewable rather than a frozen blob nobody can regenerate. What it is
*not*: a substitute for real challenges. These are classification and
planning cases built from the project's own knowledge of techniques, so they
test whether the pipeline reasons from a situation — not whether it can
exploit a real binary.
"""

from __future__ import annotations

import json
import os
import random
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from agent import taxonomy

DEFAULT_PATH = os.path.join("data", "eval", "generated.json")

BANDS = ("basic", "intermediate", "advanced", "adversarial", "multi_step", "tool_heavy")
DEFAULT_PER_BAND = 100

# Artifact phrasing per category: what the player is actually handed.
ARTIFACTS: Dict[str, Sequence[str]] = {
    "web": ("a URL and the application source", "a running service and its source tree",
            "a web endpoint with no source", "a docker-compose file and the app code"),
    "pwn": ("a 64-bit ELF and its libc", "a stripped 64-bit ELF", "an ELF and its C source",
            "a networked binary and a connection string"),
    "rev": ("a single stripped executable", "a .NET assembly", "a Go binary",
            "an executable and a sample input file"),
    "crypto": ("a ciphertext file and the encrypting script", "a parameter dump and a ciphertext",
               "an oracle endpoint and a sample token", "two ciphertexts and the public parameters"),
    "forensics": ("a disk image", "a packet capture", "an image file",
                  "an archive of recovered files", "a memory dump"),
    "osint": ("a screenshot and a handle", "a domain name", "a photograph with no caption",
              "a username and a profile page"),
    "blockchain": ("a Solidity contract and its deployed address", "a contract source and a test suite"),
    "mobile": ("an APK", "an APK and a network capture from the app"),
    "misc": ("a text file", "a scripted service and its source"),
}

# How the case asks for an answer. Deliberately never names a technique.
ASKS: Sequence[str] = (
    "Work out what is actually wrong here before touching anything.",
    "Say what you would look at first, and what would rule it out.",
    "Identify the weakness and how you would confirm it.",
    "Decide what this is, and what evidence would settle it.",
    "Explain what the setup allows, and what it does not.",
)

# Adversarial traps, mirroring the review's list. Each is a distractor that
# points somewhere plausible and wrong.
TRAPS: Sequence[Tuple[str, str]] = (
    ("misleading_filename", "The file is named {decoy_name}, which does not match its contents."),
    ("decoy_flag", "A string in the obvious flag format sits in the first few bytes of output."),
    ("false_signal", "{false_signal}, which points at a different bug than the one present."),
    ("irrelevant_source", "A second source file is included that is never reached at runtime."),
    ("tool_failure", "The usual analysis tool exits with an error on this input."),
    ("misleading_description", "The task text claims the challenge is about {wrong_category}."),
    ("incomplete_evidence", "Half the relevant output is truncated and cannot be recovered."),
)

DECOY_NAMES = ("flag.txt.enc", "definitely_not_the_binary.bin", "readme.png",
               "backup.sql", "notes.pcap", "key.pem")


@dataclass
class Case:
    """One evaluation case."""

    id: str
    band: str
    description: str
    expected_category: str
    expected_techniques: List[str] = field(default_factory=list)
    difficulty: str = "medium"
    family: str = ""
    expected_tools: List[str] = field(default_factory=list)
    expected_steps: int = 1
    trap: str = ""
    must_not_conclude: List[str] = field(default_factory=list)
    has_decisive_keyword: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Case":
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in (data or {}).items() if k in fields})


# ---------------------------------------------------------------------------
# Keyword-echo detection
# ---------------------------------------------------------------------------


def _decisive_patterns() -> List[Tuple[str, str]]:
    """The classifier's own high-weight signals, as (pattern, category)."""
    try:
        from agent.classify_challenge import DECISIVE, SIGNALS
    except Exception:  # pragma: no cover
        return []
    return [(pat, cat) for pat, cat, weight in SIGNALS if weight >= DECISIVE]


def has_decisive_keyword(text: str) -> bool:
    """
    Whether a description hands the classifier its answer.

    This is the difference between testing reasoning and testing `re.search`.
    """
    low = (text or "").lower()
    for pattern, _ in _decisive_patterns():
        try:
            if re.search(pattern, low):
                return True
        except re.error:
            if pattern in low:
                return True
    return False


def _strip_decisive_terms(text: str) -> str:
    """
    Remove technique names the classifier keys on, keeping the situation.

    Used on generated conditions so the blind subset is genuinely blind: the
    case still describes an algorithm field in a token header, it just never
    writes the letters J-W-T.
    """
    replacements = {
        r"\bjwt\b": "the bearer token",
        r"json web token": "the bearer token",
        r"sql\s*injection": "the query construction",
        r"\bsqli\b": "the query construction",
        r"\bssti\b": "the template rendering",
        r"template injection": "the template rendering",
        r"\bxss\b": "the reflected output",
        r"cross.site scripting": "the reflected output",
        r"\bssrf\b": "the outbound fetch",
        r"\bxxe\b": "the XML parse",
        r"buffer overflow": "the oversized copy",
        r"format string": "the logging call",
        r"\brop\b": "the return sequence",
        r"\bstego\b|steganograph\w*": "the hidden payload",
        r"reentranc\w*": "the repeated external call",
    }
    out = text or ""
    for pattern, rep in replacements.items():
        out = re.sub(pattern, rep, out, flags=re.IGNORECASE)
    return out


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _readable(signals: Iterable[str]) -> List[str]:
    """
    Keep only prose signals.

    Rubric signals are alternation patterns ("gets|strcpy|read into"); pasting
    one into a case description would both read like machine output and hand
    the grader its own regex back.
    """
    out: List[str] = []
    for s in signals or []:
        text = str(s)
        if any(ch in text for ch in "|\\{}()[]*^$"):
            continue
        if len(text) < 8 or len(text) > 120:
            continue
        out.append(text)
    return out


def _sentence(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    text = text[0].upper() + text[1:]
    if text[-1] not in ".!?":
        text += "."
    return text


def _pick(rng: random.Random, seq: Sequence[Any], n: int = 1) -> List[Any]:
    items = list(seq)
    if not items:
        return []
    rng.shuffle(items)
    return items[:n]


def _usable_nodes() -> List[Any]:
    from agent import knowledge_graph

    graph = knowledge_graph.get_graph()
    nodes = [
        n for n in graph.techniques()
        if _readable(n.indicators) and n.concept
    ]
    return sorted(nodes, key=lambda n: n.technique)


def _compose(
    rng: random.Random,
    node: Any,
    band: str,
    blind: bool,
) -> Tuple[str, Dict[str, Any]]:
    """Build one description plus the extra labels its band carries."""
    category = node.category
    artifact = _pick(rng, ARTIFACTS.get(category, ARTIFACTS["misc"]))[0]
    conditions = _readable(node.indicators)
    checks = list(node.first_checks or [])
    extra: Dict[str, Any] = {}

    if band == "basic":
        chosen = _pick(rng, conditions, 2)
        difficulty = "easy"
        steps = 1
    elif band == "intermediate":
        chosen = _pick(rng, conditions, 2)
        difficulty = "medium"
        steps = 2
    elif band == "advanced":
        # Fewer clues, and one of the lookalikes left open.
        chosen = _pick(rng, conditions, 1)
        difficulty = "hard"
        steps = 3
    elif band == "adversarial":
        chosen = _pick(rng, conditions, 1)
        difficulty = "hard"
        steps = 2
    elif band == "multi_step":
        chosen = _pick(rng, conditions, 2)
        difficulty = "hard"
        steps = rng.randint(3, 5)
    else:  # tool_heavy
        chosen = _pick(rng, conditions, 2)
        difficulty = "medium"
        steps = 3

    parts = [f"You are handed {artifact}."]
    for c in chosen:
        parts.append(_sentence(c))

    if band == "advanced":
        # Counterexamples carry two kinds of entry: prose lookalikes and
        # "argues against: <alternation pattern>" refuters lifted from the
        # rubric. Only the prose belongs in a case description.
        alt = _pick(rng, _readable(node.counterexamples), 1)
        if alt:
            parts.append(_sentence(
                f"An earlier note in the task claims this could just be {str(alt[0]).lstrip('argues against: ')}"
            ))
    if band == "multi_step":
        parts.append(_sentence(
            f"Reaching the answer takes {steps} distinct stages, and the first one only "
            f"gives you the input for the second"
        ))
    if band == "tool_heavy":
        if checks:
            parts.append(_sentence(f"Nothing is readable until you {checks[0]}"))
        extra["expected_tools"] = list(node.tools[:3])
    if band == "adversarial":
        trap_kind, template = _pick(rng, TRAPS)[0]
        wrong_category = _pick(rng, [c for c in ARTIFACTS if c != category])[0]
        false_signal = "A string in the binary mentions a cipher that is never used"
        parts.append(_sentence(template.format(
            decoy_name=_pick(rng, DECOY_NAMES)[0],
            wrong_category=wrong_category,
            false_signal=false_signal,
        )))
        extra["trap"] = trap_kind
        extra["must_not_conclude"] = (
            [wrong_category] if trap_kind == "misleading_description" else
            _readable(node.counterexamples)[:2]
        )

    parts.append(_pick(rng, ASKS)[0])
    description = " ".join(p for p in parts if p)
    if blind:
        description = _strip_decisive_terms(description)

    extra.update({"difficulty": difficulty, "expected_steps": steps})
    return description, extra


def build_dataset(
    seed: int = 20260918,
    per_band: int = DEFAULT_PER_BAND,
    blind_fraction: float = 0.5,
) -> List[Case]:
    """
    Generate the evaluation set.

    `blind_fraction` of each band has the classifier's own decisive keywords
    stripped out. Half the set is deliberately harder than the set it
    replaces, which is the point: a benchmark everything passes measures
    nothing.
    """
    rng = random.Random(seed)
    nodes = _usable_nodes()
    if not nodes:
        return []

    cases: List[Case] = []
    for band in BANDS:
        for i in range(per_band):
            node = nodes[(i * 7 + BANDS.index(band) * 3) % len(nodes)]
            blind = rng.random() < blind_fraction
            description, extra = _compose(rng, node, band, blind)
            techniques = [node.technique]
            if band == "multi_step":
                techniques += [t for t in node.related[:2] if not taxonomy.is_concept(t)]
            case = Case(
                id=f"{band}-{node.technique}-{i:03d}",
                band=band,
                description=description,
                expected_category=node.category,
                expected_techniques=techniques,
                family=f"{node.category}/{node.technique}",
                difficulty=str(extra.get("difficulty", "medium")),
                expected_tools=list(extra.get("expected_tools", [])),
                expected_steps=int(extra.get("expected_steps", 1)),
                trap=str(extra.get("trap", "")),
                must_not_conclude=list(extra.get("must_not_conclude", [])),
            )
            case.has_decisive_keyword = has_decisive_keyword(case.description)
            cases.append(case)
    return cases


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def leakage_report(
    cases: Sequence[Case],
    archive_dir: str = os.path.join("data", "archive"),
    corpus_file: str = os.path.join("data", "corpus", "challenges.jsonl"),
    threshold: float = 0.25,
) -> Dict[str, Any]:
    """
    How much of each case's wording is reused from a knowledge card.

    The Phase 3 bug was 74% overlap between a case and the card meant to
    teach it. This runs the same shingle check over the whole generated set.
    """
    from agent.knowledge_quality import _iter_cards
    from agent.retrieval_eval import leakage

    documents = []
    for ident, card in _iter_cards(archive_dir, corpus_file):
        text = " ".join(
            str(card.get(k) or "")
            for k in ("description", "explanation", "name", "challenge_name")
        )
        if text.strip():
            documents.append((ident, text))

    worst: List[Dict[str, Any]] = []
    over = 0
    total = 0.0
    for case in cases:
        best_id, best = "", 0.0
        for ident, text in documents:
            score = leakage(case.description, text)
            if score > best:
                best_id, best = ident, score
        total += best
        if best >= threshold:
            over += 1
        worst.append({"case": case.id, "document": best_id, "leakage": round(best, 3)})

    worst.sort(key=lambda r: -r["leakage"])
    return {
        "cases": len(cases),
        "documents": len(documents),
        "mean_max_leakage": round(total / len(cases), 4) if cases else 0.0,
        "over_threshold": over,
        "threshold": threshold,
        "worst": worst[:10],
    }


def keyword_report(cases: Sequence[Case]) -> Dict[str, Any]:
    """How much of the set hands the classifier its answer verbatim."""
    blind = [c for c in cases if not c.has_decisive_keyword]
    by_band: Dict[str, Dict[str, int]] = {}
    for c in cases:
        row = by_band.setdefault(c.band, {"total": 0, "blind": 0})
        row["total"] += 1
        if not c.has_decisive_keyword:
            row["blind"] += 1
    return {
        "cases": len(cases),
        "blind_cases": len(blind),
        "blind_fraction": round(len(blind) / len(cases), 3) if cases else 0.0,
        "by_band": dict(sorted(by_band.items())),
    }


def split(
    cases: Sequence[Case], test_fraction: float = 0.3, seed: int = 20260918
) -> Tuple[List[Case], List[Case]]:
    """
    Family-wise split: no family appears on both sides.

    Splitting case-wise would let a model see one framing of `ssti` and be
    scored on its sibling, which is memorisation dressed as generalisation.

    The family is `retrieval_eval.family_of`, not this module's per-technique
    `family` field. Splitting on the finer field looked clean and was not:
    `retrieval_eval.family_overlap` still reported sixteen families on both
    sides, because `jwt-none-bypass` and `jwt-alg-confusion` are one family
    for the purpose of "has it seen this before". Two definitions of family
    means one of them is wrong; the coarser one is the safe one to split on.
    """
    from agent.retrieval_eval import family_of

    keyed = [(family_of(c.to_dict()), c) for c in cases]
    families = sorted({f for f, _ in keyed})
    rng = random.Random(seed)
    rng.shuffle(families)
    cut = max(1, int(len(families) * test_fraction))
    test_families = set(families[:cut])
    test = [c for f, c in keyed if f in test_families]
    train = [c for f, c in keyed if f not in test_families]
    return train, test


def accuracy_report(cases: Sequence[Case], which: str = "formal") -> Dict[str, Any]:
    """
    Classification accuracy, split into the easy and the blind subsets.

    The headline number to quote is `blind_accuracy`: the easy subset mostly
    measures whether a regex fired.
    """
    from agent.classify_challenge import classify_formal

    def predict(text: str) -> str:
        if which == "formal":
            return classify_formal(text)
        import classifier

        return classifier.classify_heuristic(text)[0] or ""

    rows: List[Tuple[Case, str, bool]] = []
    for case in cases:
        got = predict(case.description)
        rows.append((case, got, got == case.expected_category))

    def rate(subset: Sequence[Tuple[Case, str, bool]]) -> Optional[float]:
        if not subset:
            return None
        # `sum(1 for ... )` counts every row, correct or not. The first run of
        # this reported 1.000 accuracy alongside 276 confusions, which is the
        # only reason the bug was visible at all.
        return round(sum(1 for _, _, ok in subset if ok) / len(subset), 3)

    blind = [r for r in rows if not r[0].has_decisive_keyword]
    keyed = [r for r in rows if r[0].has_decisive_keyword]

    by_band: Dict[str, Any] = {}
    for band in BANDS:
        subset = [r for r in rows if r[0].band == band]
        blind_subset = [r for r in subset if not r[0].has_decisive_keyword]
        by_band[band] = {
            "cases": len(subset),
            "accuracy": rate(subset),
            "blind_accuracy": rate(blind_subset),
        }

    confusion: Dict[str, Dict[str, int]] = {}
    for case, got, ok in rows:
        if not ok:
            confusion.setdefault(case.expected_category, {})
            confusion[case.expected_category][got or "<none>"] = (
                confusion[case.expected_category].get(got or "<none>", 0) + 1
            )

    return {
        "classifier": which,
        "cases": len(rows),
        "accuracy": rate(rows),
        "keyed_cases": len(keyed),
        "keyed_accuracy": rate(keyed),
        "blind_cases": len(blind),
        "blind_accuracy": rate(blind),
        "by_band": by_band,
        "confusions": {k: dict(sorted(v.items())) for k, v in sorted(confusion.items())},
    }


def render_report(
    cases: Sequence[Case],
    accuracy: Optional[Dict[str, Any]] = None,
    keywords: Optional[Dict[str, Any]] = None,
) -> str:
    acc = accuracy or accuracy_report(cases)
    kw = keywords or keyword_report(cases)
    lines = [
        f"Generated evaluation set: {len(cases)} case(s) across {len(BANDS)} band(s)",
        f"  keyword-free (blind) cases: {kw['blind_cases']} ({kw['blind_fraction']:.0%})",
        "",
        f"Classification ({acc['classifier']}):",
        f"  overall      {acc['accuracy']:.3f}  ({acc['cases']} cases)",
        f"  with keyword {acc['keyed_accuracy']}  ({acc['keyed_cases']} cases)",
        f"  blind        {acc['blind_accuracy']}  ({acc['blind_cases']} cases)  <- the honest number",
        "",
        "By band:",
    ]
    for band, row in acc["by_band"].items():
        lines.append(
            f"  {band:<13} n={row['cases']:<4} accuracy={row['accuracy']} "
            f"blind={row['blind_accuracy']}"
        )
    if acc["confusions"]:
        lines += ["", "Confusions (expected -> predicted):"]
        for expected, got in acc["confusions"].items():
            worst = ", ".join(f"{k} x{v}" for k, v in sorted(got.items(), key=lambda kv: -kv[1])[:3])
            lines.append(f"  {expected:<11} {worst}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def save_dataset(cases: Sequence[Case], path: str = DEFAULT_PATH) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump([c.to_dict() for c in cases], f, indent=1)


def load_dataset(path: str = DEFAULT_PATH) -> List[Case]:
    p = Path(path)
    if not p.is_file():
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            rows = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    return [Case.from_dict(r) for r in rows if isinstance(r, dict)]


def to_ground_truth(cases: Sequence[Case]) -> List[Dict[str, Any]]:
    """The subset of fields `eval.py` understands, so the old harness still runs."""
    return [
        {
            "id": c.id,
            "description": c.description,
            "expected_category": c.expected_category,
            "expected_techniques": list(c.expected_techniques),
            "difficulty": c.difficulty,
        }
        for c in cases
    ]
