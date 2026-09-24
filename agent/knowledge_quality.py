"""
agent/knowledge_quality.py

Not all cards deserve equal weight (item 69).

Retrieval currently ranks on relevance to the query and fit to the learner.
Neither notices that one card names its technique, its signals, its tools and
how to verify the finding, while another says "the flag was in the file" and
stops. Both can match the same query; only one is worth putting in a small
model's limited context.

Five axes, all computed from what is actually in the card -- no model calls,
no human labelling:

    specificity   does it name techniques, tools, concrete steps?
    coverage      does it fill the fields the schema defines?
    verification  does it say how you would know you were right?
    provenance    does it say where it came from?
    freshness     has it been touched recently, and does it carry a version?

The weights are deliberate rather than tuned: `specificity` and
`verification` dominate because those are the two that change what a local
model does with the card. A beautifully-sourced card with no observable
detail still leaves the agent guessing.

One caution that is worth stating plainly: this scores *form*, not truth. A
confidently wrong card that names tools and steps will score well here. It
is a prior for ranking, not a fact-check -- that is what the provenance audit
and the evidence rubrics are for.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from agent import taxonomy

ARCHIVE_DIR = os.path.join("data", "archive")
CORPUS_FILE = os.path.join("data", "corpus", "challenges.jsonl")

WEIGHTS: Dict[str, float] = {
    "specificity": 0.30,
    "coverage": 0.20,
    "verification": 0.25,
    "provenance": 0.15,
    "freshness": 0.10,
}

# Two schemas live in data/, and scoring one against the other's checklist is
# how the first run of this module reported 522 "poor" cards: the corpus index
# entries were being marked down for missing `solve_steps`, a field their
# schema never had. Coverage is judged against the schema the card actually
# uses.
ARCHIVE_FIELDS = (
    "challenge_name", "category", "techniques", "difficulty",
    "description", "explanation", "solve_steps", "tools_used", "references",
)
INDEX_FIELDS = (
    "id", "kind", "source", "provenance", "name",
    "category", "difficulty", "description", "techniques",
)


def expected_fields(card: Dict[str, Any]) -> Tuple[str, ...]:
    """Which schema this card is written in."""
    if card.get("kind") or card.get("provenance") or ("name" in card and "challenge_name" not in card):
        return INDEX_FIELDS
    return ARCHIVE_FIELDS

# Phrases that indicate the card says how to confirm a finding, rather than
# merely asserting one.
VERIFICATION_MARKERS = (
    "verify", "verifies", "confirm", "check that", "show that", "prove",
    "reproduce", "validate", "test whether", "would disprove", "rule out",
)

# Phrases that hollow out a card: present, but carrying no observation.
VAGUE_MARKERS = (
    "the flag was found", "solved it", "easy challenge", "just look",
    "obvious", "trivial", "as expected", "somehow",
)


@dataclass
class QualityScore:
    """One card's score, kept per-axis so a low score is actionable."""

    card_id: str
    specificity: Optional[float] = 0.0
    coverage: Optional[float] = 0.0
    verification: Optional[float] = 0.0
    provenance: Optional[float] = 0.0
    freshness: Optional[float] = 0.0
    notes: List[str] = field(default_factory=list)

    @property
    def measured(self) -> Dict[str, float]:
        """Axes this card's schema actually allows us to judge."""
        return {k: getattr(self, k) for k in WEIGHTS if getattr(self, k) is not None}

    @property
    def unmeasurable(self) -> List[str]:
        return [k for k in WEIGHTS if getattr(self, k) is None]

    @property
    def total(self) -> float:
        """
        Weighted mean over the measurable axes only.

        An axis the card's schema cannot carry is excluded and the remaining
        weights renormalise, rather than scoring zero. Zero says "this card
        is bad at X"; absent says "X does not apply here", and conflating
        them is what made the first run of this module call 86% of the
        shipped corpus poor.
        """
        measured = self.measured
        if not measured:
            return 0.0
        weight = sum(WEIGHTS[k] for k in measured)
        return round(sum(WEIGHTS[k] * v for k, v in measured.items()) / weight, 4)

    @property
    def band(self) -> str:
        t = self.total
        if t >= 0.75:
            return "high"
        if t >= 0.5:
            return "adequate"
        if t >= 0.3:
            return "thin"
        return "poor"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "card_id": self.card_id,
            "total": self.total,
            "band": self.band,
            **{k: (None if getattr(self, k) is None else round(getattr(self, k), 3))
               for k in WEIGHTS},
            "unmeasurable": self.unmeasurable,
            "notes": list(self.notes),
        }

    def explain(self) -> str:
        axes = ", ".join(
            f"{k} " + ("n/a" if getattr(self, k) is None else f"{getattr(self, k):.2f}")
            for k in WEIGHTS
        )
        head = f"{self.card_id}: {self.band} ({self.total:.2f}) -- {axes}"
        if not self.notes:
            return head
        return head + "\n" + "\n".join(f"    {n}" for n in self.notes)


def _text_of(card: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("description", "explanation", "notes"):
        val = card.get(key)
        if isinstance(val, str):
            parts.append(val)
    for key in ("solve_steps", "tools_used", "references"):
        val = card.get(key)
        if isinstance(val, (list, tuple)):
            parts.extend(str(v) for v in val)
    return " ".join(parts).lower()


def _days_since(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        m = re.match(r"(\d{4})-(\d{2})-(\d{2})", text)
        if not m:
            return None
        when = datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - when).total_seconds() / 86400.0)


def score_card(card: Dict[str, Any], card_id: str = "") -> QualityScore:
    """Score one knowledge card on the five axes."""
    card = card or {}
    ident = card_id or str(card.get("id") or card.get("challenge_name") or "<unnamed>")
    out = QualityScore(card_id=ident)
    text = _text_of(card)

    # -- specificity -------------------------------------------------------
    techniques = [t for t in (card.get("techniques") or []) if str(t).strip()]
    known = [t for t in techniques if taxonomy.is_known(t)]
    tools = [t for t in (card.get("tools_used") or []) if str(t).strip()]
    steps = [s for s in (card.get("solve_steps") or []) if str(s).strip()]

    spec = 0.0
    if techniques:
        spec += 0.25
    if known:
        spec += 0.15 * min(1.0, len(known) / 2.0)
    else:
        if techniques:
            out.notes.append(
                "techniques are tagged but none resolves in the taxonomy -- retrieval "
                "and mastery will split on these names"
            )
    if tools:
        spec += 0.2 * min(1.0, len(tools) / 2.0)
    if steps:
        spec += 0.25 * min(1.0, len(steps) / 3.0)
    # Concrete detail: numbers, flags, file/function names.
    if re.search(r"\b(0x[0-9a-f]+|\d{2,})\b|\.(py|c|elf|pcap|png|jar|sol)\b|\(\)", text):
        spec += 0.15
    hits = [m for m in VAGUE_MARKERS if m in text]
    if hits:
        spec -= 0.2
        out.notes.append(f"vague phrasing carries no observation: {', '.join(hits[:3])}")
    out.specificity = max(0.0, min(1.0, spec))

    # -- coverage ----------------------------------------------------------
    fields = expected_fields(card)
    present = [f for f in fields if card.get(f) not in (None, "", [], {})]
    out.coverage = len(present) / len(fields)
    missing = [f for f in fields if f not in present]
    if missing:
        out.notes.append(f"missing field(s): {', '.join(missing)}")

    # -- verification ------------------------------------------------------
    ver = 0.0
    if any(m in text for m in VERIFICATION_MARKERS):
        ver += 0.6
    if card.get("verification") or card.get("verified"):
        ver += 0.4
    if len(steps) >= 3:
        ver += 0.2
    if fields is INDEX_FIELDS and not steps and not card.get("verification"):
        # An index entry is a pointer, not a writeup: it is not supposed to
        # carry a verification step, so scoring it on one would punish the
        # card for being the kind of card it is.
        out.verification = None
        out.notes.append("index entry: verification lives in the card it points at")
    else:
        out.verification = max(0.0, min(1.0, ver))
        if out.verification < 0.3:
            out.notes.append("never says how you would know the conclusion is right")

    # -- provenance --------------------------------------------------------
    prov = 0.0
    refs = [r for r in (card.get("references") or []) if str(r).strip()]
    if card.get("source"):
        prov += 0.4
    if refs:
        prov += 0.3
    if card.get("author") or card.get("license"):
        prov += 0.15
    if card.get("content_hash") or card.get("hash"):
        prov += 0.15
    out.provenance = max(0.0, min(1.0, prov))
    if not card.get("source") and not refs:
        out.notes.append("no source or reference: where this came from is unrecoverable")

    # -- freshness ---------------------------------------------------------
    age = _days_since(card.get("updated_at") or card.get("updated") or card.get("date") or card.get("retrieved_at"))
    if age is None and not card.get("version"):
        # Unmeasurable, not bad. Scoring it zero dragged every card in the
        # shipped corpus down by a tenth for a property none of them records,
        # which made the whole distribution look worse than it is. The gap is
        # reported instead -- see `corpus_report()["unmeasurable"]`.
        out.freshness = None
        out.notes.append("no date or version: staleness cannot be judged")
    else:
        fresh = 0.35 if card.get("version") else 0.0
        if age is not None:
            # Full marks under a year, decaying to zero at three.
            fresh += 0.65 * max(0.0, min(1.0, (1095.0 - age) / 730.0))
        out.freshness = max(0.0, min(1.0, fresh))

    return out


# ---------------------------------------------------------------------------
# Corpus-wide scoring
# ---------------------------------------------------------------------------


def _iter_cards(
    archive_dir: str = ARCHIVE_DIR,
    corpus_file: str = CORPUS_FILE,
) -> Iterable[Tuple[str, Dict[str, Any]]]:
    p = Path(archive_dir)
    if p.is_dir():
        for f in sorted(p.glob("*.json")):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
            except (OSError, json.JSONDecodeError, TypeError):
                continue
            if isinstance(d, dict):
                yield f.stem, d

    cf = Path(corpus_file)
    if cf.is_file():
        try:
            with open(cf, "r", encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(d, dict):
                        yield str(d.get("id") or f"corpus:{i}"), d
        except OSError:
            pass


def score_corpus(
    archive_dir: str = ARCHIVE_DIR,
    corpus_file: str = CORPUS_FILE,
) -> List[QualityScore]:
    return [score_card(card, ident) for ident, card in _iter_cards(archive_dir, corpus_file)]


def corpus_report(scores: Optional[Sequence[QualityScore]] = None) -> Dict[str, Any]:
    scores = list(scores if scores is not None else score_corpus())
    if not scores:
        return {"cards": 0}
    bands: Dict[str, int] = {}
    for s in scores:
        bands[s.band] = bands.get(s.band, 0) + 1
    axis_means: Dict[str, Any] = {}
    unmeasurable: Dict[str, int] = {}
    for k in WEIGHTS:
        vals = [getattr(s, k) for s in scores if getattr(s, k) is not None]
        axis_means[k] = round(sum(vals) / len(vals), 3) if vals else None
        skipped = len(scores) - len(vals)
        if skipped:
            unmeasurable[k] = skipped
    worst = sorted(scores, key=lambda s: s.total)[:10]
    return {
        "cards": len(scores),
        "mean_total": round(sum(s.total for s in scores) / len(scores), 3),
        "bands": dict(sorted(bands.items())),
        "axis_means": axis_means,
        "unmeasurable": dict(sorted(unmeasurable.items())),
        "weakest": [s.to_dict() for s in worst],
    }


def render_report(report: Optional[Dict[str, Any]] = None) -> str:
    rep = report or corpus_report()
    if not rep.get("cards"):
        return "No knowledge cards found."
    lines = [
        f"Knowledge quality: {rep['cards']} card(s), mean {rep['mean_total']:.2f}",
        "  bands: " + ", ".join(f"{k} {v}" for k, v in rep["bands"].items()),
        "  axis means: " + ", ".join(
            f"{k} " + ("n/a" if v is None else str(v)) for k, v in rep["axis_means"].items()
        ),
    ]
    if rep.get("unmeasurable"):
        lines.append("  unmeasurable (schema carries no such field): " + ", ".join(
            f"{k} on {v} card(s)" for k, v in rep["unmeasurable"].items()))
    lines += [
        "",
        "Weakest cards:",
    ]
    for row in rep["weakest"]:
        lines.append(f"  {row['card_id']}: {row['band']} ({row['total']:.2f})")
        for note in row["notes"][:2]:
            lines.append(f"      {note}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Retrieval hook
# ---------------------------------------------------------------------------

_CACHE: Dict[str, float] = {}


def quality_of(card: Dict[str, Any], card_id: str = "") -> float:
    """Cached total for one card, for use inside a ranking loop."""
    ident = card_id or str(card.get("id") or card.get("challenge_name") or "")
    if ident and ident in _CACHE:
        return _CACHE[ident]
    total = score_card(card, ident).total
    if ident:
        _CACHE[ident] = total
    return total


def clear_cache() -> None:
    _CACHE.clear()


def quality_feature(candidate: Dict[str, Any]) -> float:
    """
    The reranker's per-candidate quality feature, centred on zero.

    Centred rather than absolute so that quality *breaks ties* between
    similarly relevant cards instead of overriding relevance. A high-quality
    card about the wrong technique is still the wrong card.
    """
    return max(-1.0, min(1.0, (quality_of(candidate) - 0.5) * 2.0))
