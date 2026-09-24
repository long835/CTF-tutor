"""
agent/corpus_builder.py

Build the local study corpus.

The previous version padded out to its target by emitting the same template
with "(v2)", "(v3)" suffixes. That inflated the count without adding any
information — three cards that say the same thing just teach the retriever
to return the same thing three times.

This version generates five genuinely different card types from
`data/technique_library.json`:

  concept        what the technique is and when it applies
  scenario       one concrete framing of it (each technique has several)
  triage         given these signals, what do you check first
  discrimination how to tell two easily-confused techniques apart
  prerequisite   the underlying concepts, pulled from the skill graph

Plus the curated archive entries themselves. Every card carries provenance
so `python main.py audit` can tell generated material from curated material.

Everything is deterministic: the same library produces the same corpus, so
evaluation runs stay comparable across machines and across commits.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from datetime import date
from typing import Any, Dict, List, Optional, Set, Tuple

ARCHIVE = Path("data/archive")
LIBRARY = Path("data/technique_library.json")
OUT_DIR = Path("data/corpus")
OUT_FILE = OUT_DIR / "challenges.jsonl"

CARD_KINDS = ("archive", "concept", "scenario", "triage", "discrimination", "prerequisite")

# How many same-category neighbours each technique is contrasted against.
DISCRIMINATION_FANOUT = 2


def _slug(text: str) -> str:
    out = "".join(c if c.isalnum() else "-" for c in str(text).lower())
    while "--" in out:
        out = out.replace("--", "-")
    return out.strip("-")[:60]




def _stamp(card: Dict[str, Any], library_entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Attach version/updated so knowledge_quality can score freshness (item 68)."""
    if library_entry:
        card.setdefault("version", library_entry.get("version", 1))
        card.setdefault("updated", library_entry.get("updated") or date.today().isoformat())
    else:
        card.setdefault("version", 1)
        card.setdefault("updated", date.today().isoformat())
    return card

def load_library(path: Path = LIBRARY) -> List[Dict[str, Any]]:
    """Read the technique library; an empty list if it is missing."""
    if not Path(path).is_file():
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    entries = data.get("techniques") if isinstance(data, dict) else data
    return [e for e in (entries or []) if isinstance(e, dict) and e.get("technique")]


def _load_archive() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not ARCHIVE.is_dir():
        return rows
    for fp in sorted(ARCHIVE.glob("*.json")):
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        rows.append(
            {
                "id": f"archive-{fp.stem}",
                "kind": "archive",
                "source": "archive",
                "provenance": "curated",
                "name": d.get("challenge_name") or fp.stem,
                "category": d.get("category") or "misc",
                "difficulty": d.get("difficulty") or "medium",
                "description": d.get("description") or "",
                "techniques": d.get("techniques") or d.get("tags") or [],
            }
        )
    return rows


def _concept_cards(library: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One card per technique: the idea, stripped of any specific challenge."""
    rows = []
    for entry in library:
        tech = entry["technique"]
        signals = entry.get("signals") or []
        rows.append(
            {
                "id": f"concept-{_slug(tech)}",
                "kind": "concept",
                "source": "library",
                "provenance": "derived",
                "name": f"Concept: {tech}",
                "category": entry.get("category", "misc"),
                "difficulty": entry.get("difficulty", "medium"),
                "description": (
                    f"{entry.get('concept', '')} Typical signals: {'; '.join(signals[:3])}."
                ).strip(),
                "techniques": [tech],
            }
        )
    return rows


def _scenario_cards(library: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One card per (technique, scenario): the same idea in a different skin."""
    rows = []
    for entry in library:
        tech = entry["technique"]
        for i, scenario in enumerate(entry.get("scenarios") or [], 1):
            rows.append(
                {
                    "id": f"scenario-{_slug(tech)}-{i}",
                    "kind": "scenario",
                    "source": "library",
                    "provenance": "derived",
                    "name": f"{entry.get('category', 'misc').upper()}: {scenario.rstrip('.')}",
                    "category": entry.get("category", "misc"),
                    "difficulty": entry.get("difficulty", "medium"),
                    "description": f"{scenario} {entry.get('concept', '')}".strip(),
                    "techniques": [tech],
                }
            )
    return rows


def _triage_cards(library: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Signals-to-first-moves cards — the procedural half of the knowledge."""
    rows = []
    for entry in library:
        tech = entry["technique"]
        signals = entry.get("signals") or []
        checks = entry.get("first_checks") or []
        if not signals and not checks:
            continue
        rows.append(
            {
                "id": f"triage-{_slug(tech)}",
                "kind": "triage",
                "source": "library",
                "provenance": "derived",
                "name": f"Triage: spotting {tech}",
                "category": entry.get("category", "misc"),
                "difficulty": "easy",
                "description": (
                    f"Signals that point at {tech}: {'; '.join(signals)}. "
                    f"Safe first checks before reaching for tools: {'; '.join(checks)}."
                ),
                "techniques": [tech],
            }
        )
    return rows


def _discrimination_cards(library: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    'How do I tell these two apart?' cards.

    Confusing two techniques from the same category is the most common way
    a learner burns an hour, so pair each technique with its category
    neighbours and spell out the distinguishing observation.
    """
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for entry in library:
        by_category.setdefault(entry.get("category", "misc"), []).append(entry)

    rows: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    for category, entries in sorted(by_category.items()):
        entries = sorted(entries, key=lambda e: e["technique"])
        if len(entries) < 2:
            continue
        for i, a in enumerate(entries):
            for offset in range(1, DISCRIMINATION_FANOUT + 1):
                j = (i + offset) % len(entries)
                if j == i:
                    continue
                b = entries[j]
                key = tuple(sorted((a["technique"], b["technique"])))
                if key in seen:
                    continue
                seen.add(key)
                first = a if a["technique"] == key[0] else b
                second = b if first is a else a
                rows.append(
                    {
                        "id": f"discriminate-{_slug(key[0])}-vs-{_slug(key[1])}",
                        "kind": "discrimination",
                        "source": "library",
                        "provenance": "derived",
                        "name": f"Telling {key[0]} from {key[1]}",
                        "category": category,
                        "difficulty": "medium",
                        "description": (
                            f"Both show up in {category} challenges and are easy to mix up. "
                            f"{first['technique']}: {first.get('concept', '')} "
                            f"Look for: {'; '.join((first.get('signals') or [])[:2])}. "
                            f"{second['technique']}: {second.get('concept', '')} "
                            f"Look for: {'; '.join((second.get('signals') or [])[:2])}. "
                            f"Decide from what you can observe, not from whichever you saw most recently."
                        ),
                        "techniques": [first["technique"], second["technique"]],
                    }
                )
    return rows


def _prerequisite_cards() -> List[Dict[str, Any]]:
    """Turn the skill graph's concept blurbs into retrievable cards."""
    try:
        from agent.skill_graph import CONCEPTS, PREREQUISITES
    except Exception:
        return []

    unlocks: Dict[str, List[str]] = {}
    for tech, prereqs in PREREQUISITES.items():
        for p in prereqs:
            unlocks.setdefault(p, []).append(tech)

    rows = []
    for concept, blurb in sorted(CONCEPTS.items()):
        needed_for = sorted(unlocks.get(concept, []))[:4]
        tail = f" Needed before: {', '.join(needed_for)}." if needed_for else ""
        rows.append(
            {
                "id": f"prereq-{_slug(concept)}",
                "kind": "prerequisite",
                "source": "skill_graph",
                "provenance": "derived",
                "name": f"Foundation: {concept}",
                "category": "misc",
                "difficulty": "easy",
                "description": f"{blurb}{tail}",
                "techniques": [concept],
            }
        )
    return rows


def build_corpus(min_entries: int = 120, include_archive: bool = True) -> Dict[str, Any]:
    """
    Generate the corpus and write it to data/corpus/challenges.jsonl.

    `min_entries` is a floor to report against, not a target to pad toward:
    the library produces what it produces, and the summary says whether the
    floor was met rather than duplicating cards to reach it.
    """
    library = load_library()

    rows: List[Dict[str, Any]] = []
    if include_archive:
        rows += _load_archive()
    rows += _concept_cards(library)
    rows += _scenario_cards(library)
    rows += _triage_cards(library)
    rows += _discrimination_cards(library)
    rows += _prerequisite_cards()

    seen: Set[str] = set()
    uniq: List[Dict[str, Any]] = []
    for row in rows:
        if row["id"] in seen:
            continue
        seen.add(row["id"])
        uniq.append(_stamp(row))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for row in uniq:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Evaluation slice: scenario cards make the best eval cases, since each
    # has exactly one intended technique and reads like a real prompt.
    gt_extra = [
        {
            "id": r["id"],
            "description": r["description"],
            "expected_category": r["category"],
            "expected_techniques": r["techniques"],
            "difficulty": r["difficulty"],
        }
        for r in uniq
        if r.get("kind") == "scenario"
    ]
    (OUT_DIR / "eval_extra.json").write_text(
        json.dumps(gt_extra, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    by_cat: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    by_diff: Dict[str, int] = {}
    for r in uniq:
        by_cat[r["category"]] = by_cat.get(r["category"], 0) + 1
        by_kind[r.get("kind", "unknown")] = by_kind.get(r.get("kind", "unknown"), 0) + 1
        by_diff[r["difficulty"]] = by_diff.get(r["difficulty"], 0) + 1

    techniques = {t for r in uniq for t in (r.get("techniques") or [])}
    archive_count = by_kind.get("archive", 0)

    return {
        "total": len(uniq),
        "archive": archive_count,
        "generated": len(uniq) - archive_count,
        # Retained so older callers and tests keep working.
        "synthetic": len(uniq) - archive_count,
        "distinct_techniques": len(techniques),
        "eval_cases": len(gt_extra),
        "by_kind": dict(sorted(by_kind.items())),
        "by_category": dict(sorted(by_cat.items())),
        "by_difficulty": dict(sorted(by_diff.items())),
        "meets_minimum": len(uniq) >= min_entries,
        "minimum_requested": min_entries,
        "path": str(OUT_FILE),
    }


if __name__ == "__main__":
    print(json.dumps(build_corpus(500), indent=2))
