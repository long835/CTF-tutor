"""
agent/knowledge_graph.py

One technique, one node (item 11).

Before this module, what the project knew about `format-string` was spread
across four tables that had no idea the others existed:

    skill_graph.PREREQUISITES        what you must understand first
    evidence.REQUIREMENTS            what would have to be observed
    classify_challenge.TECHNIQUE_*   which category it belongs to
    tool_capabilities.CAPABILITIES   which tool can observe those signals
    data/technique_library.json      the concept, signals and scenarios
    misconception.CATALOGUE          the wrong mental model people bring

Each was individually fine. Together they drifted: a technique could have a
rubric and no prerequisites, a prerequisite chain and no rubric, an
indicator no installed tool could ever produce, or a category that disagreed
with the one the classifier used. Nothing detected the drift, because
nothing read more than one table at a time.

This module resolves all of them into a single `TechniqueNode` and -- more
usefully -- it *audits* the join. `audit()` is the part worth keeping: it
reports exactly where the sources contradict each other, and the tests fail
if new contradictions appear.

The design decision worth stating: this is a resolved **view**, not a
replacement. The underlying tables stay editable in the shape their owners
want (a rubric is easier to maintain next to the grading code; prerequisites
are easier to maintain as a dict). Rewriting them into one giant JSON file
would have produced a file nobody wants to edit, and broken 592 tests to no
benefit.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from agent import taxonomy

LIBRARY_PATH = os.path.join("data", "technique_library.json")
ARCHIVE_DIR = os.path.join("data", "archive")
CORPUS_FILE = os.path.join("data", "corpus", "challenges.jsonl")


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@dataclass
class TechniqueNode:
    """Everything the project knows about one technique, in one place."""

    technique: str
    kind: str = "technique"          # technique | concept
    category: str = "misc"
    difficulty: str = "medium"
    concept: str = ""                # the one idea to walk away with
    aliases: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)      # observable clues
    required_signals: List[str] = field(default_factory=list)  # rubric "required"
    tools: List[str] = field(default_factory=list)
    first_checks: List[str] = field(default_factory=list)
    counterexamples: List[str] = field(default_factory=list)   # lookalikes + refuters
    misconceptions: List[str] = field(default_factory=list)    # catalogue ids
    related: List[str] = field(default_factory=list)
    scenarios: List[str] = field(default_factory=list)
    verification: str = ""
    coverage: int = 0                # corpus/archive cards mentioning it
    sources: List[str] = field(default_factory=list)

    @property
    def path(self) -> str:
        return f"{self.category}/{self.technique}"

    @property
    def has_rubric(self) -> bool:
        return bool(self.required_signals)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "path": self.path,
            "kind": self.kind,
            "category": self.category,
            "difficulty": self.difficulty,
            "concept": self.concept,
            "aliases": list(self.aliases),
            "prerequisites": list(self.prerequisites),
            "indicators": list(self.indicators),
            "required_signals": list(self.required_signals),
            "tools": list(self.tools),
            "first_checks": list(self.first_checks),
            "counterexamples": list(self.counterexamples),
            "misconceptions": list(self.misconceptions),
            "related": list(self.related),
            "verification": self.verification,
            "coverage": self.coverage,
            "sources": list(self.sources),
        }

    def render(self) -> str:
        lines = [f"# {self.path}  ({self.kind}, {self.difficulty})"]
        if self.concept:
            lines.append(f"\n{self.concept}")
        if self.aliases:
            lines.append(f"\nalso written as: {', '.join(self.aliases)}")
        if self.prerequisites:
            lines.append(f"\nunderstand first: {', '.join(self.prerequisites)}")
        if self.indicators:
            lines.append("\nindicators:")
            lines += [f"  - {s}" for s in self.indicators[:8]]
        if self.tools:
            lines.append(f"\ntools that can observe those: {', '.join(self.tools)}")
        if self.counterexamples:
            lines.append("\ncould also be (do not conclude too early):")
            lines += [f"  - {s}" for s in self.counterexamples[:5]]
        if self.misconceptions:
            lines.append(f"\ncommon misconceptions: {', '.join(self.misconceptions)}")
        if self.verification:
            lines.append(f"\nto verify: {self.verification}")
        if self.related:
            lines.append(f"\nrelated: {', '.join(self.related[:8])}")
        lines.append(f"\nsources: {', '.join(self.sources)} · corpus coverage: {self.coverage}")
        return "\n".join(lines)


@dataclass
class Inconsistency:
    """One place where the contributing tables disagree."""

    kind: str
    technique: str
    detail: str
    severity: str = "warning"   # error | warning | info

    def __str__(self) -> str:
        return f"[{self.severity}] {self.kind}: {self.technique} -- {self.detail}"

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "technique": self.technique,
                "detail": self.detail, "severity": self.severity}


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class KnowledgeGraph:
    """The resolved join over every technique-knowledge source."""

    def __init__(
        self,
        nodes: Dict[str, TechniqueNode],
        tag_counts: Dict[str, int],
        card_categories: Optional[Dict[str, str]] = None,
        library_path: str = LIBRARY_PATH,
    ):
        self.nodes = nodes
        self.tag_counts = tag_counts
        # technique -> the category the corpus cards file it under, where the
        # cards agree with each other. Disagreement among cards is left out:
        # this check is for taxonomy drift, not for card-level noise.
        self.card_categories = dict(card_categories or {})
        self.library_path = library_path

    # -- lookup ------------------------------------------------------------

    def node(self, name: str) -> Optional[TechniqueNode]:
        return self.nodes.get(taxonomy.canonical(name))

    def __contains__(self, name: str) -> bool:
        return taxonomy.canonical(name) in self.nodes

    def techniques(self, category: Optional[str] = None) -> List[TechniqueNode]:
        out = [n for n in self.nodes.values() if n.kind == "technique"]
        if category:
            out = [n for n in out if n.category == category]
        return sorted(out, key=lambda n: n.technique)

    def concepts(self) -> List[TechniqueNode]:
        return sorted((n for n in self.nodes.values() if n.kind == "concept"),
                      key=lambda n: n.technique)

    def search(self, query: str, limit: int = 8) -> List[TechniqueNode]:
        q = (query or "").strip().lower()
        if not q:
            return []
        exact = self.node(q)
        hits: List[Tuple[float, TechniqueNode]] = []
        for node in self.nodes.values():
            if exact is not None and node is exact:
                continue
            score = 0.0
            if q in node.technique:
                score += 3.0
            if q in node.concept.lower():
                score += 1.5
            if any(q in s.lower() for s in node.indicators):
                score += 1.0
            if any(q in a for a in node.aliases):
                score += 2.0
            if score:
                hits.append((score, node))
        hits.sort(key=lambda pair: (-pair[0], pair[1].technique))
        out = ([exact] if exact else []) + [n for _, n in hits]
        return out[:limit]

    # -- traversal ---------------------------------------------------------

    def teaching_path(self, technique: str, mastered: Optional[Set[str]] = None) -> List[str]:
        """
        Prerequisites first, depth-limited, concepts before techniques.

        Walks the unified graph, so a prerequisite that only exists in the
        technique library (and not in the hand-written skill graph) is still
        scheduled.
        """
        mastered = {taxonomy.canonical(m) for m in (mastered or set())}
        target = taxonomy.canonical(technique)
        needed: List[str] = []
        seen: Set[str] = set()

        def walk(name: str, depth: int) -> None:
            if depth > 4 or name in seen:
                return
            seen.add(name)
            node = self.nodes.get(name)
            if node is None:
                return
            for p in node.prerequisites:
                if p not in mastered and p not in needed:
                    needed.append(p)
                walk(p, depth + 1)

        walk(target, 0)
        concepts = [n for n in needed if taxonomy.is_concept(n)]
        techs = [n for n in needed if not taxonomy.is_concept(n)]
        return concepts + techs + [target]

    def dependents(self, name: str) -> List[str]:
        """Techniques that list `name` as a prerequisite."""
        c = taxonomy.canonical(name)
        return sorted(n.technique for n in self.nodes.values() if c in n.prerequisites)

    def neighbours(self, name: str) -> Dict[str, List[str]]:
        node = self.node(name)
        if node is None:
            return {}
        return {
            "prerequisites": list(node.prerequisites),
            "dependents": self.dependents(node.technique),
            "related": list(node.related),
            "tools": list(node.tools),
            "misconceptions": list(node.misconceptions),
        }

    def tools_for(self, name: str) -> List[str]:
        node = self.node(name)
        return list(node.tools) if node else []

    def signals_for(self, name: str) -> List[str]:
        node = self.node(name)
        return list(node.indicators) if node else []

    # -- reporting ---------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        techs = self.techniques()
        by_cat: Dict[str, int] = {}
        for n in techs:
            by_cat[n.category] = by_cat.get(n.category, 0) + 1
        return {
            "techniques": len(techs),
            "concepts": len(self.concepts()),
            "with_rubric": sum(1 for n in techs if n.has_rubric),
            "with_tools": sum(1 for n in techs if n.tools),
            "with_prerequisites": sum(1 for n in techs if n.prerequisites),
            "with_corpus_coverage": sum(1 for n in techs if n.coverage),
            "by_category": dict(sorted(by_cat.items())),
            "distinct_corpus_tags": len(self.tag_counts),
            "canonical_corpus_tags": len({taxonomy.canonical(t) for t in self.tag_counts}),
        }

    def audit(self) -> List[Inconsistency]:
        """
        Where the sources disagree.

        Severity is chosen by what the disagreement *causes*:
          error   -- a run will silently do the wrong thing
          warning -- a run will be less useful than it could be
          info    -- a gap worth filling, no misbehaviour
        """
        out: List[Inconsistency] = []

        for bad in taxonomy.collisions():
            out.append(Inconsistency("alias_collision", bad.split()[0], bad, "error"))

        # Category disagreement between the taxonomy and the sources that
        # carry a category of their own. This check was missing until the
        # generated dataset produced a "web" case describing Solidity
        # modifiers: the node's signals came from a blockchain library entry
        # while its category came from the taxonomy, and nothing compared the
        # two. A card filed under one category and resolved under another is
        # a card that category-filtered retrieval will never return.
        for entry in _load_library(self.library_path):
            name = taxonomy.canonical(entry.get("technique", ""))
            stated = str(entry.get("category") or "").lower()
            if not name or not stated:
                continue
            resolved = taxonomy.category_of(name)
            if stated != resolved:
                out.append(Inconsistency(
                    "category_conflict", name,
                    f"technique library files it under '{stated}', the taxonomy resolves it "
                    f"to '{resolved}'; retrieval and evaluation will disagree about it",
                    "error"))

        for name, stated in sorted(self.card_categories.items()):
            canon = taxonomy.canonical(name)
            # Concept cards are filed under `misc` by the corpus builder
            # because a concept like `stack-layout` is not a challenge
            # category. Only techniques are expected to agree.
            if taxonomy.is_concept(canon):
                continue
            resolved = taxonomy.category_of(canon)
            if stated and stated != resolved:
                out.append(Inconsistency(
                    "category_conflict", canon,
                    f"corpus cards tag it under '{stated}', the taxonomy resolves it to "
                    f"'{resolved}'",
                    "warning"))

        unknown = taxonomy.unknown_tags(self.tag_counts)
        for tag in unknown:
            out.append(Inconsistency(
                "untaxonomised_tag", tag,
                f"corpus tags {self.tag_counts.get(tag, 0)} card(s) with a name the taxonomy "
                f"does not know; retrieval and mastery split on it",
                "warning"))

        for canon, variants, total in taxonomy.duplicate_report(self.tag_counts):
            out.append(Inconsistency(
                "duplicate_tag", canon,
                f"corpus spells this {len(variants)} ways ({', '.join(variants)}) across "
                f"{total} card(s); resolved at read time, still worth collapsing at ingest",
                "info"))

        for node in self.nodes.values():
            for p in node.prerequisites:
                if p not in self.nodes:
                    out.append(Inconsistency(
                        "unknown_prerequisite", node.technique,
                        f"requires '{p}', which has no node -- teaching_path will skip it",
                        "error"))

            if node.kind != "technique":
                continue

            if node.required_signals and not node.tools:
                out.append(Inconsistency(
                    "unobservable_rubric", node.technique,
                    "has required evidence signals but no tool in the registry produces them; "
                    "the rubric can never be satisfied",
                    "error"))

            if node.coverage >= 5 and not node.required_signals:
                out.append(Inconsistency(
                    "no_rubric", node.technique,
                    f"{node.coverage} corpus cards teach it, but there is no evidence rubric, "
                    f"so any claim about it grades as insufficient_evidence",
                    "warning"))

            if node.coverage >= 5 and not node.prerequisites:
                out.append(Inconsistency(
                    "no_prerequisites", node.technique,
                    f"{node.coverage} corpus cards teach it, but the curriculum has nothing to "
                    f"schedule before it",
                    "warning"))

            if not node.concept:
                out.append(Inconsistency(
                    "no_concept", node.technique,
                    "no one-line concept; hints and writeups fall back to the bare tag",
                    "info"))

            if not node.coverage:
                out.append(Inconsistency(
                    "no_coverage", node.technique,
                    "named in the taxonomy but no corpus or archive card teaches it",
                    "info"))

        order = {"error": 0, "warning": 1, "info": 2}
        return sorted(out, key=lambda i: (order.get(i.severity, 3), i.kind, i.technique))

    def render_audit(self, severity: Optional[str] = None) -> str:
        items = self.audit()
        if severity:
            items = [i for i in items if i.severity == severity]
        if not items:
            return "Knowledge graph: no inconsistencies at this severity."
        counts: Dict[str, int] = {}
        for i in items:
            counts[i.severity] = counts.get(i.severity, 0) + 1
        head = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        lines = [f"Knowledge graph audit: {head}", ""]
        lines += [f"  {i}" for i in items]
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stats": self.stats(),
            "nodes": {k: v.to_dict() for k, v in sorted(self.nodes.items())},
            "audit": [i.to_dict() for i in self.audit()],
        }


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def _load_library(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError, TypeError):
        return []
    entries = data.get("techniques") if isinstance(data, dict) else data
    return [e for e in (entries or []) if isinstance(e, dict)]


def _corpus_tags(
    archive_dir: str, corpus_file: str
) -> Tuple[Dict[str, int], List[List[str]], Dict[str, str]]:
    """Tag frequencies, the per-card tag sets, and each technique's card category."""
    counts: Dict[str, int] = {}
    cards: List[List[str]] = []
    cats: Dict[str, Set[str]] = {}

    def take(techs: Sequence[str], category: str = "") -> None:
        clean = [t for t in techs if isinstance(t, str) and t.strip()]
        if not clean:
            return
        cards.append(clean)
        for t in clean:
            counts[t] = counts.get(t, 0) + 1
            if category:
                cats.setdefault(taxonomy.canonical(t), set()).add(category.lower())

    p = Path(archive_dir)
    if p.is_dir():
        for f in sorted(p.glob("*.json")):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
            except (OSError, json.JSONDecodeError, TypeError):
                continue
            if isinstance(d, dict):
                take(d.get("techniques") or [], str(d.get("category") or ""))

    cf = Path(corpus_file)
    if cf.is_file():
        try:
            with open(cf, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(d, dict):
                        take(d.get("techniques") or [], str(d.get("category") or ""))
        except OSError:
            pass

    agreed = {name: next(iter(vals)) for name, vals in cats.items() if len(vals) == 1}
    return counts, cards, agreed


def _tool_index() -> Dict[str, List[str]]:
    """signal -> tools that can produce it, from the capability registry."""
    index: Dict[str, List[str]] = {}
    try:
        from agent.tool_capabilities import CAPABILITIES
    except Exception:  # pragma: no cover - registry is always importable in-tree
        return index
    for name, cap in CAPABILITIES.items():
        for produced in getattr(cap, "produces", []) or []:
            key = str(produced).lower()
            index.setdefault(key, []).append(name)
    return index


def _tools_for_signals(signals: Iterable[str], index: Dict[str, List[str]]) -> List[str]:
    """
    Which tools could observe these signals.

    Delegates to the capability registry's own matcher rather than doing its
    own string comparison. An earlier version here matched loosely (substring
    either way) and reported six fewer gaps than
    `tool_capabilities.uncovered_signals()` did -- two "authoritative"
    answers to the same question, which is exactly the drift this module
    exists to stop. `index` is retained for callers that pass a pre-built
    map, but the registry is the source of truth.
    """
    try:
        from agent.tool_capabilities import tools_for_signal
    except Exception:  # pragma: no cover - registry is always importable in-tree
        return []
    found: List[str] = []
    for signal in signals or []:
        for name in tools_for_signal(str(signal)):
            if name not in found:
                found.append(name)
    return sorted(found)


def build_graph(
    library_path: str = LIBRARY_PATH,
    archive_dir: str = ARCHIVE_DIR,
    corpus_file: str = CORPUS_FILE,
) -> KnowledgeGraph:
    """Join every technique-knowledge source into one graph."""
    from agent import evidence as evidence_mod
    from agent import misconception as misconception_mod
    from agent import skill_graph as skill_graph_mod

    nodes: Dict[str, TechniqueNode] = {}

    def ensure(name: str, source: str) -> Optional[TechniqueNode]:
        canon = taxonomy.canonical(name)
        if not canon:
            return None
        node = nodes.get(canon)
        if node is None:
            node = TechniqueNode(
                technique=canon,
                kind="concept" if taxonomy.is_concept(canon) else "technique",
                category=taxonomy.category_of(canon),
                aliases=taxonomy.aliases_of(canon),
            )
            nodes[canon] = node
        if source not in node.sources:
            node.sources.append(source)
        return node

    # 1. Taxonomy seeds every canonical id, so a technique nothing else knows
    #    about still appears (and shows up in the audit as uncovered).
    for t in taxonomy.all_techniques():
        ensure(t, "taxonomy")
    for c in taxonomy.all_concepts():
        ensure(c, "taxonomy")

    # 2. Technique library: concept, difficulty, signals, first checks, scenarios.
    for entry in _load_library(library_path):
        node = ensure(entry.get("technique", ""), "technique_library")
        if node is None:
            continue
        node.difficulty = str(entry.get("difficulty") or node.difficulty)
        if entry.get("concept") and not node.concept:
            node.concept = str(entry["concept"])
        for s in entry.get("signals") or []:
            if s not in node.indicators:
                node.indicators.append(str(s))
        for s in entry.get("first_checks") or []:
            if s not in node.first_checks:
                node.first_checks.append(str(s))
        for s in entry.get("scenarios") or []:
            if s not in node.scenarios:
                node.scenarios.append(str(s))

    # 3. Skill graph: prerequisites and concept blurbs.
    for tech, prereqs in getattr(skill_graph_mod, "PREREQUISITES", {}).items():
        node = ensure(tech, "skill_graph")
        if node is None:
            continue
        for p in prereqs:
            canon_p = taxonomy.canonical(p)
            ensure(canon_p, "skill_graph")
            if canon_p and canon_p not in node.prerequisites:
                node.prerequisites.append(canon_p)
    for concept, blurb in getattr(skill_graph_mod, "CONCEPTS", {}).items():
        node = ensure(concept, "skill_graph")
        if node is not None and not node.concept:
            node.concept = str(blurb)

    # 4. Evidence rubrics: required/supporting signals, refuters, lookalikes.
    for tech, req in getattr(evidence_mod, "REQUIREMENTS", {}).items():
        node = ensure(tech, "evidence_rubric")
        if node is None:
            continue
        for s in getattr(req, "required", []) or []:
            if s not in node.required_signals:
                node.required_signals.append(s)
            if s not in node.indicators:
                node.indicators.append(s)
        for s in getattr(req, "supporting", []) or []:
            if s not in node.indicators:
                node.indicators.append(s)
        for s in getattr(req, "alternatives", []) or []:
            if s not in node.counterexamples:
                node.counterexamples.append(s)
        for s in getattr(req, "contradicting", []) or []:
            label = f"argues against: {s}"
            if label not in node.counterexamples:
                node.counterexamples.append(label)
        if getattr(req, "verification", ""):
            node.verification = req.verification

    # 5. Tool capability registry: who can observe the indicators.
    index = _tool_index()
    for node in nodes.values():
        node.tools = _tools_for_signals(node.required_signals or node.indicators, index)

    # 6. Misconceptions, attached through the concepts they ask you to review.
    for m in getattr(misconception_mod, "CATALOGUE", []) or []:
        review = [taxonomy.canonical(c) for c in getattr(m, "review_concepts", []) or []]
        mid = getattr(m, "id", "")
        for node in nodes.values():
            touches = node.technique in review or any(p in review for p in node.prerequisites)
            if touches and mid and mid not in node.misconceptions:
                node.misconceptions.append(mid)

    # 7. Corpus coverage and co-occurrence -> `related`.
    tag_counts, cards, card_categories = _corpus_tags(archive_dir, corpus_file)
    for tag, count in tag_counts.items():
        node = ensure(tag, "corpus")
        if node is not None:
            node.coverage += count

    co: Dict[str, Dict[str, int]] = {}
    for card in cards:
        canon = taxonomy.normalise_all(card)
        for a in canon:
            for b in canon:
                if a != b:
                    co.setdefault(a, {})[b] = co.setdefault(a, {}).get(b, 0) + 1

    for name, node in nodes.items():
        related: List[str] = []
        # co-occurring in the same card, strongest first
        for other, weight in sorted(co.get(name, {}).items(), key=lambda kv: (-kv[1], kv[0])):
            if other not in related:
                related.append(other)
        # siblings: same category, sharing a prerequisite
        for other_name, other in nodes.items():
            if other_name == name or other.category != node.category:
                continue
            if node.prerequisites and set(node.prerequisites) & set(other.prerequisites):
                if other_name not in related:
                    related.append(other_name)
        node.related = related[:10]

    return KnowledgeGraph(nodes, tag_counts, card_categories, library_path)


_GRAPH: Optional[KnowledgeGraph] = None


def get_graph(force_reload: bool = False, **kwargs: Any) -> KnowledgeGraph:
    """Process-wide cached graph. Pass `force_reload=True` after editing data."""
    global _GRAPH
    if _GRAPH is None or force_reload or kwargs:
        graph = build_graph(**kwargs)
        if not kwargs:
            _GRAPH = graph
        return graph
    return _GRAPH


# ---------------------------------------------------------------------------
# Convenience wrappers used by the rest of the agent
# ---------------------------------------------------------------------------


def describe(technique: str) -> str:
    node = get_graph().node(technique)
    if node is None:
        return f"No knowledge-graph node for '{technique}'."
    return node.render()


def prerequisites_for(technique: str) -> List[str]:
    node = get_graph().node(technique)
    return list(node.prerequisites) if node else []


def related_techniques(technique: str, limit: int = 5) -> List[str]:
    node = get_graph().node(technique)
    return list(node.related[:limit]) if node else []


def tools_for(technique: str) -> List[str]:
    return get_graph().tools_for(technique)
