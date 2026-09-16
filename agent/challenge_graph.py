"""
agent/challenge_graph.py

A graph over everything in the archive + corpus (Phase 3).

The retriever answers "what looks like this challenge?". The graph answers
the questions that come *after* that:

  - "I just solved this. What should I try next?"
  - "This is too hard. What is the gentlest thing that teaches the same idea?"
  - "How do I get from where I am to ret2libc?"

Nodes are challenges. Edges are weighted by how much two challenges share:
identical technique tags, same category, adjacent difficulty, and explicit
prerequisite links borrowed from agent.skill_graph.

Pure stdlib — the graph is small enough (hundreds of nodes) that a plain
adjacency dict beats pulling in networkx.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

ARCHIVE_DIR = os.path.join("data", "archive")
CORPUS_FILE = os.path.join("data", "corpus", "challenges.jsonl")

DIFFICULTY_ORDER = ["easy", "medium", "hard", "insane"]

# Edge weight contributions.
W_SHARED_TECHNIQUE = 1.0
W_SAME_CATEGORY = 0.25
W_ADJACENT_DIFFICULTY = 0.15
W_PREREQUISITE = 0.8

MIN_EDGE_WEIGHT = 0.3


@dataclass
class ChallengeNode:
    id: str
    name: str
    category: str
    difficulty: str = "medium"
    techniques: List[str] = field(default_factory=list)
    source: str = "archive"
    description: str = ""

    @property
    def difficulty_index(self) -> int:
        try:
            return DIFFICULTY_ORDER.index((self.difficulty or "medium").lower())
        except ValueError:
            return 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "difficulty": self.difficulty,
            "techniques": list(self.techniques),
            "source": self.source,
        }


@dataclass
class Edge:
    source: str
    target: str
    weight: float
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "weight": round(self.weight, 3),
            "reasons": list(self.reasons),
        }


class ChallengeGraph:
    """Undirected weighted graph of challenges, built from local data only."""

    def __init__(self) -> None:
        self.nodes: Dict[str, ChallengeNode] = {}
        self.adjacency: Dict[str, Dict[str, Edge]] = defaultdict(dict)
        self._by_technique: Dict[str, Set[str]] = defaultdict(set)

    # ---------------------------------------------------------------- build

    def add_node(self, node: ChallengeNode) -> None:
        self.nodes[node.id] = node
        for t in node.techniques:
            self._by_technique[str(t).lower()].add(node.id)

    def add_edge(self, a: str, b: str, weight: float, reason: str) -> None:
        if a == b or a not in self.nodes or b not in self.nodes:
            return
        existing = self.adjacency[a].get(b)
        if existing:
            existing.weight += weight
            if reason not in existing.reasons:
                existing.reasons.append(reason)
            mirror = self.adjacency[b][a]
            mirror.weight = existing.weight
            mirror.reasons = existing.reasons
            return
        edge = Edge(a, b, weight, [reason])
        self.adjacency[a][b] = edge
        self.adjacency[b][a] = Edge(b, a, weight, [reason])

    def build_edges(self) -> None:
        """Connect every pair that shares something meaningful."""
        ids = list(self.nodes)

        # Technique overlap drives most of the structure, so walk the
        # technique index instead of every O(n^2) pair.
        for technique, members in self._by_technique.items():
            members_list = sorted(members)
            if len(members_list) > 60:
                # Very common tags (e.g. "encoding-recognition") would create
                # a hairball. Link only within the same category.
                buckets: Dict[str, List[str]] = defaultdict(list)
                for nid in members_list:
                    buckets[self.nodes[nid].category].append(nid)
                groups = list(buckets.values())
            else:
                groups = [members_list]
            for group in groups:
                for i, a in enumerate(group):
                    for b in group[i + 1 :]:
                        self.add_edge(a, b, W_SHARED_TECHNIQUE, f"shares technique: {technique}")

        # Prerequisite edges from the skill graph.
        try:
            from agent.skill_graph import PREREQUISITES

            for technique, prereqs in PREREQUISITES.items():
                targets = self._by_technique.get(technique.lower(), set())
                if not targets:
                    continue
                for prereq in prereqs:
                    sources = self._by_technique.get(prereq.lower(), set())
                    for s in sources:
                        for t in targets:
                            self.add_edge(s, t, W_PREREQUISITE, f"prerequisite: {prereq} -> {technique}")
        except Exception:
            pass

        # Light category / difficulty affinity, only between nodes already
        # connected — this refines ordering without adding new links.
        for a in ids:
            for b, edge in list(self.adjacency[a].items()):
                na, nb = self.nodes[a], self.nodes[b]
                if na.category and na.category == nb.category:
                    edge.weight += W_SAME_CATEGORY
                if abs(na.difficulty_index - nb.difficulty_index) == 1:
                    edge.weight += W_ADJACENT_DIFFICULTY

    # ------------------------------------------------------------- queries

    def neighbors(self, node_id: str, limit: int = 5, min_weight: float = MIN_EDGE_WEIGHT) -> List[Edge]:
        edges = [e for e in self.adjacency.get(node_id, {}).values() if e.weight >= min_weight]
        edges.sort(key=lambda e: -e.weight)
        return edges[:limit]

    def find(self, text: str, limit: int = 5) -> List[ChallengeNode]:
        """Loose name/technique lookup so the CLI can take human input."""
        needle = (text or "").strip().lower()
        if not needle:
            return []
        exact = [n for n in self.nodes.values() if n.id.lower() == needle]
        if exact:
            return exact[:limit]
        hits = [
            n
            for n in self.nodes.values()
            if needle in n.name.lower() or any(needle in str(t).lower() for t in n.techniques)
        ]
        hits.sort(key=lambda n: (n.difficulty_index, n.name))
        return hits[:limit]

    def easier_siblings(self, node_id: str, limit: int = 3) -> List[ChallengeNode]:
        """Same idea, lower difficulty — the 'this is too hard' answer."""
        node = self.nodes.get(node_id)
        if not node:
            return []
        out = []
        for edge in self.neighbors(node_id, limit=30):
            other = self.nodes[edge.target]
            if other.difficulty_index < node.difficulty_index:
                out.append((edge.weight, other))
        out.sort(key=lambda pair: (-pair[0], pair[1].difficulty_index))
        return [n for _, n in out[:limit]]

    def next_steps(self, node_id: str, limit: int = 3) -> List[ChallengeNode]:
        """Same idea, one notch harder — the 'what now?' answer."""
        node = self.nodes.get(node_id)
        if not node:
            return []
        out = []
        for edge in self.neighbors(node_id, limit=30):
            other = self.nodes[edge.target]
            if other.difficulty_index > node.difficulty_index:
                out.append((edge.weight, other))
        out.sort(key=lambda pair: (-pair[0], pair[1].difficulty_index))
        return [n for _, n in out[:limit]]

    def shortest_path(self, start: str, goal: str, max_hops: int = 6) -> List[str]:
        """Breadth-first hop path between two challenges ([] if unreachable)."""
        if start not in self.nodes or goal not in self.nodes:
            return []
        if start == goal:
            return [start]
        seen = {start}
        queue: deque = deque([(start, [start])])
        while queue:
            current, path = queue.popleft()
            if len(path) > max_hops:
                continue
            for neighbor in sorted(
                self.adjacency.get(current, {}),
                key=lambda n: -self.adjacency[current][n].weight,
            ):
                if neighbor in seen:
                    continue
                new_path = path + [neighbor]
                if neighbor == goal:
                    return new_path
                seen.add(neighbor)
                queue.append((neighbor, new_path))
        return []

    def clusters(self, min_weight: float = 1.0) -> List[List[str]]:
        """Connected components above a weight floor — rough topic families."""
        seen: Set[str] = set()
        groups: List[List[str]] = []
        for nid in sorted(self.nodes):
            if nid in seen:
                continue
            component: List[str] = []
            stack = [nid]
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                component.append(cur)
                for other, edge in self.adjacency.get(cur, {}).items():
                    if edge.weight >= min_weight and other not in seen:
                        stack.append(other)
            groups.append(sorted(component))
        groups.sort(key=len, reverse=True)
        return groups

    def stats(self) -> Dict[str, Any]:
        edge_count = sum(len(v) for v in self.adjacency.values()) // 2
        by_cat: Dict[str, int] = defaultdict(int)
        by_diff: Dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by_cat[n.category or "unknown"] += 1
            by_diff[n.difficulty or "unknown"] += 1
        degrees = [len(v) for v in self.adjacency.values()] or [0]
        isolated = [nid for nid in self.nodes if not self.adjacency.get(nid)]
        return {
            "nodes": len(self.nodes),
            "edges": edge_count,
            "avg_degree": round(sum(degrees) / max(1, len(self.nodes)), 2),
            "isolated": len(isolated),
            "by_category": dict(sorted(by_cat.items())),
            "by_difficulty": dict(sorted(by_diff.items())),
            "clusters": len(self.clusters()),
        }

    # ------------------------------------------------------------- export

    def to_dict(self, max_edges: Optional[int] = None) -> Dict[str, Any]:
        edges: List[Edge] = []
        emitted: Set[Tuple[str, str]] = set()
        for a, targets in self.adjacency.items():
            for b, edge in targets.items():
                key = tuple(sorted((a, b)))
                if key in emitted:
                    continue
                emitted.add(key)
                edges.append(edge)
        edges.sort(key=lambda e: -e.weight)
        if max_edges:
            edges = edges[:max_edges]
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in edges],
            "stats": self.stats(),
        }

    def to_dot(self, max_edges: int = 200) -> str:
        """Graphviz export, handy for a quick visual sanity check."""
        lines = ["graph challenges {", '  node [shape=box, style=rounded];']
        for n in self.nodes.values():
            label = n.name.replace('"', "'")[:40]
            lines.append(f'  "{n.id}" [label="{label}\\n({n.category}/{n.difficulty})"];')
        data = self.to_dict(max_edges=max_edges)
        for e in data["edges"]:
            lines.append(f'  "{e["source"]}" -- "{e["target"]}" [weight={e["weight"]}];')
        lines.append("}")
        return "\n".join(lines)


# -------------------------------------------------------------------- load


def _nodes_from_archive(archive_dir: str = ARCHIVE_DIR) -> List[ChallengeNode]:
    root = Path(archive_dir)
    if not root.is_dir():
        return []
    out = []
    for fp in sorted(root.glob("*.json")):
        try:
            d = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        out.append(
            ChallengeNode(
                id=f"archive:{fp.stem}",
                name=d.get("challenge_name") or fp.stem,
                category=(d.get("category") or "misc").lower(),
                difficulty=(d.get("difficulty") or "medium").lower(),
                techniques=[str(t).lower() for t in (d.get("techniques") or [])],
                source="archive",
                description=(d.get("description") or "")[:300],
            )
        )
    return out


def _nodes_from_corpus(corpus_file: str = CORPUS_FILE) -> List[ChallengeNode]:
    fp = Path(corpus_file)
    if not fp.is_file():
        return []
    out = []
    for line in fp.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        if d.get("source") == "archive":
            continue  # already loaded from disk, avoid duplicate nodes
        out.append(
            ChallengeNode(
                id=f"corpus:{d.get('id')}",
                name=d.get("name") or str(d.get("id")),
                category=(d.get("category") or "misc").lower(),
                difficulty=(d.get("difficulty") or "medium").lower(),
                techniques=[str(t).lower() for t in (d.get("techniques") or [])],
                source="corpus",
                description=(d.get("description") or "")[:300],
            )
        )
    return out


def build_graph(
    archive_dir: str = ARCHIVE_DIR,
    corpus_file: str = CORPUS_FILE,
    include_corpus: bool = True,
) -> ChallengeGraph:
    graph = ChallengeGraph()
    for node in _nodes_from_archive(archive_dir):
        graph.add_node(node)
    if include_corpus:
        for node in _nodes_from_corpus(corpus_file):
            graph.add_node(node)
    graph.build_edges()
    return graph


_GRAPH: Optional[ChallengeGraph] = None


def get_graph(force_reload: bool = False, include_corpus: bool = True) -> ChallengeGraph:
    global _GRAPH
    if _GRAPH is None or force_reload:
        _GRAPH = build_graph(include_corpus=include_corpus)
    return _GRAPH


def render_neighborhood(graph: ChallengeGraph, query: str, limit: int = 5) -> str:
    """Terminal-friendly 'what is near this?' report."""
    matches = graph.find(query, limit=1)
    if not matches:
        return f"No challenge in the graph matches {query!r}."
    node = matches[0]
    lines = [
        f"# {node.name}",
        f"{node.category} · {node.difficulty} · techniques: {', '.join(node.techniques) or 'none tagged'}",
        "",
        "## Closely related",
    ]
    neighbors = graph.neighbors(node.id, limit=limit)
    if neighbors:
        for edge in neighbors:
            other = graph.nodes[edge.target]
            why = edge.reasons[0] if edge.reasons else "related"
            lines.append(f"- {other.name} ({other.difficulty}) — {why} [w={edge.weight:.2f}]")
    else:
        lines.append("- (nothing linked yet)")

    easier = graph.easier_siblings(node.id)
    if easier:
        lines += ["", "## Warm up with"]
        lines += [f"- {n.name} ({n.difficulty})" for n in easier]

    harder = graph.next_steps(node.id)
    if harder:
        lines += ["", "## Then try"]
        lines += [f"- {n.name} ({n.difficulty})" for n in harder]

    return "\n".join(lines)


if __name__ == "__main__":
    g = build_graph()
    print(json.dumps(g.stats(), indent=2))
