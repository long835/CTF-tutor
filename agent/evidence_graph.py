"""
agent/evidence_graph.py

One graph instead of many logs (items 34, 35).

Every tool in this project currently reports into a flat list: readelf says
one thing, strings says another, GDB a third, and the agent re-reads all of
it as prose on every step. Nothing links the observation "NX enabled" to the
claim it bears on, and nothing records that two tools said it independently
rather than one tool saying it twice.

This module fuses tool output into a typed graph:

    artifact ──yields──▶ observation ──supports──▶ technique ──concludes──▶ verdict
                              │                        │
                              └──explains──▶ lookalike  └──requires──▶ gap

Three properties make it worth the indirection:

1.  **Corroboration is counted, not double-counted.** The same signal from
    two tools raises independence; the same signal from one tool twice does
    not. Repeating a tool is not evidence.

2.  **A failed tool leaves a hole, not a negative.** `add_tool_result` puts
    observations in the graph only when the tool actually ran. A crashed
    Ghidra becomes a recorded coverage gap — never "nothing interesting in
    this binary". This is item 9 carried into the reasoning layer, where it
    does the most damage if it is wrong.

3.  **Every claim has a path back to a tool.** `provenance()` returns the
    chain, which is what makes a writeup checkable and a failure debuggable.

Support levels and the technique rubric come from `agent.evidence`, so the
graph and the verifier cannot disagree about what a technique requires.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from agent.evidence import (
    REQUIREMENTS,
    EvidenceRequirement,
    SupportLevel,
    _matches,
    requirements_for,
)


class NodeKind(str, Enum):
    ARTIFACT = "artifact"        # a file, a service, a pasted blob
    OBSERVATION = "observation"  # something a tool actually saw
    KNOWLEDGE = "knowledge"      # reference material about OTHER challenges
    TECHNIQUE = "technique"      # a candidate vulnerability class
    HYPOTHESIS = "hypothesis"    # the agent's statement under test
    LOOKALIKE = "lookalike"      # an innocent explanation for an observation
    GAP = "gap"                  # a required signal nothing has produced yet
    VERDICT = "verdict"          # the graded outcome


class EdgeKind(str, Enum):
    YIELDS = "yields"        # artifact  -> observation
    SUPPORTS = "supports"    # observation -> technique / hypothesis
    REFUTES = "refutes"      # observation -> technique / hypothesis
    REQUIRES = "requires"    # technique -> gap
    EXPLAINS = "explains"    # lookalike -> observation
    TESTS = "tests"          # hypothesis -> technique
    SUGGESTS = "suggests"    # knowledge -> technique (candidate, never support)
    CONCLUDES = "concludes"  # technique -> verdict


def _slug(text: str, limit: int = 60) -> str:
    out = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return (out or "x")[:limit]


@dataclass
class Node:
    """One vertex. `sources` is the set of tools that reported it."""

    id: str
    kind: NodeKind
    label: str
    detail: str = ""
    sources: List[str] = field(default_factory=list)
    confidence: float = 1.0
    negative: bool = False          # "ran cleanly and found nothing"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def independence(self) -> int:
        """How many distinct tools reported this. Two beats one twice."""
        return len({s for s in self.sources if s})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "label": self.label,
            "detail": self.detail,
            "sources": list(self.sources),
            "confidence": round(self.confidence, 3),
            "negative": self.negative,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Node":
        return cls(
            id=data["id"],
            kind=NodeKind(data.get("kind", "observation")),
            label=data.get("label", ""),
            detail=data.get("detail", ""),
            sources=list(data.get("sources") or []),
            confidence=float(data.get("confidence", 1.0)),
            negative=bool(data.get("negative", False)),
            metadata=dict(data.get("metadata") or {}),
        )


@dataclass
class Edge:
    src: str
    dst: str
    kind: EdgeKind
    weight: float = 1.0
    note: str = ""

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.src, self.dst, self.kind.value)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind.value,
            "weight": round(self.weight, 3),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Edge":
        return cls(
            src=data["src"],
            dst=data["dst"],
            kind=EdgeKind(data.get("kind", "supports")),
            weight=float(data.get("weight", 1.0)),
            note=data.get("note", ""),
        )


@dataclass
class CoverageGap:
    """A tool that should have contributed evidence and did not."""

    tool: str
    status: str
    reason: str = ""
    retryable: bool = False
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "reason": self.reason,
            "retryable": self.retryable,
            "target": self.target,
        }

    def __str__(self) -> str:
        tail = f" ({self.reason})" if self.reason else ""
        return f"{self.tool}: {self.status}{tail} — no evidence either way"


@dataclass
class TechniqueSupport:
    """Graded support for one technique, with the nodes that produced it."""

    technique: str
    level: SupportLevel
    score: float
    supporting: List[str] = field(default_factory=list)      # node ids
    refuting: List[str] = field(default_factory=list)        # node ids
    gaps: List[str] = field(default_factory=list)            # missing signals
    open_lookalikes: List[str] = field(default_factory=list)
    independent_sources: int = 0
    caveat: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "level": self.level.value,
            "score": round(self.score, 3),
            "supporting": list(self.supporting),
            "refuting": list(self.refuting),
            "gaps": list(self.gaps),
            "open_lookalikes": list(self.open_lookalikes),
            "independent_sources": self.independent_sources,
            "caveat": self.caveat,
        }


class EvidenceGraph:
    """
    The fused view of everything the agent has actually observed.

    Nothing enters this graph that a tool did not report. Model inference
    belongs on hypothesis nodes, which are kept a different kind precisely
    so that "the model thinks so" can never be mistaken for "a tool saw it".
    """

    def __init__(self, challenge_id: str = ""):
        self.challenge_id = challenge_id
        self.nodes: Dict[str, Node] = {}
        self._edges: Dict[Tuple[str, str, str], Edge] = {}
        self.coverage_gaps: List[CoverageGap] = []

    # ------------------------------------------------------------- basics

    @property
    def edges(self) -> List[Edge]:
        return list(self._edges.values())

    def __len__(self) -> int:
        return len(self.nodes)

    def node(self, node_id: str) -> Optional[Node]:
        return self.nodes.get(node_id)

    def nodes_of_kind(self, kind: NodeKind) -> List[Node]:
        return [n for n in self.nodes.values() if n.kind is kind]

    def add_node(
        self,
        kind: NodeKind,
        label: str,
        detail: str = "",
        source: str = "",
        confidence: float = 1.0,
        negative: bool = False,
        node_id: str = "",
        **metadata: Any,
    ) -> Node:
        """
        Add a node, merging into an existing one with the same identity.

        Merging is what makes corroboration measurable: a second tool
        reporting the same thing extends `sources` rather than creating a
        near-duplicate vertex the agent would then count twice.
        """
        nid = node_id or f"{kind.value[:3]}:{_slug(label)}"
        existing = self.nodes.get(nid)
        if existing is not None:
            if source and source not in existing.sources:
                existing.sources.append(source)
            if detail and detail not in existing.detail:
                existing.detail = (existing.detail + " | " + detail).strip(" |")[:600]
            existing.confidence = max(existing.confidence, confidence)
            existing.metadata.update({k: v for k, v in metadata.items() if v is not None})
            return existing
        node = Node(
            id=nid,
            kind=kind,
            label=label,
            detail=detail[:600],
            sources=[source] if source else [],
            confidence=confidence,
            negative=negative,
            metadata=dict(metadata),
        )
        self.nodes[nid] = node
        return node

    def add_edge(
        self,
        src: str,
        dst: str,
        kind: EdgeKind,
        weight: float = 1.0,
        note: str = "",
    ) -> Optional[Edge]:
        """Link two existing nodes. Unknown endpoints are refused, not invented."""
        if src not in self.nodes or dst not in self.nodes:
            return None
        edge = Edge(src=src, dst=dst, kind=kind, weight=weight, note=note)
        prior = self._edges.get(edge.key)
        if prior is not None:
            prior.weight = max(prior.weight, weight)
            if note and note not in prior.note:
                prior.note = (prior.note + "; " + note).strip("; ")[:300]
            return prior
        self._edges[edge.key] = edge
        return edge

    def edges_from(self, node_id: str, kind: Optional[EdgeKind] = None) -> List[Edge]:
        return [e for e in self._edges.values()
                if e.src == node_id and (kind is None or e.kind is kind)]

    def edges_to(self, node_id: str, kind: Optional[EdgeKind] = None) -> List[Edge]:
        return [e for e in self._edges.values()
                if e.dst == node_id and (kind is None or e.kind is kind)]

    # -------------------------------------------------------- ingestion

    def add_artifact(self, path: str, kind: str = "file", **meta: Any) -> Node:
        return self.add_node(
            NodeKind.ARTIFACT, path or "(unnamed artifact)",
            detail=kind, artifact_kind=kind, **meta,
        )

    def add_observation(
        self,
        label: str,
        source: str,
        detail: str = "",
        confidence: float = 1.0,
        negative: bool = False,
        artifact: str = "",
    ) -> Node:
        """Record something a tool saw, linked to the artifact it came from."""
        node = self.add_node(
            NodeKind.OBSERVATION, label, detail=detail,
            source=source, confidence=confidence, negative=negative,
        )
        if artifact:
            art = self.add_artifact(artifact)
            self.add_edge(art.id, node.id, EdgeKind.YIELDS, note=source)
        return node

    def add_knowledge(self, label: str, source: str, detail: str = "") -> Node:
        """
        Record reference material — an archive hit, a concept card, a writeup.

        Kept a separate kind from OBSERVATION on purpose. A knowledge card
        titled "Pattern WEB: JWT Validation" mentions every signal the JWT
        rubric looks for, so ingesting it as an observation would let the
        agent confirm a claim about *this* challenge using a document about
        a different one. Retrieval may nominate candidates; only a tool that
        looked at the actual artifact may support them.
        """
        return self.add_node(
            NodeKind.KNOWLEDGE, label, detail=detail, source=source, confidence=0.5,
        )

    def _is_reference_tool(self, tool: str) -> bool:
        """
        Whether a tool reports on the challenge or merely about the world.

        Read from the capability registry, which already declares that
        retrieval and decomposition produce candidates rather than
        observations, so the two modules cannot drift apart.
        """
        try:
            from agent.tool_capabilities import capability
            cap = capability(tool)
        except Exception:
            return False
        return cap is not None and not cap.produces

    def add_tool_result(self, result: Any, artifact: str = "") -> List[Node]:
        """
        Fuse one normalized `ToolResult` into the graph.

        The branch that matters is the failure branch: it adds a coverage
        gap and returns no nodes, so downstream scoring sees missing
        evidence rather than evidence of absence.
        """
        tool = str(getattr(result, "tool", "") or "tool")
        status = getattr(result, "status", None)
        status_value = getattr(status, "value", str(status or "ok"))

        if getattr(status, "is_failure", False):
            self.coverage_gaps.append(
                CoverageGap(
                    tool=tool,
                    status=status_value,
                    reason=str(getattr(result, "error", "") or "")[:200],
                    retryable=bool(getattr(result, "retryable", False)),
                    target=artifact,
                )
            )
            return []

        if getattr(result, "is_evidence_of_absence", False):
            # A clean, empty run IS a finding, and is marked as one.
            node = self.add_observation(
                label=f"{tool}: nothing found",
                source=tool,
                detail="tool ran cleanly and returned no findings",
                negative=True,
                artifact=artifact,
            )
            return [node]

        reference = self._is_reference_tool(tool)

        created: List[Node] = []
        for obs in getattr(result, "observations", None) or []:
            label = f"{getattr(obs, 'kind', 'finding')}: {getattr(obs, 'value', '')}".strip(": ")
            if reference:
                created.append(self.add_knowledge(
                    label=label, source=tool,
                    detail=str(getattr(obs, "detail", "") or ""),
                ))
                continue
            created.append(
                self.add_observation(
                    label=label,
                    source=getattr(obs, "source", "") or tool,
                    detail=str(getattr(obs, "detail", "") or ""),
                    confidence=float(getattr(obs, "confidence", 1.0)),
                    artifact=artifact,
                )
            )

        if not created:
            raw = str(getattr(result, "raw_output", "") or "").strip()
            if raw and reference:
                created.append(self.add_knowledge(
                    label=f"{tool} reference material", source=tool, detail=raw[:400],
                ))
            elif raw:
                created.append(
                    self.add_observation(
                        label=f"{tool} output",
                        source=tool,
                        detail=raw[:400],
                        confidence=0.6,
                        artifact=artifact,
                    )
                )
        for warning in getattr(result, "warnings", None) or []:
            self.coverage_gaps.append(
                CoverageGap(tool=tool, status="partial", reason=str(warning)[:200], target=artifact)
            )
        return created

    def add_hypothesis(self, hypothesis: Any) -> Node:
        """Add the agent's own claim — deliberately a different node kind."""
        hid = str(getattr(hypothesis, "id", "") or _slug(str(hypothesis)))
        statement = str(getattr(hypothesis, "statement", "") or hypothesis)
        technique = str(getattr(hypothesis, "technique", "") or "")
        node = self.add_node(
            NodeKind.HYPOTHESIS, statement,
            node_id=f"hyp:{hid}",
            source="agent",
            confidence=float(getattr(hypothesis, "confidence", 0.5)),
            technique=technique,
            status=str(getattr(hypothesis, "status", "active")),
        )
        if technique:
            tech_node = self.attach_technique(technique)
            if tech_node is not None:
                self.add_edge(node.id, tech_node.id, EdgeKind.TESTS)
        return node

    # --------------------------------------------------------- technique

    def _observation_text(self, node: Node) -> str:
        return f"{node.label}\n{node.detail}".lower()

    def attach_technique(self, technique: str) -> Optional[Node]:
        """
        Add a technique node and wire every observation that bears on it.

        Runs the rubric from `agent.evidence` against each observation
        individually, which is the part a flat text blob cannot do: it
        records *which* observation supports the claim, so the support can
        later be traced, weighted by independence, or withdrawn when the
        tool that produced it turns out to have failed.
        """
        technique = (technique or "").strip().lower()
        if not technique:
            return None
        req = requirements_for(technique)
        tech_node = self.add_node(
            NodeKind.TECHNIQUE, technique,
            node_id=f"tec:{_slug(technique)}",
            detail=(req.verification if req else "no rubric defined"),
            has_rubric=bool(req),
        )
        if req is None:
            return tech_node

        observations = self.nodes_of_kind(NodeKind.OBSERVATION)
        matched_required: Set[str] = set()

        for signal in req.required:
            hits = [o for o in observations if _matches(signal, self._observation_text(o))]
            if hits:
                matched_required.add(signal)
                for o in hits:
                    self.add_edge(o.id, tech_node.id, EdgeKind.SUPPORTS,
                                  weight=1.0, note=f"required: {signal}")
            else:
                gap = self.add_node(
                    NodeKind.GAP, signal,
                    node_id=f"gap:{_slug(technique)}:{_slug(signal)}",
                    detail=f"required for {technique}",
                    technique=technique,
                )
                self.add_edge(tech_node.id, gap.id, EdgeKind.REQUIRES)

        for signal in req.supporting:
            for o in observations:
                if _matches(signal, self._observation_text(o)):
                    self.add_edge(o.id, tech_node.id, EdgeKind.SUPPORTS,
                                  weight=0.4, note=f"supporting: {signal}")

        for signal in req.contradicting:
            for o in observations:
                if _matches(signal, self._observation_text(o)):
                    self.add_edge(o.id, tech_node.id, EdgeKind.REFUTES,
                                  weight=1.0, note=f"contradicting: {signal}")

        # Reference material is linked, but as a suggestion only: it never
        # reaches the supports/refutes edges the score is computed from.
        for card in self.nodes_of_kind(NodeKind.KNOWLEDGE):
            if any(_matches(sig, self._observation_text(card))
                   for sig in list(req.required) + list(req.supporting)):
                self.add_edge(card.id, tech_node.id, EdgeKind.SUGGESTS,
                              note="nominated by retrieval")

        # Lookalikes stay in the graph while the claim is unproven, so the
        # agent is reminded of what else produces the same signals.
        for alt in req.alternatives:
            alt_node = self.add_node(
                NodeKind.LOOKALIKE, alt,
                node_id=f"alt:{_slug(technique)}:{_slug(alt, 40)}",
                technique=technique,
            )
            self.add_edge(alt_node.id, tech_node.id, EdgeKind.EXPLAINS,
                          note="alternative explanation")
        return tech_node

    def assess_technique(self, technique: str) -> TechniqueSupport:
        """
        Grade a technique from the graph.

        Thresholds mirror `agent.evidence.assess` so the two cannot return
        conflicting verdicts; what the graph adds is independence counting
        and a caveat when every supporting signal came from one tool.
        """
        technique = (technique or "").strip().lower()
        tech_node = self.nodes.get(f"tec:{_slug(technique)}")
        if tech_node is None:
            tech_node = self.attach_technique(technique)
        req = requirements_for(technique)

        if tech_node is None or req is None:
            return TechniqueSupport(
                technique=technique or "unknown",
                level=SupportLevel.INSUFFICIENT_EVIDENCE,
                score=0.2,
                caveat="no evidence rubric defined for this technique",
            )

        supports = self.edges_to(tech_node.id, EdgeKind.SUPPORTS)
        refutes = self.edges_to(tech_node.id, EdgeKind.REFUTES)
        gaps = [self.nodes[e.dst].label for e in self.edges_from(tech_node.id, EdgeKind.REQUIRES)
                if e.dst in self.nodes]

        supporting_ids = sorted({e.src for e in supports})
        refuting_ids = sorted({e.src for e in refutes})
        sources: Set[str] = set()
        for nid in supporting_ids:
            sources.update(self.nodes[nid].sources)
        # Neither the agent's own inference nor the user's description is an
        # independent tool, so neither may corroborate the other.
        independence = len({s for s in sources if s and s not in ("agent", "user")})

        if refuting_ids:
            return TechniqueSupport(
                technique=technique, level=SupportLevel.REFUTED, score=0.1,
                supporting=supporting_ids, refuting=refuting_ids, gaps=gaps,
                independent_sources=independence,
                caveat="a contradicting observation is present",
            )

        total_req = len(req.required) or 1
        matched_req = total_req - len([g for g in gaps if g in req.required])
        req_ratio = matched_req / total_req
        sup_hits = len([e for e in supports if e.note.startswith("supporting")])
        sup_ratio = sup_hits / (len(req.supporting) or 1)

        if req_ratio >= 1.0 and sup_hits:
            level, score = SupportLevel.SUPPORTED, min(0.95, 0.7 + 0.25 * sup_ratio)
            lookalikes: List[str] = []
        elif req_ratio >= 1.0:
            level, score = SupportLevel.LIKELY, 0.65
            lookalikes = list(req.alternatives)
        elif req_ratio >= 0.5:
            level, score = SupportLevel.UNCERTAIN, 0.4 + 0.1 * sup_ratio
            lookalikes = list(req.alternatives)
        else:
            level, score = SupportLevel.INSUFFICIENT_EVIDENCE, 0.2
            lookalikes = list(req.alternatives)

        caveat = ""
        if level in (SupportLevel.SUPPORTED, SupportLevel.LIKELY) and independence <= 1:
            caveat = (
                "every supporting observation came from a single tool; "
                "corroborate with an independent one before relying on this"
            )
        if self.coverage_gaps:
            failed = ", ".join(sorted({g.tool for g in self.coverage_gaps}))
            caveat = (caveat + f" | incomplete coverage: {failed} produced no evidence").strip(" |")

        return TechniqueSupport(
            technique=technique, level=level, score=score,
            supporting=supporting_ids, refuting=refuting_ids, gaps=gaps,
            open_lookalikes=lookalikes, independent_sources=independence,
            caveat=caveat,
        )

    def missing_signals(self, technique: str = "") -> List[str]:
        """Required signals with nothing backing them — the planner's to-do list."""
        out: List[str] = []
        for node in self.nodes_of_kind(NodeKind.GAP):
            if technique and node.metadata.get("technique") != (technique or "").lower():
                continue
            if node.label not in out:
                out.append(node.label)
        return out

    def best_technique(self) -> Optional[TechniqueSupport]:
        """Highest-scoring technique that is not refuted."""
        scored = [self.assess_technique(n.label) for n in self.nodes_of_kind(NodeKind.TECHNIQUE)]
        scored = [s for s in scored if s.level is not SupportLevel.REFUTED]
        if not scored:
            return None
        return max(scored, key=lambda s: s.score)

    # -------------------------------------------------------- provenance

    def provenance(self, node_id: str) -> List[str]:
        """
        Where a node came from, as a readable chain.

        A claim whose chain ends at `agent` rather than at a tool is model
        inference; keeping that visible is the point.
        """
        node = self.nodes.get(node_id)
        if node is None:
            return []
        chain = [f"{node.kind.value}: {node.label}"]
        seen = {node_id}
        frontier = [node_id]
        while frontier:
            current = frontier.pop(0)
            for edge in self.edges_to(current):
                if edge.src in seen:
                    continue
                seen.add(edge.src)
                upstream = self.nodes[edge.src]
                chain.append(f"  ←{edge.kind.value}— {upstream.kind.value}: {upstream.label}"
                             + (f" [{', '.join(upstream.sources)}]" if upstream.sources else ""))
                frontier.append(edge.src)
        return chain

    # ------------------------------------------------------------ output

    def render(self, technique: str = "", max_observations: int = 12) -> str:
        """
        ASCII view for prompts, traces, and writeups.

        Small models reason over this considerably better than over
        concatenated tool logs, because the structure states the relation
        instead of leaving it to be inferred.
        """
        lines: List[str] = ["EVIDENCE GRAPH" + (f" — {technique}" if technique else "")]
        artifacts = self.nodes_of_kind(NodeKind.ARTIFACT)
        if artifacts:
            lines.append("Artifacts:")
            for a in artifacts[:6]:
                lines.append(f"  ▪ {a.label}" + (f" ({a.detail})" if a.detail else ""))

        observations = self.nodes_of_kind(NodeKind.OBSERVATION)
        if observations:
            lines.append("Observations:")
            for o in observations[:max_observations]:
                mark = "∅" if o.negative else "•"
                corro = f" ×{o.independence} tools" if o.independence > 1 else ""
                src = ", ".join(o.sources[:3])
                lines.append(f"  {mark} {o.label} [{src}]{corro}")

        knowledge = self.nodes_of_kind(NodeKind.KNOWLEDGE)
        if knowledge:
            lines.append("Reference material (candidates only — not evidence about this challenge):")
            for k in knowledge[:5]:
                lines.append(f"  ▷ {k.label} [{', '.join(k.sources[:2])}]")

        techniques = self.nodes_of_kind(NodeKind.TECHNIQUE)
        if technique:
            techniques = [t for t in techniques if t.label == technique.strip().lower()]
        for t in techniques[:4]:
            support = self.assess_technique(t.label)
            lines.append(f"Candidate: {t.label} → {support.level.value} ({support.score:.2f})")
            for nid in support.supporting[:6]:
                lines.append(f"    ✓ {self.nodes[nid].label}")
            for nid in support.refuting[:4]:
                lines.append(f"    ✗ {self.nodes[nid].label}")
            for gap in support.gaps[:4]:
                lines.append(f"    ? still needed: {gap}")
            for alt in support.open_lookalikes[:2]:
                lines.append(f"    ~ could also be: {alt}")
            if support.caveat:
                lines.append(f"    ! {support.caveat}")

        if self.coverage_gaps:
            lines.append("Coverage gaps (absence of evidence, not evidence of absence):")
            for gap in self.coverage_gaps[:5]:
                lines.append(f"  ⚠ {gap}")
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self._edges),
            "observations": len(self.nodes_of_kind(NodeKind.OBSERVATION)),
            "knowledge": len(self.nodes_of_kind(NodeKind.KNOWLEDGE)),
            "techniques": len(self.nodes_of_kind(NodeKind.TECHNIQUE)),
            "gaps": len(self.nodes_of_kind(NodeKind.GAP)),
            "coverage_gaps": len(self.coverage_gaps),
            "corroborated": len([n for n in self.nodes_of_kind(NodeKind.OBSERVATION)
                                 if n.independence > 1]),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self._edges.values()],
            "coverage_gaps": [g.to_dict() for g in self.coverage_gaps],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceGraph":
        graph = cls(challenge_id=data.get("challenge_id", ""))
        for raw in data.get("nodes") or []:
            node = Node.from_dict(raw)
            graph.nodes[node.id] = node
        for raw in data.get("edges") or []:
            edge = Edge.from_dict(raw)
            if edge.src in graph.nodes and edge.dst in graph.nodes:
                graph._edges[edge.key] = edge
        for raw in data.get("coverage_gaps") or []:
            graph.coverage_gaps.append(CoverageGap(**{
                k: v for k, v in raw.items()
                if k in ("tool", "status", "reason", "retryable", "target")
            }))
        return graph


def build_graph(state: Any) -> EvidenceGraph:
    """
    Construct a graph from an `AgentState`.

    Used for states built before the graph existed, and for re-deriving the
    graph during replay. Evidence records carry their source tool, which is
    what makes independence counting possible after the fact.
    """
    graph = EvidenceGraph(challenge_id=str(getattr(state, "challenge_id", "") or ""))

    for path in getattr(state, "discovered_artifacts", None) or []:
        graph.add_artifact(str(path))

    summary = str(getattr(state, "challenge_summary", "") or "")
    if summary:
        graph.add_observation(
            label="challenge description",
            source="user",
            detail=summary[:400],
            confidence=0.9,
        )

    for fact in getattr(state, "known_facts", None) or []:
        text = str(fact)
        source = "agent"
        match = re.match(r"\[([^\]]+)\]\s*(.*)", text)
        if match:
            source, text = match.group(1), match.group(2)
        graph.add_observation(label=text[:120], source=source, detail=text, confidence=0.7)

    for ev in getattr(state, "evidence", None) or []:
        source = str(getattr(ev, "source", "") or "tool")
        finding = str(getattr(ev, "finding", "") or "")
        content = str(getattr(ev, "content", "") or "")
        label = (finding or content)[:120]
        if not label.strip():
            continue
        if content.startswith("ERROR:"):
            graph.coverage_gaps.append(
                CoverageGap(tool=source, status="error", reason=content[6:206].strip())
            )
            continue
        if graph._is_reference_tool(source):
            graph.add_knowledge(label=label, source=source, detail=content[:400])
            continue
        graph.add_observation(
            label=label,
            source=source,
            detail=content[:400],
            confidence=float(getattr(ev, "confidence", 0.7)),
        )

    for h in getattr(state, "hypotheses", None) or []:
        graph.add_hypothesis(h)
    for technique in getattr(state, "candidate_techniques", None) or []:
        graph.attach_technique(str(technique))
    return graph


def graph_context_block(graph: EvidenceGraph, technique: str = "", max_tokens: int = 700) -> str:
    """Render for prompt injection, trimmed to a rough token budget."""
    text = graph.render(technique=technique)
    limit = int(max_tokens * 3.6)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n… (graph truncated)"
