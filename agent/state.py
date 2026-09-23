"""
agent/state.py

Explicit working memory for the CTF agent.

This is the single source of truth the agent loop reads and writes.
It is deliberately serializable so sessions can be paused/resumed and
traces can be logged for evaluation and teaching.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import uuid


class Confidence(float, Enum):
    """Discrete confidence bands used for ranking and teaching."""
    VERY_LOW = 0.10
    LOW = 0.30
    MEDIUM = 0.55
    HIGH = 0.75
    VERY_HIGH = 0.90


class ActionStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"


@dataclass
class Hypothesis:
    """A single ranked hypothesis about the challenge."""
    id: str
    statement: str
    technique: str = ""
    category: str = ""
    confidence: float = 0.5
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    status: str = "active"  # active | confirmed | rejected | superseded
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def update_confidence(self, delta: float, reason: str = "") -> None:
        self.confidence = max(0.0, min(1.0, self.confidence + delta))
        self.updated_at = datetime.now(timezone.utc).isoformat()
        if reason:
            if delta >= 0:
                self.supporting_evidence.append(reason)
            else:
                self.contradicting_evidence.append(reason)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Hypothesis":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Evidence:
    """A single piece of observed evidence."""
    id: str
    source: str  # tool name, user, archive, research, etc.
    content: str
    finding: str = ""
    confidence: float = 0.7
    related_hypotheses: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ActionRecord:
    """One planned or executed action in the agent loop."""
    id: str
    tool: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    expected_observation: str = ""
    status: str = ActionStatus.PLANNED.value
    result_summary: str = ""
    raw_output: str = ""
    error: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionRecord":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AgentState:
    """
    Complete working memory for one challenge investigation.

    The agent loop treats this object as the only mutable context.
    """
    challenge_id: str
    challenge_summary: str
    category: Optional[str] = None
    difficulty: Optional[str] = None

    known_facts: List[str] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    actions: List[ActionRecord] = field(default_factory=list)

    discovered_artifacts: List[str] = field(default_factory=list)
    candidate_techniques: List[str] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)

    overall_confidence: float = 0.0
    status: str = "investigating"  # investigating | solved | stuck | verified | failed
    solution_summary: str = ""
    flag_candidate: str = ""

    # Audit trail for Bayesian belief updates (agent/belief.py). Doubles as
    # the de-duplication source: a signal already counted from a given tool
    # must not move confidence a second time.
    belief_updates: List[Dict[str, Any]] = field(default_factory=list)
    # Reasoning-loop bookkeeping (agent/reasoning.py, agent/recovery.py).
    phase: str = "observe"
    phase_history: List[str] = field(default_factory=list)
    abandoned_actions: List[str] = field(default_factory=list)
    recovery_events: List[Dict[str, Any]] = field(default_factory=list)

    max_steps: int = 12
    step_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # Teaching / progressive disclosure
    hint_level_reached: int = 0
    lessons: List[str] = field(default_factory=list)

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_fact(self, fact: str) -> None:
        fact = fact.strip()
        if fact and fact not in self.known_facts:
            self.known_facts.append(fact)
            self.touch()

    def add_hypothesis(
        self,
        statement: str,
        technique: str = "",
        category: str = "",
        confidence: float = 0.5,
    ) -> Hypothesis:
        h = Hypothesis(
            id=f"H{len(self.hypotheses) + 1}-{uuid.uuid4().hex[:6]}",
            statement=statement,
            technique=technique,
            category=category or (self.category or ""),
            confidence=confidence,
        )
        self.hypotheses.append(h)
        self.touch()
        return h

    def get_active_hypotheses(self, min_confidence: float = 0.0) -> List[Hypothesis]:
        return [
            h for h in self.hypotheses
            if h.status == "active" and h.confidence >= min_confidence
        ]

    def top_hypothesis(self) -> Optional[Hypothesis]:
        active = self.get_active_hypotheses()
        if not active:
            return None
        return max(active, key=lambda h: h.confidence)

    def add_evidence(
        self,
        source: str,
        content: str,
        finding: str = "",
        confidence: float = 0.7,
        related_hypothesis_ids: Optional[List[str]] = None,
        raw: Optional[Dict[str, Any]] = None,
    ) -> Evidence:
        e = Evidence(
            id=f"E{len(self.evidence) + 1}-{uuid.uuid4().hex[:6]}",
            source=source,
            content=content[:4000],
            finding=finding,
            confidence=confidence,
            related_hypotheses=related_hypothesis_ids or [],
            raw=raw,
        )
        self.evidence.append(e)
        self.touch()
        return e

    def record_action(self, tool: str, arguments: Optional[Dict[str, Any]] = None,
                      reason: str = "", expected: str = "") -> ActionRecord:
        a = ActionRecord(
            id=f"A{len(self.actions) + 1}-{uuid.uuid4().hex[:6]}",
            tool=tool,
            arguments=arguments or {},
            reason=reason,
            expected_observation=expected,
            status=ActionStatus.PLANNED.value,
        )
        self.actions.append(a)
        self.touch()
        return a

    def mark_action_result(
        self,
        action_id: str,
        status: str,
        result_summary: str = "",
        raw_output: str = "",
        error: str = "",
        duration_ms: Optional[int] = None,
    ) -> None:
        for a in self.actions:
            if a.id == action_id:
                a.status = status
                a.result_summary = result_summary
                a.raw_output = raw_output[:8000]
                a.error = error
                a.finished_at = datetime.now(timezone.utc).isoformat()
                a.duration_ms = duration_ms
                break
        self.touch()

    def recompute_overall_confidence(self) -> float:
        active = self.get_active_hypotheses()
        if not active:
            self.overall_confidence = 0.0
            return 0.0
        # Weighted by confidence, slightly boosted when evidence exists
        scores = [h.confidence for h in active]
        base = max(scores)
        evidence_boost = min(0.15, 0.03 * len(self.evidence))
        self.overall_confidence = min(1.0, base + evidence_boost)
        return self.overall_confidence

    def summary_for_llm(self, max_chars: int = 3500) -> str:
        """Compact textual snapshot for prompts (never dump full raw tool output)."""
        lines = [
            f"Challenge: {self.challenge_summary[:400]}",
            f"Category: {self.category or 'unknown'} | Status: {self.status} | "
            f"Steps: {self.step_count}/{self.max_steps} | Confidence: {self.overall_confidence:.2f}",
        ]
        if self.known_facts:
            lines.append("Known facts:")
            for f in self.known_facts[-8:]:
                lines.append(f"  - {f}")
        if self.hypotheses:
            lines.append("Hypotheses (active):")
            for h in sorted(self.get_active_hypotheses(), key=lambda x: -x.confidence)[:5]:
                lines.append(f"  [{h.confidence:.2f}] {h.id}: {h.statement} ({h.technique})")
        if self.evidence:
            lines.append("Recent evidence:")
            for e in self.evidence[-5:]:
                lines.append(f"  - [{e.source}] {e.finding or e.content[:120]}")
        if self.contradictions:
            lines.append("Contradictions:")
            for c in self.contradictions[-3:]:
                lines.append(f"  ! {c}")
        if self.actions:
            last = self.actions[-3:]
            lines.append("Recent actions:")
            for a in last:
                lines.append(f"  - {a.tool} → {a.status}: {a.result_summary[:100] or a.error[:80]}")
        text = "\n".join(lines)
        return text[:max_chars]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentState":
        hyps = [Hypothesis.from_dict(h) for h in data.get("hypotheses", [])]
        evs = [Evidence.from_dict(e) for e in data.get("evidence", [])]
        acts = [ActionRecord.from_dict(a) for a in data.get("actions", [])]
        base = {k: v for k, v in data.items()
                if k not in ("hypotheses", "evidence", "actions")}
        state = cls(**base)
        state.hypotheses = hyps
        state.evidence = evs
        state.actions = acts
        return state

    @classmethod
    def from_json(cls, text: str) -> "AgentState":
        return cls.from_dict(json.loads(text))


def new_challenge_state(
    summary: str,
    category: Optional[str] = None,
    challenge_id: Optional[str] = None,
    max_steps: int = 12,
) -> AgentState:
    """Factory for a fresh investigation state."""
    return AgentState(
        challenge_id=challenge_id or f"chal-{uuid.uuid4().hex[:10]}",
        challenge_summary=summary.strip(),
        category=category,
        max_steps=max_steps,
    )
