"""
agent/context.py

Deciding what the model actually gets to see (items 2, 36, 37).

The failure mode this prevents is quiet and expensive. A challenge
accumulates source code, tool output, retrieved cards, prior hypotheses and
conversation history. Concatenate all of it and an 8B model with a nominal
32k window will still degrade badly, because the signal it needs is buried
in the middle of a wall of `strings` output.

So instead of:

    EVERYTHING -> LLM

this module does:

    EVERYTHING -> score by relevance -> fit to budget -> LLM

Three ideas do most of the work:

**Scoped memory** (item 36/37). Facts are tagged with a scope: session,
challenge, student, knowledge, tool. Challenge-scoped facts are dropped
when the challenge changes, so "PIE disabled" from the last binary cannot
leak into reasoning about this one. That bug is nearly impossible to spot
from the outside, because the output stays plausible.

**Decay.** Tool output from eight steps ago is usually stale. Recency is a
tiebreaker, not a ranking — an old fact that directly matches the current
hypothesis still outranks fresh noise.

**Honest truncation.** When something is cut, the model is told it was cut.
A silently truncated listing invites confident conclusions about data the
model never saw.

Token counting is a ~4-chars-per-token estimate. That is imprecise, and
deliberately so: a real tokenizer would add a heavyweight dependency for
a number only used to decide what to drop. The estimate errs high.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

CHARS_PER_TOKEN = 3.6  # errs high, which is the safe direction here


class Scope(str, Enum):
    """Which lifetime a piece of context belongs to."""

    SESSION = "session"      # this run
    CHALLENGE = "challenge"  # this challenge; cleared when it changes
    STUDENT = "student"      # persists across challenges
    KNOWLEDGE = "knowledge"  # retrieved reference material
    TOOL = "tool"            # raw tool output


class Priority(int, Enum):
    CRITICAL = 100   # never dropped: the task, the current hypothesis
    HIGH = 75        # verified evidence
    MEDIUM = 50      # observations, retrieved cards
    LOW = 25         # raw output, history
    TRIVIAL = 10     # nice to have


def estimate_tokens(text: str) -> int:
    """Cheap token estimate. Intentionally conservative (over-counts)."""
    if not text:
        return 0
    return max(1, int(len(text) / CHARS_PER_TOKEN) + 1)


@dataclass
class ContextItem:
    """One candidate piece of context."""

    content: str
    scope: Scope = Scope.SESSION
    priority: Priority = Priority.MEDIUM
    label: str = ""
    step: int = 0                       # agent step that produced it
    created: float = field(default_factory=time.time)
    keywords: Set[str] = field(default_factory=set)
    pinned: bool = False                # survives budget pressure regardless

    @property
    def tokens(self) -> int:
        return estimate_tokens(self.content)

    def relevance(self, query_terms: Set[str], current_step: int = 0) -> float:
        """
        Score this item against what the agent is currently thinking about.

        Priority dominates; keyword overlap and recency adjust within a
        band. Ordering matters more than the absolute numbers here.
        """
        score = float(self.priority.value)

        if query_terms:
            own = self.keywords or _terms(self.content)
            if own:
                overlap = len(query_terms & own)
                score += min(40.0, overlap * 8.0)

        # Recency decay, but only for volatile scopes. Knowledge and student
        # facts do not become less true because time passed.
        if self.scope in (Scope.TOOL, Scope.SESSION) and current_step:
            age = max(0, current_step - self.step)
            score -= min(30.0, age * 4.0)

        if self.pinned:
            score += 1000.0
        return score


_STOP = {
    "the", "a", "an", "and", "or", "is", "are", "was", "were", "to", "of", "in",
    "on", "for", "with", "this", "that", "it", "be", "by", "as", "at", "from",
    "has", "have", "can", "will", "would", "should", "could", "there", "their",
}


def _terms(text: str) -> Set[str]:
    return {w for w in re.findall(r"[a-z0-9_\-]{3,}", (text or "").lower()) if w not in _STOP}


def truncate_middle(text: str, max_tokens: int, label: str = "") -> str:
    """
    Cut the middle, keep both ends, and say so.

    Head and tail are where the useful parts of tool output live — a file
    header at the top, a conclusion at the bottom. The marker matters as
    much as the cut: without it the model treats a partial listing as
    complete and reasons confidently about data it never saw.
    """
    if estimate_tokens(text) <= max_tokens:
        return text
    budget_chars = int(max_tokens * CHARS_PER_TOKEN)
    if budget_chars < 200:
        return text[: max(0, budget_chars)]
    head = int(budget_chars * 0.6)
    tail = budget_chars - head - 80
    removed = len(text) - head - tail
    marker = f"\n\n... [{removed} characters omitted from the middle{' of ' + label if label else ''}] ...\n\n"
    return text[:head] + marker + text[-tail:]


@dataclass
class ContextBudget:
    """How the window is divided up."""

    total: int = 6000
    reserved_system: int = 600
    reserved_response: int = 1200

    @property
    def available(self) -> int:
        return max(500, self.total - self.reserved_system - self.reserved_response)

    @classmethod
    def from_profile(cls, profile: Any = None) -> "ContextBudget":
        """Derive a budget from a ModelProfile (or sensible defaults)."""
        if profile is None:
            try:
                from agent.model_profile import get_profile
                profile = get_profile()
            except Exception:
                return cls()
        total = getattr(profile, "context_budget", 6000)
        return cls(
            total=total,
            reserved_system=min(1000, int(total * 0.1)),
            reserved_response=min(2000, int(total * 0.2)),
        )


class ContextManager:
    """
    Collects candidate context, then assembles the best-fitting subset.

    Add freely; `build()` decides what survives.
    """

    def __init__(self, budget: Optional[ContextBudget] = None, challenge_id: str = ""):
        self.budget = budget or ContextBudget.from_profile()
        self.challenge_id = challenge_id
        self.items: List[ContextItem] = []
        self.last_report: Dict[str, Any] = {}

    # ------------------------------------------------------------ adding

    def add(
        self,
        content: str,
        scope: Scope = Scope.SESSION,
        priority: Priority = Priority.MEDIUM,
        label: str = "",
        step: int = 0,
        pinned: bool = False,
    ) -> "ContextManager":
        content = (content or "").strip()
        if not content:
            return self
        self.items.append(
            ContextItem(
                content=content, scope=scope, priority=priority, label=label,
                step=step, keywords=_terms(content), pinned=pinned,
            )
        )
        return self

    def add_task(self, description: str) -> "ContextManager":
        """The challenge itself. Always survives."""
        return self.add(description, Scope.CHALLENGE, Priority.CRITICAL, "task", pinned=True)

    def add_tool_result(self, result: Any, step: int = 0) -> "ContextManager":
        """
        Add a ToolResult, preserving the failure/emptiness distinction.

        A failed tool is recorded at HIGH priority precisely because the
        agent must not mistake its absence for a negative finding.
        """
        try:
            from agent.tool_result import ToolResult, ToolStatus
        except Exception:
            return self.add(str(result), Scope.TOOL, Priority.LOW, "tool", step)

        if not isinstance(result, ToolResult):
            return self.add(str(result), Scope.TOOL, Priority.LOW, "tool", step)

        if result.status.is_failure:
            return self.add(
                f"[{result.tool}] DID NOT RUN ({result.status.value}): {result.error}. "
                f"This is not evidence of absence.",
                Scope.TOOL, Priority.HIGH, f"{result.tool}:failed", step,
            )
        if result.is_evidence_of_absence:
            return self.add(
                f"[{result.tool}] ran successfully and found nothing. This IS a finding.",
                Scope.TOOL, Priority.MEDIUM, f"{result.tool}:empty", step,
            )

        if result.observations:
            lines = [f"[{result.tool}] observations:"]
            for obs in result.observations[:15]:
                lines.append(f"  - {obs.kind}: {obs.value}" + (f" ({obs.detail[:80]})" if obs.detail else ""))
            self.add("\n".join(lines), Scope.TOOL, Priority.MEDIUM, f"{result.tool}:obs", step)

        if result.raw_output.strip():
            self.add(
                f"[{result.tool}] raw output:\n{result.raw_output}",
                Scope.TOOL, Priority.LOW, f"{result.tool}:raw", step,
            )
        return self

    def add_hypotheses(self, hypotheses: Sequence[Any], step: int = 0) -> "ContextManager":
        if not hypotheses:
            return self
        lines = ["Current hypotheses (ranked):"]
        for h in list(hypotheses)[:5]:
            conf = getattr(h, "confidence", None)
            stmt = getattr(h, "statement", None) or str(h)
            tech = getattr(h, "technique", "") or ""
            conf_text = f"{conf:.2f}" if isinstance(conf, (int, float)) else "?"
            lines.append(f"  - [{conf_text}] {stmt}" + (f" (technique: {tech})" if tech else ""))
        return self.add("\n".join(lines), Scope.CHALLENGE, Priority.CRITICAL, "hypotheses", step, pinned=True)

    def add_knowledge(self, matches: Sequence[Dict[str, Any]], limit: int = 5) -> "ContextManager":
        if not matches:
            return self
        lines = ["Relevant archive entries:"]
        for m in list(matches)[:limit]:
            name = m.get("name", "?")
            techs = ", ".join(str(t) for t in (m.get("techniques") or [])[:3])
            snippet = (m.get("snippet") or m.get("description") or "")[:200]
            lines.append(f"  - {name} [{techs}]: {snippet}")
        return self.add("\n".join(lines), Scope.KNOWLEDGE, Priority.MEDIUM, "knowledge")

    # ------------------------------------------------- scoped memory (37)

    def clear_scope(self, scope: Scope) -> int:
        """Drop everything in one scope. Returns how many items went."""
        before = len(self.items)
        self.items = [i for i in self.items if i.scope is not scope]
        return before - len(self.items)

    def switch_challenge(self, challenge_id: str) -> int:
        """
        Move to a new challenge, discarding the previous one's facts.

        This is the fix for cross-challenge contamination: without it,
        "PIE disabled" from the last binary silently informs reasoning
        about a binary where PIE is enabled.
        """
        if challenge_id == self.challenge_id:
            return 0
        removed = self.clear_scope(Scope.CHALLENGE) + self.clear_scope(Scope.TOOL)
        self.challenge_id = challenge_id
        return removed

    # ---------------------------------------------------------- building

    def build(
        self,
        query: str = "",
        current_step: int = 0,
        include_scopes: Optional[Sequence[Scope]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Assemble the prompt body within budget.

        Returns (text, report). The report records what was included and
        what was dropped, so a bad answer can be traced to missing context
        rather than guessed at.
        """
        pool = list(self.items)
        if include_scopes is not None:
            allowed = set(include_scopes)
            pool = [i for i in pool if i.scope in allowed]

        query_terms = _terms(query)
        ranked = sorted(pool, key=lambda i: -i.relevance(query_terms, current_step))

        available = self.budget.available
        used = 0
        chosen: List[ContextItem] = []
        dropped: List[str] = []
        truncated: List[str] = []

        for item in ranked:
            cost = item.tokens
            if used + cost <= available:
                chosen.append(item)
                used += cost
                continue

            remaining = available - used
            # Only bother truncating when a useful amount would survive.
            if remaining > 150 and item.priority.value >= Priority.MEDIUM.value:
                shrunk = ContextItem(
                    content=truncate_middle(item.content, remaining, item.label),
                    scope=item.scope, priority=item.priority, label=item.label,
                    step=item.step, keywords=item.keywords,
                )
                chosen.append(shrunk)
                used += shrunk.tokens
                truncated.append(item.label or item.scope.value)
                continue

            if item.pinned:
                # Pinned content is never dropped; make room by force.
                chosen.append(item)
                used += cost
                continue

            dropped.append(item.label or item.scope.value)

        # Present in a stable, readable order rather than score order —
        # the task first, then what was found, then reference material.
        order = {
            Priority.CRITICAL: 0, Priority.HIGH: 1, Priority.MEDIUM: 2,
            Priority.LOW: 3, Priority.TRIVIAL: 4,
        }
        chosen.sort(key=lambda i: (order.get(i.priority, 5), i.step))

        blocks = []
        for item in chosen:
            header = f"## {item.label}" if item.label else f"## {item.scope.value}"
            blocks.append(f"{header}\n{item.content}")
        text = "\n\n".join(blocks)

        report = {
            "budget_total": self.budget.total,
            "budget_available": available,
            "tokens_used": used,
            "utilisation": round(used / available, 3) if available else 0.0,
            "items_available": len(pool),
            "items_included": len(chosen),
            "items_dropped": len(dropped),
            "dropped": dropped[:20],
            "truncated": truncated[:20],
            "challenge_id": self.challenge_id,
        }
        self.last_report = report
        return text, report

    def stats(self) -> Dict[str, Any]:
        by_scope: Dict[str, int] = {}
        for item in self.items:
            by_scope[item.scope.value] = by_scope.get(item.scope.value, 0) + 1
        return {
            "items": len(self.items),
            "estimated_tokens": sum(i.tokens for i in self.items),
            "budget_available": self.budget.available,
            "by_scope": dict(sorted(by_scope.items())),
            "over_budget": sum(i.tokens for i in self.items) > self.budget.available,
        }


def build_agent_context(
    state: Any,
    query: str = "",
    profile: Any = None,
) -> Tuple[str, Dict[str, Any]]:
    """
    Convenience wrapper: turn an AgentState into a budgeted prompt body.

    Tolerant of missing attributes so it can be adopted incrementally
    without a coordinated change to AgentState.
    """
    manager = ContextManager(
        budget=ContextBudget.from_profile(profile),
        challenge_id=str(getattr(state, "challenge_id", "") or ""),
    )

    summary = getattr(state, "challenge_summary", "") or ""
    if summary:
        manager.add_task(summary)

    for fact in list(getattr(state, "known_facts", []) or [])[:30]:
        manager.add(str(fact), Scope.CHALLENGE, Priority.HIGH, "fact")

    hypotheses = getattr(state, "hypotheses", None)
    if hypotheses:
        manager.add_hypotheses(hypotheses, step=getattr(state, "step_count", 0))

    step = getattr(state, "step_count", 0)
    for ev in list(getattr(state, "evidence", []) or [])[-15:]:
        content = getattr(ev, "finding", "") or getattr(ev, "content", "") or str(ev)
        manager.add(str(content), Scope.TOOL, Priority.MEDIUM, "evidence", step)

    return manager.build(query=query or summary, current_step=step)
