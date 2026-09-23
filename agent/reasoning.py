"""
agent/reasoning.py

The loop as a state machine, and the questions each turn must answer (item 3).

`loop.py` already runs plan → act → observe → verify, but the sequence lives
in the control flow of one method, which means nothing can inspect it,
nothing can refuse an illegal move, and no step has to justify itself. The
practical cost shows up with small models: they will happily run a tool
whose result could not change any belief, then treat having run it as
progress.

So two things are made explicit here.

**The phases.** OBSERVE → CLASSIFY → HYPOTHESIZE → PLAN → ACT → INTERPRET →
VERIFY → UPDATE → DECIDE, with RECOVER reachable from anywhere and DONE or
STUCK as terminals. Transitions are declared, so a violation is caught and
recorded instead of silently becoming the new order of operations.

**The six questions.** Before acting, the agent states what it knows, what
it does not, which hypothesis it is testing, why this action, what result
would confirm it, and — the one that matters — what result would *disprove*
it. An action with no disconfirming outcome is not an experiment, and
`gate()` says so before the step is spent.

The disconfirmation requirement is what separates investigation from
accumulation. An agent that can only gather support will always find some.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


class Phase(str, Enum):
    OBSERVE = "observe"           # take in the challenge and its artifacts
    CLASSIFY = "classify"         # what kind of challenge is this
    HYPOTHESIZE = "hypothesize"   # what could be true
    PLAN = "plan"                 # which single action, and why
    ACT = "act"                   # run it
    INTERPRET = "interpret"       # turn output into observations
    VERIFY = "verify"             # does the evidence support the claim
    UPDATE = "update"             # move beliefs
    DECIDE = "decide"             # continue, recover, or stop
    RECOVER = "recover"           # the current line has failed
    DONE = "done"
    STUCK = "stuck"


# Declared transitions. RECOVER and the terminals are reachable from any
# non-terminal phase, since a stall or a flag can turn up at any point.
_TRANSITIONS: Dict[Phase, Set[Phase]] = {
    Phase.OBSERVE: {Phase.CLASSIFY, Phase.HYPOTHESIZE},
    Phase.CLASSIFY: {Phase.HYPOTHESIZE, Phase.OBSERVE},
    Phase.HYPOTHESIZE: {Phase.PLAN, Phase.VERIFY},
    Phase.PLAN: {Phase.ACT, Phase.HYPOTHESIZE, Phase.DECIDE},
    Phase.ACT: {Phase.INTERPRET},
    Phase.INTERPRET: {Phase.UPDATE, Phase.VERIFY},
    Phase.UPDATE: {Phase.VERIFY, Phase.DECIDE},
    Phase.VERIFY: {Phase.DECIDE, Phase.UPDATE},
    Phase.DECIDE: {Phase.PLAN, Phase.HYPOTHESIZE, Phase.OBSERVE},
    Phase.RECOVER: {Phase.HYPOTHESIZE, Phase.PLAN, Phase.OBSERVE, Phase.DECIDE},
    Phase.DONE: set(),
    Phase.STUCK: {Phase.HYPOTHESIZE, Phase.OBSERVE},  # a user answer can revive it
}

_ALWAYS_REACHABLE = {Phase.RECOVER, Phase.DONE, Phase.STUCK}


class IllegalTransition(RuntimeError):
    """Raised only in strict mode; the loop prefers the recorded refusal."""


def can_transition(source: Phase, target: Phase) -> bool:
    if source is target:
        return True
    if target in _ALWAYS_REACHABLE and source not in (Phase.DONE,):
        return True
    return target in _TRANSITIONS.get(source, set())


@dataclass
class StepRationale:
    """The six questions, answered, for one planned action."""

    known: List[str] = field(default_factory=list)
    unknown: List[str] = field(default_factory=list)
    hypothesis: str = ""
    hypothesis_id: str = ""
    action: str = ""
    why: str = ""
    would_confirm: str = ""
    would_disprove: str = ""
    discriminating: bool = True
    concerns: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        """
        A rationale is complete only with a disconfirming outcome.

        Everything else here is description; this field is the commitment.
        """
        return bool(self.action and self.hypothesis and self.would_disprove)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "known": list(self.known),
            "unknown": list(self.unknown),
            "hypothesis": self.hypothesis,
            "hypothesis_id": self.hypothesis_id,
            "action": self.action,
            "why": self.why,
            "would_confirm": self.would_confirm,
            "would_disprove": self.would_disprove,
            "discriminating": self.discriminating,
            "concerns": list(self.concerns),
            "complete": self.is_complete,
        }

    def render(self) -> str:
        lines = [f"Testing: {self.hypothesis or '(no hypothesis)'}"
                 + (f"  [{self.hypothesis_id}]" if self.hypothesis_id else "")]
        if self.known:
            lines.append("  known: " + "; ".join(self.known[:4]))
        if self.unknown:
            lines.append("  not yet known: " + "; ".join(self.unknown[:4]))
        lines.append(f"  action: {self.action or '(none)'} — {self.why or 'no reason given'}")
        lines.append(f"  would confirm: {self.would_confirm or '(unstated)'}")
        lines.append(f"  would disprove: {self.would_disprove or '(unstated)'}")
        if not self.discriminating:
            lines.append("  ! this action cannot separate the leading hypotheses")
        for concern in self.concerns:
            lines.append(f"  ! {concern}")
        return "\n".join(lines)


class ReasoningMachine:
    """
    Phase tracking and per-step justification over an `AgentState`.

    Phase lives on the state, so it survives serialization and a resumed
    session does not restart mid-thought.
    """

    def __init__(self, state: Any, strict: bool = False):
        self.state = state
        self.strict = strict
        self.violations: List[str] = []
        if not getattr(state, "phase", ""):
            try:
                state.phase = Phase.OBSERVE.value
            except Exception:
                pass

    # ---------------------------------------------------------- phases

    @property
    def phase(self) -> Phase:
        try:
            return Phase(str(getattr(self.state, "phase", "") or "observe"))
        except ValueError:
            return Phase.OBSERVE

    def transition(self, target: Phase, note: str = "") -> bool:
        """
        Move to a phase. Illegal moves are refused and recorded.

        Refusing rather than raising keeps a control-flow bug from killing
        an investigation, while still leaving the evidence of it in
        `violations` and in the phase history for the trace.
        """
        source = self.phase
        if not can_transition(source, target):
            message = f"illegal transition {source.value} → {target.value}" + (
                f" ({note})" if note else "")
            self.violations.append(message)
            if self.strict:
                raise IllegalTransition(message)
            return False
        try:
            self.state.phase = target.value
            history = getattr(self.state, "phase_history", None)
            if isinstance(history, list):
                history.append(target.value + (f":{note}" if note else ""))
                del history[:-100]
        except Exception:
            pass
        return True

    def next_phase(self) -> Phase:
        """
        The phase the record says should come next.

        Consulted by the loop so the ordering lives in one readable place
        rather than being implied by the sequence of calls.
        """
        state = self.state
        status = str(getattr(state, "status", "") or "")
        if status in ("verified", "solved"):
            return Phase.DONE
        if status == "failed":
            return Phase.STUCK
        if int(getattr(state, "step_count", 0) or 0) >= int(getattr(state, "max_steps", 0) or 0):
            return Phase.VERIFY

        try:
            from agent.recovery import is_stuck
            if is_stuck(state):
                return Phase.RECOVER
        except Exception:
            pass

        current = self.phase
        if current in (Phase.OBSERVE,):
            return Phase.CLASSIFY if not getattr(state, "category", None) else Phase.HYPOTHESIZE
        if current is Phase.CLASSIFY:
            return Phase.HYPOTHESIZE
        if current is Phase.HYPOTHESIZE:
            return Phase.PLAN if (getattr(state, "hypotheses", None) or []) else Phase.OBSERVE
        if current is Phase.PLAN:
            return Phase.ACT
        if current is Phase.ACT:
            return Phase.INTERPRET
        if current is Phase.INTERPRET:
            return Phase.UPDATE
        if current is Phase.UPDATE:
            return Phase.VERIFY
        if current is Phase.VERIFY:
            return Phase.DECIDE
        if current in (Phase.DECIDE, Phase.RECOVER):
            return Phase.PLAN
        return Phase.OBSERVE

    def advance(self, note: str = "") -> Phase:
        """Take the next phase the record implies."""
        target = self.next_phase()
        self.transition(target, note=note)
        return self.phase

    # ------------------------------------------------------- rationale

    def rationale(self, plan: Any = None, graph: Any = None) -> StepRationale:
        """
        Build the six answers from the state, the plan, and the graph.

        Everything here is derived from the record. Nothing is asked of a
        model, so a model that cannot produce a disconfirming condition
        cannot skip the check by declining to mention one.
        """
        state = self.state
        rationale = StepRationale()

        facts = [str(f) for f in (getattr(state, "known_facts", None) or [])]
        rationale.known = facts[-4:]

        top = None
        try:
            from agent.belief import rank_by_belief
            ranked = rank_by_belief(state)
            top = ranked[0] if ranked else None
        except Exception:
            try:
                top = state.top_hypothesis()
            except Exception:
                top = None

        technique = str(getattr(top, "technique", "") or "")
        if top is not None:
            rationale.hypothesis = str(getattr(top, "statement", "") or "")
            rationale.hypothesis_id = str(getattr(top, "id", "") or "")

        # The graph is authoritative when present. An empty gap list from it
        # means "everything required has been observed" — falling back to the
        # fact-text scan there would re-report satisfied signals as missing,
        # which is the same failure this project fixed for tool results.
        gaps: List[str] = []
        consulted_graph = False
        if graph is not None:
            try:
                gaps = list(graph.missing_signals(technique))
                if not gaps:
                    gaps = list(graph.missing_signals())
                consulted_graph = True
            except Exception:
                consulted_graph = False
        if not consulted_graph and technique:
            try:
                from agent.evidence import requirements_for
                req = requirements_for(technique)
                if req:
                    observed = "\n".join(facts).lower()
                    from agent.evidence import _matches
                    gaps = [s for s in req.required if not _matches(s, observed)]
            except Exception:
                gaps = []
        rationale.unknown = gaps[:4]

        if plan is not None:
            rationale.action = str(getattr(plan, "tool", "") or "")
            rationale.why = str(getattr(plan, "reason", "") or "")
            rationale.would_confirm = str(getattr(plan, "expected_observation", "") or "")

        rationale.would_disprove = self._disconfirming_outcome(technique, rationale.action, gaps)
        rationale.discriminating, concern = self._is_discriminating(rationale.action, gaps)
        if concern:
            rationale.concerns.append(concern)

        if graph is not None:
            try:
                for gap in graph.coverage_gaps[:2]:
                    rationale.concerns.append(str(gap))
            except Exception:
                pass
        return rationale

    def _disconfirming_outcome(self, technique: str, tool: str, gaps: Sequence[str]) -> str:
        """
        What result would argue against the hypothesis under test.

        Taken from the technique's own contradicting signals where a rubric
        exists, and from the missing required signals otherwise: failing to
        observe a signal the tool was chosen to observe is itself a result.
        """
        try:
            from agent.evidence import requirements_for
            req = requirements_for(technique)
        except Exception:
            req = None
        if req and req.contradicting:
            return "observing " + " or ".join(req.contradicting[:2])
        if gaps:
            return f"{tool or 'this action'} running cleanly without producing: {gaps[0]}"
        if tool:
            return f"{tool} running cleanly and finding nothing relevant"
        return ""

    def _is_discriminating(self, tool: str, gaps: Sequence[str]) -> Tuple[bool, str]:
        """
        Could this action change any belief?

        A tool that cannot observe any missing signal is not necessarily
        wrong — retrieval and decomposition legitimately produce candidates
        rather than observations — but it should not be mistaken for a test,
        and two of them in a row means the agent has stopped investigating.
        """
        if not tool:
            return True, ""
        try:
            from agent.tool_capabilities import capability
            cap = capability(tool)
        except Exception:
            return True, ""
        if cap is None:
            return True, ""
        if not cap.produces:
            return False, (f"{tool} produces candidates, not observations about this "
                           f"challenge — it cannot confirm or refute the current claim")
        if gaps and not any(cap.can_observe(signal) for signal in gaps):
            return False, (f"{tool} cannot observe any of the signals still missing "
                           f"({'; '.join(list(gaps)[:2])})")
        return True, ""

    def gate(self, plan: Any, graph: Any = None) -> Tuple[bool, StepRationale]:
        """
        Should this action be taken?

        Blocks only the case that cannot be justified at all: no hypothesis
        and no stated disconfirming outcome. A non-discriminating action is
        allowed through with its concern attached, because early retrieval
        is a reasonable move — it is being unable to say what would change
        your mind that is not.
        """
        rationale = self.rationale(plan, graph=graph)
        if rationale.hypothesis and not rationale.would_disprove:
            return False, rationale
        return True, rationale

    # ---------------------------------------------------------- output

    def render(self, plan: Any = None, graph: Any = None) -> str:
        rationale = self.rationale(plan, graph=graph)
        lines = [f"Phase: {self.phase.value}", rationale.render()]
        if self.violations:
            lines.append("Transition violations: " + "; ".join(self.violations[-3:]))
        return "\n".join(lines)

    def stats(self) -> Dict[str, Any]:
        history = [str(h) for h in (getattr(self.state, "phase_history", None) or [])]
        return {
            "phase": self.phase.value,
            "phases_entered": len(history),
            "violations": len(self.violations),
            "cycles": history.count(Phase.ACT.value),
        }
