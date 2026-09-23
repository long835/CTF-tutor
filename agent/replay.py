"""
agent/replay.py

Record a run completely enough to re-run it (items 26, 27).

`trace.py` writes an append-only JSONL log, which is good for reading after
the fact and useless for reproducing anything: it captures what happened but
not enough of the inputs to make it happen again. So a bug found in run #124
has to be reproduced by guessing at the conditions, and once a fix lands
there is no way to tell whether the new behaviour is better or merely
different.

A `RunRecord` holds the inputs (challenge, model, parameters, artifacts) and
every step's tool call with its exact output. Replaying it swaps the real
executor for `ReplayExecutor`, which returns the recorded output instead of
running the tool. Two consequences:

*   **Replay is deterministic and offline.** No Ghidra, no network, no
    model — so a failure can be re-examined on a laptop, and a regression
    suite can run in CI in seconds.
*   **A fix can be compared against the original.** `diff_records` reports
    where the decisions diverged, which is the question actually being
    asked: did the change alter the reasoning, and for the better?

The recorded output is what the tool said at the time. Replaying a run after
changing a tool tests the *agent*, not the tool — which is the point, and
also the limitation to keep in mind.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

REPLAY_DIR = Path("data") / "replays"


def _args_key(tool: str, arguments: Any) -> str:
    """Stable key for one tool invocation."""
    try:
        rendered = json.dumps(arguments or {}, sort_keys=True, default=str)
    except Exception:
        rendered = str(arguments)
    digest = hashlib.sha1(rendered.encode("utf-8")).hexdigest()[:10]
    return f"{tool}:{digest}"


@dataclass
class StepRecord:
    """One executed step: what was decided, what was run, what came back."""

    index: int
    phase: str = ""
    tool: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    success: bool = False
    output: str = ""
    error: str = ""
    duration_ms: int = 0
    rationale: Dict[str, Any] = field(default_factory=dict)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    recovery: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return _args_key(self.tool, self.arguments)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "phase": self.phase,
            "tool": self.tool,
            "arguments": dict(self.arguments),
            "reason": self.reason,
            "success": self.success,
            "output": self.output[:20000],
            "error": self.error[:2000],
            "duration_ms": self.duration_ms,
            "rationale": dict(self.rationale),
            "hypotheses": list(self.hypotheses),
            "recovery": list(self.recovery),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StepRecord":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class RunRecord:
    """Everything needed to reproduce one investigation."""

    challenge: str
    challenge_id: str = ""
    category: str = ""
    model: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    challenge_path: str = ""
    max_steps: int = 12
    steps: List[StepRecord] = field(default_factory=list)
    final_status: str = ""
    final_confidence: float = 0.0
    final_flag: str = ""
    verdict: Dict[str, Any] = field(default_factory=dict)
    graph: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "challenge": self.challenge,
            "challenge_id": self.challenge_id,
            "category": self.category,
            "model": self.model,
            "parameters": dict(self.parameters),
            "challenge_path": self.challenge_path,
            "max_steps": self.max_steps,
            "steps": [s.to_dict() for s in self.steps],
            "final_status": self.final_status,
            "final_confidence": round(self.final_confidence, 3),
            "final_flag": self.final_flag,
            "verdict": dict(self.verdict),
            "graph": dict(self.graph),
            "metrics": dict(self.metrics),
            "created_at": self.created_at,
            "version": self.version,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RunRecord":
        steps = [StepRecord.from_dict(s) for s in data.get("steps") or []]
        base = {k: v for k, v in data.items() if k in cls.__dataclass_fields__ and k != "steps"}
        record = cls(**base)
        record.steps = steps
        return record

    @classmethod
    def from_json(cls, text: str) -> "RunRecord":
        return cls.from_dict(json.loads(text))

    def save(self, path: Optional[str] = None) -> str:
        target = Path(path) if path else REPLAY_DIR / f"run_{int(self.created_at)}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_json(), encoding="utf-8")
        return str(target)

    @classmethod
    def load(cls, path: str) -> "RunRecord":
        return cls.from_json(Path(path).read_text(encoding="utf-8"))

    def decisions(self) -> List[str]:
        """The decision sequence, which is what a replay comparison is about."""
        return [f"{s.index}:{s.tool}" for s in self.steps]


class Recorder:
    """
    Event sink that builds a `RunRecord` from a live run.

    Attach it as the loop's `on_event` and it captures decisions, tool
    output, and per-step rationale without the loop knowing it exists.
    """

    def __init__(self, challenge: str, model: str = "", **parameters: Any):
        self.record = RunRecord(challenge=challenge, model=model, parameters=dict(parameters))
        self._pending: Optional[StepRecord] = None
        self._outputs: Dict[str, Tuple[bool, str, str]] = {}

    # The loop's event signature: (name, payload)
    def __call__(self, event: str, payload: Dict[str, Any]) -> None:
        self.on_event(event, payload)

    def on_event(self, event: str, payload: Dict[str, Any]) -> None:
        if event == "action_planned":
            self._pending = StepRecord(
                index=int(payload.get("step", len(self.record.steps) + 1)),
                tool=str(payload.get("tool", "")),
                arguments=dict(payload.get("args") or {}),
                reason=str(payload.get("reason", "")),
            )
        elif event == "rationale" and self._pending is not None:
            self._pending.rationale = {k: v for k, v in payload.items() if k != "step"}
        elif event == "recovery" and self._pending is not None:
            self._pending.recovery = list(payload.get("actions") or [])
        elif event == "action_finished" and self._pending is not None:
            self._pending.success = bool(payload.get("success"))
            self.record.steps.append(self._pending)
            self._pending = None
        elif event == "verification":
            self.record.verdict = dict(payload)
        elif event == "finished":
            self.record.final_status = str(payload.get("status", ""))
            self.record.final_confidence = float(payload.get("confidence", 0.0) or 0.0)

    def capture_executor(self, inner: Callable[[Any], Any]) -> Callable[[Any], Any]:
        """
        Wrap an executor so its exact output is recorded.

        Events alone cannot carry full tool output — the loop truncates
        summaries for display — so the raw result is captured here, where it
        is complete.
        """
        def wrapped(record: Any) -> Any:
            result = inner(record)
            try:
                success, output, error = result
            except Exception:
                return result
            key = _args_key(str(getattr(record, "tool", "")), getattr(record, "arguments", {}))
            self._outputs[key] = (bool(success), str(output or ""), str(error or ""))
            return result
        return wrapped

    def finalize(self, state: Any = None, graph: Any = None) -> RunRecord:
        """Attach captured output, final state, graph, and metrics."""
        for step in self.record.steps:
            captured = self._outputs.get(step.key)
            if captured:
                step.success, step.output, step.error = captured
        if state is not None:
            self.record.challenge_id = str(getattr(state, "challenge_id", "") or "")
            self.record.category = str(getattr(state, "category", "") or "")
            self.record.max_steps = int(getattr(state, "max_steps", 12) or 12)
            self.record.final_status = self.record.final_status or str(getattr(state, "status", ""))
            self.record.final_flag = str(getattr(state, "flag_candidate", "") or "")
            for step, action in zip(self.record.steps, getattr(state, "actions", None) or []):
                step.duration_ms = int(getattr(action, "duration_ms", 0) or 0)
            for step in self.record.steps:
                step.hypotheses = [
                    {"id": h.id, "confidence": round(float(h.confidence), 3),
                     "technique": h.technique, "status": h.status}
                    for h in (getattr(state, "hypotheses", None) or [])
                ][:8]
            try:
                from agent.metrics import efficiency
                self.record.metrics = efficiency(state).to_dict()
            except Exception:
                pass
        if graph is not None:
            try:
                self.record.graph = graph.to_dict()
            except Exception:
                pass
        return self.record


class ReplayExecutor:
    """
    Executor that returns recorded output instead of running anything.

    A call the record does not contain is reported as `unavailable` rather
    than as an empty success, because a replay that silently hands back
    "nothing found" would teach the agent the same false lesson this project
    spent Phase 1 removing.
    """

    def __init__(self, record: RunRecord, strict: bool = False):
        self.record = record
        self.strict = strict
        self.misses: List[str] = []
        self.hits: List[str] = []
        self._by_key: Dict[str, Tuple[bool, str, str]] = {}
        self._by_tool: Dict[str, List[Tuple[bool, str, str]]] = {}
        for step in record.steps:
            payload = (step.success, step.output, step.error)
            self._by_key[step.key] = payload
            self._by_tool.setdefault(step.tool, []).append(payload)

    def __call__(self, action: Any) -> Tuple[bool, str, str]:
        tool = str(getattr(action, "tool", ""))
        key = _args_key(tool, getattr(action, "arguments", {}))
        if key in self._by_key:
            self.hits.append(key)
            return self._by_key[key]
        # Same tool, different arguments: the agent chose differently this
        # time. Fall back to that tool's first recorded output so the replay
        # can continue, but record the divergence.
        queued = self._by_tool.get(tool)
        if queued:
            self.misses.append(f"{tool}: different arguments than recorded")
            return queued[0]
        self.misses.append(f"{tool}: not in record")
        if self.strict:
            raise KeyError(f"no recorded output for {key}")
        return (False, "", f"replay: no recorded output for {tool} (tool unavailable)")

    @property
    def fidelity(self) -> float:
        """Share of calls answered from the exact recorded invocation."""
        total = len(self.hits) + len(self.misses)
        return (len(self.hits) / total) if total else 1.0


def replay(record: RunRecord, strict: bool = False, **overrides: Any) -> Tuple[Any, ReplayExecutor]:
    """
    Re-run a recorded investigation against the current code.

    Returns the resulting state and the executor, whose `misses` and
    `fidelity` say how far the new run drifted from the recorded one.
    """
    from agent.loop import AgentLoop

    executor = ReplayExecutor(record, strict=strict)
    agent = AgentLoop(
        challenge_summary=overrides.get("challenge", record.challenge),
        category=overrides.get("category", record.category or None),
        max_steps=int(overrides.get("max_steps", record.max_steps)),
        challenge_path=overrides.get("challenge_path", record.challenge_path or None),
        enable_trace=False,
        executor=executor,
    )
    state = agent.run()
    return state, executor


@dataclass
class RecordDiff:
    """Where a replay diverged from the run it came from."""

    same_decisions: bool
    same_outcome: bool
    recorded_decisions: List[str] = field(default_factory=list)
    replayed_decisions: List[str] = field(default_factory=list)
    first_divergence: int = -1
    recorded_status: str = ""
    replayed_status: str = ""
    confidence_delta: float = 0.0
    notes: List[str] = field(default_factory=list)

    @property
    def regressed(self) -> bool:
        """
        Whether the change made things worse.

        Verified → anything else is a regression. A different route to the
        same outcome is not: the agent is allowed to improve its path.
        """
        good = ("verified", "solved")
        return self.recorded_status in good and self.replayed_status not in good

    def to_dict(self) -> Dict[str, Any]:
        return {
            "same_decisions": self.same_decisions,
            "same_outcome": self.same_outcome,
            "first_divergence": self.first_divergence,
            "recorded_status": self.recorded_status,
            "replayed_status": self.replayed_status,
            "confidence_delta": round(self.confidence_delta, 3),
            "regressed": self.regressed,
            "notes": list(self.notes),
        }

    def render(self) -> str:
        lines = [
            f"decisions: {'identical' if self.same_decisions else 'diverged'}"
            + (f" at step {self.first_divergence}" if self.first_divergence >= 0 else ""),
            f"outcome:   {self.recorded_status} → {self.replayed_status}"
            + (f"  ({self.confidence_delta:+.2f} confidence)" if self.confidence_delta else ""),
        ]
        if self.regressed:
            lines.append("REGRESSION: a previously verified run no longer verifies")
        lines.append("recorded:  " + " → ".join(self.recorded_decisions[:8] or ["(none)"]))
        lines.append("replayed:  " + " → ".join(self.replayed_decisions[:8] or ["(none)"]))
        for note in self.notes[:5]:
            lines.append(f"  note: {note}")
        return "\n".join(lines)


def diff_records(record: RunRecord, state: Any, executor: Optional[ReplayExecutor] = None) -> RecordDiff:
    """Compare a replayed state against the record it was replayed from."""
    recorded = record.decisions()
    replayed = [f"{i + 1}:{getattr(a, 'tool', '')}"
                for i, a in enumerate(getattr(state, "actions", None) or [])]

    first = -1
    for index, (left, right) in enumerate(zip(recorded, replayed)):
        if left.split(":", 1)[1] != right.split(":", 1)[1]:
            first = index + 1
            break
    if first < 0 and len(recorded) != len(replayed):
        first = min(len(recorded), len(replayed)) + 1

    replayed_status = str(getattr(state, "status", ""))
    diff = RecordDiff(
        same_decisions=(first < 0),
        same_outcome=(record.final_status == replayed_status),
        recorded_decisions=recorded,
        replayed_decisions=replayed,
        first_divergence=first,
        recorded_status=record.final_status,
        replayed_status=replayed_status,
        confidence_delta=float(getattr(state, "overall_confidence", 0.0)) - record.final_confidence,
    )
    if executor is not None:
        diff.notes.extend(executor.misses[:5])
        if executor.fidelity < 1.0:
            diff.notes.append(f"replay fidelity {executor.fidelity:.0%} "
                              f"— some calls were answered approximately")
    return diff


def record_run(
    challenge: str,
    category: Optional[str] = None,
    max_steps: int = 8,
    challenge_path: Optional[str] = None,
    model: str = "",
    executor: Optional[Callable[[Any], Any]] = None,
    save_to: Optional[str] = None,
) -> Tuple[Any, RunRecord]:
    """Run an investigation and capture a replayable record of it."""
    from agent.executor import execute_action
    from agent.loop import AgentLoop

    recorder = Recorder(challenge=challenge, model=model, max_steps=max_steps)
    agent = AgentLoop(
        challenge_summary=challenge,
        category=category,
        max_steps=max_steps,
        challenge_path=challenge_path,
        on_event=recorder.on_event,
        executor=recorder.capture_executor(executor or execute_action),
    )
    state = agent.run()
    record = recorder.finalize(state=state, graph=agent.graph)
    record.challenge_path = challenge_path or ""
    if save_to:
        record.save(save_to)
    return state, record
