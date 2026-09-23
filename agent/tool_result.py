"""
agent/tool_result.py

One shape for every tool's output (upgrade items 7 and 9).

The old contract was `(ok: bool, output: str, error: str)`. Two things go
wrong with it, and both are agent-reliability bugs rather than cosmetic
issues:

1. **A failure and an empty finding look identical.** `_run_retrieve`
   returned `(True, '{"matches": []}', "")` when the vector store was
   *unavailable*. The agent read that as "retrieval worked and there is
   nothing relevant" and lowered its confidence in a perfectly good
   hypothesis. "I have no evidence" and "there is no evidence" are
   different claims and must not share a representation.

2. **Everything is a string.** Each consumer re-parses the payload with its
   own ad-hoc rules, so observations extracted from Ghidra and observations
   extracted from `strings` cannot be compared or ranked.

`ToolResult` fixes both. Status is an explicit enum, observations are
structured, and `is_evidence_of_absence` is the single place that answers
"may I treat this emptiness as a finding?"

Backward compatibility matters here: `execute_action` still returns the old
tuple, and `ToolResult.from_tuple` / `.to_tuple()` bridge the two so the
migration can be incremental rather than a flag day.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple


class ToolStatus(str, Enum):
    """Why a tool produced what it produced."""

    OK = "ok"                      # ran, found something
    EMPTY = "empty"                # ran correctly, genuinely found nothing
    PARTIAL = "partial"            # ran, incomplete (truncated, capped)
    ERROR = "error"                # ran and failed
    TIMEOUT = "timeout"            # exceeded its budget
    UNAVAILABLE = "unavailable"    # dependency/tool/model not installed
    DENIED = "denied"              # blocked by permission policy
    SKIPPED = "skipped"            # preconditions not met (no path, wrong type)

    @property
    def ran_successfully(self) -> bool:
        return self in (ToolStatus.OK, ToolStatus.EMPTY, ToolStatus.PARTIAL)

    @property
    def is_failure(self) -> bool:
        return self in (ToolStatus.ERROR, ToolStatus.TIMEOUT, ToolStatus.UNAVAILABLE, ToolStatus.DENIED)


# Statuses that are retryable, and those that never are. A missing binary
# will still be missing on the second attempt; a timeout might not be.
RETRYABLE = {ToolStatus.TIMEOUT, ToolStatus.ERROR}
NEVER_RETRY = {ToolStatus.UNAVAILABLE, ToolStatus.DENIED, ToolStatus.SKIPPED}


@dataclass
class Observation:
    """
    One structured finding.

    `confidence` is the tool's own confidence in the observation, not the
    agent's belief about the hypothesis. `readelf` reporting NX is 1.0;
    a heuristic guessing a framework from a filename is not.
    """

    kind: str                  # e.g. "mitigation", "string", "import", "metadata"
    value: str
    confidence: float = 1.0
    detail: str = ""
    source: str = ""           # which tool/subsystem produced it

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    """Normalized result from any tool, local analysis, or retrieval call."""

    tool: str
    status: ToolStatus = ToolStatus.OK
    observations: List[Observation] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)   # paths produced
    warnings: List[str] = field(default_factory=list)
    raw_output: str = ""
    error: str = ""
    error_type: str = ""
    retryable: bool = False
    duration_ms: int = 0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ----------------------------------------------------------- semantics

    @property
    def ok(self) -> bool:
        """True when the tool ran, whether or not it found anything."""
        return self.status.ran_successfully

    @property
    def found_something(self) -> bool:
        return self.status in (ToolStatus.OK, ToolStatus.PARTIAL) and bool(
            self.observations or self.raw_output.strip()
        )

    @property
    def is_evidence_of_absence(self) -> bool:
        """
        May the agent treat this emptiness as a finding?

        Only when the tool actually ran and correctly found nothing. This
        single property is the fix for the class of bug where a crashed
        Ghidra becomes "there is nothing interesting in this binary".
        """
        return self.status is ToolStatus.EMPTY

    def summary(self) -> str:
        """One line for traces and planner context."""
        if self.status.is_failure:
            return f"{self.tool}: {self.status.value} — {self.error or 'no detail'}"
        if self.status is ToolStatus.EMPTY:
            return f"{self.tool}: ran cleanly, found nothing"
        if self.status is ToolStatus.SKIPPED:
            return f"{self.tool}: skipped — {self.error or 'preconditions not met'}"
        count = len(self.observations)
        tail = f"{count} observation(s)" if count else "output only"
        return f"{self.tool}: {self.status.value}, {tail}"

    # ----------------------------------------------------------- building

    def add(self, kind: str, value: str, confidence: float = 1.0, detail: str = "") -> "ToolResult":
        self.observations.append(
            Observation(kind=kind, value=value, confidence=confidence, detail=detail, source=self.tool)
        )
        return self

    def warn(self, message: str) -> "ToolResult":
        if message and message not in self.warnings:
            self.warnings.append(message)
        return self

    def finalize(self) -> "ToolResult":
        """
        Settle the status once building is done.

        A result still marked OK with nothing in it is really EMPTY — that
        distinction is the whole point of this module, so it is enforced
        here rather than trusted to every call site.
        """
        if self.status is ToolStatus.OK and not self.observations and not self.raw_output.strip():
            self.status = ToolStatus.EMPTY
        self.retryable = self.status in RETRYABLE
        return self

    # ------------------------------------------------------ serialisation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status.value,
            "ok": self.ok,
            "found_something": self.found_something,
            "evidence_of_absence": self.is_evidence_of_absence,
            "observations": [o.to_dict() for o in self.observations],
            "artifacts": list(self.artifacts),
            "warnings": list(self.warnings),
            "error": self.error,
            "error_type": self.error_type,
            "retryable": self.retryable,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp,
            "metadata": dict(self.metadata),
            "raw_output": self.raw_output[:4000],
        }

    def to_tuple(self) -> Tuple[bool, str, str]:
        """Bridge back to the legacy `(ok, output, error)` contract."""
        if self.status.is_failure:
            return False, self.raw_output, self.error or self.status.value
        return True, self.raw_output, ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolResult":
        obs = [
            Observation(**{k: v for k, v in o.items() if k in Observation.__dataclass_fields__})
            for o in (data.get("observations") or [])
        ]
        return cls(
            tool=data.get("tool", "unknown"),
            status=ToolStatus(data.get("status", "ok")),
            observations=obs,
            artifacts=list(data.get("artifacts") or []),
            warnings=list(data.get("warnings") or []),
            raw_output=data.get("raw_output", ""),
            error=data.get("error", ""),
            error_type=data.get("error_type", ""),
            retryable=bool(data.get("retryable", False)),
            duration_ms=int(data.get("duration_ms", 0) or 0),
            metadata=dict(data.get("metadata") or {}),
        )

    # --------------------------------------------------- legacy migration

    @classmethod
    def from_tuple(
        cls,
        tool: str,
        legacy: Tuple[bool, str, str],
        duration_ms: int = 0,
    ) -> "ToolResult":
        """
        Wrap a legacy `(ok, output, error)` triple.

        The interesting work is inferring a real status from a payload that
        was never designed to carry one: a tool that "succeeded" while
        announcing it was unavailable is UNAVAILABLE, not OK.
        """
        ok, output, error = legacy
        output = output or ""
        error = error or ""

        if not ok:
            status = classify_error(error)
            return cls(
                tool=tool,
                status=status,
                raw_output=output,
                error=error,
                error_type=status.value,
                retryable=status in RETRYABLE,
                duration_ms=duration_ms,
            ).finalize()

        result = cls(tool=tool, raw_output=output, duration_ms=duration_ms)

        # Successful-looking payloads that actually describe a failure.
        note = _extract_note(output)
        if note:
            lowered = note.lower()
            if any(w in lowered for w in ("unavailable", "not installed", "not found", "missing")):
                result.status = ToolStatus.UNAVAILABLE
                result.error = note
                result.error_type = "unavailable"
            elif any(w in lowered for w in ("skipped", "no path", "disabled")):
                result.status = ToolStatus.SKIPPED
                result.error = note
            else:
                result.warn(note)

        result.observations.extend(observations_from_payload(output, tool))
        return result.finalize()


# --------------------------------------------------------------- helpers

_ERROR_PATTERNS: List[Tuple[str, ToolStatus]] = [
    (r"timed?\s*out|timeout", ToolStatus.TIMEOUT),
    (r"permission denied|not permitted|policy|requires approval", ToolStatus.DENIED),
    (r"no such file|not installed|command not found|cannot find|unavailable|"
     r"modulenotfounderror|importerror|is not recognized", ToolStatus.UNAVAILABLE),
]


def classify_error(message: str) -> ToolStatus:
    """Map a free-text error onto a status so retry logic can act on it."""
    lowered = (message or "").lower()
    for pattern, status in _ERROR_PATTERNS:
        if re.search(pattern, lowered):
            return status
    return ToolStatus.ERROR


def _extract_note(output: str) -> str:
    """Pull a `note` field out of a JSON payload, if there is one."""
    text = (output or "").strip()
    if not text.startswith("{"):
        return ""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in ("note", "error", "warning"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


# Payload keys worth promoting into structured observations, and the kind
# each becomes. Keeps extraction declarative instead of a chain of ifs.
_OBSERVATION_KEYS: Dict[str, str] = {
    "matches": "retrieval_match",
    "category": "classification",
    "frameworks": "framework",
    "framework": "framework",
    "jwts": "jwt",
    "tokens": "jwt",
    "auth_patterns": "auth_pattern",
    "headers": "http_header",
    "mitigations": "mitigation",
    "protections": "mitigation",
    "imports": "import",
    "strings": "string",
    "hashes": "hash",
    "algorithms": "algorithm",
    "flags": "flag_candidate",
    "findings": "finding",
    "subproblems": "subproblem",
    "techniques": "technique",
}


def observations_from_payload(output: str, tool: str, limit: int = 40) -> List[Observation]:
    """
    Lift known keys out of a JSON tool payload into Observations.

    Deliberately conservative: unrecognised keys stay in `raw_output`
    rather than being guessed at, because a wrong structured observation is
    more damaging than an unstructured one.
    """
    text = (output or "").strip()
    if not text.startswith("{"):
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    out: List[Observation] = []
    for key, kind in _OBSERVATION_KEYS.items():
        if key not in data:
            continue
        value = data[key]
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (str, int, float, bool)):
            out.append(Observation(kind=kind, value=str(value), source=tool))
        elif isinstance(value, dict):
            for k, v in list(value.items())[:limit]:
                out.append(Observation(kind=kind, value=str(k), detail=str(v)[:200], source=tool))
        elif isinstance(value, (list, tuple)):
            for item in list(value)[:limit]:
                if isinstance(item, dict):
                    label = (
                        item.get("name")
                        or item.get("technique")
                        or item.get("id")
                        or item.get("value")
                        or json.dumps(item)[:80]
                    )
                    out.append(
                        Observation(
                            kind=kind,
                            value=str(label),
                            detail=json.dumps(item, default=str)[:200],
                            confidence=float(item.get("score", 1.0)) if isinstance(item.get("score"), (int, float)) else 1.0,
                            source=tool,
                        )
                    )
                else:
                    out.append(Observation(kind=kind, value=str(item)[:200], source=tool))
        if len(out) >= limit:
            break
    return out[:limit]


def run_tool_safely(
    tool: str,
    fn,
    args: Optional[Dict[str, Any]] = None,
    timeout_hint: Optional[float] = None,
) -> ToolResult:
    """
    Call a tool function and always come back with a ToolResult.

    This replaces the `except Exception: return []` pattern: an exception
    becomes an explicit ERROR status with a type and a retryable flag,
    never an empty success that the agent would misread as a finding.
    """
    started = time.time()
    try:
        raw = fn(args or {})
    except Exception as exc:  # noqa: BLE001 - converting to data is the point
        status = classify_error(f"{type(exc).__name__}: {exc}")
        return ToolResult(
            tool=tool,
            status=status,
            error=f"{type(exc).__name__}: {exc}",
            error_type=type(exc).__name__,
            retryable=status in RETRYABLE,
            duration_ms=int((time.time() - started) * 1000),
        ).finalize()

    duration = int((time.time() - started) * 1000)

    if isinstance(raw, ToolResult):
        raw.duration_ms = raw.duration_ms or duration
        return raw.finalize()
    if isinstance(raw, tuple) and len(raw) == 3:
        return ToolResult.from_tuple(tool, raw, duration_ms=duration)
    if isinstance(raw, dict):
        return ToolResult(
            tool=tool,
            raw_output=json.dumps(raw, default=str),
            observations=observations_from_payload(json.dumps(raw, default=str), tool),
            duration_ms=duration,
        ).finalize()
    return ToolResult(tool=tool, raw_output=str(raw or ""), duration_ms=duration).finalize()


def merge(results: Iterable[ToolResult]) -> Dict[str, Any]:
    """
    Aggregate several results into a planner-facing summary.

    Separating `failed` from `empty` is what lets the planner decide
    between "try a different tool" and "this line of enquiry is closed".
    """
    results = list(results)
    failed = [r for r in results if r.status.is_failure]
    empty = [r for r in results if r.is_evidence_of_absence]
    productive = [r for r in results if r.found_something]
    return {
        "total": len(results),
        "productive": len(productive),
        "empty": len(empty),
        "failed": len(failed),
        "retryable": [r.tool for r in failed if r.retryable],
        "unavailable": [r.tool for r in results if r.status is ToolStatus.UNAVAILABLE],
        "observations": sum(len(r.observations) for r in results),
        "summaries": [r.summary() for r in results],
    }
