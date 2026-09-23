"""
agent/structured.py

Getting usable structured data out of small local models (upgrade item 47).

An 8B model asked for JSON will, often enough to matter, return: a code
fence around it, a `<think>` block before it, trailing prose after it,
single quotes, trailing commas, `True` instead of `true`, or a perfectly
valid object that is missing a required field.

The wrong response to that is a crash, and the second-wrongest is a silent
`{}`. Both destroy an agent step for a reason that is almost always
recoverable. This module runs a ladder instead:

    parse → repair → validate → coerce → retry with a stricter prompt
         → deterministic fallback

Every rung is recorded, so `StructuredResult.method` tells you how much
work the model actually needed. That number is worth watching: if repairs
spike after a model change, the model changed for the worse.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

# Order matters: these run cheapest-first.
REPAIR_STRATEGIES = (
    "strip_fences",
    "strip_thinking",
    "extract_object",
    "fix_quotes",
    "fix_trailing_commas",
    "fix_python_literals",
    "close_brackets",
)


@dataclass
class FieldSpec:
    """One expected field: its type, whether it is required, and its default."""

    name: str
    types: Tuple[type, ...] = (str,)
    required: bool = False
    default: Any = None
    choices: Optional[Sequence[Any]] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None

    def coerce(self, value: Any) -> Tuple[bool, Any, str]:
        """
        Try to make `value` fit. Returns (ok, coerced, note).

        Coercion is deliberately generous about *representation* and strict
        about *meaning*: "0.8" becoming 0.8 is fine, "banana" becoming 0.0
        is not, because a silently invented number is worse than a rejected
        field.
        """
        if value is None:
            return (not self.required), self.default, "missing"

        if isinstance(value, self.types) and not (
            bool in self.types and not isinstance(value, bool)
        ):
            coerced = value
        else:
            coerced, note = self._convert(value)
            if coerced is None:
                return (not self.required), self.default, note

        if float in self.types or int in self.types:
            try:
                numeric = float(coerced)
                if self.min_value is not None:
                    numeric = max(self.min_value, numeric)
                if self.max_value is not None:
                    numeric = min(self.max_value, numeric)
                coerced = int(numeric) if int in self.types and float not in self.types else numeric
            except (TypeError, ValueError):
                return (not self.required), self.default, "not numeric"

        if self.choices is not None and coerced not in self.choices:
            lowered = str(coerced).strip().lower()
            match = next((c for c in self.choices if str(c).lower() == lowered), None)
            if match is None:
                return (not self.required), self.default, f"not one of {list(self.choices)}"
            coerced = match

        return True, coerced, ""

    def _convert(self, value: Any) -> Tuple[Any, str]:
        target = self.types[0]
        try:
            if target is str:
                return (json.dumps(value) if isinstance(value, (dict, list)) else str(value)), ""
            if target in (int, float):
                if isinstance(value, str):
                    match = re.search(r"-?\d+(?:\.\d+)?", value)
                    if not match:
                        return None, "no number found"
                    return target(float(match.group())), "extracted number"
                return target(value), ""
            if target is bool:
                if isinstance(value, str):
                    return value.strip().lower() in ("true", "yes", "1"), "parsed bool"
                return bool(value), ""
            if target is list:
                if isinstance(value, str):
                    return [p.strip() for p in re.split(r"[,;\n]", value) if p.strip()], "split string"
                return list(value), ""
            if target is dict and isinstance(value, str):
                return json.loads(value), "parsed nested json"
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            return None, f"convert failed: {exc}"
        return None, "no conversion rule"


@dataclass
class Schema:
    """A flat expected shape. Nested objects are validated as plain dicts."""

    name: str
    fields: List[FieldSpec] = field(default_factory=list)

    def validate(self, data: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], List[str]]:
        if not isinstance(data, dict):
            return False, {}, ["payload is not an object"]
        out: Dict[str, Any] = {}
        problems: List[str] = []
        for spec in self.fields:
            ok, value, note = spec.coerce(data.get(spec.name))
            if not ok:
                problems.append(f"{spec.name}: {note}")
                out[spec.name] = spec.default
            else:
                out[spec.name] = value
        # Keep unexpected keys; a model volunteering extra context is not an
        # error, and discarding it loses information.
        for key, value in data.items():
            out.setdefault(key, value)
        return (not problems), out, problems

    def prompt_hint(self) -> str:
        """A compact shape description to paste into a retry prompt."""
        lines = []
        for spec in self.fields:
            kind = spec.types[0].__name__
            bits = [kind]
            if spec.choices:
                bits.append("one of " + "|".join(str(c) for c in spec.choices))
            if spec.required:
                bits.append("REQUIRED")
            lines.append(f'  "{spec.name}": <{", ".join(bits)}>')
        return "{\n" + ",\n".join(lines) + "\n}"


@dataclass
class StructuredResult:
    """What came back, and how hard it was to get."""

    ok: bool
    data: Dict[str, Any] = field(default_factory=dict)
    method: str = "direct"       # direct | repaired:<strategy> | retry | fallback
    repairs: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    attempts: int = 1
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "method": self.method,
            "repairs": list(self.repairs),
            "problems": list(self.problems),
            "attempts": self.attempts,
            "data": self.data,
        }


# ----------------------------------------------------------------- repair


def _strip_fences(text: str) -> str:
    return re.sub(r"```(?:json|javascript|js)?\s*|\s*```", "", text)


def _strip_thinking(text: str) -> str:
    """Remove reasoning blocks that models such as qwen3 emit by default."""
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE)
    return re.sub(r"<\|?thinking\|?>.*?<\|?/?thinking\|?>", "", text, flags=re.DOTALL | re.IGNORECASE)


def _extract_object(text: str) -> str:
    """Take the outermost balanced {...}, ignoring braces inside strings."""
    start = text.find("{")
    if start < 0:
        return text
    depth, in_string, escaped = 0, False, False
    for i, ch in enumerate(text[start:], start):
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def _fix_quotes(text: str) -> str:
    """Single-quoted keys/values → double-quoted, without touching apostrophes."""
    text = re.sub(r"(?<=[{,\s])'([^'\"]*?)'(\s*:)", r'"\1"\2', text)
    return re.sub(r"(:\s*)'([^'\"]*?)'(\s*[,}\]])", r'\1"\2"\3', text)


def _fix_trailing_commas(text: str) -> str:
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _fix_python_literals(text: str) -> str:
    text = re.sub(r"(?<![\w\"])True(?![\w\"])", "true", text)
    text = re.sub(r"(?<![\w\"])False(?![\w\"])", "false", text)
    return re.sub(r"(?<![\w\"])None(?![\w\"])", "null", text)


def _close_brackets(text: str) -> str:
    """Close a truncated object — common when a model hits its token cap."""
    in_string, escaped, stack = False, False, []
    for ch in text:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch in "{[":
            stack.append(ch)
        elif ch in "}]" and stack:
            stack.pop()
    if in_string:
        text += '"'
    return text + "".join("}" if ch == "{" else "]" for ch in reversed(stack))


_REPAIRS: Dict[str, Callable[[str], str]] = {
    "strip_fences": _strip_fences,
    "strip_thinking": _strip_thinking,
    "extract_object": _extract_object,
    "fix_quotes": _fix_quotes,
    "fix_trailing_commas": _fix_trailing_commas,
    "fix_python_literals": _fix_python_literals,
    "close_brackets": _close_brackets,
}


def parse_json_resilient(text: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    Parse JSON, applying repairs cumulatively until something works.

    Returns (data, repairs_applied). `None` means every rung failed.
    """
    if not text or not text.strip():
        return None, []

    try:
        data = json.loads(text)
        return (data if isinstance(data, dict) else {"value": data}), []
    except json.JSONDecodeError:
        pass

    applied: List[str] = []
    current = text
    for name in REPAIR_STRATEGIES:
        current = _REPAIRS[name](current)
        applied.append(name)
        try:
            data = json.loads(current)
            return (data if isinstance(data, dict) else {"value": data}), list(applied)
        except json.JSONDecodeError:
            continue
    return None, applied


# ------------------------------------------------------------- public API


def parse_structured(
    text: str,
    schema: Optional[Schema] = None,
    fallback: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> StructuredResult:
    """Parse one model response. No network, no retry — pure function."""
    data, repairs = parse_json_resilient(text)

    if data is None:
        if fallback is not None:
            try:
                return StructuredResult(
                    ok=True, data=fallback(text) or {}, method="fallback",
                    repairs=repairs, raw=text[:2000],
                )
            except Exception as exc:  # noqa: BLE001
                return StructuredResult(
                    ok=False, method="fallback_failed", repairs=repairs,
                    problems=[f"fallback raised: {exc}"], raw=text[:2000],
                )
        return StructuredResult(
            ok=False, method="unparseable", repairs=repairs,
            problems=["no valid JSON object found"], raw=text[:2000],
        )

    method = f"repaired:{repairs[-1]}" if repairs else "direct"

    if schema is None:
        return StructuredResult(ok=True, data=data, method=method, repairs=repairs, raw=text[:2000])

    valid, coerced, problems = schema.validate(data)
    return StructuredResult(
        ok=valid, data=coerced, method=method, repairs=repairs,
        problems=problems, raw=text[:2000],
    )


def request_structured(
    call_model: Callable[[str, str], str],
    system: str,
    user: str,
    schema: Schema,
    max_attempts: int = 2,
    fallback: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> StructuredResult:
    """
    Ask a model for structured output, retrying with a stricter prompt.

    `call_model(system, user)` should return raw text. On a failed attempt
    the retry names the specific fields that were wrong, which works far
    better on small models than repeating "return valid JSON" louder.
    """
    last = StructuredResult(ok=False, method="no_attempt")

    for attempt in range(1, max(1, max_attempts) + 1):
        if attempt == 1:
            sys_prompt, usr_prompt = system, user
        else:
            missing = ", ".join(p.split(":")[0] for p in last.problems) or "the required fields"
            sys_prompt = (
                f"{system}\n\n"
                f"Your previous reply could not be used. Return ONLY a JSON object "
                f"with no prose, no markdown fences and no reasoning block. "
                f"Problems: {missing}.\n"
                f"Exact shape:\n{schema.prompt_hint()}"
            )
            usr_prompt = user

        try:
            raw = call_model(sys_prompt, usr_prompt)
        except Exception as exc:  # noqa: BLE001
            last = StructuredResult(
                ok=False, method="model_error", attempts=attempt,
                problems=[f"{type(exc).__name__}: {exc}"],
            )
            continue

        result = parse_structured(raw, schema, fallback=fallback if attempt == max_attempts else None)
        result.attempts = attempt
        if result.ok:
            if attempt > 1:
                result.method = f"retry({result.method})"
            return result
        last = result

    # Everything failed: hand back schema defaults rather than raising, so
    # the caller degrades to heuristics instead of losing the whole step.
    if fallback is None:
        defaults = {f.name: f.default for f in schema.fields}
        last.data = {**defaults, **(last.data or {})}
        last.method = "defaults"
    return last


# ------------------------------------------------- schemas used in-repo

CLASSIFY_SCHEMA = Schema(
    "classify",
    [
        FieldSpec("category", (str,), required=True,
                  choices=["pwn", "rev", "web", "crypto", "forensics", "osint", "misc",
                           "blockchain", "mobile"]),
        FieldSpec("confidence", (float,), default=0.5, min_value=0.0, max_value=1.0),
        FieldSpec("reasoning", (str,), default=""),
    ],
)

VERIFY_SCHEMA = Schema(
    "verify",
    [
        FieldSpec("verdict", (str,), required=True,
                  choices=["pass", "fail", "insufficient_evidence"]),
        FieldSpec("confidence", (float,), default=0.0, min_value=0.0, max_value=1.0),
        FieldSpec("reasons", (list,), default=[]),
        FieldSpec("missing_evidence", (list,), default=[]),
    ],
)

PLAN_SCHEMA = Schema(
    "plan",
    [
        FieldSpec("tool", (str,), required=True),
        FieldSpec("args", (dict,), default={}),
        FieldSpec("reason", (str,), default=""),
        FieldSpec("expected_evidence", (str,), default=""),
    ],
)

HYPOTHESIS_SCHEMA = Schema(
    "hypothesis",
    [
        FieldSpec("statement", (str,), required=True),
        FieldSpec("technique", (str,), default=""),
        FieldSpec("confidence", (float,), default=0.5, min_value=0.0, max_value=1.0),
        FieldSpec("supporting_evidence", (list,), default=[]),
        FieldSpec("refuting_evidence", (list,), default=[]),
    ],
)
