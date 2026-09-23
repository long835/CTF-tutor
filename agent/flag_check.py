"""
agent/flag_check.py

Whether a flag is *verified* or merely *flag-shaped* (items 62, 63).

`verifier.py` still contains an early-accept path: if the candidate matches a
flag regex, the verdict is `pass` at confidence 0.9 with no further
questions. That is the single most dangerous shortcut in the project,
because every part of a CTF is full of flag-shaped strings that are not the
flag — the example in the README, the decoy in `.git`, the format hint in
the challenge description, the `flag{...}` in an archive card the agent
retrieved a minute earlier.

Four things are checked here, in order of how much they matter.

**Provenance.** Did this string come out of a tool that looked at the
challenge, or out of the challenge description, a knowledge card, or the
model? A flag with no tool behind it is not a finding. This check alone
catches the majority of false positives.

**Decoys.** Known decoy wording, format-hint context ("the flag format is
…"), placeholder bodies, and the case where several distinct candidates
appeared — which usually means the agent found the decoy field and the real
one.

**Format.** Prefix, delimiters, length, character set, and any constraint
the challenge itself stated. A challenge that says the flag starts with
`picoCTF{` is stating a testable constraint.

**Reproduction.** The strongest available evidence short of submitting:
re-deriving the flag by a second, independent route. `reproduce` takes a
callable so the check stays honest about what it verified.

The output is a level, not a boolean: VERIFIED · REPRODUCED · PLAUSIBLE ·
FORMAT_ONLY · DECOY · REJECTED. `PLAUSIBLE` is not `VERIFIED`, and the
distinction is the whole point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class FlagVerdict(str, Enum):
    REPRODUCED = "reproduced"        # re-derived independently — strongest
    VERIFIED = "verified"            # came from a tool, format fits, no decoy signs
    PLAUSIBLE = "plausible"          # from a tool, but something is unresolved
    FORMAT_ONLY = "format_only"      # looks like a flag; nothing observed it
    DECOY = "decoy"                  # positively looks like a plant
    REJECTED = "rejected"            # fails a stated constraint

    @property
    def is_acceptable(self) -> bool:
        """Whether the agent may present this as the answer."""
        return self in (FlagVerdict.REPRODUCED, FlagVerdict.VERIFIED)


# Common competition formats. Used to recognise a flag, never to accept one.
FLAG_PATTERNS = [
    re.compile(r"\b([A-Za-z][A-Za-z0-9_\-]{1,20})\{[^}\r\n]{1,200}\}"),
    re.compile(r"\bflag_[A-Za-z0-9_]{6,}\b"),
]

# Wording that marks a plant. Real flags do not describe themselves.
DECOY_MARKERS = [
    "decoy", "not the flag", "nice try", "wrong flag", "fake", "example",
    "sample", "placeholder", "dummy", "try again", "keep looking",
    "this is not", "almost", "troll", "bait",
]

# Contexts in which a flag-shaped string is a *description* of the format
# rather than an instance of it.
FORMAT_HINT_CONTEXT = [
    "flag format", "format is", "submit as", "wrap the", "the flag looks like",
    "flags are of the form", "format:", "e.g.", "for example",
]

PLACEHOLDER_BODIES = {
    "flag", "your_flag_here", "redacted", "xxx", "xxxx", "todo", "changeme",
    "flag_here", "insert_flag", "...", "????", "test",
}


@dataclass
class FlagCheck:
    """The graded result for one flag candidate."""

    candidate: str
    verdict: FlagVerdict
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)      # tools that produced it
    reasons: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    competing: List[str] = field(default_factory=list)

    @property
    def acceptable(self) -> bool:
        return self.verdict.is_acceptable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "candidate": self.candidate,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 3),
            "acceptable": self.acceptable,
            "sources": list(self.sources),
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "competing": list(self.competing),
        }

    def explain(self) -> str:
        lines = [f"{self.candidate} → **{self.verdict.value}** ({self.confidence:.2f})"]
        if self.sources:
            lines.append(f"  observed by: {', '.join(self.sources)}")
        else:
            lines.append("  observed by: nothing — no tool produced this string")
        for reason in self.reasons:
            lines.append(f"  · {reason}")
        for warning in self.warnings:
            lines.append(f"  ! {warning}")
        if self.competing:
            lines.append(f"  other candidates: {', '.join(self.competing[:4])}")
        return "\n".join(lines)


def find_flags(text: str, limit: int = 20) -> List[str]:
    """Every flag-shaped string in some text. Recognition only."""
    out: List[str] = []
    for pattern in FLAG_PATTERNS:
        for match in pattern.finditer(text or ""):
            value = match.group(0).strip().rstrip('",;')
            if value and value not in out and len(value) < 300:
                out.append(value)
            if len(out) >= limit:
                return out
    return out


@dataclass
class FormatSpec:
    """Constraints the challenge itself stated about its flag."""

    prefix: str = ""
    min_length: int = 0
    max_length: int = 0
    charset: str = ""            # a regex character class for the body
    exact_count: int = 0         # expected number of flags

    def check(self, candidate: str) -> List[str]:
        """Violations. An empty list means nothing stated was broken."""
        problems: List[str] = []
        if self.prefix and not candidate.lower().startswith(self.prefix.lower()):
            problems.append(f"does not start with the stated prefix {self.prefix!r}")
        if self.min_length and len(candidate) < self.min_length:
            problems.append(f"shorter than the stated minimum ({len(candidate)} "
                            f"< {self.min_length})")
        if self.max_length and len(candidate) > self.max_length:
            problems.append(f"longer than the stated maximum ({len(candidate)} "
                            f"> {self.max_length})")
        if self.charset:
            body = candidate[candidate.find("{") + 1:candidate.rfind("}")] \
                if "{" in candidate and "}" in candidate else candidate
            if not re.fullmatch(f"[{self.charset}]+", body or ""):
                problems.append(f"body contains characters outside [{self.charset}]")
        return problems


def infer_format(description: str) -> FormatSpec:
    """
    Read stated flag constraints out of the challenge description.

    Only patterns that are unambiguous statements about the format. A guess
    here would create false rejections, which are worse than no check.
    """
    spec = FormatSpec()
    text = description or ""
    prefix = re.search(r"(?i)flag\s+format\s*(?:is|:)?\s*['\"`]?([A-Za-z][A-Za-z0-9_\-]{1,20})\{",
                       text)
    if not prefix:
        prefix = re.search(r"(?i)flags?\s+(?:start|begin)s?\s+with\s+['\"`]?"
                           r"([A-Za-z][A-Za-z0-9_\-]{1,20})\{?", text)
    if prefix:
        spec.prefix = prefix.group(1) + "{"
    length = re.search(r"(?i)flag\s+is\s+(\d{1,3})\s+characters", text)
    if length:
        spec.min_length = spec.max_length = int(length.group(1))
    if re.search(r"(?i)(hex|hexadecimal)\s+flag", text):
        spec.charset = "0-9a-fA-F"
    return spec


def _observed_sources(candidate: str, state: Any) -> Tuple[List[str], List[str]]:
    """
    Which tools produced this string, and which merely mentioned it.

    The split matters: a flag appearing in retrieval output or in the
    challenge description is *mentioned*, not observed, and cannot verify
    anything.
    """
    observed: List[str] = []
    mentioned: List[str] = []
    try:
        from agent.tool_capabilities import capability
    except Exception:
        capability = None  # type: ignore

    for ev in getattr(state, "evidence", None) or []:
        content = f"{getattr(ev, 'content', '')}\n{getattr(ev, 'finding', '')}"
        if candidate not in content:
            continue
        source = str(getattr(ev, "source", "") or "tool")
        cap = capability(source) if capability else None
        is_reference = cap is not None and not cap.produces
        (mentioned if is_reference else observed).append(source)

    for action in getattr(state, "actions", None) or []:
        if candidate in str(getattr(action, "raw_output", "") or ""):
            tool = str(getattr(action, "tool", "") or "")
            if tool and tool not in observed:
                observed.append(tool)

    description = str(getattr(state, "challenge_summary", "") or "")
    if candidate in description:
        mentioned.append("challenge description")
    return sorted(set(observed)), sorted(set(mentioned))


def check_flag(
    candidate: str,
    state: Any = None,
    spec: Optional[FormatSpec] = None,
    reproduce: Optional[Callable[[str], bool]] = None,
) -> FlagCheck:
    """
    Grade one flag candidate.

    `reproduce` is an optional callable that re-derives the flag by a second
    route and returns whether it matched. When supplied and successful it is
    the strongest verdict available offline; when absent, VERIFIED is the
    ceiling and the check says so.
    """
    candidate = (candidate or "").strip()
    result = FlagCheck(candidate=candidate, verdict=FlagVerdict.REJECTED)

    if not candidate:
        result.reasons.append("no candidate supplied")
        return result

    if not find_flags(candidate):
        result.reasons.append("does not match any known flag shape")
        return result

    # Callers pass whatever they have: a bare flag, or a sentence like
    # "Flag candidate(s): CTF{...}" built by the observer. Grade the flag, not
    # the sentence — the sentence never appears in tool output, so leaving it
    # unnormalised would make every real flag look unobserved.
    extracted = find_flags(candidate)
    if extracted and extracted[0] != candidate:
        result.reasons.append(f"extracted {extracted[0]} from the supplied text")
        candidate = extracted[0]
        result.candidate = candidate

    description = str(getattr(state, "challenge_summary", "") or "") if state else ""
    spec = spec or infer_format(description)

    # 1. Stated constraints. A violation is decisive: the challenge told us.
    violations = spec.check(candidate)
    if violations:
        result.verdict = FlagVerdict.REJECTED
        result.reasons.extend(violations)
        result.confidence = 0.05
        return result

    # 2. Decoy markers, placeholders, and format-hint context.
    lowered = candidate.lower()
    body = lowered[lowered.find("{") + 1:lowered.rfind("}")] if "{" in lowered else lowered
    for marker in DECOY_MARKERS:
        if marker in lowered:
            result.verdict = FlagVerdict.DECOY
            result.reasons.append(f"candidate text contains {marker!r}")
            result.confidence = 0.05
            return result
    if body.strip() in PLACEHOLDER_BODIES:
        result.verdict = FlagVerdict.DECOY
        result.reasons.append("body is a placeholder, not a value")
        result.confidence = 0.05
        return result

    if description and candidate in description:
        window_start = max(0, description.find(candidate) - 120)
        window = description[window_start:description.find(candidate)].lower()
        if any(hint in window for hint in FORMAT_HINT_CONTEXT):
            result.verdict = FlagVerdict.DECOY
            result.reasons.append("appears in the description as a format example, "
                                  "not as a value")
            result.confidence = 0.05
            return result

    # 3. Provenance. The check that does the real work.
    observed, mentioned = _observed_sources(candidate, state) if state is not None else ([], [])
    result.sources = observed
    if not observed:
        result.verdict = FlagVerdict.FORMAT_ONLY
        result.confidence = 0.2
        result.reasons.append("no tool that examined the challenge produced this string")
        if mentioned:
            result.warnings.append(
                f"only mentioned by {', '.join(mentioned)} — reference material and "
                f"the challenge text are not observations"
            )
        return result

    # 4. Competing candidates. Several flag-shaped strings usually means one
    # of them is the plant.
    if state is not None:
        pool: Set[str] = set()
        for action in getattr(state, "actions", None) or []:
            pool.update(find_flags(str(getattr(action, "raw_output", "") or ""), limit=10))
        competing = sorted(pool - {candidate})
        result.competing = competing
        if competing:
            result.warnings.append(
                f"{len(competing)} other flag-shaped string(s) were seen; one of them "
                f"may be the real flag or a decoy"
            )

    # 5. Reproduction.
    if reproduce is not None:
        try:
            if reproduce(candidate):
                result.verdict = FlagVerdict.REPRODUCED
                result.confidence = 0.95
                result.reasons.append("re-derived independently by a second route")
                return result
            result.verdict = FlagVerdict.PLAUSIBLE
            result.confidence = 0.4
            result.warnings.append("independent reproduction did not return this value")
            return result
        except Exception as exc:
            result.warnings.append(f"reproduction attempt failed: {str(exc)[:80]}")

    independent = len(set(observed))
    if result.competing:
        result.verdict = FlagVerdict.PLAUSIBLE
        result.confidence = 0.55
    else:
        result.verdict = FlagVerdict.VERIFIED
        result.confidence = min(0.9, 0.7 + 0.1 * independent)
        result.reasons.append(
            f"produced by {', '.join(observed)}, format consistent, no decoy signals"
        )
        result.warnings.append("not reproduced by a second route — this is the ceiling "
                               "without re-running the exploit")
    return result


def best_candidate(state: Any, reproduce: Optional[Callable[[str], bool]] = None
                   ) -> Optional[FlagCheck]:
    """
    Grade every flag-shaped string the run produced and return the best.

    Considers all candidates rather than the first one seen, which is how the
    decoy wins under the current early-accept path: decoys are usually
    planted where a tool will hit them first.
    """
    candidates: List[str] = []
    stated = str(getattr(state, "flag_candidate", "") or "").strip()
    if stated:
        candidates.append(stated)
    for action in getattr(state, "actions", None) or []:
        for found in find_flags(str(getattr(action, "raw_output", "") or "")):
            if found not in candidates:
                candidates.append(found)
    for ev in getattr(state, "evidence", None) or []:
        for found in find_flags(str(getattr(ev, "content", "") or "")):
            if found not in candidates:
                candidates.append(found)
    if not candidates:
        return None

    order = {
        FlagVerdict.REPRODUCED: 5, FlagVerdict.VERIFIED: 4, FlagVerdict.PLAUSIBLE: 3,
        FlagVerdict.FORMAT_ONLY: 2, FlagVerdict.DECOY: 1, FlagVerdict.REJECTED: 0,
    }
    checks = [check_flag(c, state=state, reproduce=reproduce) for c in candidates]
    return max(checks, key=lambda c: (order[c.verdict], c.confidence))


def verify_solution_steps(state: Any, graph: Any = None) -> Dict[str, Any]:
    """
    Whether the *solution* — not just the flag — stands up (item 62).

    A solution is a claim that a specific technique, supported by specific
    observations, produces the result. All three parts are checked, so
    "plausible narrative plus a flag-shaped string" cannot pass as a
    verified solution.
    """
    report: Dict[str, Any] = {
        "technique_supported": False,
        "flag_verified": False,
        "steps_recorded": False,
        "reproducible": False,
        "verdict": "insufficient_evidence",
        "reasons": [],
    }

    top = None
    try:
        top = state.top_hypothesis()
    except Exception:
        top = None
    technique = str(getattr(top, "technique", "") or "") if top else ""

    if technique:
        try:
            from agent.evidence import SupportLevel, assess_state

            assessment = assess_state(state, technique)
            report["technique_supported"] = assessment.level in (
                SupportLevel.SUPPORTED, SupportLevel.LIKELY)
            report["support_level"] = assessment.level.value
            if not report["technique_supported"]:
                report["reasons"].append(
                    f"support for {technique} is only '{assessment.level.value}'")
        except Exception:
            pass
    else:
        report["reasons"].append("no technique was established")

    if graph is not None and technique:
        try:
            support = graph.assess_technique(technique)
            report["graph_gaps"] = list(support.gaps)
            if support.gaps:
                report["reasons"].append(
                    f"{len(support.gaps)} required observation(s) were never made")
        except Exception:
            pass

    check = best_candidate(state)
    if check is not None:
        report["flag_check"] = check.to_dict()
        report["flag_verified"] = check.acceptable
        if not check.acceptable:
            report["reasons"].append(f"flag candidate is {check.verdict.value}")

    succeeded = [a for a in (getattr(state, "actions", None) or [])
                 if str(getattr(a, "status", "")) == "succeeded"]
    report["steps_recorded"] = len(succeeded) >= 1
    if not report["steps_recorded"]:
        report["reasons"].append("no action succeeded, so there are no steps to reproduce")

    if report["flag_verified"] and report["technique_supported"] and report["steps_recorded"]:
        report["verdict"] = "verified"
    elif report["flag_verified"] or report["technique_supported"]:
        report["verdict"] = "partially_supported"
    else:
        report["verdict"] = "insufficient_evidence"
    return report
