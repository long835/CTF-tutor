"""
agent/evidence.py

What would actually have to be true (items 5, 61, 12).

The verifier's weak point was that it could conclude "pass" from a
confident-sounding model reply plus a couple of evidence items, without
ever asking *which* observations a claim of this kind requires. That is how
an agent ends up asserting a format-string vulnerability because the word
"printf" appeared somewhere.

This module inverts it. Each technique declares the observations that would
support it, and — just as importantly — the ones that would argue against
it, plus the innocent explanations that produce the same signal. Then a
claim is graded against what was actually collected:

    SUPPORTED · LIKELY · UNCERTAIN · INSUFFICIENT_EVIDENCE · REFUTED

`INSUFFICIENT_EVIDENCE` is a first-class outcome, not a failure to decide.
An agent that can say "I don't know" hallucinates much less than one whose
only options are yes and no.

The `alternatives` field is the negative-knowledge idea from item 12: high
entropy is consistent with a packer, and equally consistent with
compression, an encrypted blob, or an embedded media asset. Listing the
lookalikes is what stops a single suggestive signal from being treated as
proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class SupportLevel(str, Enum):
    """How well the collected evidence backs a claim."""

    SUPPORTED = "supported"                          # required signals present
    LIKELY = "likely"                                # most present
    UNCERTAIN = "uncertain"                          # some, with lookalikes open
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # not enough to say anything
    REFUTED = "refuted"                              # a contradicting signal is present

    @property
    def is_conclusive(self) -> bool:
        return self in (SupportLevel.SUPPORTED, SupportLevel.REFUTED)


@dataclass
class EvidenceRequirement:
    """What a claim about one technique needs in order to stand up."""

    technique: str
    required: List[str] = field(default_factory=list)      # all of these
    supporting: List[str] = field(default_factory=list)    # any of these help
    contradicting: List[str] = field(default_factory=list) # any of these refute
    alternatives: List[str] = field(default_factory=list)  # innocent explanations
    verification: str = ""                                 # how to confirm it

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "required": list(self.required),
            "supporting": list(self.supporting),
            "contradicting": list(self.contradicting),
            "alternatives": list(self.alternatives),
            "verification": self.verification,
        }


# Signals are matched as case-insensitive substrings/patterns against the
# collected evidence text. Kept phrase-based rather than regex-heavy so the
# table stays readable and editable by non-programmers.
REQUIREMENTS: Dict[str, EvidenceRequirement] = {
    "stack-buffer-overflow": EvidenceRequirement(
        technique="stack-buffer-overflow",
        required=["unbounded copy|gets|strcpy|read into|fixed buffer|no bounds",
                  "buffer|stack|local array"],
        supporting=["nx", "no canary", "pie disabled", "win function", "crash", "segfault"],
        contradicting=["bounds check|bounds checked|checks the length",
                       r"fgets with size|fgets\(.*sizeof|strncpy|snprintf",
                       "length validated|length is validated",
                       "rust|go|java|python source"],
        alternatives=["a bounded copy that merely looks unsafe",
                      "a heap buffer rather than a stack one",
                      "a read that is actually limited by the caller"],
        verification="Confirm the write crosses the saved return address, e.g. a controlled crash offset.",
    ),
    "format-string": EvidenceRequirement(
        technique="format-string",
        required=["printf|fprintf|sprintf|snprintf|syslog", "user.{0,20}format|non-literal format|variable format"],
        supporting=["%x|%n|%s in input", "stack values leaked", "unexpected output"],
        # Phrased as patterns, not as one exact sentence. The adversarial suite
        # showed "printf is called with a literal format string" slipping past
        # the old literal phrase, which let a refuted claim stay live.
        contradicting=["format string is a literal|literal format|constant format",
                       r"puts\(",
                       "passed as (?:an |the )?argument|not (?:as )?the format|"
                       "input passed as argument not format"],
        alternatives=["printf called with a correct literal format and the user data as an argument",
                      "a logging wrapper that escapes its input"],
        verification="Show that input reaches the format parameter, not an argument slot.",
    ),
    "ret2libc": EvidenceRequirement(
        technique="ret2libc",
        required=["overflow|control.{0,15}(rip|eip|return)", "nx|non-executable|dep"],
        supporting=["dynamically linked", "libc", "leak", "puts|printf plt"],
        contradicting=["statically linked", "nx disabled", "no overflow"],
        alternatives=["a ret2win where a convenient function already exists",
                      "shellcode being viable because NX is off"],
        verification="Confirm NX is on and an address leak is obtainable.",
    ),
    "sql-injection": EvidenceRequirement(
        technique="sql-injection",
        required=["query|select|insert|where|sql", "concat|interpolat|format|f-string|\\+ user|user input"],
        supporting=["sql error", "syntax error", "response differs on quote", "no parameterisation"],
        contradicting=["parameterised|prepared statement|placeholder|orm binding", "input escaped"],
        alternatives=["an ORM that looks like string building but parameterises underneath",
                      "a query whose variable part is a validated enum"],
        verification="Show the input reaching the query as syntax rather than as a bound parameter.",
    ),
    "jwt-none-bypass": EvidenceRequirement(
        technique="jwt-none-bypass",
        required=["jwt|json web token", "alg|algorithm"],
        supporting=["none", "header honoured", "verify without allowlist", "decode without verify"],
        contradicting=["algorithm allowlist", "alg pinned", "signature required", "algorithms=\\[.*\\]"],
        alternatives=["a library that already rejects alg=none by default",
                      "a token that is verified but whose payload is merely readable"],
        verification="Show the verifier selects its algorithm from the token header.",
    ),
    "jwt-alg-confusion": EvidenceRequirement(
        technique="jwt-alg-confusion",
        required=["jwt", "rs256|asymmetric|public key"],
        supporting=["jwks", "public key reachable", "generic verify", "hs256 accepted"],
        contradicting=["algorithm pinned to rs256", "key type checked"],
        alternatives=["a correctly pinned verifier that merely exposes its public key",
                      "a weak HMAC secret, which is a different bug"],
        verification="Show one verify call accepts both key types without distinguishing them.",
    ),
    "path-traversal": EvidenceRequirement(
        technique="path-traversal",
        required=["path|filename|file", "join|concat|open|read"],
        supporting=["user controlled path", "no normalisation", "prefix check only", "\\.\\."],
        contradicting=["normalised then validated", "allowlist of filenames", "basename only"],
        alternatives=["a validated allowlist that happens to take a name",
                      "a chroot or container boundary that contains the traversal"],
        verification="Show normalisation happens after, not before, the validation.",
    ),
    "ssti": EvidenceRequirement(
        technique="ssti",
        required=["template|render|jinja|twig|freemarker|handlebars"],
        supporting=["user input in template string", "expression evaluated", "engine in traceback"],
        contradicting=["input passed as context variable", "autoescape", "template is a constant"],
        alternatives=["reflected XSS, where the input is rendered but not evaluated",
                      "an input passed safely as a template variable"],
        verification="Show a trivial expression is evaluated rather than printed literally.",
    ),
    "packed-binary": EvidenceRequirement(
        technique="packed-binary",
        required=["entropy|packed|compressed section"],
        supporting=["few imports", "upx|themida|vmprotect", "unusual section name", "rwx section"],
        contradicting=["normal import table", "readable strings", "standard sections"],
        alternatives=["ordinary compressed data such as an embedded archive",
                      "an embedded media asset, which is also high entropy",
                      "an encrypted blob unrelated to packing"],
        verification="Identify a packer signature or observe the unpacking stub executing.",
    ),
    "xor-single-byte": EvidenceRequirement(
        technique="xor-single-byte",
        required=["xor|ciphertext|encoded bytes"],
        supporting=["short key", "repeating byte", "printable after xor", "frequency match"],
        contradicting=["key length > 1 established", "aes|rsa|block cipher"],
        alternatives=["a repeating multi-byte key, which needs a different approach",
                      "a simple substitution that is not XOR at all"],
        verification="Recover plaintext under a single key byte and score it against natural language.",
    ),
    "idor": EvidenceRequirement(
        technique="idor",
        required=["id|identifier|object reference", "fetch|lookup|get|load"],
        supporting=["sequential id", "no ownership check", "other user's record accessible"],
        contradicting=["ownership verified", "authorization check present", "scoped query"],
        alternatives=["a deliberately public resource",
                      "an unguessable identifier that is checked anyway"],
        verification="Show a record belonging to another principal is returned without an authorization check.",
    ),
    "steganography": EvidenceRequirement(
        technique="steganography",
        required=["image|audio|media file"],
        supporting=["size mismatch", "extra chunk", "lsb anomaly", "appended data"],
        contradicting=["metadata contains the answer", "data appended after eof", "file is a plain archive"],
        alternatives=["data hidden in metadata rather than pixels",
                      "a second file simply concatenated on the end",
                      "an extra format chunk a viewer ignores"],
        verification="Check structure and trailing bytes before concluding pixel-level embedding.",
    ),
}


@dataclass
class EvidenceAssessment:
    """The graded result for one claim."""

    technique: str
    level: SupportLevel
    confidence: float
    matched_required: List[str] = field(default_factory=list)
    missing_required: List[str] = field(default_factory=list)
    matched_supporting: List[str] = field(default_factory=list)
    matched_contradicting: List[str] = field(default_factory=list)
    open_alternatives: List[str] = field(default_factory=list)
    verification_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "level": self.level.value,
            "confidence": round(self.confidence, 3),
            "matched_required": list(self.matched_required),
            "missing_required": list(self.missing_required),
            "matched_supporting": list(self.matched_supporting),
            "matched_contradicting": list(self.matched_contradicting),
            "open_alternatives": list(self.open_alternatives),
            "verification_hint": self.verification_hint,
        }

    def explain(self) -> str:
        lines = [f"{self.technique}: **{self.level.value}** (confidence {self.confidence:.2f})"]
        if self.matched_required:
            lines.append(f"  present: {', '.join(self.matched_required)}")
        if self.missing_required:
            lines.append(f"  still needed: {', '.join(self.missing_required)}")
        if self.matched_contradicting:
            lines.append(f"  argues against: {', '.join(self.matched_contradicting)}")
        if self.open_alternatives:
            lines.append(f"  could also be: {'; '.join(self.open_alternatives[:3])}")
        if self.verification_hint and not self.level.is_conclusive:
            lines.append(f"  to confirm: {self.verification_hint}")
        return "\n".join(lines)


def _matches(signal: str, text: str) -> bool:
    """Match a signal spec (alternatives separated by |) against evidence."""
    for option in signal.split("|"):
        option = option.strip()
        if not option:
            continue
        try:
            if re.search(option, text, re.IGNORECASE):
                return True
        except re.error:
            if option.lower() in text:
                return True
    return False


def assess(
    technique: str,
    evidence_text: str,
    requirement: Optional[EvidenceRequirement] = None,
) -> EvidenceAssessment:
    """
    Grade a technique claim against the collected evidence.

    An unknown technique returns INSUFFICIENT_EVIDENCE rather than
    defaulting to "probably fine" — silence is the honest answer when
    there is no rubric to apply.
    """
    technique = (technique or "").strip().lower()
    req = requirement or REQUIREMENTS.get(technique)
    text = (evidence_text or "").lower()

    if req is None:
        return EvidenceAssessment(
            technique=technique or "unknown",
            level=SupportLevel.INSUFFICIENT_EVIDENCE,
            confidence=0.2,
            verification_hint="No evidence rubric defined for this technique; treat the claim as unverified.",
        )

    matched_req = [s for s in req.required if _matches(s, text)]
    missing_req = [s for s in req.required if s not in matched_req]
    matched_sup = [s for s in req.supporting if _matches(s, text)]
    matched_con = [s for s in req.contradicting if _matches(s, text)]

    # A contradicting signal outranks everything: it is a positive
    # observation that the claim is wrong, not merely missing support.
    if matched_con:
        return EvidenceAssessment(
            technique=technique, level=SupportLevel.REFUTED, confidence=0.1,
            matched_required=matched_req, missing_required=missing_req,
            matched_supporting=matched_sup, matched_contradicting=matched_con,
            verification_hint=req.verification,
        )

    total_req = len(req.required) or 1
    req_ratio = len(matched_req) / total_req
    sup_ratio = len(matched_sup) / (len(req.supporting) or 1)

    if req_ratio >= 1.0 and matched_sup:
        level, confidence = SupportLevel.SUPPORTED, min(0.95, 0.7 + 0.25 * sup_ratio)
        alternatives: List[str] = []
    elif req_ratio >= 1.0:
        level, confidence = SupportLevel.LIKELY, 0.65
        alternatives = list(req.alternatives)
    elif req_ratio >= 0.5:
        level, confidence = SupportLevel.UNCERTAIN, 0.4 + 0.1 * sup_ratio
        alternatives = list(req.alternatives)
    else:
        level, confidence = SupportLevel.INSUFFICIENT_EVIDENCE, 0.2
        alternatives = list(req.alternatives)

    return EvidenceAssessment(
        technique=technique, level=level, confidence=confidence,
        matched_required=matched_req, missing_required=missing_req,
        matched_supporting=matched_sup, matched_contradicting=matched_con,
        open_alternatives=alternatives, verification_hint=req.verification,
    )


def _is_reference_source(source: str) -> bool:
    """
    Whether a source describes the world rather than this challenge.

    Archive hits and concept cards mention every signal their topic
    involves. Grading a claim about this challenge against a document about
    a different one is how an agent talks itself into a technique it has no
    local evidence for, so reference material is kept out of the evidence
    text entirely.
    """
    try:
        from agent.tool_capabilities import capability
        cap = capability((source or "").strip())
    except Exception:
        return False
    return cap is not None and not cap.produces


def collect_evidence_text(state: Any) -> str:
    """
    Flatten an AgentState into one searchable blob.

    Hypothesis statements are excluded: they are the claims being graded,
    and letting a claim supply its own supporting text is circular. Only
    observations reach the rubric.
    """
    parts: List[str] = [str(getattr(state, "challenge_summary", "") or "")]
    for fact in getattr(state, "known_facts", None) or []:
        text = str(fact)
        match = re.match(r"\[([^\]]+)\]\s*(.*)", text)
        if match and _is_reference_source(match.group(1)):
            continue
        parts.append(text)
    for ev in getattr(state, "evidence", None) or []:
        if _is_reference_source(str(getattr(ev, "source", "") or "")):
            continue
        parts.append(str(getattr(ev, "finding", "") or getattr(ev, "content", "") or ev))
    return "\n".join(p for p in parts if p)


def assess_state(state: Any, technique: Optional[str] = None) -> EvidenceAssessment:
    """Grade the state's top hypothesis (or a named technique)."""
    text = collect_evidence_text(state)
    if technique is None:
        top = None
        try:
            top = state.top_hypothesis()
        except Exception:
            pass
        technique = (getattr(top, "technique", "") or "") if top else ""
    return assess(technique, text)


def requirements_for(technique: str) -> Optional[EvidenceRequirement]:
    return REQUIREMENTS.get((technique or "").strip().lower())


def next_evidence_to_seek(assessment: EvidenceAssessment, limit: int = 3) -> List[str]:
    """
    What the agent should go and look for next.

    Turning the gap into a concrete list is what makes the planner
    evidence-driven rather than hypothesis-driven — it stops the agent
    re-running tools that cannot change the assessment.
    """
    if assessment.level is SupportLevel.REFUTED:
        return ["abandon this hypothesis; a contradicting signal is present"]
    out = [f"confirm: {s}" for s in assessment.missing_required[:limit]]
    if len(out) < limit and assessment.open_alternatives:
        out.append(f"rule out: {assessment.open_alternatives[0]}")
    return out[:limit]
