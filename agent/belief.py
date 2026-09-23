"""
agent/belief.py

Evidence moves belief by a stated amount (item 4).

`hypothesis.py` already keeps several hypotheses and nudges their confidence
by deltas, but the deltas come from whatever the model felt like emitting,
clamped to ±0.35. Three things go wrong with that:

*   **Direction is unprincipled.** The same observation can be nudged up for
    every live hypothesis, because nothing consults what each hypothesis
    actually predicts.
*   **Repetition accumulates.** Re-running a tool re-delivers the same
    observation and the confidence climbs again, so tunnel vision is
    rewarded by the arithmetic.
*   **Additive steps distort near the ends.** +0.1 from 0.85 is a much
    bigger claim than +0.1 from 0.35, and treating them alike is how a
    hypothesis reaches 0.95 on four weak signals.

So updates happen in log-odds, with a likelihood ratio per matched signal
drawn from each hypothesis's own rubric in `agent.evidence`. A signal that a
technique *requires* is strong support for it; a signal that technique lists
as *contradicting* is strong evidence against it — and because each
hypothesis is graded against its own rubric, one observation legitimately
raises H1 while lowering H2, which is the behaviour the review asked for.

Every update is fingerprinted, so the second delivery of the same signal
from the same source changes nothing at all.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from agent.evidence import REQUIREMENTS, SupportLevel, _matches, requirements_for


# Likelihood ratios: P(observation | hypothesis) / P(observation | not
# hypothesis). Deliberately modest — a single signal should shift belief,
# not settle it. REQUIRED_HIT at 3.2 means roughly "three such signals take
# a 0.3 prior to about 0.9", which matches how a careful human reasons.
LR_REQUIRED_HIT = 3.2
LR_SUPPORTING_HIT = 1.6
LR_CONTRADICTED = 0.06        # a positive observation that the claim is wrong
LR_REQUIRED_ABSENT = 0.75     # searched for and not found, having looked
LR_KEYWORD_HIT = 1.25         # no rubric: weak topical agreement only
LR_NEGATIVE_LANGUAGE = 0.85

# Cap on how much one observation may move a hypothesis (in log space).
# e^1.6 ≈ 5×, so no single tool result can carry a hypothesis from doubt to
# certainty however many signals it happens to mention.
MAX_LOG_SHIFT = 1.6

P_FLOOR, P_CEILING = 0.02, 0.97

# Techniques that cannot both be the answer to the same finding. Used only
# to damp rivals once one claim is genuinely supported — never to invent
# support for the winner.
EXCLUSION_GROUPS: List[Set[str]] = [
    {"jwt-none-bypass", "jwt-alg-confusion", "jwt-weak-secret"},
    {"stack-buffer-overflow", "heap-overflow", "format-string"},
    {"ret2libc", "ret2win", "shellcode-injection"},
    {"xor-single-byte", "xor-repeating-key", "aes-ecb-oracle"},
    {"sql-injection", "nosql-injection"},
    {"ssti", "xss-reflected"},
]


def _p_to_log_odds(p: float) -> float:
    p = min(max(float(p), P_FLOOR), P_CEILING)
    return math.log(p / (1.0 - p))


def _log_odds_to_p(log_odds: float) -> float:
    p = 1.0 / (1.0 + math.exp(-log_odds))
    return min(max(p, P_FLOOR), P_CEILING)


def _fingerprint(hypothesis_id: str, signal: str, source: str) -> str:
    raw = f"{hypothesis_id}|{signal}|{source}".lower()
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


@dataclass
class SignalHit:
    """One matched signal and the ratio it contributes."""

    signal: str
    role: str          # required | supporting | contradicting | keyword | absence
    ratio: float
    fingerprint: str = ""

    @property
    def log_ratio(self) -> float:
        return math.log(max(self.ratio, 1e-6))

    def to_dict(self) -> Dict[str, Any]:
        return {"signal": self.signal, "role": self.role,
                "ratio": round(self.ratio, 3), "fingerprint": self.fingerprint}


@dataclass
class BeliefUpdate:
    """The audit record for one hypothesis against one observation."""

    hypothesis_id: str
    technique: str
    prior: float
    posterior: float
    hits: List[SignalHit] = field(default_factory=list)
    source: str = ""
    had_rubric: bool = True
    note: str = ""

    @property
    def delta(self) -> float:
        return self.posterior - self.prior

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "technique": self.technique,
            "prior": round(self.prior, 3),
            "posterior": round(self.posterior, 3),
            "delta": round(self.delta, 3),
            "hits": [h.to_dict() for h in self.hits],
            "source": self.source,
            "had_rubric": self.had_rubric,
            "note": self.note,
        }

    def explain(self) -> str:
        arrow = "▲" if self.delta > 0.001 else ("▼" if self.delta < -0.001 else "=")
        head = (f"{arrow} {self.hypothesis_id} ({self.technique or 'no technique'}): "
                f"{self.prior:.2f} → {self.posterior:.2f}")
        if not self.hits:
            return head + f"  — {self.note or 'observation bears on nothing this predicts'}"
        detail = "; ".join(f"{h.role}:{h.signal[:40]}" for h in self.hits[:4])
        return head + f"  [{detail}]"


def _seen_fingerprints(state: Any) -> Set[str]:
    out: Set[str] = set()
    for entry in getattr(state, "belief_updates", None) or []:
        for hit in entry.get("hits") or []:
            fp = hit.get("fingerprint")
            if fp:
                out.add(fp)
    return out


def _keywords(text: str) -> Set[str]:
    return {w for w in (text or "").lower().replace("-", " ").split() if len(w) > 3}


def score_observation(
    hypothesis: Any,
    observation: str,
    source: str = "tool",
    seen: Optional[Set[str]] = None,
) -> Tuple[List[SignalHit], bool]:
    """
    Which of this hypothesis's predicted signals the observation contains.

    Returns the hits and whether a rubric existed. Signals already counted
    from the same source are dropped here, which is what makes a repeated
    tool run inert rather than self-reinforcing.
    """
    seen = seen or set()
    hid = str(getattr(hypothesis, "id", "") or "")
    technique = str(getattr(hypothesis, "technique", "") or "").strip().lower()
    text = (observation or "").lower()
    req = requirements_for(technique)
    hits: List[SignalHit] = []

    def _push(signal: str, role: str, ratio: float) -> None:
        fp = _fingerprint(hid, signal, source)
        if fp in seen:
            return
        seen.add(fp)
        hits.append(SignalHit(signal=signal, role=role, ratio=ratio, fingerprint=fp))

    if req is None:
        # No rubric: fall back to topical overlap, and say so. Weak ratios
        # keep an unrubriced hypothesis from drifting upward on vibes.
        overlap = _keywords(getattr(hypothesis, "statement", "")) & _keywords(text)
        overlap |= _keywords(technique) & _keywords(text)
        for word in sorted(overlap)[:3]:
            _push(word, "keyword", LR_KEYWORD_HIT)
        if any(phrase in text for phrase in
               ("not present", "no evidence", "none found", "not found", "nothing found")):
            _push("negative language", "absence", LR_NEGATIVE_LANGUAGE)
        return hits, False

    for signal in req.contradicting:
        if _matches(signal, text):
            _push(signal, "contradicting", LR_CONTRADICTED)
    for signal in req.required:
        if _matches(signal, text):
            _push(signal, "required", LR_REQUIRED_HIT)
    for signal in req.supporting:
        if _matches(signal, text):
            _push(signal, "supporting", LR_SUPPORTING_HIT)

    # "Ran cleanly and found nothing" is a real, if weak, argument against a
    # technique whose required signals that tool would have surfaced.
    if any(phrase in text for phrase in ("nothing found", "found nothing", "no findings")):
        _push("clean scan", "absence", LR_REQUIRED_ABSENT)
    return hits, True


def update_beliefs(
    state: Any,
    observation: str,
    source: str = "tool",
    record: bool = True,
) -> List[BeliefUpdate]:
    """
    Apply one observation to every active hypothesis.

    Each hypothesis is graded against its own rubric, so a single tool
    result can raise one claim and lower another. The result is written back
    through `Hypothesis.update_confidence`, so the rest of the codebase sees
    ordinary confidences and nothing else needs to know this module exists.
    """
    if not (observation or "").strip():
        return []
    hypotheses = list(getattr(state, "hypotheses", None) or [])
    if not hypotheses:
        return []

    seen = _seen_fingerprints(state)
    updates: List[BeliefUpdate] = []

    for h in hypotheses:
        if getattr(h, "status", "active") not in ("active", "confirmed"):
            continue
        hits, had_rubric = score_observation(h, observation, source=source, seen=seen)
        prior = float(getattr(h, "confidence", 0.5))
        if not hits:
            updates.append(BeliefUpdate(
                hypothesis_id=str(getattr(h, "id", "")),
                technique=str(getattr(h, "technique", "") or ""),
                prior=prior, posterior=prior, source=source, had_rubric=had_rubric,
                note="no predicted signal present" if had_rubric else "no rubric and no overlap",
            ))
            continue

        shift = sum(hit.log_ratio for hit in hits)
        shift = max(-MAX_LOG_SHIFT, min(MAX_LOG_SHIFT, shift))
        posterior = _log_odds_to_p(_p_to_log_odds(prior) + shift)

        reason_bits = ", ".join(f"{hit.role}: {hit.signal[:48]}" for hit in hits[:3])
        h.update_confidence(
            posterior - prior,
            reason=f"[{source}] {reason_bits}" if reason_bits else f"[{source}] evidence",
        )
        # A contradicting observation is a positive finding that the claim is
        # wrong, so it retires the hypothesis rather than merely discounting it.
        if any(hit.role == "contradicting" for hit in hits):
            h.status = "rejected"
            contradiction = f"{h.id} refuted by {source}: " + ", ".join(
                hit.signal[:40] for hit in hits if hit.role == "contradicting"
            )
            contradictions = getattr(state, "contradictions", None)
            if isinstance(contradictions, list) and contradiction not in contradictions:
                contradictions.append(contradiction)

        updates.append(BeliefUpdate(
            hypothesis_id=str(getattr(h, "id", "")),
            technique=str(getattr(h, "technique", "") or ""),
            prior=prior, posterior=posterior, hits=hits,
            source=source, had_rubric=had_rubric,
        ))

    if record:
        log = getattr(state, "belief_updates", None)
        if isinstance(log, list):
            for upd in updates:
                if upd.hits:
                    log.append(upd.to_dict())
            del log[:-200]  # bounded audit trail

    apply_competition(state)
    try:
        state.recompute_overall_confidence()
    except Exception:
        pass
    return updates


def are_exclusive(technique_a: str, technique_b: str) -> bool:
    """Whether two techniques cannot both explain the same finding."""
    a = (technique_a or "").strip().lower()
    b = (technique_b or "").strip().lower()
    if not a or not b or a == b:
        return False
    return any(a in group and b in group for group in EXCLUSION_GROUPS)


def apply_competition(state: Any, damping: float = 0.55) -> List[str]:
    """
    Damp rivals of a well-supported claim.

    Only mutually exclusive techniques are touched, and only once one of
    them is genuinely supported — a CTF challenge can perfectly well contain
    both an SSRF and a weak JWT secret, and treating every pair as rivals
    would suppress real chains.
    """
    hypotheses = [h for h in (getattr(state, "hypotheses", None) or [])
                  if getattr(h, "status", "active") == "active"]
    if len(hypotheses) < 2:
        return []
    leaders = [h for h in hypotheses if float(getattr(h, "confidence", 0)) >= 0.7]
    notes: List[str] = []
    for leader in leaders:
        for other in hypotheses:
            if other is leader:
                continue
            if not are_exclusive(getattr(leader, "technique", ""), getattr(other, "technique", "")):
                continue
            prior = float(getattr(other, "confidence", 0.5))
            if prior <= 0.15:
                continue
            posterior = _log_odds_to_p(_p_to_log_odds(prior) + math.log(damping))
            other.update_confidence(
                posterior - prior,
                reason=f"mutually exclusive with better-supported {leader.id}",
            )
            notes.append(f"{other.id} damped by {leader.id}")
    return notes


def rank_by_belief(state: Any) -> List[Any]:
    """Active hypotheses, strongest first."""
    active = [h for h in (getattr(state, "hypotheses", None) or [])
              if getattr(h, "status", "active") == "active"]
    return sorted(active, key=lambda h: -float(getattr(h, "confidence", 0)))


def belief_spread(state: Any) -> float:
    """
    Gap between the best and second-best hypothesis.

    A spread near zero after several steps means the evidence collected so
    far does not discriminate — which is a signal to change tactic rather
    than to keep testing the nominal leader.
    """
    ranked = rank_by_belief(state)
    if len(ranked) < 2:
        return 1.0 if ranked else 0.0
    return float(ranked[0].confidence) - float(ranked[1].confidence)


def explain_beliefs(state: Any, limit: int = 6) -> str:
    """Readable belief table for traces, teaching, and prompts."""
    ranked = rank_by_belief(state)
    if not ranked:
        return "No active hypotheses."
    lines = ["Belief state (posterior after evidence):"]
    for h in ranked[:limit]:
        tech = getattr(h, "technique", "") or "—"
        lines.append(f"  [{float(h.confidence):.2f}] {h.id} {tech}: {getattr(h, 'statement', '')[:90]}")
    rejected = [h for h in (getattr(state, "hypotheses", None) or [])
                if getattr(h, "status", "") == "rejected"]
    for h in rejected[:3]:
        lines.append(f"  [rejected] {h.id} {getattr(h, 'technique', '') or '—'}")
    spread = belief_spread(state)
    lines.append(f"  discrimination: {spread:.2f}"
                 + ("  (evidence does not yet separate the leaders)" if spread < 0.1 else ""))
    return "\n".join(lines)
