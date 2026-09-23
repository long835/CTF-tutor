"""
agent/difficulty.py

Difficulty as a measurement, not a label (item 65).

Static labels are unreliable in two directions. Authors label by how hard
the challenge was to build, players label by whether they happened to know
the trick, and the same "medium" covers a five-minute base64 peel and a
two-hour heap grind. For a tutor this matters more than for a scoreboard:
the next challenge to recommend depends on how hard this one *actually*
was for this learner.

Six factors, each derived from something observable:

    techniques      how many distinct techniques were involved
    depth           prerequisite depth in the skill graph
    tool complexity how specialised the tooling had to be
    ambiguity       how many plausible hypotheses stayed live
    steps           how many actions the investigation took
    evidence        how much had to be established before concluding

The estimate is reported with the factors that produced it, because a
number nobody can argue with is a number nobody can fix. A stated label is
kept alongside rather than overwritten: disagreement between the two is
information, and often says the learner found an unintended path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

BANDS = [
    (0.0, "trivial"),
    (0.20, "easy"),
    (0.40, "medium"),
    (0.62, "hard"),
    (0.82, "expert"),
]

LABEL_TO_SCORE = {
    "trivial": 0.1, "very easy": 0.1, "beginner": 0.15,
    "easy": 0.3, "medium": 0.5, "intermediate": 0.5,
    "hard": 0.7, "difficult": 0.7, "advanced": 0.75,
    "expert": 0.9, "insane": 0.95,
}

# Tools whose use implies a harder problem. Reading base64 is not the same
# work as driving a debugger.
TOOL_WEIGHT = {
    "decode_toolkit": 0.1, "auto_decode": 0.1, "classify": 0.0, "decompose": 0.1,
    "retrieve_archive": 0.1, "research": 0.15, "ask_user": 0.0,
    "crypto_toolkit": 0.35, "forensics_toolkit": 0.35, "web_recon": 0.35,
    "xor_crack": 0.45, "static_analysis": 0.55, "verify_candidate": 0.2,
    "gdb_inspect": 0.85, "ghidra": 0.9, "dotnet_decompile": 0.8,
}


def band_for(score: float) -> str:
    """Name the band a score falls in."""
    label = BANDS[0][1]
    for threshold, name in BANDS:
        if score >= threshold:
            label = name
    return label


@dataclass
class DifficultyEstimate:
    """A score in [0, 1] with the factors behind it."""

    score: float = 0.0
    band: str = "unknown"
    factors: Dict[str, float] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    stated: str = ""

    @property
    def disagrees_with_label(self) -> bool:
        """
        Whether the measurement contradicts the stated label by a band or more.

        Worth surfacing: it usually means either the label is wrong or the
        learner took a route the author did not anticipate.
        """
        if not self.stated:
            return False
        stated_score = LABEL_TO_SCORE.get(self.stated.strip().lower())
        if stated_score is None:
            return False
        return abs(stated_score - self.score) >= 0.2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 3),
            "band": self.band,
            "stated": self.stated,
            "disagrees_with_label": self.disagrees_with_label,
            "factors": {k: round(v, 3) for k, v in self.factors.items()},
            "notes": list(self.notes),
        }

    def render(self) -> str:
        lines = [f"Difficulty: {self.band} ({self.score:.2f})"
                 + (f" — stated: {self.stated}" if self.stated else "")]
        for name, value in sorted(self.factors.items(), key=lambda kv: -kv[1]):
            bar = "▪" * int(round(value * 10))
            lines.append(f"  {name:16s} {value:.2f} {bar}")
        for note in self.notes:
            lines.append(f"  · {note}")
        if self.disagrees_with_label:
            lines.append("  ! measured difficulty disagrees with the stated label")
        return "\n".join(lines)


def _prerequisite_depth(techniques: Iterable[str]) -> float:
    """
    Deepest prerequisite chain among the techniques involved.

    Uses the existing skill graph, so difficulty and the curriculum agree
    about what depends on what instead of each keeping its own opinion.
    """
    try:
        from agent.skill_graph import prerequisites_for
    except Exception:
        return 0.0

    def depth(technique: str, seen: Optional[set] = None) -> int:
        seen = seen or set()
        if technique in seen:
            return 0
        seen.add(technique)
        try:
            parents = list(prerequisites_for(technique) or [])
        except Exception:
            parents = []
        if not parents:
            return 0
        return 1 + max(depth(p, seen) for p in parents)

    depths = [depth(t) for t in techniques if t]
    return float(max(depths)) if depths else 0.0


def estimate(state: Any, stated: str = "") -> DifficultyEstimate:
    """
    Measure how hard this investigation actually was.

    Normalisation constants are chosen against this project's own step
    budget (12) and technique library rather than against a public
    benchmark, so the scale is internally consistent and should not be
    compared across forks without recalibration.
    """
    techniques = sorted({
        str(getattr(h, "technique", "") or "").lower()
        for h in (getattr(state, "hypotheses", None) or [])
        if getattr(h, "technique", "")
    })
    actions = list(getattr(state, "actions", None) or [])
    evidence = list(getattr(state, "evidence", None) or [])
    live = [h for h in (getattr(state, "hypotheses", None) or [])
            if str(getattr(h, "status", "active")) == "active"]

    factors: Dict[str, float] = {}
    notes: List[str] = []

    factors["techniques"] = min(1.0, len(techniques) / 4.0)

    depth = _prerequisite_depth(techniques)
    factors["depth"] = min(1.0, depth / 3.0)
    if depth >= 2:
        notes.append(f"prerequisite chain {int(depth)} deep")

    if actions:
        weights = [TOOL_WEIGHT.get(str(getattr(a, "tool", "")), 0.3) for a in actions]
        factors["tool_complexity"] = max(weights)
        heaviest = max(actions, key=lambda a: TOOL_WEIGHT.get(str(getattr(a, "tool", "")), 0.3))
        notes.append(f"heaviest tool: {getattr(heaviest, 'tool', '?')}")
    else:
        factors["tool_complexity"] = 0.0

    # Ambiguity: hypotheses that stayed plausible. Several unresolved
    # candidates is the clearest sign a challenge was hard to read, which a
    # count of solved steps would miss entirely.
    if live:
        close = [h for h in live if float(getattr(h, "confidence", 0)) >= 0.3]
        factors["ambiguity"] = min(1.0, max(0, len(close) - 1) / 3.0)
        if len(close) > 2:
            notes.append(f"{len(close)} hypotheses stayed plausible")
    else:
        factors["ambiguity"] = 0.0

    budget = max(1, int(getattr(state, "max_steps", 12) or 12))
    factors["steps"] = min(1.0, len(actions) / budget)
    factors["evidence"] = min(1.0, len(evidence) / 8.0)

    # Weighted because the factors are not equally informative: what the
    # problem required outranks how long the agent happened to take.
    weights = {
        "techniques": 0.20, "depth": 0.25, "tool_complexity": 0.20,
        "ambiguity": 0.15, "steps": 0.10, "evidence": 0.10,
    }
    score = sum(factors.get(k, 0.0) * w for k, w in weights.items())

    if str(getattr(state, "status", "")) == "stuck":
        score = min(1.0, score + 0.1)
        notes.append("investigation stalled — floor raised")

    return DifficultyEstimate(
        score=round(min(1.0, max(0.0, score)), 3),
        band=band_for(score),
        factors=factors,
        notes=notes,
        stated=stated or str(getattr(state, "difficulty", "") or ""),
    )


def estimate_from_spec(
    techniques: Sequence[str],
    tools: Sequence[str] = (),
    steps: int = 0,
    stated: str = "",
) -> DifficultyEstimate:
    """
    Estimate before a run, from a challenge description alone.

    Used when recommending what to attempt next, where there is no
    investigation to measure yet.
    """
    factors = {
        "techniques": min(1.0, len(techniques) / 4.0),
        "depth": min(1.0, _prerequisite_depth(techniques) / 3.0),
        "tool_complexity": max([TOOL_WEIGHT.get(t, 0.3) for t in tools], default=0.0),
        "ambiguity": 0.0,
        "steps": min(1.0, steps / 12.0) if steps else 0.0,
        "evidence": 0.0,
    }
    weights = {"techniques": 0.30, "depth": 0.35, "tool_complexity": 0.25, "steps": 0.10}
    score = sum(factors.get(k, 0.0) * w for k, w in weights.items())
    return DifficultyEstimate(
        score=round(score, 3), band=band_for(score), factors=factors,
        stated=stated, notes=["estimated from specification, not from a run"],
    )
