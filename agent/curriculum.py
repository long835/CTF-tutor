"""
agent/curriculum.py

Personalised learning paths and adaptive difficulty (Phase 4).

The pieces already existed separately: a skill graph that knows what
depends on what, a learner memory that knows what has been attempted, a
challenge graph that knows what resembles what, and a misconception engine
that knows what has been misunderstood. This module is the part that reads
all four and answers one question:

    "Given where this person actually is, what should they do next?"

Design rules
------------
1. Never schedule a technique whose prerequisites are unmet — teach the
   prerequisite instead.
2. Prefer the boundary: not what they already know, not what is three
   levels beyond them.
3. Repair before advance. A live misconception outranks new material.
4. Show the reasoning. Every lesson says why it was picked, because an
   opaque curriculum is one the learner cannot argue with.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

DIFFICULTY_ORDER = ["easy", "medium", "hard", "insane"]

# Mastery thresholds.
MASTERED = 0.75
SHAKY = 0.45

# How many attempts before we trust a mastery number at all.
MIN_ATTEMPTS_FOR_SIGNAL = 2

LESSON_KINDS = ("repair", "prerequisite", "practice", "stretch", "review")


@dataclass
class Lesson:
    """One scheduled unit of study."""

    kind: str  # one of LESSON_KINDS
    topic: str  # technique or concept id
    title: str
    rationale: str
    difficulty: str = "medium"
    concepts: List[str] = field(default_factory=list)
    challenges: List[str] = field(default_factory=list)
    hint_level: int = 2
    priority: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "topic": self.topic,
            "title": self.title,
            "rationale": self.rationale,
            "difficulty": self.difficulty,
            "concepts": list(self.concepts),
            "challenges": list(self.challenges),
            "hint_level": self.hint_level,
            "priority": round(self.priority, 3),
        }


@dataclass
class LearnerProfile:
    """A flattened, read-only view of where the learner stands."""

    mastered: Set[str] = field(default_factory=set)
    weak: Set[str] = field(default_factory=set)
    attempted: Set[str] = field(default_factory=set)
    mastery: Dict[str, float] = field(default_factory=dict)
    attempts: Dict[str, int] = field(default_factory=dict)
    misconception_concepts: List[str] = field(default_factory=list)
    level: str = "easy"
    total_sessions: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "total_sessions": self.total_sessions,
            "mastered": sorted(self.mastered),
            "weak": sorted(self.weak),
            "attempted": len(self.attempted),
            "misconception_concepts": list(self.misconception_concepts),
        }


def _difficulty_index(value: Optional[str]) -> int:
    try:
        return DIFFICULTY_ORDER.index((value or "medium").lower())
    except ValueError:
        return 1


def estimate_level(profile_mastery: Dict[str, float], attempts: Dict[str, int]) -> str:
    """
    Map raw mastery stats onto a single difficulty band.

    Deliberately slow to promote: three solid techniques move you up one
    band. A learner who is bumped to 'hard' too early just gets frustrated
    and stops, which is the one failure mode a tutor cannot recover from.
    """
    confident = [
        t
        for t, m in profile_mastery.items()
        if m >= MASTERED and attempts.get(t, 0) >= MIN_ATTEMPTS_FOR_SIGNAL
    ]
    scored = len(confident)
    if scored >= 9:
        return "insane"
    if scored >= 6:
        return "hard"
    if scored >= 3:
        return "medium"
    return "easy"


def build_profile(memory: Any = None) -> LearnerProfile:
    """Read a LearnerMemory into a profile. A missing memory is a beginner."""
    if memory is None:
        return LearnerProfile()

    mastery: Dict[str, float] = {}
    attempts: Dict[str, int] = {}
    try:
        for name, stats in (memory.techniques or {}).items():
            mastery[name] = float(stats.mastery)
            attempts[name] = int(stats.attempts)
    except Exception:
        return LearnerProfile()

    try:
        mastered = set(memory.mastered_techniques())
        weak = set(memory.weak_techniques())
    except Exception:
        mastered, weak = set(), set()

    try:
        from agent.misconception import concepts_to_review

        mis_concepts = concepts_to_review(memory)
    except Exception:
        mis_concepts = []

    return LearnerProfile(
        mastered=mastered,
        weak=weak,
        attempted=set(mastery),
        mastery=mastery,
        attempts=attempts,
        misconception_concepts=mis_concepts,
        level=estimate_level(mastery, attempts),
        total_sessions=int(getattr(memory, "total_sessions", 0) or 0),
    )


def next_difficulty(profile: LearnerProfile, last_success: Optional[bool] = None) -> str:
    """
    Pick the difficulty for the next challenge.

    A single success nudges up, a single failure nudges down, and the
    baseline band moves only as overall mastery moves. This is a simple
    one-step controller rather than a rating system — it is transparent,
    and at CTF-session scale a full Elo model would be fitting noise.
    """
    idx = _difficulty_index(profile.level)
    if last_success is True:
        idx = min(len(DIFFICULTY_ORDER) - 1, idx + 1)
    elif last_success is False:
        idx = max(0, idx - 1)
    return DIFFICULTY_ORDER[idx]


def recommended_hint_level(profile: LearnerProfile, technique: str = "") -> int:
    """
    Fewer hints as mastery rises. A learner who already half-knows a topic
    gets a nudge (level 2); someone meeting it cold gets scaffolding (4).
    """
    if technique:
        m = profile.mastery.get(technique.lower())
        if m is not None:
            if m >= MASTERED:
                return 1
            if m >= SHAKY:
                return 2
            return 4
    return {"easy": 3, "medium": 2, "hard": 2, "insane": 1}.get(profile.level, 2)


def _challenge_titles(technique: str, difficulty: str, limit: int = 3) -> List[str]:
    """Ask the challenge graph for concrete things to work on."""
    try:
        from agent.challenge_graph import get_graph

        graph = get_graph()
    except Exception:
        return []

    want = _difficulty_index(difficulty)
    scored: List[Tuple[int, str]] = []
    for node in graph.nodes.values():
        if technique.lower() in {str(t).lower() for t in node.techniques}:
            scored.append((abs(node.difficulty_index - want), node.name))
    scored.sort(key=lambda pair: (pair[0], pair[1]))
    seen: Set[str] = set()
    out: List[str] = []
    for _, name in scored:
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
        if len(out) >= limit:
            break
    return out


def _candidate_techniques() -> List[str]:
    """Every technique the system can actually teach something about."""
    techniques: Set[str] = set()
    try:
        from agent.skill_graph import PREREQUISITES

        techniques |= set(PREREQUISITES)
    except Exception:
        pass
    try:
        from agent.challenge_graph import get_graph

        for node in get_graph().nodes.values():
            techniques |= {str(t).lower() for t in node.techniques}
    except Exception:
        pass
    # Resolve through the taxonomy before offering anything. Without this the
    # plan could schedule "android" and "android-basics" as two separate
    # lessons, and could offer a concept ("stack-layout") as though it were a
    # technique the learner could go and solve.
    try:
        from agent import taxonomy

        resolved = {taxonomy.canonical(t) for t in techniques if t}
        techniques = {t for t in resolved if t and not taxonomy.is_concept(t)}
    except Exception:
        pass
    return sorted(t for t in techniques if t)


def _readiness(technique: str, profile: LearnerProfile) -> Tuple[bool, List[str]]:
    """Is this technique reachable now? If not, what is missing?"""
    try:
        from agent.skill_graph import missing_prerequisites

        missing = missing_prerequisites(technique, profile.mastered)
    except Exception:
        missing = []
    # Concepts (leaf explanations) are readable inline; unmet *technique*
    # prerequisites are the real blockers.
    try:
        from agent.skill_graph import PREREQUISITES

        blocking = [m for m in missing if m in PREREQUISITES]
    except Exception:
        blocking = list(missing)
    return (not blocking), missing


def build_curriculum(
    memory: Any = None,
    goal: Optional[str] = None,
    length: int = 5,
    last_success: Optional[bool] = None,
    record: Any = None,
) -> Dict[str, Any]:
    """
    Produce an ordered plan.

    `goal` optionally pins the curriculum to a target technique, in which
    case the path walks its unmet prerequisites first.

    `record` is an optional `learner_model.LearnerRecord`. Where it exists it
    outranks raw mastery, because mastery counts successes and the record
    knows whether the learner was handed the answer. A technique solved three
    times at hint level 4 has high mastery and no independence; scheduling it
    as "known" is the mistake item 14 is about.
    """
    profile = build_profile(memory)
    target_difficulty = next_difficulty(profile, last_success)
    lessons: List[Lesson] = []

    # 0. Independence repair — a technique that only ever succeeds with deep
    #    hints is not learned, whatever the success count says.
    if record is not None:
        try:
            from agent.learner_model import transfer_check

            for technique in list(record.hint_dependent_techniques())[:2]:
                check = transfer_check(technique, record)
                lessons.append(Lesson(
                    kind="repair",
                    topic=technique,
                    title=f"Solve unaided: {technique}",
                    rationale=(
                        "Solved before, but only after deep hints — retry a different "
                        "framing with less scaffolding."
                    ),
                    difficulty="easy",
                    concepts=[technique],
                    challenges=[check["next_variation"]] if check.get("next_variation") else [],
                    hint_level=1,
                    priority=1.0,
                ))
            # A technique solved unaided once is retested on a new framing
            # before it counts as transferred (item 15).
            for technique in record.techniques():
                if len(lessons) >= length:
                    break
                check = transfer_check(technique, record)
                if check["verdict"] != "retest" or not check.get("next_variation"):
                    continue
                lessons.append(Lesson(
                    kind="practice",
                    topic=technique,
                    title=f"Variation: {technique}",
                    rationale=(
                        "Solved unaided once. A second, differently-framed challenge is "
                        "what separates knowing the technique from remembering the puzzle."
                    ),
                    difficulty=target_difficulty,
                    concepts=[technique],
                    challenges=[check["next_variation"]],
                    hint_level=1,
                    priority=0.95,
                ))
        except Exception:
            # The record is an optional input; a malformed one must not cost
            # the learner their plan.
            pass

    # 1. Repair — recorded misconceptions come first, always.
    for concept in profile.misconception_concepts[:2]:
        try:
            from agent.skill_graph import explain_concept

            blurb = explain_concept(concept)
        except Exception:
            blurb = ""
        lessons.append(
            Lesson(
                kind="repair",
                topic=concept,
                title=f"Re-ground: {concept}",
                rationale="A recent session showed a misunderstanding that touches this concept.",
                difficulty="easy",
                concepts=[concept],
                hint_level=4,
                priority=1.0,
            )
        )

    # 2. Goal-directed path, if one was given.
    if goal:
        goal = goal.strip().lower()
        ready, missing = _readiness(goal, profile)
        for prereq in missing[:3]:
            lessons.append(
                Lesson(
                    kind="prerequisite",
                    topic=prereq,
                    title=f"Prerequisite for {goal}: {prereq}",
                    rationale=f"{goal} builds directly on {prereq}, which is not solid yet.",
                    difficulty="easy" if not ready else target_difficulty,
                    concepts=[prereq],
                    challenges=_challenge_titles(prereq, "easy"),
                    hint_level=recommended_hint_level(profile, prereq),
                    priority=0.9,
                )
            )
        lessons.append(
            Lesson(
                kind="practice" if ready else "stretch",
                topic=goal,
                title=f"Target: {goal}",
                rationale=(
                    "Prerequisites look covered — go straight at it."
                    if ready
                    else "Attempt after the prerequisites above; expect to need hints."
                ),
                difficulty=target_difficulty,
                concepts=[goal],
                challenges=_challenge_titles(goal, target_difficulty),
                hint_level=recommended_hint_level(profile, goal),
                priority=0.85,
            )
        )

    # 3. Shore up weak techniques the learner has already met.
    for technique in sorted(profile.weak, key=lambda t: profile.mastery.get(t, 0.0))[:2]:
        lessons.append(
            Lesson(
                kind="review",
                topic=technique,
                title=f"Second pass: {technique}",
                rationale=(
                    f"Attempted {profile.attempts.get(technique, 0)}x with mastery "
                    f"{profile.mastery.get(technique, 0):.2f} — close, not solid."
                ),
                difficulty=DIFFICULTY_ORDER[max(0, _difficulty_index(target_difficulty) - 1)],
                concepts=[technique],
                challenges=_challenge_titles(technique, target_difficulty),
                hint_level=recommended_hint_level(profile, technique),
                priority=0.75,
            )
        )

    # 4. New material at the frontier: ready, unattempted, right difficulty.
    if len(lessons) < length:
        for technique in _candidate_techniques():
            if len(lessons) >= length + 2:
                break
            if technique in profile.attempted or technique in profile.mastered:
                continue
            if any(l.topic == technique for l in lessons):
                continue
            ready, missing = _readiness(technique, profile)
            candidates = _challenge_titles(technique, target_difficulty, limit=2)
            if not candidates:
                continue
            lessons.append(
                Lesson(
                    kind="practice" if ready else "prerequisite",
                    topic=technique,
                    title=f"New: {technique}",
                    rationale=(
                        "Unseen, prerequisites met, and sits at your current level."
                        if ready
                        else f"Unseen; review {', '.join(missing[:2])} alongside it."
                    ),
                    difficulty=target_difficulty,
                    concepts=[technique] + missing[:2],
                    challenges=candidates,
                    hint_level=recommended_hint_level(profile, technique),
                    priority=0.6 if ready else 0.45,
                )
            )

    # 5. One stretch goal, so the plan has a horizon.
    if profile.mastered and len(lessons) < length + 1:
        harder = DIFFICULTY_ORDER[min(len(DIFFICULTY_ORDER) - 1, _difficulty_index(target_difficulty) + 1)]
        for technique in _candidate_techniques():
            if technique in profile.attempted or any(l.topic == technique for l in lessons):
                continue
            challenges = _challenge_titles(technique, harder, limit=1)
            if not challenges:
                continue
            lessons.append(
                Lesson(
                    kind="stretch",
                    topic=technique,
                    title=f"Stretch: {technique}",
                    rationale="Deliberately above your current band — attempt it with hints available.",
                    difficulty=harder,
                    concepts=[technique],
                    challenges=challenges,
                    hint_level=4,
                    priority=0.3,
                )
            )
            break

    lessons.sort(key=lambda l: -l.priority)
    lessons = lessons[:length]

    return {
        "profile": profile.to_dict(),
        "target_difficulty": target_difficulty,
        "lessons": [l.to_dict() for l in lessons],
        "generated_from": {
            "techniques_known": len(profile.attempted),
            "misconceptions_open": len(profile.misconception_concepts),
            "goal": goal or None,
        },
    }


def render_curriculum(plan: Dict[str, Any]) -> str:
    """Terminal-friendly rendering of a curriculum dict."""
    profile = plan.get("profile", {})
    lines = [
        "# Your next steps",
        "",
        f"Level: **{profile.get('level', 'easy')}** · "
        f"sessions: {profile.get('total_sessions', 0)} · "
        f"techniques touched: {profile.get('attempted', 0)} · "
        f"next challenges at: **{plan.get('target_difficulty', 'easy')}**",
    ]

    mastered = profile.get("mastered") or []
    if mastered:
        lines.append(f"Solid: {', '.join(mastered[:8])}")
    weak = profile.get("weak") or []
    if weak:
        lines.append(f"Shaky: {', '.join(weak[:8])}")

    lessons = plan.get("lessons") or []
    if not lessons:
        lines += ["", "Not enough history yet — run a few challenges and check back."]
        return "\n".join(lines)

    lines.append("")
    icons = {
        "repair": "!",
        "prerequisite": "^",
        "practice": ">",
        "stretch": "*",
        "review": "~",
    }
    for i, lesson in enumerate(lessons, 1):
        icon = icons.get(lesson.get("kind", ""), "-")
        lines.append(f"## {i}. [{icon}] {lesson.get('title')}")
        lines.append(f"{lesson.get('rationale')}")
        meta = [
            f"difficulty: {lesson.get('difficulty')}",
            f"suggested hint level: {lesson.get('hint_level')}",
        ]
        lines.append("_" + " · ".join(meta) + "_")
        challenges = lesson.get("challenges") or []
        if challenges:
            lines.append("")
            for c in challenges:
                lines.append(f"- {c}")
        concepts = lesson.get("concepts") or []
        if concepts:
            lines.append(f"Concepts: {', '.join(concepts[:4])}")
        lines.append("")

    lines.append("Legend: `!` repair · `^` prerequisite · `>` practice · `~` review · `*` stretch")
    return "\n".join(lines).rstrip()


if __name__ == "__main__":
    from agent.memory import load_memory

    print(render_curriculum(build_curriculum(load_memory())))
