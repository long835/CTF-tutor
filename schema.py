"""
schema.py

Defines the data structure for archive entries (past solved challenges)
and sub-problems (pieces a challenge gets decomposed into).

Technique tags are normalized against data/technique_vocab.json so two
people ingesting the same idea don't invent two spellings of one tag.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Set
import json
import os
import re


TAG_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

_VOCAB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "technique_vocab.json")
_VOCAB_FLAT: Optional[Set[str]] = None
_VOCAB_MTIME: Optional[float] = None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            delete = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, delete, sub))
        prev = curr
    return prev[-1]


def load_technique_vocab(path: str = _VOCAB_PATH) -> Set[str]:
    """Flatten the per-category vocab file into a set of canonical tags."""
    global _VOCAB_FLAT, _VOCAB_MTIME
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return _VOCAB_FLAT or set()
    if _VOCAB_FLAT is not None and _VOCAB_MTIME == mtime:
        return _VOCAB_FLAT
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    tags: Set[str] = set()
    if isinstance(data, dict):
        for group in data.values():
            tags.update(str(t) for t in group)
    elif isinstance(data, list):
        tags.update(str(t) for t in data)
    _VOCAB_FLAT = tags
    _VOCAB_MTIME = mtime
    return tags


def _shape_tag(tag: str) -> str:
    tag = tag.strip().lower()
    tag = re.sub(r"[\s_]+", "-", tag)
    tag = re.sub(r"[^a-z0-9\-]", "", tag)
    tag = re.sub(r"-+", "-", tag).strip("-")
    return tag


def normalize_tag(tag: str, vocab: Optional[Set[str]] = None) -> str:
    """Force a technique tag into the lowercase-hyphenated convention, then
    fuzzy-match it against the controlled vocabulary when a close canonical
    spelling already exists (Levenshtein distance <= 2, or 25% of length)."""
    shaped = _shape_tag(tag)
    if not shaped:
        return ""
    if not TAG_PATTERN.match(shaped):
        raise ValueError(f"technique tag {tag!r} normalized to {shaped!r}, which is not a valid tag")
    known = vocab if vocab is not None else load_technique_vocab()
    if not known or shaped in known:
        return shaped
    best = min(known, key=lambda v: _levenshtein(shaped, v))
    dist = _levenshtein(shaped, best)
    threshold = 2 if len(shaped) <= 8 else max(2, len(shaped) // 4)
    if dist <= threshold:
        return best
    return shaped


@dataclass
class SubProblem:
    """One piece of a decomposed challenge."""
    id: str
    description: str
    likely_techniques: List[str] = field(default_factory=list)
    evidence: str = ""

    def __post_init__(self):
        cleaned = []
        for t in self.likely_techniques:
            if not str(t).strip():
                continue
            try:
                cleaned.append(normalize_tag(t))
            except ValueError:
                continue
        self.likely_techniques = cleaned

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ArchiveEntry:
    """One past solved challenge, stored for future retrieval."""
    challenge_name: str
    category: str
    techniques: List[str]
    difficulty: Optional[str] = None
    source: Optional[str] = None
    description: str = ""
    explanation: str = ""
    solve_steps: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    notes: Optional[str] = None

    def __post_init__(self):
        cleaned = []
        for t in self.techniques:
            if not str(t).strip():
                continue
            try:
                cleaned.append(normalize_tag(t))
            except ValueError:
                continue
        self.techniques = cleaned

    def to_dict(self) -> dict:
        return asdict(self)

    def to_embedding_text(self) -> str:
        parts = [
            f"Challenge: {self.challenge_name} ({self.category})",
            f"Techniques: {', '.join(self.techniques)}",
            f"Description: {self.description}",
            f"Explanation: {self.explanation}",
        ]
        if self.solve_steps:
            parts.append("Solve approach: " + " -> ".join(self.solve_steps))
        if self.tools_used:
            parts.append("Tools used: " + ", ".join(self.tools_used))
        if self.notes:
            parts.append(f"Notes: {self.notes}")
        return "\n".join(parts)

    @staticmethod
    def load(path: str) -> "ArchiveEntry":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return ArchiveEntry(**data)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    entry = ArchiveEntry(
        challenge_name="WebCTF2024 - AuthBreaker",
        category="web",
        techniques=["JWT Alg Confusion", "none algorithm bypass"],
        difficulty="medium",
        source="ExampleCTF 2024",
        description="A login portal issues JWTs signed with RS256.",
        explanation=(
            "The server accepts tokens with alg=none, so an attacker can "
            "forge an unsigned token claiming to be admin."
        ),
        solve_steps=[
            "Capture a valid JWT from a normal login",
            "Decode the header/payload, change alg to none",
            "Strip the signature, change role claim to admin",
            "Replay the forged token",
        ],
        tools_used=["jwt_tool", "burpsuite"],
        references=["https://ctf-wiki.org/crypto/jwt/"],
    )
    print(json.dumps(entry.to_dict(), indent=2))
    print("\n--- embedding text ---\n")
    print(entry.to_embedding_text())
