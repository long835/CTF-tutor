"""
agent/misconception.py

Misconception detection and remediation (Phase 4).

Bad CTF advice usually comes from a small number of confidently-held wrong
beliefs — "base64 is encryption", "ASLR stops buffer overflows", "the flag
is hidden in the image so I need a stego tool". A tutor that only answers
the asked question will never correct those, because the learner does not
know to ask.

This module keeps a catalogue of those beliefs. Each card carries a
detector, a plain correction, a Socratic probe that makes the learner test
the belief themselves, and the concepts worth reviewing afterwards.

Detection is deliberately conservative: it takes a `confidence` score and
only fires above a threshold, because a tutor that "corrects" things the
learner never said is worse than one that stays quiet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Confidence floor for surfacing a correction unprompted.
DEFAULT_THRESHOLD = 0.55


@dataclass
class Misconception:
    """One wrong-but-common belief, plus how to notice and unpick it."""

    id: str
    category: str
    summary: str
    correction: str
    probe: str
    review_concepts: List[str] = field(default_factory=list)
    # A match needs at least one trigger AND one context term nearby.
    triggers: List[str] = field(default_factory=list)
    context: List[str] = field(default_factory=list)
    # Phrases that make a hit near-certain on their own.
    strong_phrases: List[str] = field(default_factory=list)
    # Phrases that mean the learner already understands — suppress the card.
    negations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "summary": self.summary,
            "correction": self.correction,
            "probe": self.probe,
            "review_concepts": list(self.review_concepts),
        }


CATALOGUE: List[Misconception] = [
    Misconception(
        id="encoding-is-encryption",
        category="crypto",
        summary="Treating an encoding as if it were encryption.",
        correction=(
            "Base64, hex and URL encoding are reversible representations with no key. "
            "Anyone can decode them. Encryption needs a key and is meant to resist someone who has the ciphertext."
        ),
        probe="If you had to explain the difference to a teammate, what does encryption have that base64 does not?",
        review_concepts=["encoding-basics"],
        triggers=["base64", "b64", "hex encode", "url encode", "rot13"],
        context=["encrypt", "encryption", "decrypt", "cipher", "key", "crack"],
        strong_phrases=[
            "base64 encryption",
            "base64 encrypted",
            "decrypt the base64",
            "rot13 encryption",
            "crack the base64",
        ],
        negations=["not encryption", "just encoding", "only encoding", "isn't encryption"],
    ),
    Misconception(
        id="hash-is-reversible",
        category="crypto",
        summary="Expecting a hash to be decrypted back to its input.",
        correction=(
            "Hashes are one-way. There is no decrypt operation. You recover an input by guessing "
            "candidates and hashing them (dictionary/brute force), or by exploiting a weakness in the construction."
        ),
        probe="If MD5 could be reversed, what would that mean for every password database in the world?",
        review_concepts=["encoding-basics"],
        triggers=["md5", "sha1", "sha256", "hash", "bcrypt"],
        context=["decrypt", "reverse", "unhash", "decode"],
        strong_phrases=["decrypt the hash", "decrypt md5", "reverse the sha", "unhash"],
        negations=["one-way", "one way function", "cannot be reversed", "can't be reversed"],
    ),
    Misconception(
        id="jwt-is-encrypted",
        category="web",
        summary="Assuming a JWT payload is confidential.",
        correction=(
            "A standard JWT is signed, not encrypted. The payload is base64url and readable by anyone "
            "holding the token. Signing protects integrity; it does not hide anything."
        ),
        probe="Paste a JWT payload into a decoder. What did you just learn that the token's author may not have intended?",
        review_concepts=["jwt-basics", "auth-bypass"],
        triggers=["jwt", "json web token", "bearer token"],
        context=["encrypt", "encrypted", "secret", "hidden", "confidential", "decrypt"],
        strong_phrases=["jwt is encrypted", "encrypted jwt payload", "decrypt the jwt"],
        negations=["signed not encrypted", "only signed", "not encrypted"],
    ),
    Misconception(
        id="authn-vs-authz",
        category="web",
        summary="Collapsing authentication and authorization into one check.",
        correction=(
            "Authentication establishes who you are. Authorization decides what that identity may do. "
            "Most IDOR and privilege-escalation bugs are valid authentication plus missing authorization."
        ),
        probe="You are logged in as a normal user and can read /api/users/2. Which of the two checks failed?",
        review_concepts=["auth-bypass", "http-basics"],
        triggers=["authenticated", "logged in", "authentication"],
        context=["so i can access", "therefore admin", "means admin", "should be allowed", "authorized"],
        strong_phrases=[
            "authentication and authorization are the same",
            "logged in so i am authorized",
            "authenticated means authorized",
        ],
        negations=["different checks", "authz is separate", "two different"],
    ),
    Misconception(
        id="client-side-validation-is-security",
        category="web",
        summary="Trusting checks that run in the browser.",
        correction=(
            "Anything enforced only in JavaScript, a hidden field or a disabled button is a suggestion. "
            "The client is fully under the user's control; the server has to re-check every rule."
        ),
        probe="If you removed the JavaScript entirely and posted the request by hand, what would still stop you?",
        review_concepts=["http-basics", "web-input-handling"],
        triggers=["javascript check", "client side", "hidden field", "disabled button", "frontend validation"],
        context=["secure", "safe", "prevents", "protects", "validation"],
        strong_phrases=["client side validation is enough", "javascript prevents", "hidden field is safe"],
        negations=["server side too", "server re-checks", "never trust the client"],
    ),
    Misconception(
        id="aslr-prevents-overflow",
        category="pwn",
        summary="Confusing mitigations that solve different problems.",
        correction=(
            "ASLR randomises where things live; it does not stop the write itself. Stack canaries detect "
            "overwrites before return. NX stops executing injected data. They compose — none of them is 'the' fix."
        ),
        probe="Which mitigation would still be intact if you leaked one libc address? Which would not?",
        review_concepts=["aslr", "canary", "nx", "stack-layout"],
        triggers=["aslr", "canary", "nx", "dep", "pie"],
        context=["prevents overflow", "stops overflow", "same thing", "fixes the overflow", "makes it unexploitable"],
        strong_phrases=["aslr prevents buffer overflow", "canary and aslr are the same", "nx stops the overflow"],
        negations=["different mitigations", "solve different problems", "complementary"],
    ),
    Misconception(
        id="overflow-needs-shellcode",
        category="pwn",
        summary="Believing every overflow ends in injected shellcode.",
        correction=(
            "With NX on, injected bytes are not executable. Modern overflows redirect control to code that "
            "already exists — a win() function, a libc call, or a chain of gadgets."
        ),
        probe="If the stack is non-executable, what code is still guaranteed to be executable in the process?",
        review_concepts=["nx", "stack-buffer-overflow", "gadgets"],
        triggers=["shellcode", "inject code", "execute my payload"],
        context=["overflow", "buffer", "stack", "nx", "always"],
        strong_phrases=["overflow always needs shellcode", "must inject shellcode"],
        negations=["ret2libc", "rop", "code reuse", "already in the binary"],
    ),
    Misconception(
        id="stego-everywhere",
        category="forensics",
        summary="Reaching for steganography before checking the basics.",
        correction=(
            "Most image challenges hide data somewhere far more boring: metadata, appended bytes after the "
            "end-of-file marker, an extra chunk, or a second file concatenated on. Check structure before LSB tooling."
        ),
        probe="Before running a stego tool: what do `file`, a hex view of the tail, and the metadata say?",
        review_concepts=["image-formats", "file-carving"],
        triggers=["stego", "steganography", "lsb", "hidden in the image"],
        context=["must be", "has to be", "obviously", "just run", "always"],
        strong_phrases=["it must be stego", "always lsb", "definitely steganography"],
        negations=["checked metadata", "ran exiftool", "checked the trailer", "after binwalk"],
    ),
    Misconception(
        id="entropy-means-encryption",
        category="rev",
        summary="Reading high entropy as proof of encryption.",
        correction=(
            "Compressed data, packed executables and media files all look random. High entropy narrows the "
            "options — it does not identify the transform. Check headers, section names and packer signatures first."
        ),
        probe="A file scores 7.9 bits of entropy. Name three very different things it could be.",
        review_concepts=["file-formats", "packed-binary", "static-analysis"],
        triggers=["entropy", "looks random", "random bytes"],
        context=["encrypted", "encryption", "must be", "so it is"],
        strong_phrases=["high entropy means encrypted", "random so it is encrypted"],
        negations=["could be compressed", "might be packed", "or compression"],
    ),
    Misconception(
        id="obscurity-is-security",
        category="rev",
        summary="Assuming obfuscation makes a secret safe.",
        correction=(
            "A key that ships inside the binary is a key the user has. Obfuscation raises the time cost of "
            "finding it; it never changes who can eventually read it."
        ),
        probe="The check runs on the user's machine. Who ultimately controls every byte it touches?",
        review_concepts=["static-analysis", "string-decryption"],
        triggers=["obfuscated", "obfuscation", "hidden in the binary", "hardcoded"],
        context=["secure", "safe", "cannot be found", "protects", "no one can"],
        strong_phrases=["obfuscation makes it secure", "hardcoded key is safe"],
        negations=["still recoverable", "only slows", "not real security"],
    ),
    Misconception(
        id="brute-force-first",
        category="misc",
        summary="Jumping to brute force before understanding the structure.",
        correction=(
            "Brute force is the fallback, not the opening move. CTF challenges are built around one insight; "
            "if the search space looks astronomically large, you have almost certainly missed the intended shortcut."
        ),
        probe="How large is the search space you are about to attack, and what would shrink it by a factor of a thousand?",
        review_concepts=["static-analysis"],
        triggers=["brute force", "bruteforce", "try every", "all combinations"],
        context=["just", "simply", "first", "start by"],
        strong_phrases=["just brute force it", "brute force everything"],
        negations=["after analysis", "as a last resort", "narrowed it down"],
    ),
    Misconception(
        id="flag-format-is-the-flag",
        category="misc",
        summary="Treating anything shaped like flag{...} as the answer.",
        correction=(
            "Challenge authors plant decoys. A string matching the format is a candidate, not a result — "
            "confirm it came from the intended path before submitting."
        ),
        probe="Where exactly did this candidate come from, and does that path match the vulnerability you found?",
        review_concepts=[],
        triggers=["flag{", "ctf{", "found the flag"],
        context=["in strings", "just grep", "must be it", "done"],
        strong_phrases=["strings gave me the flag", "grepped the flag"],
        negations=["decoy", "verify", "confirmed"],
    ),
]


CATALOGUE_BY_ID: Dict[str, Misconception] = {m.id: m for m in CATALOGUE}


@dataclass
class Detection:
    misconception: Misconception
    confidence: float
    matched: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = self.misconception.to_dict()
        d["confidence"] = round(self.confidence, 3)
        d["matched"] = list(self.matched)
        return d


def _contains(haystack: str, needle: str) -> bool:
    """Substring match with word-ish boundaries for short needles."""
    needle = needle.lower().strip()
    if not needle:
        return False
    if len(needle) <= 4 and " " not in needle:
        return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack) is not None
    return needle in haystack


def detect(
    text: str,
    threshold: float = DEFAULT_THRESHOLD,
    category: Optional[str] = None,
) -> List[Detection]:
    """
    Score the catalogue against a piece of learner text.

    Scoring: a strong phrase alone is near-certain (0.9). A trigger plus a
    nearby context word is a moderate hit (0.6, plus a little for each extra
    match). Anything the learner explicitly negated is dropped.
    """
    lower = (text or "").lower()
    if not lower.strip():
        return []

    out: List[Detection] = []
    for m in CATALOGUE:
        if any(_contains(lower, n) for n in m.negations):
            continue

        matched: List[str] = []
        confidence = 0.0

        strong = [p for p in m.strong_phrases if _contains(lower, p)]
        if strong:
            confidence = 0.9
            matched.extend(strong)

        triggers = [t for t in m.triggers if _contains(lower, t)]
        contexts = [c for c in m.context if _contains(lower, c)]
        if triggers and contexts:
            confidence = max(confidence, 0.6 + 0.05 * (len(triggers) + len(contexts) - 2))
            matched.extend(triggers[:2] + contexts[:2])
        elif triggers and not strong:
            # A trigger with no supporting context is usually just topic talk.
            confidence = max(confidence, 0.25)
            matched.extend(triggers[:2])

        if category and m.category != category.lower():
            confidence *= 0.85  # slight discount, not a hard filter

        confidence = min(1.0, confidence)
        if confidence >= threshold:
            seen: Set[str] = set()
            uniq = [x for x in matched if not (x in seen or seen.add(x))]
            out.append(Detection(m, confidence, uniq))

    out.sort(key=lambda d: -d.confidence)
    return out


def remediation(detection: Detection, include_probe: bool = True) -> str:
    """Render one detection as a short teaching block."""
    m = detection.misconception
    lines = [f"**Worth double-checking:** {m.summary}", "", m.correction]
    if include_probe:
        lines += ["", f"_Try this:_ {m.probe}"]
    if m.review_concepts:
        try:
            from agent.skill_graph import explain_concept

            lines.append("")
            for concept in m.review_concepts[:3]:
                lines.append(f"- **{concept}** — {explain_concept(concept)}")
        except Exception:
            lines.append("")
            lines.append("Review: " + ", ".join(m.review_concepts[:3]))
    return "\n".join(lines)


def remediation_report(
    text: str,
    threshold: float = DEFAULT_THRESHOLD,
    category: Optional[str] = None,
    limit: int = 2,
) -> str:
    """Full block for the teaching layer — empty string when nothing fires."""
    hits = detect(text, threshold=threshold, category=category)[:limit]
    if not hits:
        return ""
    blocks = ["## Before you go further", ""]
    for h in hits:
        blocks.append(remediation(h))
        blocks.append("")
    return "\n".join(blocks).rstrip()


def record_to_memory(text: str, memory: Any, threshold: float = DEFAULT_THRESHOLD) -> List[str]:
    """
    Log detected misconceptions into LearnerMemory so the curriculum can
    schedule the relevant concepts for review. Returns the ids recorded.
    """
    ids: List[str] = []
    for d in detect(text, threshold=threshold):
        try:
            memory.add_misconception(f"{d.misconception.id}: {d.misconception.summary}")
            ids.append(d.misconception.id)
        except Exception:
            continue
    return ids


def concepts_to_review(memory: Any, limit: int = 6) -> List[str]:
    """Map recorded misconceptions back to skill-graph concepts."""
    out: List[str] = []
    try:
        entries = list(getattr(memory, "misconceptions", []) or [])
    except Exception:
        return out
    for entry in reversed(entries):
        mid = str(entry).split(":", 1)[0].strip()
        card = CATALOGUE_BY_ID.get(mid)
        if not card:
            continue
        for concept in card.review_concepts:
            if concept not in out:
                out.append(concept)
        if len(out) >= limit:
            break
    return out[:limit]


def list_catalogue(category: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = CATALOGUE
    if category:
        rows = [m for m in rows if m.category == category.lower()]
    return [m.to_dict() for m in rows]
