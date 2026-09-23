"""
agent/classify_challenge.py

Classification as evidence-weighing, and it always answers (item 13).

`classifier.classify_heuristic` counts keyword occurrences and returns `None`
whenever the top two categories tie or the winner scores below a floor. On
this project's own evaluation set that happens for 45% of cases, and `None`
is the worst possible answer: the planner's category branches all fall
through, the skill pack is not loaded, the technique seeds are generic, and
every later stage works from nothing. An uncertain guess with its
uncertainty attached is strictly more useful than silence.

Three changes.

**Signals are weighted, not counted.** "smart contract" is decisive;
"api" is nearly worthless, and appears in most web *and* most mobile
descriptions. Counting them equally is why a single coincidental keyword
could tie against a real marker.

**Artifacts outrank prose.** A description is a person's summary; a `.sol`
file in the directory is a fact. When triage has seen the files, their kinds
dominate — which also handles the adversarial case where the description is
deliberately misleading but the artifacts are not.

**The output is a profile, not a label.** Category with a calibrated
confidence and the signals behind it, the runner-up, candidate techniques
ranked by rubric match, artifact kinds, and the tools that could produce the
missing evidence. Downstream stages need all of that, and each was
previously re-deriving its own worse version.

`ambiguous` is set when the margin is thin. That is the honest form of the
old `None`: the agent still gets a working category to plan against, plus an
explicit note that it should expect to revise it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

CATEGORIES = [
    "web", "pwn", "crypto", "rev", "forensics", "osint",
    "blockchain", "mobile", "misc",
]

# Weight bands. A decisive marker names the category almost by itself; a weak
# one only matters in aggregate, and must never outvote a decisive one.
DECISIVE, STRONG, MODERATE, WEAK = 4.0, 2.5, 1.2, 0.4

# (pattern, category, weight). Patterns are regexes matched case-insensitively
# with word-ish boundaries where it matters, so "api" does not match "rapid".
SIGNALS: List[Tuple[str, str, float]] = [
    # --- web
    (r"\bjwt\b|json web token", "web", DECISIVE),
    (r"sql\s*injection|\bsqli\b", "web", DECISIVE),
    (r"\bssti\b|template injection", "web", DECISIVE),
    (r"\bxss\b|cross.site scripting", "web", DECISIVE),
    (r"\bssrf\b|server.side request forgery", "web", DECISIVE),
    (r"\bcsrf\b|\bcors\b", "web", STRONG),
    (r"path traversal|directory traversal|\blfi\b", "web", STRONG),
    (r"admin panel|admin route|staff.only endpoint", "web", STRONG),
    (r"bearer token|session cookie|\bset-cookie\b", "web", STRONG),
    (r"\bflask\b|\bdjango\b|express\.js|\bphp\b|\bnode\b", "web", MODERATE),
    (r"\bhttp\b|\bhttps\b|\burl\b|\bendpoint\b|web app|website", "web", MODERATE),
    (r"log(?:ging)?\s*in|logs? in|login|sign(?:ing)? in|authentication", "web", MODERATE),
    (r"\bapi\b|\brequest\b|\bresponse\b|\bheader\b|\bcookie\b", "web", WEAK),

    # --- pwn
    (r"buffer overflow|stack overflow|heap overflow", "pwn", DECISIVE),
    (r"\brop\b|ret2libc|ret2win|ret2csu|\bsrop\b", "pwn", DECISIVE),
    (r"format string|%n\b", "pwn", DECISIVE),
    (r"use.after.free|double free|\btcache\b|\bfastbin\b", "pwn", DECISIVE),
    (r"\bshellcode\b|got overwrite|\bplt\b", "pwn", STRONG),
    (r"stack (?:protector|canary)|\bcanary\b", "pwn", STRONG),
    (r"\bgets\(|\bstrcpy\b|\bsprintf\b|unchecked (?:copy|length)", "pwn", STRONG),
    (r"without checking the length|no bounds check", "pwn", STRONG),
    (r"non.executable stack|\bnx\b|\baslr\b|\bpie\b|position.independent", "pwn", MODERATE),
    (r"\bpwntools\b|\blibc\b|get a shell|spawn a shell", "pwn", MODERATE),
    (r"\bsegfault\b|\bcrash(?:es)?\b|local array|stack frame", "pwn", MODERATE),

    # --- crypto
    (r"\brsa\b|\bmodulus\b|public exponent", "crypto", DECISIVE),
    (r"padding oracle|\becb\b|\bcbc\b|\bctr\b mode", "crypto", DECISIVE),
    (r"\bxor\b.{0,20}(?:key|cipher)|single.byte xor|repeating.key", "crypto", DECISIVE),
    (r"elliptic curve|\becdsa\b|nonce reuse|\blattice\b", "crypto", DECISIVE),
    (r"length extension|hash collision", "crypto", DECISIVE),
    # Classical ciphers are named, unambiguous crypto markers. Their absence
    # here demoted a Caesar challenge to misc on the evidence floor.
    (r"caesar|\brot-?13\b|vigen[eè]re|atbash|playfair|rail fence|substitution cipher",
     "crypto", DECISIVE),
    (r"shift cipher|frequency analysis|recover (?:the )?(?:english )?plaintext",
     "crypto", STRONG),
    (r"\baes\b|\bdes\b|block cipher|stream cipher", "crypto", STRONG),
    (r"\bcipher(?:text)?\b|encrypt(?:ed|ion)?|decrypt", "crypto", MODERATE),
    (r"\bmd5\b|\bsha-?\d+\b|\bhash\b|private key|\bprime\b|\bnonce\b", "crypto", MODERATE),

    # --- rev
    (r"reverse engineer|\bcrackme\b|\bkeygen\b", "rev", DECISIVE),
    (r"decompil|disassembl|\bghidra\b|\bida pro\b|\bilspy\b|\bdnspy\b", "rev", DECISIVE),
    (r"obfuscat|anti.debug|control.flow flattening|\bupx\b|\bpacked\b", "rev", DECISIVE),
    (r"license (?:key|check)|serial (?:key|number) check", "rev", STRONG),
    (r"\bassembly\b|\bopcodes?\b|\.net assembly|go binary|rust binary", "rev", MODERATE),
    (r"binary analysis|static analysis|symbol table", "rev", MODERATE),

    # --- forensics
    (r"\bpcap(?:ng)?\b|\bwireshark\b|\btshark\b|network capture", "forensics", DECISIVE),
    (r"steganograph|\bstego\b|\blsb\b|hidden in (?:the )?image", "forensics", DECISIVE),
    (r"memory dump|disk image|\bvolatility\b|file carving", "forensics", DECISIVE),
    (r"\bexif\b|\bmetadata\b|embedded (?:file|data)|appended data", "forensics", STRONG),
    (r"hidden file|deleted file|recover the file|\bartifacts?\b", "forensics", MODERATE),
    (r"\bpng\b|\bjpe?g\b|\bwav\b|\bzip\b archive|log file", "forensics", WEAK),

    # --- osint
    (r"\bosint\b|open.source intelligence", "osint", DECISIVE),
    (r"geolocat|reverse image search|\bwhois\b|\bshodan\b|google dork", "osint", DECISIVE),
    (r"social media|public record|find (?:this|the) person|\bhandle\b", "osint", STRONG),

    # --- blockchain
    (r"smart contract|\bsolidity\b|\berc-?20\b|\bweb3\b", "blockchain", DECISIVE),
    (r"\breentran|\bethereum\b|\bgas\b limit|\bwallet\b|\bether\b", "blockchain", STRONG),
    (r"on.chain|\btestnet\b|\btransaction\b hash", "blockchain", MODERATE),

    # --- mobile
    (r"\bapk\b|\bandroid\b|\bipa\b|\bios app\b", "mobile", DECISIVE),
    (r"\bfrida\b|\bjadx\b|exported activity|shared preferences|\bkeystore\b", "mobile", DECISIVE),
    (r"mobile app|\bmanifest\.xml\b|\bdex\b", "mobile", STRONG),
]

_COMPILED: List[Tuple[re.Pattern, str, float]] = [
    (re.compile(pattern, re.IGNORECASE), category, weight)
    for pattern, category, weight in SIGNALS
]

# Artifact kinds are facts about the challenge, so they carry decisive weight.
# Several kinds are genuinely shared, and a shared kind votes for each.
ARTIFACT_PRIORS: Dict[str, List[Tuple[str, float]]] = {
    "elf": [("pwn", DECISIVE), ("rev", STRONG)],
    "pe": [("rev", DECISIVE), ("pwn", MODERATE)],
    "macho": [("rev", DECISIVE)],
    "dotnet": [("rev", DECISIVE)],
    "binary": [("rev", STRONG), ("pwn", STRONG)],
    "pcap": [("forensics", DECISIVE)],
    "image": [("forensics", STRONG), ("osint", MODERATE)],
    "audio": [("forensics", STRONG)],
    "solidity": [("blockchain", DECISIVE)],
    "apk": [("mobile", DECISIVE)],
    "source": [("web", MODERATE), ("rev", WEAK)],
    "python": [("web", MODERATE), ("crypto", MODERATE)],
    "php": [("web", DECISIVE)],
    "javascript": [("web", STRONG)],
    "archive": [("forensics", MODERATE), ("misc", WEAK)],
    "text": [("crypto", MODERATE), ("misc", MODERATE)],
    "document": [("forensics", MODERATE), ("osint", WEAK)],
}

_EXT_KIND: Dict[str, str] = {
    ".sol": "solidity", ".apk": "apk", ".ipa": "apk",
    ".pcap": "pcap", ".pcapng": "pcap",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image", ".bmp": "image",
    ".wav": "audio", ".mp3": "audio",
    ".py": "python", ".php": "php", ".js": "javascript", ".ts": "javascript",
    ".rb": "source", ".go": "source", ".java": "source", ".c": "source",
    ".cpp": "source", ".rs": "source", ".html": "source",
    ".cs": "dotnet", ".dll": "dotnet", ".exe": "pe",
    ".so": "elf", ".elf": "elf", ".bin": "binary", ".o": "binary",
    ".zip": "archive", ".tar": "archive", ".gz": "archive", ".7z": "archive",
    ".txt": "text", ".md": "text", ".json": "text", ".log": "text",
    ".pdf": "document", ".docx": "document",
}

# Which category a technique belongs to. Used to nominate techniques from the
# rubric table in agent.evidence and to let a technique match vote for its
# category — a description that describes alg=none is a web challenge even if
# it never says "web".
TECHNIQUE_CATEGORY: Dict[str, str] = {
    "jwt-none-bypass": "web", "jwt-alg-confusion": "web", "sql-injection": "web",
    "ssti": "web", "path-traversal": "web", "idor": "web", "xss-reflected": "web",
    "stack-buffer-overflow": "pwn", "format-string": "pwn", "ret2libc": "pwn",
    "xor-single-byte": "crypto", "xor-repeating-key": "crypto",
    "packed-binary": "rev", "steganography": "forensics",
}


@dataclass
class Signal:
    """One piece of evidence for a category."""

    name: str
    category: str
    weight: float
    source: str = "description"   # description | artifact | technique

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "category": self.category,
                "weight": round(self.weight, 2), "source": self.source}


@dataclass
class ChallengeProfile:
    """The formal pre-reasoning classification of a challenge."""

    category: str = "misc"
    confidence: float = 0.0
    runner_up: str = ""
    margin: float = 0.0
    ambiguous: bool = True
    scores: Dict[str, float] = field(default_factory=dict)
    signals: List[Signal] = field(default_factory=list)
    artifact_kinds: List[str] = field(default_factory=list)
    candidate_techniques: List[Tuple[str, float]] = field(default_factory=list)
    recommended_tools: List[str] = field(default_factory=list)
    missing_signals: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def top_techniques(self) -> List[str]:
        return [name for name, _ in self.candidate_techniques]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "runner_up": self.runner_up,
            "margin": round(self.margin, 3),
            "ambiguous": self.ambiguous,
            "scores": {k: round(v, 2) for k, v in self.scores.items() if v},
            "signals": [s.to_dict() for s in self.signals],
            "artifact_kinds": list(self.artifact_kinds),
            "candidate_techniques": [[n, round(s, 3)] for n, s in self.candidate_techniques],
            "recommended_tools": list(self.recommended_tools),
            "missing_signals": list(self.missing_signals),
            "notes": list(self.notes),
        }

    def render(self) -> str:
        lines = [f"Category: {self.category} ({self.confidence:.2f})"
                 + (f"  — ambiguous, runner-up {self.runner_up}" if self.ambiguous else "")]
        if self.artifact_kinds:
            lines.append(f"  artifacts: {', '.join(self.artifact_kinds)}")
        top = sorted((kv for kv in self.scores.items() if kv[1]),
                     key=lambda kv: -kv[1])[:3]
        if top:
            lines.append("  scores: " + ", ".join(f"{k} {v:.1f}" for k, v in top))
        strongest = sorted(self.signals, key=lambda s: -s.weight)[:5]
        if strongest:
            lines.append("  signals: " + ", ".join(
                f"{s.name}[{s.source[:4]}]" for s in strongest))
        if self.candidate_techniques:
            lines.append("  techniques: " + ", ".join(
                f"{n} ({s:.2f})" for n, s in self.candidate_techniques[:4]))
        if self.recommended_tools:
            lines.append(f"  tools: {', '.join(self.recommended_tools)}")
        for note in self.notes:
            lines.append(f"  · {note}")
        return "\n".join(lines)


def kind_of_path(path: str) -> str:
    """Artifact kind from a filename, with magic-free extension rules."""
    lowered = str(path or "").lower()
    name = lowered.rsplit("/", 1)[-1]
    for ext, kind in _EXT_KIND.items():
        if name.endswith(ext):
            return kind
    if "." not in name:
        return "binary"
    return "text"


def _artifact_kinds(
    artifacts: Optional[Iterable[str]] = None,
    inventory: Any = None,
) -> List[str]:
    """
    Collect artifact kinds, preferring a triage inventory when present.

    The inventory has looked at magic bytes; filenames are only a guess, and
    a deliberately misleading filename is a documented CTF trick.
    """
    kinds: List[str] = []
    if inventory is not None:
        for artifact in getattr(inventory, "artifacts", None) or []:
            kind = str(getattr(artifact, "kind", "") or "").lower()
            if kind and kind not in kinds:
                kinds.append(kind)
    for path in artifacts or []:
        kind = kind_of_path(str(path))
        if kind not in kinds:
            kinds.append(kind)
    return kinds


def _technique_matches(text: str) -> List[Tuple[str, float]]:
    """
    Which techniques the text already shows signals for.

    Scored against the same rubric the verifier uses, so a technique
    nominated here is one the evidence layer can later grade — the two
    cannot disagree about what a technique looks like.
    """
    try:
        from agent.evidence import REQUIREMENTS, _matches
    except Exception:
        return []

    scored: List[Tuple[str, float]] = []
    lowered = text.lower()
    for technique, req in REQUIREMENTS.items():
        required_hits = sum(1 for s in req.required if _matches(s, lowered))
        support_hits = sum(1 for s in req.supporting if _matches(s, lowered))
        contra_hits = sum(1 for s in req.contradicting if _matches(s, lowered))
        if not (required_hits or support_hits):
            continue
        score = (required_hits / (len(req.required) or 1)) * 0.7
        score += (support_hits / (len(req.supporting) or 1)) * 0.3
        # A contradicting signal in the description is a strong hint the
        # obvious reading is the wrong one — the decoy case.
        score -= 0.4 * contra_hits
        if score > 0.05:
            scored.append((technique, round(score, 3)))
    scored.sort(key=lambda kv: -kv[1])
    return scored


def classify_challenge(
    description: str = "",
    artifacts: Optional[Iterable[str]] = None,
    inventory: Any = None,
    content_sample: str = "",
) -> ChallengeProfile:
    """
    Build a full profile. Always returns a category.

    `content_sample` is a slice of an actual file when one is available; it
    is weighted like a description because it is prose-level evidence, not a
    verified observation.
    """
    profile = ChallengeProfile()
    text = f"{description}\n{content_sample}"
    scores: Dict[str, float] = {c: 0.0 for c in CATEGORIES}

    # 1. Description and content signals.
    for pattern, category, weight in _COMPILED:
        found = pattern.findall(text)
        if not found:
            continue
        # Repeats add, but with diminishing returns: saying "jwt" eight times
        # is not eight independent pieces of evidence.
        occurrences = min(len(found), 3)
        contribution = weight * (1.0 + 0.25 * (occurrences - 1))
        scores[category] += contribution
        profile.signals.append(Signal(
            name=pattern.pattern[:40], category=category,
            weight=contribution, source="description",
        ))

    # 2. Artifact kinds, which outrank prose.
    profile.artifact_kinds = _artifact_kinds(artifacts, inventory)
    for kind in profile.artifact_kinds:
        for category, weight in ARTIFACT_PRIORS.get(kind, []):
            scores[category] += weight
            profile.signals.append(Signal(
                name=f"artifact:{kind}", category=category,
                weight=weight, source="artifact",
            ))

    # 3. Technique matches vote for their own category.
    profile.candidate_techniques = _technique_matches(text)[:6]
    for technique, score in profile.candidate_techniques:
        category = TECHNIQUE_CATEGORY.get(technique)
        if category:
            contribution = STRONG * score
            scores[category] += contribution
            profile.signals.append(Signal(
                name=f"technique:{technique}", category=category,
                weight=contribution, source="technique",
            ))

    # 4. Inventory's own category hints, if triage produced any.
    for hint in (getattr(inventory, "categories_hint", None) or []):
        category = str(hint).lower()
        if category in scores:
            scores[category] += MODERATE
            profile.signals.append(Signal(
                name=f"triage:{category}", category=category,
                weight=MODERATE, source="artifact",
            ))

    profile.scores = scores
    ranked = sorted(scores.items(), key=lambda kv: -kv[1])
    top_category, top_score = ranked[0]
    runner_category, runner_score = ranked[1] if len(ranked) > 1 else ("", 0.0)

    # An evidence floor. A handful of weak matches -- "url", "header", "file"
    # -- is a vocabulary coincidence, not a category, and naming a specialised
    # category on that basis is worse than naming none: it sends the planner
    # down a branch with no support. "misc" is the honest answer, and unlike
    # the old None it is still a category the planner can work with.
    if 0 < top_score < MODERATE * 1.5 and top_category != "misc":
        profile.notes.append(
            f"only weak signals ({top_score:.1f}), strongest pointing at "
            f"{top_category} — treating as misc until an artifact says otherwise"
        )
        profile.category = "misc"
        profile.confidence = 0.1
        profile.runner_up = top_category
        profile.margin = 0.0
        profile.ambiguous = True
        return _finish(profile, text)

    if top_score <= 0:
        # Nothing matched at all. "misc" with zero confidence is still a
        # working category: the planner can triage and re-classify, which it
        # cannot do with None.
        profile.category = "misc"
        profile.confidence = 0.0
        profile.ambiguous = True
        profile.notes.append("no category signals found — triage the files and re-classify")
    else:
        profile.category = top_category
        profile.margin = (top_score - runner_score) / top_score
        profile.runner_up = runner_category
        # Confidence combines absolute evidence with separation. Plenty of
        # evidence for two categories is not confidence; it is a chain.
        volume = min(1.0, top_score / (DECISIVE * 2))
        separation = min(1.0, profile.margin)
        profile.confidence = round(
            min(0.97, max(0.05, 0.05 + 0.3 * volume + 0.65 * separation * volume)), 3
        )
        profile.ambiguous = profile.margin < 0.35 or profile.confidence < 0.35
        if profile.ambiguous and runner_category:
            profile.notes.append(
                f"{top_category} and {runner_category} are close "
                f"({top_score:.1f} vs {runner_score:.1f}) — expect to revise, "
                f"and consider a chained challenge"
            )

    return _finish(profile, text)


def _finish(profile: ChallengeProfile, text: str) -> ChallengeProfile:
    """Attach the missing signals and the tools that could close them."""
    if profile.candidate_techniques:
        try:
            from agent.evidence import _matches, requirements_for

            req = requirements_for(profile.candidate_techniques[0][0])
            if req:
                profile.missing_signals = [
                    s for s in req.required if not _matches(s, text.lower())
                ]
        except Exception:
            pass
    try:
        from agent.tool_capabilities import candidates

        shortlist = candidates(
            category=profile.category,
            artifact_kinds=profile.artifact_kinds or None,
            missing_signals=profile.missing_signals,
            limit=4,
        )
        profile.recommended_tools = [c.tool for c in shortlist]
    except Exception:
        pass
    return profile


def classify_formal(description: str, **kwargs: Any) -> str:
    """
    Category only, never `None`.

    Drop-in for `classifier.classify` where a bare label is wanted and the
    absence of one would stall the caller.
    """
    return classify_challenge(description, **kwargs).category


def profile_for_state(state: Any, inventory: Any = None) -> ChallengeProfile:
    """Classify from an `AgentState`, using whatever triage has found."""
    return classify_challenge(
        description=str(getattr(state, "challenge_summary", "") or ""),
        artifacts=[str(a) for a in (getattr(state, "discovered_artifacts", None) or [])],
        inventory=inventory,
    )


def apply_profile_to_state(state: Any, profile: ChallengeProfile) -> None:
    """
    Write a profile into the state.

    The ambiguity is recorded as a fact rather than discarded, so a later
    contradiction reads as an expected revision instead of a surprise, and
    the candidate techniques become explicit rather than being re-guessed by
    each stage.
    """
    if not getattr(state, "category", None):
        state.category = profile.category
    try:
        state.add_fact(
            f"Classified as {profile.category} (confidence {profile.confidence:.2f}"
            + (f", ambiguous vs {profile.runner_up}" if profile.ambiguous and profile.runner_up
               else "") + ")"
        )
    except Exception:
        pass
    existing = list(getattr(state, "candidate_techniques", None) or [])
    for technique, _score in profile.candidate_techniques[:5]:
        if technique not in existing:
            existing.append(technique)
    try:
        state.candidate_techniques = existing
    except Exception:
        pass
    for note in profile.notes:
        try:
            state.add_fact(note)
        except Exception:
            pass
