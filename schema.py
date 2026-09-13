"""
schema.py

Defines the data structure for archive entries (past solved challenges)
and sub-problems (pieces a challenge gets decomposed into).

Every past challenge you've solved gets stored as one ArchiveEntry, tagged
with the *techniques* it used (not just its category). This is what lets
the retriever match challenges by underlying technique rather than surface
similarity -- e.g. a "crypto" challenge and a "web" challenge can both
surface as relevant if they both hinge on, say, a padding oracle.

Design note: keep `techniques` as a controlled-ish vocabulary over time.
Reusing the same tag string ("jwt-alg-confusion" not "jwt alg confusion"
one time and "JWT Algorithm Confusion" the next) is what makes retrieval
actually work well. See TECHNIQUE_TAG_GUIDE below for conventions.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import json
import re


# ---------------------------------------------------------------------------
# Controlled vocabulary guidance (not enforced, just documented convention)
# ---------------------------------------------------------------------------
# Use lowercase, hyphen-separated tags. Examples by category:
#
# web:      jwt-alg-confusion, jwt-none-bypass, ssrf, idor, sqli-union,
#           sqli-blind-boolean, xxe, deserialization-rce, ssti, path-traversal,
#           auth-bypass, race-condition, cors-misconfig
#
# pwn:      stack-buffer-overflow, format-string, rop-chain, ret2libc,
#           heap-overflow, use-after-free, integer-overflow, fsop,
#           got-overwrite, canary-bypass, aslr-bypass
#
# crypto:   padding-oracle, xor-repeating-key, rsa-small-e, rsa-common-modulus,
#           ecb-byte-at-a-time, hash-length-extension, weak-rng, ecdsa-nonce-reuse
#
# rev:      anti-debug-bypass, vm-obfuscation, string-decryption,
#           control-flow-flattening, packed-binary
#
# forensics: pcap-carving, memory-forensics, steganography, file-carving,
#            metadata-analysis, log-analysis
#
# misc:     osint, esoteric-encoding, jail-escape, side-channel
# ---------------------------------------------------------------------------

TAG_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def normalize_tag(tag: str) -> str:
    """Force a technique tag into the lowercase-hyphenated convention."""
    tag = tag.strip().lower()
    tag = re.sub(r"[\s_]+", "-", tag)
    tag = re.sub(r"[^a-z0-9\-]", "", tag)
    tag = re.sub(r"-+", "-", tag).strip("-")
    return tag


@dataclass
class SubProblem:
    """One piece of a decomposed challenge."""
    id: str                        # short slug, e.g. "auth-bypass-part"
    description: str               # plain-language description of this piece
    likely_techniques: List[str] = field(default_factory=list)  # guessed tags
    evidence: str = ""              # what in the challenge suggests this
                                     # (e.g. "JWT header has alg:none accepted")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ArchiveEntry:
    """One past solved challenge, stored for future retrieval."""
    challenge_name: str
    category: str                   # web | pwn | crypto | rev | forensics | misc
    techniques: List[str]           # normalized tags, see guide above
    difficulty: Optional[str] = None       # easy | medium | hard | insane
    source: Optional[str] = None           # e.g. "PicoCTF 2025", "HTB", own-made
    description: str = ""                  # the original challenge prompt/summary
    explanation: str = ""                  # WHY the vuln/technique exists here
    solve_steps: List[str] = field(default_factory=list)   # high-level steps,
                                                              # not just a flag dump
    tools_used: List[str] = field(default_factory=list)     # e.g. ["ghidra", "pwntools"]
    references: List[str] = field(default_factory=list)     # wiki links, writeups
    notes: Optional[str] = None            # personal notes, gotchas, what you
                                            # personally struggled with

    def __post_init__(self):
        self.techniques = [normalize_tag(t) for t in self.techniques if t.strip()]

    def to_dict(self) -> dict:
        return asdict(self)

    def to_embedding_text(self) -> str:
        """
        Flatten this entry into a single text blob for embedding.
        This is what actually gets vectorized -- keep it information-dense
        but not just a raw dump, so semantic search has clean signal.
        """
        parts = [
            f"Challenge: {self.challenge_name} ({self.category})",
            f"Techniques: {', '.join(self.techniques)}",
            f"Description: {self.description}",
            f"Explanation: {self.explanation}",
        ]
        if self.solve_steps:
            parts.append("Solve approach: " + " -> ".join(self.solve_steps))
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
    # quick self-test
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
