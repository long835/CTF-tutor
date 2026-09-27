"""
agent/taxonomy.py

One canonical name per technique (item 67).

The corpus had grown 118 distinct technique tags for rather fewer than 118
distinct techniques. `buffer-overflow`, `stack-smashing` and
`stack-buffer-overflow` are the same idea wearing three labels; so are
`username-osint` and `osint-username`. That is not a cosmetic problem:

* retrieval splits its recall across the variants,
* the skill graph has prerequisites for one spelling and not the others,
* the evidence rubric keys off one spelling, so a claim tagged with a
  synonym silently gets no rubric and grades as INSUFFICIENT_EVIDENCE,
* mastery statistics are recorded against whichever label the run used, so
  a learner can be "weak" and "mastered" at the same technique at once.

This module is deliberately dependency-free so that everything else --
evidence rubrics, the knowledge graph, retrieval, the learner model -- can
resolve a name through it without an import cycle.

Two rules:

1. A canonical id is `<category>/<slug>` when rendered as a taxonomy path,
   but the bare slug stays the key everywhere else. Renaming every existing
   tag would invalidate the corpus, the archive and the learner memory for
   no benefit; mapping the synonyms onto one key gets the same result.
2. Aliases resolve; they never disappear. Old data keeps loading.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Canonical ids and their category
# ---------------------------------------------------------------------------

# Technique -> category. This is the single source of truth for "what kind of
# challenge is this technique used on"; other modules should read it rather
# than keeping their own copy.
CATEGORY_OF: Dict[str, str] = {
    # web
    "sql-injection": "web",
    "sqli-union": "web",
    "sqli-blind-boolean": "web",
    "ssti": "web",
    "xss-reflected": "web",
    "ssrf": "web",
    "xxe": "web",
    "path-traversal": "web",
    "idor": "web",
    "jwt-none-bypass": "web",
    "jwt-alg-confusion": "web",
    "auth-bypass": "web",
    "prototype-pollution": "web",
    "deserialization-rce": "web",
    "race-condition": "web",
    "http-request-smuggling": "web",
    "cors-misconfiguration": "web",
    "cache-poisoning": "web",
    "graphql-introspection": "web",
    "nosql-injection": "web",
    "file-upload-chain": "web",
    "oauth-flow-abuse": "web",
    # pwn
    "stack-buffer-overflow": "pwn",
    "format-string": "pwn",
    "ret2libc": "pwn",
    "rop-chain": "pwn",
    "ret2csu": "pwn",
    "srop": "pwn",
    "canary-bypass": "pwn",
    "aslr-bypass": "pwn",
    "heap-overflow": "pwn",
    "use-after-free": "pwn",
    "tcache-poisoning": "pwn",
    "fastbin-dup": "pwn",
    "unsorted-bin-leak": "pwn",
    "file-structure-abuse": "pwn",
    "off-by-one": "pwn",
    "integer-overflow": "pwn",
    "arbitrary-write": "pwn",
    "seccomp-escape": "pwn",
    "info-leak": "pwn",
    # rev
    "packed-binary": "rev",
    "anti-debug-bypass": "rev",
    "string-decryption": "rev",
    "control-flow-flattening": "rev",
    "vm-obfuscation": "rev",
    "opaque-predicates": "rev",
    "symbolic-execution": "rev",
    "api-hashing": "rev",
    "dotnet-deobfuscation": "rev",
    "go-binary-analysis": "rev",
    "rust-binary-analysis": "rev",
    "keygen": "rev",
    "algorithm-recovery": "rev",
    # crypto
    "xor-single-byte": "crypto",
    "xor-repeating-key": "crypto",
    "classical-caesar": "crypto",
    "classical-substitution": "crypto",
    "rsa-small-e": "crypto",
    "rsa-common-modulus": "crypto",
    "rsa-factorisation": "crypto",
    "rsa-wiener": "crypto",
    "rsa-franklin-reiter": "crypto",
    "rsa-broadcast": "crypto",
    "padding-oracle": "crypto",
    "ecb-byte-at-a-time": "crypto",
    "ctr-nonce-reuse": "crypto",
    "hash-length-extension": "crypto",
    "ecdsa-nonce-reuse": "crypto",
    "lattice-reduction": "crypto",
    "prng-prediction": "crypto",
    "timing-side-channel": "crypto",
    "encoding-recognition": "crypto",
    # forensics
    "file-carving": "forensics",
    "pcap-carving": "forensics",
    "steganography": "forensics",
    "image-metadata": "forensics",
    "memory-forensics": "forensics",
    "log-analysis": "forensics",
    "disk-image-analysis": "forensics",
    # osint
    "osint-geolocation": "osint",
    "osint-username": "osint",
    "osint-domain-dns": "osint",
    "osint-metadata": "osint",
    # blockchain / mobile
    "reentrancy": "blockchain",
    "integer-accounting": "blockchain",
    "solidity-access-control": "blockchain",
    "android-exported-component": "mobile",
    "insecure-storage": "mobile",
    "certificate-pinning-bypass": "mobile",
    "hardcoded-secret": "mobile",
    # misc. These three sit here because the technique library and the corpus
    # cards built from it say so. The knowledge-graph audit now fails on any
    # disagreement between the two, and when they disagreed the data won: a
    # card filed under `misc` that the taxonomy calls `crypto` is a card
    # category-filtered retrieval will never return.
    "multilayer-encoding": "misc",
    "archive-analysis": "misc",
    "file-signature": "misc",
    "nested-archive": "misc",
    "esoteric-lang": "misc",
}

# Concept nodes: things a learner needs to understand, but which are not
# themselves a way to solve a challenge. Kept separate so the curriculum can
# schedule them and the classifier never proposes them as an answer.
CONCEPT_CATEGORY: Dict[str, str] = {
    "http-basics": "web",
    "web-input-handling": "web",
    "template-engines": "web",
    "jwt-basics": "web",
    "c-memory": "pwn",
    "stack-layout": "pwn",
    "calling-convention": "pwn",
    "nx": "pwn",
    "plt-got": "pwn",
    "gadgets": "pwn",
    "canary": "pwn",
    "aslr": "pwn",
    "heap-layout": "pwn",
    "encoding-basics": "crypto",
    "xor-properties": "crypto",
    "frequency-analysis": "crypto",
    "rsa-basics": "crypto",
    "modular-arithmetic": "crypto",
    "block-ciphers": "crypto",
    "cbc": "crypto",
    "lattice-basics": "crypto",
    "assembly-basics": "rev",
    "static-analysis-basics": "rev",
    "debugger-basics": "rev",
    "file-formats": "rev",
    "control-flow": "rev",
    # Tagged as "techniques" in the corpus, but none of them is an answer to a
    # challenge: they are how you look, not what you found. Left as concepts so
    # the classifier can never propose "the vulnerability is static-analysis".
    "string-analysis": "rev",
    "network-basics": "forensics",
    "image-formats": "forensics",
    "osint-basics": "osint",
    "solidity-basics": "blockchain",
    "smart-contract-state": "blockchain",
    "android-basics": "mobile",
}

# ---------------------------------------------------------------------------
# Aliases
# ---------------------------------------------------------------------------

# Every one of these was observed in the shipped corpus or archive as a
# *separate* tag for something already named above. Left-hand side is what the
# data says; right-hand side is what it means.
ALIASES: Dict[str, str] = {
    # pwn
    "buffer-overflow": "stack-buffer-overflow",
    "stack-smashing": "stack-buffer-overflow",
    "stack-overflow": "stack-buffer-overflow",
    "bof": "stack-buffer-overflow",
    "format-string-vulnerability": "format-string",
    "fmtstr": "format-string",
    "ret2win": "stack-buffer-overflow",
    "rop": "rop-chain",
    "uaf": "use-after-free",
    # web
    "boolean-blind-sqli": "sqli-blind-boolean",
    "blind-sqli": "sqli-blind-boolean",
    "sqli": "sql-injection",
    "union-sqli": "sqli-union",
    "server-side-template-injection": "ssti",
    "directory-traversal": "path-traversal",
    "lfi": "path-traversal",
    "jwt-none": "jwt-none-bypass",
    "jwt-alg-none": "jwt-none-bypass",
    "alg-confusion": "jwt-alg-confusion",
    "xss": "xss-reflected",
    "insecure-direct-object-reference": "idor",
    # crypto
    "single-byte-xor": "xor-single-byte",
    "crypto-single-byte-xor": "xor-single-byte",
    "crypto-xor-single-byte": "xor-single-byte",
    "repeating-key-xor": "xor-repeating-key",
    "vigenere": "xor-repeating-key",
    "caesar": "classical-caesar",
    "rot13": "classical-caesar",
    "substitution-cipher": "classical-substitution",
    "crypto-classical-substitution": "classical-substitution",
    "monoalphabetic": "classical-substitution",
    "rsa-weak-parameters": "rsa-factorisation",
    "crypto-weak-rsa-parameters": "rsa-factorisation",
    "small-exponent": "rsa-small-e",
    "hash-extension": "hash-length-extension",
    "base64": "encoding-recognition",
    "encoding": "encoding-recognition",
    "crypto-base-encoding-layers": "multilayer-encoding",
    "number-theory": "modular-arithmetic",
    "rsa": "rsa-basics",
    # rev
    "packing": "packed-binary",
    "packer": "packed-binary",
    "cff": "control-flow-flattening",
    "vm-protect": "vm-obfuscation",
    "antidebug": "anti-debug-bypass",
    # forensics
    "pcap-analysis": "pcap-carving",
    "pcap": "pcap-carving",
    "lsb": "steganography",
    "stego": "steganography",
    "exif": "image-metadata",
    "exif-gps": "image-metadata",
    "metadata": "image-metadata",
    "carving": "file-carving",
    "magic-bytes": "file-signature",
    "static-analysis": "static-analysis-basics",
    # The library entry and every corpus card tagged `access-control` are about
    # Solidity modifiers, not web roles. Web authorisation is covered by idor
    # and auth-bypass.
    "access-control": "solidity-access-control",
    "http-analysis": "http-basics",
    # osint
    "geolocation": "osint-geolocation",
    "username-osint": "osint-username",
    "domain-osint": "osint-domain-dns",
    "dns-osint": "osint-domain-dns",
    # blockchain / mobile
    "smart-contract": "solidity-access-control",
    "solidity": "solidity-basics",
    "integer-arithmetic": "integer-accounting",
    "reentrancy-classic": "reentrancy",
    "android": "android-basics",
    "jwt": "jwt-basics",
}


def _slug(name: str) -> str:
    s = (name or "").strip().lower()
    s = s.replace("_", "-").replace(" ", "-")
    s = re.sub(r"-+", "-", s)
    return s.strip("- ")


def canonical(name: str) -> str:
    """
    Resolve any spelling to its canonical technique/concept id.

    Unknown names come back slugified but otherwise untouched: a taxonomy
    that swallows names it does not recognise would hide exactly the gap
    `unknown_tags()` is there to report.
    """
    s = _slug(name)
    if not s:
        return ""
    seen: Set[str] = set()
    while s in ALIASES and s not in seen:
        seen.add(s)
        s = ALIASES[s]
    return s


def is_known(name: str) -> bool:
    c = canonical(name)
    return c in CATEGORY_OF or c in CONCEPT_CATEGORY


def is_concept(name: str) -> bool:
    """A concept is taught, never proposed as the answer to a challenge."""
    c = canonical(name)
    return c in CONCEPT_CATEGORY and c not in CATEGORY_OF


def category_of(name: str) -> str:
    c = canonical(name)
    return CATEGORY_OF.get(c) or CONCEPT_CATEGORY.get(c) or "misc"


def path_of(name: str) -> str:
    """The `<category>/<slug>` form the review asked for, e.g. `web/path-traversal`."""
    c = canonical(name)
    if not c:
        return ""
    return f"{category_of(c)}/{c}"


def all_techniques() -> List[str]:
    return sorted(CATEGORY_OF)


def all_concepts() -> List[str]:
    return sorted(CONCEPT_CATEGORY)


def aliases_of(name: str) -> List[str]:
    c = canonical(name)
    return sorted(a for a, target in ALIASES.items() if canonical(target) == c)


def normalise_all(names: Iterable[str]) -> List[str]:
    """Canonicalise a list, dropping blanks and duplicates but keeping order."""
    out: List[str] = []
    for n in names or []:
        c = canonical(n)
        if c and c not in out:
            out.append(c)
    return out


def unknown_tags(names: Iterable[str]) -> List[str]:
    """Names that resolve to nothing this taxonomy knows about."""
    return sorted({canonical(n) for n in names or [] if canonical(n) and not is_known(n)})


def collisions() -> List[str]:
    """
    Aliases that are also canonical ids.

    This is the one way the table can actively lie: if `x` is both a key in
    ALIASES and a key in CATEGORY_OF, half the codebase resolves it and half
    does not. Asserted in the tests.
    """
    bad = []
    for alias, target in ALIASES.items():
        if alias in CATEGORY_OF or alias in CONCEPT_CATEGORY:
            bad.append(f"{alias} is both an alias (-> {target}) and a canonical id")
        t = canonical(target)
        if not (t in CATEGORY_OF or t in CONCEPT_CATEGORY):
            bad.append(f"{alias} -> {target}, which is not a canonical id")
    return sorted(bad)


def duplicate_report(tag_counts: Dict[str, int]) -> List[Tuple[str, List[str], int]]:
    """
    Group observed corpus tags by what they actually mean.

    Returns `(canonical, [variants seen], total uses)` for every canonical id
    that the data spells more than one way -- the concrete item-67 list of
    what still needs collapsing at ingest time.
    """
    groups: Dict[str, List[str]] = {}
    totals: Dict[str, int] = {}
    for tag, count in (tag_counts or {}).items():
        c = canonical(tag)
        if not c:
            continue
        groups.setdefault(c, []).append(tag)
        totals[c] = totals.get(c, 0) + int(count)
    out = []
    for c, variants in groups.items():
        if len(set(variants)) > 1:
            out.append((c, sorted(set(variants)), totals[c]))
    return sorted(out, key=lambda row: (-row[2], row[0]))
