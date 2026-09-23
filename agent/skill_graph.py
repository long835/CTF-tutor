"""
agent/skill_graph.py

Technique prerequisite graph for adaptive teaching.

If a learner struggles with a node, the tutor can walk prerequisites first.
"""

from __future__ import annotations

from typing import Dict, List, Set


# technique -> list of prerequisite techniques
PREREQUISITES: Dict[str, List[str]] = {
    # Web
    "jwt-none-bypass": ["jwt-basics", "auth-bypass"],
    "jwt-alg-confusion": ["jwt-basics", "auth-bypass"],
    "sql-injection": ["http-basics", "web-input-handling"],
    "sqli-union": ["sql-injection"],
    "sqli-blind-boolean": ["sql-injection"],
    "ssti": ["web-input-handling", "template-engines"],
    "xss-reflected": ["http-basics", "web-input-handling"],
    "ssrf": ["http-basics"],
    "path-traversal": ["web-input-handling"],
    # Pwn
    "stack-buffer-overflow": ["c-memory", "stack-layout", "calling-convention"],
    "ret2libc": ["stack-buffer-overflow", "nx", "plt-got"],
    "rop-chain": ["stack-buffer-overflow", "nx", "gadgets"],
    "format-string": ["c-memory", "stack-layout"],
    "canary-bypass": ["stack-buffer-overflow", "canary"],
    "aslr-bypass": ["aslr", "stack-buffer-overflow"],
    # Crypto
    "xor-single-byte": ["encoding-basics", "xor-properties"],
    "xor-repeating-key": ["xor-single-byte", "frequency-analysis"],
    "rsa-small-e": ["rsa-basics", "modular-arithmetic"],
    "rsa-common-modulus": ["rsa-basics"],
    "padding-oracle": ["block-ciphers", "cbc"],
    # Rev
    "string-decryption": ["assembly-basics", "static-analysis"],
    "anti-debug-bypass": ["assembly-basics", "debugger-basics"],
    "packed-binary": ["static-analysis", "file-formats"],
    # Forensics / OSINT
    "pcap-carving": ["network-basics", "file-carving"],
    "steganography": ["image-formats", "file-carving"],
    "osint-geolocation": ["osint-basics"],
    # Blockchain / mobile
    "reentrancy": ["solidity-basics", "smart-contract-state"],
    "android-exported-component": ["android-basics"],
    "insecure-storage": ["android-basics"],

    # -----------------------------------------------------------------------
    # Filled in after the knowledge-graph join (item 11) reported 34
    # techniques that the corpus actively teaches with nothing scheduled
    # before them. The curriculum could offer them, but never in an order --
    # a learner asking for `heap-overflow` got it cold, with no pointer to
    # c-memory or heap-layout first.
    # -----------------------------------------------------------------------

    # Web
    "sqli-union": ["sql-injection"],
    "xxe": ["http-basics", "web-input-handling", "file-formats"],
    "idor": ["http-basics", "auth-bypass"],
    "solidity-access-control": ["solidity-basics", "smart-contract-state"],
    "auth-bypass": ["http-basics"],
    "prototype-pollution": ["web-input-handling"],
    "deserialization-rce": ["web-input-handling", "file-formats"],
    "race-condition": ["http-basics", "web-input-handling"],
    "http-request-smuggling": ["http-basics"],
    "cors-misconfiguration": ["http-basics"],
    "cache-poisoning": ["http-basics"],
    "graphql-introspection": ["http-basics", "web-input-handling"],
    "nosql-injection": ["http-basics", "web-input-handling"],
    "file-upload-chain": ["web-input-handling", "file-formats"],
    "oauth-flow-abuse": ["http-basics", "auth-bypass"],

    # Pwn
    "heap-overflow": ["c-memory", "heap-layout"],
    "use-after-free": ["c-memory", "heap-layout"],
    "tcache-poisoning": ["heap-overflow", "heap-layout"],
    "fastbin-dup": ["heap-overflow", "heap-layout"],
    "unsorted-bin-leak": ["heap-layout", "aslr"],
    "file-structure-abuse": ["heap-layout", "c-memory"],
    "off-by-one": ["c-memory", "stack-layout"],
    "integer-overflow": ["c-memory"],
    "arbitrary-write": ["c-memory", "plt-got"],
    "ret2csu": ["rop-chain", "calling-convention"],
    "srop": ["rop-chain", "calling-convention"],
    "seccomp-escape": ["rop-chain"],
    "info-leak": ["c-memory", "aslr"],

    # Rev
    "control-flow-flattening": ["assembly-basics", "control-flow"],
    "vm-obfuscation": ["assembly-basics", "control-flow"],
    "opaque-predicates": ["assembly-basics", "control-flow"],
    "symbolic-execution": ["assembly-basics", "control-flow"],
    "api-hashing": ["assembly-basics", "file-formats"],
    "dotnet-deobfuscation": ["static-analysis-basics", "file-formats"],
    "go-binary-analysis": ["static-analysis-basics", "file-formats"],
    "rust-binary-analysis": ["static-analysis-basics", "file-formats"],
    "algorithm-recovery": ["assembly-basics", "static-analysis-basics"],
    "esoteric-lang": ["control-flow"],
    "keygen": ["assembly-basics", "algorithm-recovery"],
    "static-analysis": ["static-analysis-basics"],
    "string-analysis": ["static-analysis-basics"],

    # Crypto
    "rsa-factorisation": ["rsa-basics", "modular-arithmetic"],
    "rsa-wiener": ["rsa-basics", "modular-arithmetic"],
    "rsa-franklin-reiter": ["rsa-basics", "modular-arithmetic"],
    "rsa-broadcast": ["rsa-small-e", "modular-arithmetic"],
    "ecb-byte-at-a-time": ["block-ciphers"],
    "ctr-nonce-reuse": ["block-ciphers", "xor-properties"],
    "hash-length-extension": ["encoding-basics"],
    "ecdsa-nonce-reuse": ["modular-arithmetic"],
    "lattice-reduction": ["lattice-basics", "modular-arithmetic"],
    "prng-prediction": ["modular-arithmetic"],
    "timing-side-channel": ["block-ciphers"],
    "classical-caesar": ["frequency-analysis"],
    "classical-substitution": ["frequency-analysis"],
    "encoding-recognition": ["encoding-basics"],
    "multilayer-encoding": ["encoding-basics"],

    # Forensics
    "file-carving": ["file-formats"],
    "image-metadata": ["image-formats"],
    "memory-forensics": ["file-formats"],
    "log-analysis": ["network-basics"],
    "nested-archive": ["file-formats", "file-carving"],
    "archive-analysis": ["file-formats"],
    "file-signature": ["file-formats"],
    "disk-image-analysis": ["file-formats", "file-carving"],

    # OSINT
    "osint-username": ["osint-basics"],
    "osint-domain-dns": ["osint-basics", "network-basics"],
    "osint-metadata": ["osint-basics", "image-formats"],

    # Blockchain / mobile
    "integer-accounting": ["solidity-basics", "smart-contract-state"],
    "certificate-pinning-bypass": ["android-basics", "network-basics"],
    "hardcoded-secret": ["android-basics"],
}


# Human-readable concept blurbs for prerequisites that are not full techniques
CONCEPTS: Dict[str, str] = {
    "jwt-basics": "JSON Web Tokens: header.payload.signature; alg selects the verification method.",
    "auth-bypass": "Authentication checks that can be skipped or forged (claims, cookies, tokens).",
    "http-basics": "HTTP methods, status codes, headers, cookies, and request/response structure.",
    "web-input-handling": "How user input reaches sinks (SQL, templates, shells, files).",
    "template-engines": "Server-side templates (Jinja, Twig, etc.) and expression injection.",
    "c-memory": "Stack vs heap, buffers, pointers, and undefined behavior in C.",
    "stack-layout": "Local variables, saved frame pointer, return address on the stack.",
    "calling-convention": "How arguments and return addresses are passed (x86/x64).",
    "nx": "Non-executable stack/heap — forces code reuse (ret2libc/ROP) instead of shellcode.",
    "plt-got": "Procedure Linkage Table / Global Offset Table used for dynamic linking.",
    "gadgets": "Short instruction sequences ending in ret, used to build ROP chains.",
    "canary": "Stack canary/cookie checked before return to detect overflows.",
    "aslr": "Address Space Layout Randomization — addresses change per run.",
    "encoding-basics": "Base64, hex, URL encoding — reversible representations, not encryption.",
    "xor-properties": "XOR is its own inverse; key reuse leaks structure.",
    "frequency-analysis": "Letter/byte frequency used to recover classical or XOR keys.",
    "rsa-basics": "n = p*q, ciphertext = m^e mod n; private exponent d.",
    "modular-arithmetic": "Working modulo n; small e and related-message attacks.",
    "block-ciphers": "Fixed-size block encryption (AES, DES) and modes of operation.",
    "cbc": "Cipher Block Chaining — chaining IV and previous ciphertext blocks.",
    "assembly-basics": "Registers, instructions, control flow in disassembly.",
    "static-analysis": "Inspecting binaries/source without running them.",
    "debugger-basics": "Breakpoints, stepping, registers, and memory in a debugger.",
    "file-formats": "ELF/PE/Mach-O structure, sections, and headers.",
    "network-basics": "TCP/UDP, HTTP inside PCAP, streams and sessions.",
    "file-carving": "Recovering files from blobs by magic bytes and structure.",
    "image-formats": "PNG/JPEG structure and common stego channels.",
    "osint-basics": "Public sources, correlation, and verification of open data.",
    "solidity-basics": "Contracts, msg.sender, storage vs memory, external calls.",
    "smart-contract-state": "How contract state updates across calls and reentrancy risk.",
    "android-basics": "APK layout, manifest, activities/services, and local storage.",
    # Referenced by the prerequisites added for the heap, lattice and
    # obfuscation families. A prerequisite with no card is worse than none:
    # the curriculum schedules it and then has nothing to say.
    "heap-layout": "Chunks, bins, and allocator metadata — how an allocator reuses memory.",
    "lattice-basics": "Lattices as integer grids; short vectors recover small unknowns.",
    "static-analysis-basics": "Reading a binary or source tree without running it.",
    "control-flow": "Basic blocks, branches, and how obfuscation rewrites them.",
}


def prerequisites_for(technique: str) -> List[str]:
    return list(PREREQUISITES.get(technique, []))


def missing_prerequisites(technique: str, mastered: Set[str]) -> List[str]:
    """Return prereqs not yet in the mastered set (including transitive, depth-limited)."""
    needed: List[str] = []
    seen: Set[str] = set()

    def walk(t: str, depth: int) -> None:
        if depth > 4 or t in seen:
            return
        seen.add(t)
        for p in PREREQUISITES.get(t, []):
            if p not in mastered:
                needed.append(p)
            walk(p, depth + 1)

    walk(technique, 0)
    # unique preserve order
    out: List[str] = []
    for x in needed:
        if x not in out:
            out.append(x)
    return out


def explain_concept(name: str) -> str:
    if name in CONCEPTS:
        return CONCEPTS[name]
    if name in PREREQUISITES:
        return f"Technique '{name}' builds on: {', '.join(PREREQUISITES[name])}."
    return f"No concept card for '{name}' yet."


def teaching_path(technique: str, mastered: Set[str]) -> List[str]:
    """Ordered list of concepts/techniques to review before the target."""
    missing = missing_prerequisites(technique, mastered)
    # put pure concepts first, then technique nodes
    concepts = [m for m in missing if m in CONCEPTS]
    techs = [m for m in missing if m not in CONCEPTS]
    return concepts + techs + [technique]
