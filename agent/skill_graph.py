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
