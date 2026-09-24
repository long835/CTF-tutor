"""
agent/evidence.py

What would actually have to be true (items 5, 61, 12).

The verifier's weak point was that it could conclude "pass" from a
confident-sounding model reply plus a couple of evidence items, without
ever asking *which* observations a claim of this kind requires. That is how
an agent ends up asserting a format-string vulnerability because the word
"printf" appeared somewhere.

This module inverts it. Each technique declares the observations that would
support it, and — just as importantly — the ones that would argue against
it, plus the innocent explanations that produce the same signal. Then a
claim is graded against what was actually collected:

    SUPPORTED · LIKELY · UNCERTAIN · INSUFFICIENT_EVIDENCE · REFUTED

`INSUFFICIENT_EVIDENCE` is a first-class outcome, not a failure to decide.
An agent that can say "I don't know" hallucinates much less than one whose
only options are yes and no.

The `alternatives` field is the negative-knowledge idea from item 12: high
entropy is consistent with a packer, and equally consistent with
compression, an encrypted blob, or an embedded media asset. Listing the
lookalikes is what stops a single suggestive signal from being treated as
proof.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


class SupportLevel(str, Enum):
    """How well the collected evidence backs a claim."""

    SUPPORTED = "supported"                          # required signals present
    LIKELY = "likely"                                # most present
    UNCERTAIN = "uncertain"                          # some, with lookalikes open
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"  # not enough to say anything
    REFUTED = "refuted"                              # a contradicting signal is present

    @property
    def is_conclusive(self) -> bool:
        return self in (SupportLevel.SUPPORTED, SupportLevel.REFUTED)


@dataclass
class EvidenceRequirement:
    """What a claim about one technique needs in order to stand up."""

    technique: str
    required: List[str] = field(default_factory=list)      # all of these
    supporting: List[str] = field(default_factory=list)    # any of these help
    contradicting: List[str] = field(default_factory=list) # any of these refute
    alternatives: List[str] = field(default_factory=list)  # innocent explanations
    verification: str = ""                                 # how to confirm it

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "required": list(self.required),
            "supporting": list(self.supporting),
            "contradicting": list(self.contradicting),
            "alternatives": list(self.alternatives),
            "verification": self.verification,
        }


# Signals are matched as case-insensitive substrings/patterns against the
# collected evidence text. Kept phrase-based rather than regex-heavy so the
# table stays readable and editable by non-programmers.
REQUIREMENTS: Dict[str, EvidenceRequirement] = {
    "stack-buffer-overflow": EvidenceRequirement(
        technique="stack-buffer-overflow",
        required=["unbounded copy|gets|strcpy|read into|fixed buffer|no bounds",
                  "buffer|stack|local array"],
        supporting=["nx", "no canary", "pie disabled", "win function", "crash", "segfault"],
        contradicting=["bounds check|bounds checked|checks the length",
                       r"fgets with size|fgets\(.*sizeof|strncpy|snprintf",
                       "length validated|length is validated",
                       "rust|go|java|python source"],
        alternatives=["a bounded copy that merely looks unsafe",
                      "a heap buffer rather than a stack one",
                      "a read that is actually limited by the caller"],
        verification="Confirm the write crosses the saved return address, e.g. a controlled crash offset.",
    ),
    "format-string": EvidenceRequirement(
        technique="format-string",
        required=["printf|fprintf|sprintf|snprintf|syslog", "user.{0,20}format|non-literal format|variable format"],
        supporting=["%x|%n|%s in input", "stack values leaked", "unexpected output"],
        # Phrased as patterns, not as one exact sentence. The adversarial suite
        # showed "printf is called with a literal format string" slipping past
        # the old literal phrase, which let a refuted claim stay live.
        contradicting=["format string is a literal|literal format|constant format",
                       r"puts\(",
                       "passed as (?:an |the )?argument|not (?:as )?the format|"
                       "input passed as argument not format"],
        alternatives=["printf called with a correct literal format and the user data as an argument",
                      "a logging wrapper that escapes its input"],
        verification="Show that input reaches the format parameter, not an argument slot.",
    ),
    "ret2libc": EvidenceRequirement(
        technique="ret2libc",
        required=["overflow|control.{0,15}(rip|eip|return)", "nx|non-executable|dep"],
        supporting=["dynamically linked", "libc", "leak", "puts|printf plt"],
        contradicting=["statically linked", "nx disabled", "no overflow"],
        alternatives=["a ret2win where a convenient function already exists",
                      "shellcode being viable because NX is off"],
        verification="Confirm NX is on and an address leak is obtainable.",
    ),
    "sql-injection": EvidenceRequirement(
        technique="sql-injection",
        required=["query|select|insert|where|sql", "concat|interpolat|format|f-string|\\+ user|user input"],
        supporting=["sql error", "syntax error", "response differs on quote", "no parameterisation"],
        contradicting=["parameterised|prepared statement|placeholder|orm binding", "input escaped"],
        alternatives=["an ORM that looks like string building but parameterises underneath",
                      "a query whose variable part is a validated enum"],
        verification="Show the input reaching the query as syntax rather than as a bound parameter.",
    ),
    "jwt-none-bypass": EvidenceRequirement(
        technique="jwt-none-bypass",
        required=["jwt|json web token", "alg|algorithm"],
        supporting=["none", "header honoured", "verify without allowlist", "decode without verify"],
        contradicting=["algorithm allowlist", "alg pinned", "signature required", "algorithms=\\[.*\\]"],
        alternatives=["a library that already rejects alg=none by default",
                      "a token that is verified but whose payload is merely readable"],
        verification="Show the verifier selects its algorithm from the token header.",
    ),
    "jwt-alg-confusion": EvidenceRequirement(
        technique="jwt-alg-confusion",
        required=["jwt", "rs256|asymmetric|public key"],
        supporting=["jwks", "public key reachable", "generic verify", "hs256 accepted"],
        contradicting=["algorithm pinned to rs256", "key type checked"],
        alternatives=["a correctly pinned verifier that merely exposes its public key",
                      "a weak HMAC secret, which is a different bug"],
        verification="Show one verify call accepts both key types without distinguishing them.",
    ),
    "path-traversal": EvidenceRequirement(
        technique="path-traversal",
        required=["path|filename|file", "join|concat|open|read"],
        supporting=["user controlled path", "no normalisation", "prefix check only", "\\.\\."],
        contradicting=["normalised then validated", "allowlist of filenames", "basename only"],
        alternatives=["a validated allowlist that happens to take a name",
                      "a chroot or container boundary that contains the traversal"],
        verification="Show normalisation happens after, not before, the validation.",
    ),
    "ssti": EvidenceRequirement(
        technique="ssti",
        required=["template|render|jinja|twig|freemarker|handlebars"],
        supporting=["user input in template string", "expression evaluated", "engine in traceback"],
        contradicting=["input passed as context variable", "autoescape", "template is a constant"],
        alternatives=["reflected XSS, where the input is rendered but not evaluated",
                      "an input passed safely as a template variable"],
        verification="Show a trivial expression is evaluated rather than printed literally.",
    ),
    "packed-binary": EvidenceRequirement(
        technique="packed-binary",
        required=["entropy|packed|compressed section"],
        supporting=["few imports", "upx|themida|vmprotect", "unusual section name", "rwx section"],
        contradicting=["normal import table", "readable strings", "standard sections"],
        alternatives=["ordinary compressed data such as an embedded archive",
                      "an embedded media asset, which is also high entropy",
                      "an encrypted blob unrelated to packing"],
        verification="Identify a packer signature or observe the unpacking stub executing.",
    ),
    "xor-single-byte": EvidenceRequirement(
        technique="xor-single-byte",
        required=["xor|ciphertext|encoded bytes"],
        supporting=["short key", "repeating byte", "printable after xor", "frequency match"],
        contradicting=["key length > 1 established", "aes|rsa|block cipher"],
        alternatives=["a repeating multi-byte key, which needs a different approach",
                      "a simple substitution that is not XOR at all"],
        verification="Recover plaintext under a single key byte and score it against natural language.",
    ),
    "idor": EvidenceRequirement(
        technique="idor",
        required=["id|identifier|object reference", "fetch|lookup|get|load"],
        supporting=["sequential id", "no ownership check", "other user's record accessible"],
        contradicting=["ownership verified", "authorization check present", "scoped query"],
        alternatives=["a deliberately public resource",
                      "an unguessable identifier that is checked anyway"],
        verification="Show a record belonging to another principal is returned without an authorization check.",
    ),
    "steganography": EvidenceRequirement(
        technique="steganography",
        required=["image|audio|media file"],
        supporting=["size mismatch", "extra chunk", "lsb anomaly", "appended data"],
        contradicting=["metadata contains the answer", "data appended after eof", "file is a plain archive"],
        alternatives=["data hidden in metadata rather than pixels",
                      "a second file simply concatenated on the end",
                      "an extra format chunk a viewer ignores"],
        verification="Check structure and trailing bytes before concluding pixel-level embedding.",
    ),

    # -----------------------------------------------------------------------
    # Added after the knowledge-graph join (item 11) showed 51 techniques that
    # the corpus teaches but no rubric could grade. Without a rubric, a claim
    # about one of these could only ever come back INSUFFICIENT_EVIDENCE --
    # technically honest, practically useless, since the agent then had no way
    # to ever conclude anything about two thirds of what it was teaching.
    #
    # Ordered by corpus coverage. Every `required` signal here is one that a
    # tool in the capability registry actually produces; `agent/knowledge_graph
    # .audit()` fails with `unobservable_rubric` otherwise, and that check runs
    # in the test suite.
    # -----------------------------------------------------------------------

    "sqli-union": EvidenceRequirement(
        technique="sqli-union",
        required=["query|select|insert|where|sql", "rendered rows|result table|listing|select that renders"],
        supporting=["column-count error", "concat|interpolat|format|f-string", "text column identified"],
        contradicting=["parameterised|prepared statement|placeholder|orm binding",
                       "no rendered output|blind|response identical"],
        alternatives=["a blind injection where no rows are rendered back",
                      "an error-based leak that never needs UNION"],
        verification="Match the column count and types, then show data from a second table rendered.",
    ),
    "sqli-blind-boolean": EvidenceRequirement(
        technique="sqli-blind-boolean",
        required=["query|select|insert|where|sql", "response differs|true vs false|length differs"],
        supporting=["no error text", "concat|interpolat|format|f-string", "timing difference"],
        contradicting=["parameterised|prepared statement|placeholder|orm binding",
                       "identical responses|no observable difference"],
        alternatives=["an unrelated cause for the response difference, such as caching",
                      "a rate limiter producing the timing difference"],
        verification="Show a condition that is always true and one always false produce reliably different responses.",
    ),
    "ssrf": EvidenceRequirement(
        technique="ssrf",
        required=["url|address|endpoint parameter", "server.{0,20}(fetch|request|curl|open)|outbound request"],
        supporting=["redirect", "internal host reachable", "metadata endpoint", "protocol accepted"],
        contradicting=["allowlist of hosts|host allowlist", "scheme restricted", "no outbound network",
                       "resolved address validated"],
        alternatives=["a client-side fetch the browser makes, not the server",
                      "an open redirect with no server-side request behind it"],
        verification="Show the request originates from the server, e.g. an interaction from the server's own address.",
    ),
    "xxe": EvidenceRequirement(
        technique="xxe",
        required=["xml|soap|svg|docx", "external entity|doctype|entity declaration|parser"],
        supporting=["file read", "dtd fetched", "error discloses path", "resolve_entities"],
        contradicting=["entity resolution disabled", "defusedxml", "dtd disallowed", "schema-validated only"],
        alternatives=["an XML parser that accepts the document but never resolves entities",
                      "a path disclosure from an ordinary parse error"],
        verification="Show the parser resolves a declared entity, not merely that XML is accepted.",
    ),
    "xss-reflected": EvidenceRequirement(
        technique="xss-reflected",
        required=["parameter|input", "rendered|reflected|echoed into.{0,20}(page|html|response)"],
        supporting=["no escaping", "attribute context", "script context", "content-type html"],
        contradicting=["escaped|html-encoded|autoescape", "content security policy blocks inline",
                       "rendered as text|textContent"],
        alternatives=["output that is reflected but HTML-encoded",
                      "a JSON response a browser never renders as HTML"],
        verification="Show the reflection lands in a context where markup is parsed, not encoded.",
    ),
    "prototype-pollution": EvidenceRequirement(
        technique="prototype-pollution",
        required=["merge|extend|clone|assign|set path", "user.{0,20}(key|property|path)|__proto__|constructor"],
        supporting=["deep merge", "no key filtering", "object literal target", "later behaviour changes"],
        contradicting=["key allowlist|filters __proto__|null-prototype object", "map instead of object",
                       "frozen prototype"],
        alternatives=["a deep merge that copies only own enumerable keys",
                      "a library that already rejects the dangerous keys"],
        verification="Show a polluted prototype key is visible on an unrelated object afterwards.",
    ),
    "deserialization-rce": EvidenceRequirement(
        technique="deserialization-rce",
        required=["deserialis|unserialize|pickle|readObject|yaml.load|marshal", "user.{0,20}(data|input|payload)"],
        supporting=["gadget class available", "magic method", "no type restriction", "binary blob in a cookie"],
        contradicting=["safe_load|allowlist of classes|type filter", "json only|signed payload",
                       "hmac verified before parse"],
        alternatives=["a signed serialised blob that cannot be tampered with",
                      "a parser that only produces plain data types"],
        verification="Show attacker-controlled bytes reach the deserialiser before any signature check.",
    ),
    "race-condition": EvidenceRequirement(
        technique="race-condition",
        required=["check.{0,20}then.{0,20}(use|write|update)|read-modify-write|concurrent",
                  "shared (state|resource|balance|counter)|same record"],
        supporting=["no lock", "no transaction", "retry endpoint", "limit enforced after the effect"],
        contradicting=["transaction|select for update|atomic|mutex|lock held", "idempotency key",
                       "single-threaded and serialised"],
        alternatives=["a sequence that only looks concurrent in the logs",
                      "duplicate requests that the server already de-duplicates"],
        verification="Show two overlapping requests both pass the check before either writes.",
    ),
    "solidity-access-control": EvidenceRequirement(
        technique="solidity-access-control",
        required=["role|permission|privilege|admin|modifier|owner",
                  "check|guard|authorize|enforce|onlyowner|require"],
        supporting=["client-side only check", "hidden endpoint", "role from request", "no server-side enforcement"],
        contradicting=["server-side enforcement present", "role derived from session",
                       "deny by default|default deny"],
        alternatives=["an endpoint that is intentionally public",
                      "a UI-only restriction that the server also enforces"],
        verification="Call the endpoint with a lower-privileged principal and show the action still happens.",
    ),
    "auth-bypass": EvidenceRequirement(
        technique="auth-bypass",
        required=["login|session|authentication|credential", "skip|forge|bypass|trusted without|not verified"],
        supporting=["client-controlled claim", "cookie", "session", "predictable token"],
        contradicting=["signature required", "verified server-side", "algorithm allowlist",
                       "constant-time comparison"],
        alternatives=["a token that is forgeable in form but verified in practice",
                      "a second factor that still blocks the flow"],
        verification="Reach an authenticated action without presenting valid credentials.",
    ),
    "heap-overflow": EvidenceRequirement(
        technique="heap-overflow",
        required=["malloc|calloc|realloc|new\\[|heap (buffer|chunk)",
                  "unbounded copy|read into|no bounds|memcpy|size mismatch"],
        supporting=["chunk metadata", "adjacent allocation", "crash", "size from user"],
        contradicting=["bounds checked", "length validated", "allocation sized from the copy",
                       "rust|go|java|python source"],
        alternatives=["a stack buffer that happens to hold heap pointers",
                      "an allocator abort that is not an overflow at all"],
        verification="Show the write passes the end of its own chunk into neighbouring heap data.",
    ),
    "use-after-free": EvidenceRequirement(
        technique="use-after-free",
        required=["free|delete|release", "used|dereferenced|called after|still referenced|dangling"],
        supporting=["pointer not nulled", "reallocation of the same size", "crash", "vtable|function pointer"],
        contradicting=["pointer set to null after free", "ownership transferred", "refcounted",
                       "rust|go|java|python source"],
        alternatives=["a double free, which is a different bug with the same crash",
                      "a read of uninitialised memory that was never freed"],
        verification="Show the freed chunk is reused while the stale pointer is still dereferenced.",
    ),
    "off-by-one": EvidenceRequirement(
        technique="off-by-one",
        required=["<=|index|length|size|count", "loop|copy|buffer|fixed buffer"],
        supporting=["one byte past", "null terminator", "boundary", "adjacent variable changes"],
        contradicting=["bounds checked", "length validated", "size - 1 used"],
        alternatives=["a correct loop whose bound merely looks suspicious",
                      "a deliberate sentinel write inside the allocation"],
        verification="Show exactly one element past the allocated end is written.",
    ),
    "integer-overflow": EvidenceRequirement(
        technique="integer-overflow",
        required=["int|size_t|short|length|count|multiply|add", "wrap|overflow|negative|cast|truncat"],
        supporting=["size computed from user input", "signed/unsigned mix", "allocation size", "no range check"],
        contradicting=["range checked", "checked arithmetic|saturating", "size validated before allocation",
                       "arbitrary precision|python int"],
        alternatives=["a value that is large but never wraps in this width",
                      "a cast that is lossy but never reaches an allocation"],
        verification="Show the computed size wraps, and that the wrapped value is the one used.",
    ),
    "rop-chain": EvidenceRequirement(
        technique="rop-chain",
        required=["overflow|control.{0,15}(rip|eip|return)", "nx|non-executable|dep"],
        supporting=["gadgets", "statically linked", "libc", "controllable rip", "no canary"],
        contradicting=["nx disabled", "no overflow", "canary intact and unknown"],
        alternatives=["a single ret2win that needs no chain at all",
                      "shellcode being viable because NX is off"],
        verification="Show enough gadgets are reachable to set up the call, not merely that NX is on.",
    ),
    "canary-bypass": EvidenceRequirement(
        technique="canary-bypass",
        required=["canary", "leak|stack values leaked|overwrite partially|fork|brute"],
        supporting=["overflow|control", "format string", "child process reuses the canary", "unexpected output"],
        contradicting=["no canary", "canary value never observable", "process re-randomises per request"],
        alternatives=["an overflow that never reaches the canary",
                      "a crash caused by something other than the canary check"],
        verification="Show the canary value is recoverable or bypassable before claiming the overflow lands.",
    ),
    "aslr-bypass": EvidenceRequirement(
        technique="aslr-bypass",
        required=["aslr|pie enabled|randomis", "leak|address disclosed|stack values leaked|offset"],
        supporting=["libc", "format string", "partial overwrite", "puts|printf plt"],
        contradicting=["pie disabled", "no leak available", "addresses fixed"],
        alternatives=["a fixed-address binary where no bypass is needed",
                      "a leak of a value that is not actually an address"],
        verification="Show a leaked value resolves to a known base after subtracting its offset.",
    ),
    "anti-debug-bypass": EvidenceRequirement(
        technique="anti-debug-bypass",
        required=["ptrace|isdebuggerpresent|anti-debug|timing check|breakpoint detection",
                  "disassembly|imports|symbols|register state"],
        supporting=["exits early under a debugger", "different behaviour when traced", "tls callback"],
        contradicting=["runs identically under a debugger", "no anti-debug import"],
        alternatives=["a crash under the debugger caused by the environment, not a check",
                      "an ordinary error path that happens to trigger while tracing"],
        verification="Show the specific check, and that patching or bypassing it changes execution.",
    ),
    "string-decryption": EvidenceRequirement(
        technique="string-decryption",
        required=["few readable strings|no readable strings|obfuscated strings",
                  "xor|decrypt|decode routine|disassembly"],
        supporting=["called before use", "key in binary", "high entropy", "same routine on many buffers"],
        contradicting=["readable strings", "strings already in plaintext"],
        alternatives=["strings stored in a resource section the tool did not scan",
                      "a compiler-encoded literal that is not an anti-analysis measure"],
        verification="Run or emulate the routine on one buffer and show meaningful plaintext.",
    ),
    "padding-oracle": EvidenceRequirement(
        technique="padding-oracle",
        required=["cbc", "padding"],
        supporting=["error differs on bad padding", "iv reuse", "ciphertext accepted from the client",
                    "aes|rsa|block cipher"],
        contradicting=["authenticated encryption|gcm|encrypt-then-mac", "identical error for all failures",
                       "mac verified before decrypt"],
        alternatives=["a generic decryption error that leaks nothing about padding",
                      "an authenticated mode where tampering is rejected first"],
        verification="Show two ciphertexts differing only in padding validity produce distinguishable responses.",
    ),
    "ecb-byte-at-a-time": EvidenceRequirement(
        technique="ecb-byte-at-a-time",
        required=["ecb", "user input prepended|attacker-controlled prefix|input concatenated before the secret"],
        supporting=["repeating byte", "identical blocks", "block size detected", "aes|rsa|block cipher"],
        contradicting=["cbc", "random iv per block", "input appended after the secret only",
                       "authenticated encryption|gcm"],
        alternatives=["a CBC mode that merely looks blocky in the output",
                      "deterministic output caused by a fixed IV rather than ECB"],
        verification="Show two identical plaintext blocks produce identical ciphertext blocks.",
    ),
    "hash-length-extension": EvidenceRequirement(
        technique="hash-length-extension",
        required=["md5|sha", "secret.{0,25}(prefix|prepended)|hash\\(secret \\+|merkle"],
        supporting=["length known", "hash appended as a token", "no hmac", "message extendable"],
        contradicting=["hmac", "sha3|blake", "secret appended not prepended", "length unknown and unguessable"],
        alternatives=["an HMAC that looks like a bare hash in the token",
                      "a construction where the secret is appended, which is not extendable"],
        verification="Extend a known message and show the server accepts the recomputed digest.",
    ),
    "rsa-small-e": EvidenceRequirement(
        technique="rsa-small-e",
        required=["modulus", "public exponent|small exponent"],
        supporting=["e = 3", "no padding", "short message", "ciphertext smaller than the modulus"],
        contradicting=["oaep|pkcs#1 v2|padding applied", "e = 65537", "message longer than the modulus root"],
        alternatives=["a small exponent that is still safe because the message is padded",
                      "a message long enough that no integer root exists"],
        verification="Take the integer e-th root of the ciphertext and show it decodes to the plaintext.",
    ),
    "rsa-common-modulus": EvidenceRequirement(
        technique="rsa-common-modulus",
        required=["modulus", "two (ciphertexts|exponents)|same n|shared modulus"],
        supporting=["public exponent", "coprime exponents", "same plaintext encrypted twice"],
        contradicting=["different modulus", "exponents share a factor", "different plaintexts"],
        alternatives=["two keys that merely share a bit length, not a modulus",
                      "the same exponent used twice, which this attack cannot use"],
        verification="Confirm gcd(e1, e2) = 1 and that both ciphertexts encrypt the same message.",
    ),
    "rsa-factorisation": EvidenceRequirement(
        technique="rsa-factorisation",
        required=["modulus", "small modulus|close primes|shared factor|weak parameters"],
        supporting=["public exponent", "n factors quickly", "primes near the square root", "key reuse"],
        contradicting=["2048-bit modulus", "primes independent and well separated",
                       "modulus does not factor"],
        alternatives=["a modulus that is large but merely printed in an unusual form",
                      "a weak-looking key that still resists factoring in practice"],
        verification="Factor n and reconstruct d, then decrypt a known ciphertext.",
    ),
    "xor-repeating-key": EvidenceRequirement(
        technique="xor-repeating-key",
        required=["xor|ciphertext|encoded bytes", "key length > 1 established|repeating byte|key length"],
        supporting=["frequency match", "printable after xor", "hamming distance minimum", "high entropy"],
        contradicting=["short key", "single byte key recovered", "aes|rsa|block cipher"],
        alternatives=["a single-byte key, which needs no key-length search",
                      "a stream cipher whose keystream does not repeat"],
        verification="Recover the key length, then solve each column as a single-byte XOR and score the result.",
    ),
    "classical-caesar": EvidenceRequirement(
        technique="classical-caesar",
        required=["letters only|alphabetic ciphertext|rot", "shift|caesar|rotation"],
        supporting=["frequency match", "readable strings", "word lengths preserved"],
        contradicting=["frequency flat|frequency match absent", "non-alphabetic bytes",
                       "high entropy"],
        alternatives=["a general substitution cipher, which a single shift will not solve",
                      "ROT13 applied twice, leaving the text unchanged"],
        verification="Show one of the 25 shifts produces natural language across the whole message.",
    ),
    "classical-substitution": EvidenceRequirement(
        technique="classical-substitution",
        required=["letters only|alphabetic ciphertext", "frequency match|letter frequency|word pattern"],
        supporting=["word lengths preserved", "repeated short words", "readable strings"],
        contradicting=["high entropy", "shift|caesar|rotation solves it", "non-alphabetic bytes"],
        alternatives=["a Caesar shift, which is a substitution with only 25 possibilities",
                      "a transposition, where the letters are right but the order is not"],
        verification="Solve the mapping and show the whole message reads, not just a fragment.",
    ),
    "encoding-recognition": EvidenceRequirement(
        technique="encoding-recognition",
        required=["base64|hex|rot|url encoding|encoded bytes"],
        supporting=["printable after xor", "nested encoding", "padding", "alphabet matches"],
        contradicting=["high entropy", "decodes to nothing printable"],
        alternatives=["ciphertext that happens to be base64-wrapped for transport",
                      "compressed data that decodes to bytes, not text"],
        verification="Decode and show the result is meaningful, not merely well-formed.",
    ),
    "multilayer-encoding": EvidenceRequirement(
        technique="multilayer-encoding",
        required=["base64|hex|rot|url encoding|encoded bytes", "nested encoding|nested archive|decodes again"],
        supporting=["printable after xor", "compressed data", "repeated decode steps"],
        contradicting=["decodes to nothing printable", "single decode yields the answer"],
        alternatives=["one encoding whose output happens to look like another",
                      "an encoding wrapped around genuine ciphertext, where decoding stops early"],
        verification="Decode each layer and show every step yields a well-formed input for the next.",
    ),
    "pcap-carving": EvidenceRequirement(
        technique="pcap-carving",
        required=["pcap|capture|network traffic", "stream|session|transferred file|http object"],
        supporting=["magic", "file type", "embedded", "size mismatch"],
        contradicting=["encrypted session only|tls with no keys", "no payload captured"],
        alternatives=["a capture where the interesting data is in the metadata, not a payload",
                      "a transfer that is present but encrypted"],
        verification="Reassemble the stream and show the carved object is a valid file.",
    ),
    "file-carving": EvidenceRequirement(
        technique="file-carving",
        required=["magic|file signature|header bytes", "embedded|appended data|blob|data appended after eof"],
        supporting=["size mismatch", "file type", "nested archive", "extra chunk"],
        contradicting=["file is a plain archive", "no embedded signature found"],
        alternatives=["an ordinary container format whose parts look like separate files",
                      "a coincidental byte sequence that matches a magic number"],
        verification="Extract from the offset and show the carved bytes parse as the claimed format.",
    ),
    "image-metadata": EvidenceRequirement(
        technique="image-metadata",
        required=["image|audio|media file", "metadata|exif|thumbnail|timestamps"],
        supporting=["magic", "file type", "embedded", "gps"],
        contradicting=["metadata stripped", "no exif block"],
        alternatives=["pixel-level steganography, where metadata is a distraction",
                      "a thumbnail that differs from the image for innocent reasons"],
        verification="Read the specific tag and show it carries the information claimed.",
    ),
    "memory-forensics": EvidenceRequirement(
        technique="memory-forensics",
        required=["memory (image|dump)|raw dump|volatile", "process|handle|injected|readable strings"],
        supporting=["magic", "file type", "timestamps", "embedded"],
        contradicting=["not a memory image", "profile does not match the dump"],
        alternatives=["a disk image mistaken for a memory dump",
                      "strings present in the dump that came from a file, not from process memory"],
        verification="Attribute the finding to a specific process or structure, not just to a string in the dump.",
    ),
    "log-analysis": EvidenceRequirement(
        technique="log-analysis",
        required=["log|access log|audit trail|timestamps", "sequence|pattern|anomaly|readable strings"],
        supporting=["repeated requests", "status codes", "user agent", "time gap"],
        contradicting=["logs truncated|no relevant window", "single entry only"],
        alternatives=["ordinary scanner noise that resembles an attack",
                      "a clock skew producing an apparent ordering that did not happen"],
        verification="Show the events in order, with timestamps, supporting the sequence claimed.",
    ),
    "nested-archive": EvidenceRequirement(
        technique="nested-archive",
        required=["file is a plain archive|nested archive|compressed data", "another archive inside|repeated extraction"],
        supporting=["magic", "file type", "size mismatch", "many levels"],
        contradicting=["single archive only", "extraction yields the answer immediately"],
        alternatives=["one archive containing many files, which is not nesting",
                      "a compression bomb, where depth is the trap rather than the puzzle"],
        verification="Extract each level and show the next archive is genuinely inside the previous one.",
    ),
    "osint-geolocation": EvidenceRequirement(
        technique="osint-geolocation",
        required=["image|audio|media file|photograph|screenshot",
                  "landmark|signage|metadata|exif|terrain|street furniture"],
        supporting=["gps", "timestamps", "language on signs", "vegetation or architecture"],
        contradicting=["metadata stripped and no visual cue", "stock photograph"],
        alternatives=["EXIF GPS that was set by the camera's last known fix, not the scene",
                      "a stock or reused image whose location is not the subject's"],
        verification="Corroborate at least two independent cues before naming a location.",
    ),
    "osint-username": EvidenceRequirement(
        technique="osint-username",
        required=["username|handle|account name", "reused|same handle|cross-platform|profile"],
        supporting=["matching avatar", "matching bio", "linked account", "timestamps"],
        contradicting=["common word handle|generic username", "no corroborating detail"],
        alternatives=["a coincidental handle collision between two unrelated people",
                      "an impersonation account reusing someone else's handle"],
        verification="Corroborate with a second independent signal before linking accounts to one person.",
    ),
    "osint-domain-dns": EvidenceRequirement(
        technique="osint-domain-dns",
        required=["domain|dns|whois|certificate transparency", "record|subdomain|registrant|nameserver"],
        supporting=["shared registrar", "shared ip", "historical record", "timestamps"],
        contradicting=["privacy-protected registration", "shared hosting|cdn address"],
        alternatives=["a shared CDN or hosting address that links nothing about ownership",
                      "a parked domain whose records say nothing about its operator"],
        verification="Confirm the link with a record that is specific to the owner, not to their host.",
    ),
    "reentrancy": EvidenceRequirement(
        technique="reentrancy",
        required=["external call|call\\.value|transfer to a contract|send",
                  "state (updated|written) after|balance updated after the call"],
        supporting=["no reentrancy guard", "fallback function", "shared state", "withdraw pattern"],
        contradicting=["checks-effects-interactions|state updated before the call",
                       "nonreentrant|reentrancy guard", "no external call"],
        alternatives=["a call to an address that cannot execute code",
                      "a cross-function race that is not classic reentrancy"],
        verification="Show state read during the re-entrant call is the pre-update value.",
    ),
    "insecure-storage": EvidenceRequirement(
        technique="insecure-storage",
        required=["shared ?preferences|sqlite|local storage|keystore|file written",
                  "plaintext|unencrypted|hardcoded|world-readable"],
        supporting=["credential", "token", "readable strings", "backup allowed"],
        contradicting=["encrypted at rest", "keystore-backed", "permissions restricted"],
        alternatives=["a cached value that is not itself a secret",
                      "an encrypted store whose key is held by the platform"],
        verification="Read the artefact from a non-privileged context and show the secret is recoverable.",
    ),
    "android-exported-component": EvidenceRequirement(
        technique="android-exported-component",
        required=["manifest|activity|service|receiver|provider", "exported|intent-filter"],
        supporting=["no permission attribute", "deep link", "implicit intent", "readable strings"],
        contradicting=["exported=\"false\"", "permission required", "signature-level permission"],
        alternatives=["a component exported deliberately as the app's public entry point",
                      "an intent filter guarded by a signature permission"],
        verification="Launch the component from a separate app and show it acts without permission.",
    ),
    "hardcoded-secret": EvidenceRequirement(
        technique="hardcoded-secret",
        required=["readable strings|symbols|imports|source", "key|token|password|credential|api key"],
        supporting=["high entropy", "base64", "committed in source", "same value in several places"],
        contradicting=["value read from the environment", "placeholder|example|dummy",
                       "fetched at runtime"],
        alternatives=["a public identifier that looks secret but is not",
                      "a test fixture value that is never used in production"],
        verification="Show the value is used as a credential, not merely that it looks like one.",
    ),
    "control-flow-flattening": EvidenceRequirement(
        technique="control-flow-flattening",
        required=["disassembly|control flow graph|basic blocks",
                  "dispatcher|state variable|switch over a state|flattened"],
        supporting=["single large switch", "no natural loops", "opaque predicates", "symbols"],
        contradicting=["ordinary control flow", "readable structure", "compiler-typical layout"],
        alternatives=["a large state machine that was written that way by hand",
                      "an interpreter loop, which looks similar but is the program's real design"],
        verification="Recover the state ordering and show the blocks form the original sequence.",
    ),
    "vm-obfuscation": EvidenceRequirement(
        technique="vm-obfuscation",
        required=["disassembly|control flow graph|basic blocks",
                  "bytecode|handler table|dispatch loop|virtual (machine|instruction)"],
        supporting=["opcode array", "fetch-decode-execute", "custom instruction set", "readable strings"],
        contradicting=["ordinary control flow", "no handler table", "native instructions only"],
        alternatives=["an ordinary interpreter that is the program's actual purpose",
                      "control-flow flattening, which has a dispatcher but no bytecode"],
        verification="Map opcodes to handlers and show a sample program traces through them.",
    ),
    "algorithm-recovery": EvidenceRequirement(
        technique="algorithm-recovery",
        required=["disassembly|readable strings|symbols|imports",
                  "constant|s-box|magic value|round|transform"],
        supporting=["known constant matches", "loop with fixed count", "table lookup", "register state"],
        contradicting=["library call does the work", "no transform present"],
        alternatives=["a standard library routine inlined by the compiler",
                      "a well-known algorithm with modified constants, which is not a new algorithm"],
        verification="Reimplement the routine and show it reproduces the program's output exactly.",
    ),
    "esoteric-lang": EvidenceRequirement(
        technique="esoteric-lang",
        required=["readable strings|source|text", "unusual character set|repeating operators|non-standard syntax"],
        supporting=["brainfuck|whitespace|malbolge|piet", "no recognisable keywords", "high symbol density"],
        contradicting=["recognisable language syntax", "compiles as a known language"],
        alternatives=["minified or obfuscated code in an ordinary language",
                      "an encoding of text rather than a program at all"],
        verification="Run it in the identified interpreter and show the output matches the challenge.",
    ),
    "certificate-pinning-bypass": EvidenceRequirement(
        technique="certificate-pinning-bypass",
        required=["manifest|network security config|trustmanager|pinning",
                  "certificate|pin|ca|trust anchor"],
        supporting=["custom trustmanager", "readable strings", "traffic not interceptable", "hook point"],
        contradicting=["no pinning present", "system trust store only"],
        alternatives=["a proxy failure that has nothing to do with pinning",
                      "a second channel that does not go through the pinned client"],
        verification="Show traffic becomes interceptable only after the specific check is neutralised.",
    ),
    "integer-accounting": EvidenceRequirement(
        technique="integer-accounting",
        required=["balance|accounting|supply|amount", "add|subtract|multiply|divide|arithmetic"],
        supporting=["no invariant check", "unchecked arithmetic", "rounding", "shared (state|resource|balance|counter)"],
        contradicting=["safemath|checked arithmetic", "invariant asserted", "balances reconciled"],
        alternatives=["a rounding difference that is intended and bounded",
                      "an accounting quirk that never lets value leave the contract"],
        verification="State the invariant, then show a sequence of operations that breaks it.",
    ),
    "tcache-poisoning": EvidenceRequirement(
        technique="tcache-poisoning",
        required=['tcache|freed chunk|free list', 'fd pointer|next pointer|poison'],
        supporting=['glibc 2.26', 'same-size allocate', 'uaf|use after free', 'double free'],
        contradicting=['safe-linking enforced without leak', 'tcache disabled'],
        alternatives=['a fastbin attack on an older glibc'],
        verification='Show a free slot whose next pointer is attacker-controlled before the next malloc of that size.',
    ),
    "fastbin-dup": EvidenceRequirement(
        technique="fastbin-dup",
        required=['fastbin|double free', 'same chunk returned|allocate twice'],
        supporting=['size field forge', 'LIFO free list'],
        contradicting=['tcache only path', 'double-free detector trips'],
        alternatives=['tcache poisoning on a newer glibc'],
        verification='Demonstrate the same address handed out by two consecutive allocations after a double-free or size forge.',
    ),
    "unsorted-bin-leak": EvidenceRequirement(
        technique="unsorted-bin-leak",
        required=['unsorted bin|large free|main_arena', 'leak|read freed|print after free'],
        supporting=['libc pointer', 'bk|fd residual'],
        contradicting=['tcache absorbs the free', 'buffer zeroed on free'],
        alternatives=['a format-string stack leak'],
        verification='Read a residual main_arena or libc pointer from a chunk that entered the unsorted bin.',
    ),
    "ret2csu": EvidenceRequirement(
        technique="ret2csu",
        required=['csu|__libc_csu_init|gadget', 'control registers|rdi|rsi|rdx'],
        supporting=['limited gadget set', 'rop chain'],
        contradicting=['plenty of individual pop gadgets'],
        alternatives=['ordinary ret2libc with pops'],
        verification='Show the csu gadgets setting the argument registers used by the subsequent call.',
    ),
    "srop": EvidenceRequirement(
        technique="srop",
        required=['sigreturn|rt_sigreturn|ucontext', 'syscall gadget|frame on stack'],
        supporting=['large stack control', 'execve frame'],
        contradicting=['no syscall gadget'],
        alternatives=['ordinary ROP with enough pops'],
        verification='Demonstrate a forged signal frame restored by sigreturn that yields controlled registers.',
    ),
    "seccomp-escape": EvidenceRequirement(
        technique="seccomp-escape",
        required=['seccomp|prctl|bpf filter|syscall blacklist', 'allowed primitive|open|read|write|orw'],
        supporting=['execve blocked'],
        contradicting=['filter allows execve'],
        alternatives=['escaping before the filter is installed'],
        verification='List the still-allowed syscalls and show a path that reaches the flag under the filter.',
    ),
    "info-leak": EvidenceRequirement(
        technique="info-leak",
        required=['leak|print|format string|uninitialized', 'address|canary|libc|heap pointer'],
        supporting=['%p', 'freed buffer echoed'],
        contradicting=['all output sanitized'],
        alternatives=['symbols available without a leak'],
        verification='Show attacker-controlled output that reveals a secret address or canary value.',
    ),
    "rsa-wiener": EvidenceRequirement(
        technique="rsa-wiener",
        required=['rsa|n and e', 'small d|wiener|continued fraction'],
        supporting=['large e'],
        contradicting=['d is full size'],
        alternatives=['factorisation of a weak n'],
        verification='Recover d via continued fractions (or state the Wiener bound that applies).',
    ),
    "rsa-franklin-reiter": EvidenceRequirement(
        technique="rsa-franklin-reiter",
        required=['two ciphertexts|same modulus', 'related plaintext|linear relation|small e'],
        supporting=['stereotyped prefix', 'm and m+1'],
        contradicting=['independent random plaintexts'],
        alternatives=['broadcast attack across different moduli'],
        verification='Recover one plaintext from the known algebraic relation between the two messages.',
    ),
    "rsa-broadcast": EvidenceRequirement(
        technique="rsa-broadcast",
        required=['same message|broadcast', 'multiple moduli|crt', 'small e'],
        supporting=['hastad'],
        contradicting=['different messages per recipient'],
        alternatives=['Franklin-Reiter on one modulus'],
        verification='Combine ciphertexts with CRT and take the integer e-th root of the result.',
    ),
    "ecdsa-nonce-reuse": EvidenceRequirement(
        technique="ecdsa-nonce-reuse",
        required=['ecdsa|signature', 'same r|nonce reuse|identical k'],
        supporting=['two signatures'],
        contradicting=['all r values unique'],
        alternatives=['lattice attack on biased nonces'],
        verification='From two signatures sharing r, recover k then the private key d.',
    ),
    "lattice-reduction": EvidenceRequirement(
        technique="lattice-reduction",
        required=['lattice|lll|bkz|coppersmith|hidden number', 'partial bits|approximate equation'],
        supporting=['known MSBs of nonce'],
        contradicting=['full randomness with no partial information'],
        alternatives=['direct Wiener continued fractions'],
        verification='Exhibit the lattice basis and the short vector that yields the secret.',
    ),
    "ctr-nonce-reuse": EvidenceRequirement(
        technique="ctr-nonce-reuse",
        required=['ctr|gcm|stream cipher', 'same nonce|iv reuse|identical counter'],
        supporting=['xor of ciphertexts', 'crib dragging'],
        contradicting=['unique nonces enforced'],
        alternatives=['ecb block rearrangement'],
        verification='XOR two ciphertexts that share a nonce and recover structure or plaintext via crib.',
    ),
    "http-request-smuggling": EvidenceRequirement(
        technique="http-request-smuggling",
        required=['content-length|transfer-encoding|cl.te|te.cl', 'proxy|front-end|desync'],
        supporting=['poisoned queue', 'cdn'],
        contradicting=['http/2 end-to-end'],
        alternatives=['ordinary path traversal'],
        verification='Show front-end and back-end disagree on request boundaries so one bytestring becomes two requests.',
    ),
    "graphql-introspection": EvidenceRequirement(
        technique="graphql-introspection",
        required=['graphql|__schema|__type', 'introspection'],
        supporting=['/graphql', 'nested query'],
        contradicting=['introspection disabled'],
        alternatives=['REST endpoint enumeration'],
        verification='Run an introspection query and list sensitive fields or mutations that should not be public.',
    ),
    "nosql-injection": EvidenceRequirement(
        technique="nosql-injection",
        required=['mongo|nosql|\\$ne|\\$gt|\\$regex', 'json operator|query object'],
        supporting=['login bypass'],
        contradicting=['parameterized driver only'],
        alternatives=['ordinary sql injection'],
        verification='Show an operator object changing query logic to bypass a check.',
    ),
    "oauth-flow-abuse": EvidenceRequirement(
        technique="oauth-flow-abuse",
        required=['oauth|oidc|redirect_uri|authorization code', 'state|callback'],
        supporting=['open redirect'],
        contradicting=['strict redirect allowlist'],
        alternatives=['password reset token theft'],
        verification='Abuse redirect_uri or state handling to capture a code or link an attacker identity.',
    ),
    "cors-misconfiguration": EvidenceRequirement(
        technique="cors-misconfiguration",
        required=['access-control-allow-origin|cors', 'credentials|reflect origin'],
        supporting=['null origin'],
        contradicting=['fixed allowlist'],
        alternatives=['csrf that does not need to read the response'],
        verification='From a malicious origin, read an authenticated response that should have been opaque.',
    ),
    "go-binary-analysis": EvidenceRequirement(
        technique="go-binary-analysis",
        required=['go binary|golang|gopclntab|runtime.main', 'pclntab|buildid'],
        supporting=['itab'],
        contradicting=['pure c binary'],
        alternatives=['generic elf reverse engineering'],
        verification='Recover function or type names from pclntab/itab.',
    ),
    "rust-binary-analysis": EvidenceRequirement(
        technique="rust-binary-analysis",
        required=['rust|rust_begin_unwind|core::panicking', 'mangled rust symbol'],
        supporting=['panic message'],
        contradicting=['no rust runtime strings'],
        alternatives=['c++ itanium mangling'],
        verification='Locate the check via panic strings or demangled symbols.',
    ),
    "dotnet-deobfuscation": EvidenceRequirement(
        technique="dotnet-deobfuscation",
        required=['\\.net|mscoree|clr|dnspy|ilspy', 'obfuscat|confuser|smartassembly'],
        supporting=['encrypted resource'],
        contradicting=['native only pe'],
        alternatives=['native unpacking of a non-CLR packer'],
        verification='Deobfuscate to readable IL/C# and identify the flag check.',
    ),
    "api-hashing": EvidenceRequirement(
        technique="api-hashing",
        required=['hash|ror|djb2|api hash', 'LoadLibrary|GetProcAddress|resolve'],
        supporting=['empty import table'],
        contradicting=['full static import table'],
        alternatives=['ordinary delayed imports'],
        verification='Recover the hash algorithm and map a constant to a real API name.',
    ),
    "arbitrary-write": EvidenceRequirement(
        technique="arbitrary-write",
        required=['write.?what.?where|arbitrary write|controlled write', 'address|pointer|got|hook'],
        supporting=['format string %n'],
        contradicting=['read only primitive'],
        alternatives=['fixed-destination overflow'],
        verification='Show attacker control of both destination address and value written.',
    ),
    "archive-analysis": EvidenceRequirement(
        technique="archive-analysis",
        required=['zip|tar|7z|rar|archive', 'nested|member|extract'],
        supporting=['password', 'polyglot'],
        contradicting=['single plain file'],
        alternatives=['file-signature repair only'],
        verification='List and extract the nested member that contains the flag.',
    ),
    "cache-poisoning": EvidenceRequirement(
        technique="cache-poisoning",
        required=['cache|cdn|x-cache', 'unkeyed|poison|reflected header'],
        supporting=['x-forwarded-host'],
        contradicting=['no shared cache'],
        alternatives=['reflected xss without a cache'],
        verification='Show a crafted request stored and later served to a different client.',
    ),
    "disk-image-analysis": EvidenceRequirement(
        technique="disk-image-analysis",
        required=['disk image|\\.dd|\\.img|e01|partition', 'filesystem|unallocated|mount'],
        supporting=['mmls', 'deleted file'],
        contradicting=['single regular file only'],
        alternatives=['memory dump analysis'],
        verification='Recover a file from a partition, slack, or unallocated space.',
    ),
    "file-signature": EvidenceRequirement(
        technique="file-signature",
        required=['magic|file signature|header bytes', 'extension|mislabeled|polyglot'],
        supporting=['file command', 'xxd'],
        contradicting=['extension matches content'],
        alternatives=['nested archive without wrong magic'],
        verification='Identify the true type from magic bytes and open or repair the file.',
    ),
    "file-structure-abuse": EvidenceRequirement(
        technique="file-structure-abuse",
        required=['FILE\\*|fopen|_IO_|vtable|fsop', 'heap|glibc'],
        supporting=['wide_vtable', 'house of orange'],
        contradicting=['no FILE usage'],
        alternatives=['ordinary GOT overwrite'],
        verification='Show control of a FILE field leading to controlled code flow.',
    ),
    "file-upload-chain": EvidenceRequirement(
        technique="file-upload-chain",
        required=['upload|multipart|file input', 'extension|content-type|web root'],
        supporting=['double extension', 'webshell'],
        contradicting=['uploads outside web root'],
        alternatives=['path traversal without upload'],
        verification='Get attacker-controlled content stored where the server will execute or serve it.',
    ),
    "keygen": EvidenceRequirement(
        technique="keygen",
        required=['serial|license|registration|keygen', 'validate|checksum|derive'],
        supporting=['name to key'],
        contradicting=['online activation only'],
        alternatives=['patch the check to always succeed'],
        verification='Produce a serial that the binary accepts for a chosen name.',
    ),
    "opaque-predicates": EvidenceRequirement(
        technique="opaque-predicates",
        required=['opaque|always true|always false|dead branch', 'predicate|mba|obfuscat'],
        supporting=['bloated cfg'],
        contradicting=['straight-line code only'],
        alternatives=['control-flow flattening without opaques'],
        verification='Show a predicate that is invariant and remove the dead path.',
    ),
    "osint-metadata": EvidenceRequirement(
        technique="osint-metadata",
        required=['exif|metadata|gps|author|producer', 'document|image|pdf'],
        supporting=['exiftool'],
        contradicting=['metadata stripped'],
        alternatives=['osint from public web only'],
        verification='Extract an identifying field that advances the investigation.',
    ),
    "prng-prediction": EvidenceRequirement(
        technique="prng-prediction",
        required=['prng|rand\\(|mt19937|mersenne|seed', 'token|nonce|predict'],
        supporting=['time seed', 'consecutive outputs'],
        contradicting=['csprng|/dev/urandom'],
        alternatives=['brute force without PRNG structure'],
        verification='Predict a future output or recover the seed from observed outputs.',
    ),
    "symbolic-execution": EvidenceRequirement(
        technique="symbolic-execution",
        required=['symbolic|angr|klee|constraint|path condition', 'input bytes|satisfiable'],
        supporting=['heavy branching'],
        contradicting=['trivial linear check'],
        alternatives=['manual reverse of a simple compare'],
        verification='Obtain a concrete input that satisfies the path constraints.',
    ),
    "timing-side-channel": EvidenceRequirement(
        technique="timing-side-channel",
        required=['timing|response time|early exit|strcmp', 'byte by byte|prefix'],
        supporting=['measurable latency'],
        contradicting=['constant-time compare'],
        alternatives=['padding oracle via error messages'],
        verification='Show statistically significant timing differences that reveal secret bytes.',
    ),
    "solidity-access-control": EvidenceRequirement(
        technique="solidity-access-control",
        required=['onlyOwner|access control|modifier|msg.sender|tx.origin', 'public|external function'],
        supporting=['initialize', 'missing modifier'],
        contradicting=['every state change gated'],
        alternatives=['reentrancy bypassing a correct guard'],
        verification='Call a privileged function from an unauthorized account.',
    ),
}


@dataclass
class EvidenceAssessment:
    """The graded result for one claim."""

    technique: str
    level: SupportLevel
    confidence: float
    matched_required: List[str] = field(default_factory=list)
    missing_required: List[str] = field(default_factory=list)
    matched_supporting: List[str] = field(default_factory=list)
    matched_contradicting: List[str] = field(default_factory=list)
    open_alternatives: List[str] = field(default_factory=list)
    verification_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "level": self.level.value,
            "confidence": round(self.confidence, 3),
            "matched_required": list(self.matched_required),
            "missing_required": list(self.missing_required),
            "matched_supporting": list(self.matched_supporting),
            "matched_contradicting": list(self.matched_contradicting),
            "open_alternatives": list(self.open_alternatives),
            "verification_hint": self.verification_hint,
        }

    def explain(self) -> str:
        lines = [f"{self.technique}: **{self.level.value}** (confidence {self.confidence:.2f})"]
        if self.matched_required:
            lines.append(f"  present: {', '.join(self.matched_required)}")
        if self.missing_required:
            lines.append(f"  still needed: {', '.join(self.missing_required)}")
        if self.matched_contradicting:
            lines.append(f"  argues against: {', '.join(self.matched_contradicting)}")
        if self.open_alternatives:
            lines.append(f"  could also be: {'; '.join(self.open_alternatives[:3])}")
        if self.verification_hint and not self.level.is_conclusive:
            lines.append(f"  to confirm: {self.verification_hint}")
        return "\n".join(lines)


def _matches(signal: str, text: str) -> bool:
    """Match a signal spec (alternatives separated by |) against evidence."""
    for option in signal.split("|"):
        option = option.strip()
        if not option:
            continue
        try:
            if re.search(option, text, re.IGNORECASE):
                return True
        except re.error:
            if option.lower() in text:
                return True
    return False


def assess(
    technique: str,
    evidence_text: str,
    requirement: Optional[EvidenceRequirement] = None,
) -> EvidenceAssessment:
    """
    Grade a technique claim against the collected evidence.

    An unknown technique returns INSUFFICIENT_EVIDENCE rather than
    defaulting to "probably fine" — silence is the honest answer when
    there is no rubric to apply.
    """
    technique = (technique or "").strip().lower()
    req = requirement or REQUIREMENTS.get(technique)
    text = (evidence_text or "").lower()

    if req is None:
        return EvidenceAssessment(
            technique=technique or "unknown",
            level=SupportLevel.INSUFFICIENT_EVIDENCE,
            confidence=0.2,
            verification_hint="No evidence rubric defined for this technique; treat the claim as unverified.",
        )

    matched_req = [s for s in req.required if _matches(s, text)]
    missing_req = [s for s in req.required if s not in matched_req]
    matched_sup = [s for s in req.supporting if _matches(s, text)]
    matched_con = [s for s in req.contradicting if _matches(s, text)]

    # A contradicting signal outranks everything: it is a positive
    # observation that the claim is wrong, not merely missing support.
    if matched_con:
        return EvidenceAssessment(
            technique=technique, level=SupportLevel.REFUTED, confidence=0.1,
            matched_required=matched_req, missing_required=missing_req,
            matched_supporting=matched_sup, matched_contradicting=matched_con,
            verification_hint=req.verification,
        )

    total_req = len(req.required) or 1
    req_ratio = len(matched_req) / total_req
    sup_ratio = len(matched_sup) / (len(req.supporting) or 1)

    if req_ratio >= 1.0 and matched_sup:
        level, confidence = SupportLevel.SUPPORTED, min(0.95, 0.7 + 0.25 * sup_ratio)
        alternatives: List[str] = []
    elif req_ratio >= 1.0:
        level, confidence = SupportLevel.LIKELY, 0.65
        alternatives = list(req.alternatives)
    elif req_ratio >= 0.5:
        level, confidence = SupportLevel.UNCERTAIN, 0.4 + 0.1 * sup_ratio
        alternatives = list(req.alternatives)
    else:
        level, confidence = SupportLevel.INSUFFICIENT_EVIDENCE, 0.2
        alternatives = list(req.alternatives)

    return EvidenceAssessment(
        technique=technique, level=level, confidence=confidence,
        matched_required=matched_req, missing_required=missing_req,
        matched_supporting=matched_sup, matched_contradicting=matched_con,
        open_alternatives=alternatives, verification_hint=req.verification,
    )


def _is_reference_source(source: str) -> bool:
    """
    Whether a source describes the world rather than this challenge.

    Archive hits and concept cards mention every signal their topic
    involves. Grading a claim about this challenge against a document about
    a different one is how an agent talks itself into a technique it has no
    local evidence for, so reference material is kept out of the evidence
    text entirely.
    """
    try:
        from agent.tool_capabilities import capability
        cap = capability((source or "").strip())
    except Exception:
        return False
    return cap is not None and not cap.produces


def collect_evidence_text(state: Any) -> str:
    """
    Flatten an AgentState into one searchable blob.

    Hypothesis statements are excluded: they are the claims being graded,
    and letting a claim supply its own supporting text is circular. Only
    observations reach the rubric.
    """
    parts: List[str] = [str(getattr(state, "challenge_summary", "") or "")]
    for fact in getattr(state, "known_facts", None) or []:
        text = str(fact)
        match = re.match(r"\[([^\]]+)\]\s*(.*)", text)
        if match and _is_reference_source(match.group(1)):
            continue
        parts.append(text)
    for ev in getattr(state, "evidence", None) or []:
        if _is_reference_source(str(getattr(ev, "source", "") or "")):
            continue
        parts.append(str(getattr(ev, "finding", "") or getattr(ev, "content", "") or ev))
    return "\n".join(p for p in parts if p)


def assess_state(state: Any, technique: Optional[str] = None) -> EvidenceAssessment:
    """Grade the state's top hypothesis (or a named technique)."""
    text = collect_evidence_text(state)
    if technique is None:
        top = None
        try:
            top = state.top_hypothesis()
        except Exception:
            pass
        technique = (getattr(top, "technique", "") or "") if top else ""
    return assess(technique, text)


def requirements_for(technique: str) -> Optional[EvidenceRequirement]:
    return REQUIREMENTS.get((technique or "").strip().lower())


def next_evidence_to_seek(assessment: EvidenceAssessment, limit: int = 3) -> List[str]:
    """
    What the agent should go and look for next.

    Turning the gap into a concrete list is what makes the planner
    evidence-driven rather than hypothesis-driven — it stops the agent
    re-running tools that cannot change the assessment.
    """
    if assessment.level is SupportLevel.REFUTED:
        return ["abandon this hypothesis; a contradicting signal is present"]
    out = [f"confirm: {s}" for s in assessment.missing_required[:limit]]
    if len(out) < limit and assessment.open_alternatives:
        out.append(f"rule out: {assessment.open_alternatives[0]}")
    return out[:limit]
