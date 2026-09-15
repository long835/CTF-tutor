"""Repeating-key XOR cracker for CTF-tutor.

Uses the compiled `xor_crack_native` Rust extension when it's been built
(see xor_crack_native/README or run `maturin develop` inside that
directory), and transparently falls back to a slower pure-Python
implementation otherwise -- the same graceful-degradation pattern used
throughout the rest of tools/ (checksec, ghidra, binwalk, etc. all skip
rather than crash when a dependency is missing).

Both paths implement the same algorithm and return the same shape:
    crack_repeating_xor(data, max_keysize=40, candidates=3)
        -> List[Tuple[key: bytes, plaintext: bytes, score: float]]

Results are sorted best-guess-first. This is a ranked-guess tool, not a
guarantee -- like the rest of decode_toolkit.py, it presents candidates
for the tutor/learner to evaluate, it does not claim certainty.
"""
from __future__ import annotations

from typing import List, Tuple

Bytes = bytes

try:
    import xor_crack_native as _native

    if not hasattr(_native, "crack_repeating_xor"):
        # The source crate lives at xor_crack_native/ (its directory name
        # has to match the #[pymodule] name for maturin to produce an
        # importable extension of that name). If the repo root ends up on
        # sys.path ahead of site-packages -- which happens here, since
        # every test file in tests/ does sys.path.insert(0, repo_root) --
        # that bare source directory (no __init__.py) is itself a valid
        # Python *namespace* package and can shadow the real compiled
        # extension of the same name. Treat "imported but missing the
        # actual function" the same as "not built" rather than letting an
        # AttributeError leak out of what's supposed to be an optional
        # dependency.
        _native = None
        _BACKEND = "python"
    else:
        _BACKEND = "native"
except ImportError:
    _native = None
    _BACKEND = "python"


# --- pure-Python fallback -------------------------------------------------

_ENGLISH_FREQ = {
    " ": 13.0, "e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7,
    "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3, "l": 4.0, "c": 2.8, "u": 2.8,
    "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0, "p": 1.9, "b": 1.5,
    "v": 1.0, "k": 0.8, "j": 0.15, "x": 0.15, "q": 0.10, "z": 0.07,
}


def _english_score(data: bytes) -> float:
    score = 0.0
    for b in data:
        c = chr(b)
        if c.isprintable() or c == " ":
            score += _ENGLISH_FREQ.get(c.lower(), 0.0)
        elif c in "\n\t":
            score += 0.5
        else:
            score -= 10.0
    return score


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _guess_keysizes(data: bytes, max_keysize: int, top_n: int) -> List[int]:
    scored = []
    upper = min(max_keysize, max(2, len(data) // 2))
    for keysize in range(2, upper + 1):
        blocks = [data[i:i + keysize] for i in range(0, min(len(data), keysize * 9), keysize)][:9]
        if len(blocks) < 2:
            continue
        total, pairs = 0.0, 0
        for a, b in zip(blocks, blocks[1:]):
            if len(a) == keysize and len(b) == keysize:
                total += _hamming(a, b) / keysize
                pairs += 1
        if pairs:
            scored.append((keysize, total / pairs))

    scored.sort(key=lambda item: item[1])
    return [k for k, _ in scored[:top_n]]


def _crack_column(column: bytes) -> int:
    best_byte, best_score = 0, float("-inf")
    for key_byte in range(256):
        decoded = bytes(b ^ key_byte for b in column)
        s = _english_score(decoded)
        if s > best_score:
            best_score, best_byte = s, key_byte
    return best_byte


def _crack_repeating_xor_python(
    data: bytes, max_keysize: int = 40, candidates: int = 3
) -> List[Tuple[bytes, bytes, float]]:
    if not data:
        return []
    keysizes = _guess_keysizes(data, max_keysize, max_keysize)
    results = []
    for keysize in keysizes:
        key = bytes(_crack_column(data[i::keysize]) for i in range(keysize))
        plaintext = bytes(b ^ key[i % keysize] for i, b in enumerate(data))
        score = _english_score(plaintext) / max(1, len(data))
        results.append((key, plaintext, score))

    # Collapse key-length multiples that decode to the same plaintext down
    # to the shortest key (see xor_crack_native/src/lib.rs for why).
    dedup: List[Tuple[bytes, bytes, float]] = []
    for key, plaintext, score in results:
        match = next((i for i, r in enumerate(dedup) if r[1] == plaintext), None)
        if match is not None:
            if len(key) < len(dedup[match][0]):
                dedup[match] = (key, plaintext, score)
        else:
            dedup.append((key, plaintext, score))
    dedup.sort(key=lambda r: r[2], reverse=True)
    return dedup[: max(1, candidates)]


# --- public entry point ----------------------------------------------------

def crack_repeating_xor(
    data: Bytes, max_keysize: int = 40, candidates: int = 3
) -> List[Tuple[bytes, bytes, float]]:
    """Attempt to crack `data` as repeating-key XOR ciphertext.

    Returns up to `candidates` (key, plaintext, score) tuples sorted by
    descending score (best guess first). Uses the native Rust extension
    when available (see BACKEND), otherwise a slower pure-Python path.
    On large blobs (multi-KB) the native path is roughly 30-55x faster --
    this matters here specifically because magic_decode() in
    decode_toolkit.py may try this against every gzip/zlib-shaped blob it
    sees, and the pure-Python path can take several seconds per attempt.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    data = bytes(data)
    if max_keysize < 2:
        raise ValueError("max_keysize must be >= 2")
    if candidates < 1:
        raise ValueError("candidates must be >= 1")

    if _native is not None:
        return _native.crack_repeating_xor(data, max_keysize, candidates)
    return _crack_repeating_xor_python(data, max_keysize, candidates)


def backend() -> str:
    """Returns 'native' or 'python' depending on which implementation is
    active -- useful for tests and for surfacing to the user which path
    ran (e.g. in a --verbose CLI flag)."""
    return _BACKEND
