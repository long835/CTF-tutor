"""
tools/decode_toolkit.py

A small CyberChef-style toolkit of composable encode/decode operations,
implemented in pure Python (no Node.js / CyberChef install required). Covers
the transforms that come up constantly in CTF challenges: base64, hex,
URL encoding, ROT13/Caesar, XOR, gzip, and a "magic" auto-detector that
tries the likely candidates on a blob of text the way CyberChef's Magic
wand does, minus the ML classifier.

Each operation is a plain function taking/returning str or bytes so they
compose easily: run_recipe() chains a list of named operations by name,
mirroring CyberChef's "recipe" concept, e.g.:

    run_recipe(ciphertext, ["from_base64", "from_hex", "rot13"])

This deliberately does NOT shell out to a `cyberchef` CLI -- there isn't
a first-class one to depend on (CyberChef is normally a static web app).
If you specifically want the real CyberChef UI/recipes, run it locally
(https://github.com/gchq/CyberChef) or via cyberchef-server and treat this
module as the fast, scriptable subset for automated/LLM-driven use.
"""

import base64
import binascii
import collections
import gzip
import math
import re
import zlib
from typing import List, Optional, Tuple, Union
from urllib.parse import quote, unquote

from config import MAX_DECOMPRESSED_SIZE
from tools.xor_crack import crack_repeating_xor

Bytes = Union[str, bytes]


def _as_bytes(data: Bytes) -> bytes:
    return data.encode() if isinstance(data, str) else data


def _as_text(data: Bytes) -> str:
    if isinstance(data, str):
        return data
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


# --- base64 -----------------------------------------------------------

def to_base64(data: Bytes) -> str:
    return base64.b64encode(_as_bytes(data)).decode()


def from_base64(data: Bytes) -> bytes:
    text = _as_text(data).strip()
    # tolerate missing padding, the #1 source of "ValueError: Invalid base64"
    text += "=" * (-len(text) % 4)
    return base64.b64decode(text)


# --- hex ----------------------------------------------------------------

def to_hex(data: Bytes) -> str:
    return _as_bytes(data).hex()


def from_hex(data: Bytes) -> bytes:
    text = re.sub(r"[^0-9a-fA-F]", "", _as_text(data))
    return bytes.fromhex(text)


# --- URL encoding ---------------------------------------------------------

def to_url(data: Bytes) -> str:
    return quote(_as_text(data))


def from_url(data: Bytes) -> str:
    return unquote(_as_text(data))


# --- ROT13 / Caesar --------------------------------------------------------

def rot13(data: Bytes) -> str:
    return caesar_shift(data, 13)


def caesar_shift(data: Bytes, shift: int) -> str:
    text = _as_text(data)
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


# --- XOR --------------------------------------------------------------------

def xor_bytes(data: Bytes, key: Bytes) -> bytes:
    data_b = _as_bytes(data)
    key_b = _as_bytes(key)
    if not key_b:
        raise ValueError("xor_bytes: key must not be empty")
    return bytes(b ^ key_b[i % len(key_b)] for i, b in enumerate(data_b))


def xor_bruteforce_single_byte(data: Bytes, min_printable_ratio: float = 0.85) -> List[dict]:
    """Try every single-byte XOR key (0-255) and return the ones whose
    output is mostly printable ASCII, sorted best-first -- the classic
    single-byte-XOR CTF crypto move."""
    data_b = _as_bytes(data)
    candidates = []
    for key in range(256):
        out = bytes(b ^ key for b in data_b)
        printable = sum(1 for b in out if 32 <= b < 127)
        ratio = printable / len(out) if out else 0
        if ratio >= min_printable_ratio:
            candidates.append({"key": key, "output": out, "printable_ratio": ratio})
    candidates.sort(key=lambda c: c["printable_ratio"], reverse=True)
    return candidates


def shannon_entropy(data: Bytes) -> float:
    """Bits of Shannon entropy per byte, in [0, 8]. Used to pick decode
    candidates: high entropy tends toward compression/encryption; low,
    uniform-looking text tends toward Caesar/substitution."""
    blob = _as_bytes(data)
    if not blob:
        return 0.0
    counts = collections.Counter(blob)
    length = len(blob)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _safe_inflate(data: bytes, wbits: int, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    decoder = zlib.decompressobj(wbits)
    out = decoder.decompress(data, max_size)
    if decoder.unconsumed_tail:
        raise ValueError(
            "decompressed output exceeds size cap — possible decompression bomb"
        )
    leftover = decoder.flush()
    if leftover:
        if len(out) + len(leftover) > max_size:
            raise ValueError(
                "decompressed output exceeds size cap — possible decompression bomb"
            )
        out += leftover
    return out


def gunzip_bytes(data: Bytes) -> bytes:
    return _safe_inflate(_as_bytes(data), 16 + zlib.MAX_WBITS)


def gzip_bytes(data: Bytes) -> bytes:
    return gzip.compress(_as_bytes(data))


def zlib_inflate(data: Bytes) -> bytes:
    return _safe_inflate(_as_bytes(data), zlib.MAX_WBITS)


def zlib_deflate(data: Bytes) -> bytes:
    return zlib.compress(_as_bytes(data))


# --- repeating-key XOR (CryptoPals-style identification helper) ------------

ENGLISH_FREQ = {
    "a": 0.082, "b": 0.015, "c": 0.028, "d": 0.043, "e": 0.13,
    "f": 0.022, "g": 0.02, "h": 0.061, "i": 0.07, "j": 0.0015,
    "k": 0.0077, "l": 0.04, "m": 0.024, "n": 0.067, "o": 0.075,
    "p": 0.019, "q": 0.00095, "r": 0.06, "s": 0.063, "t": 0.091,
    "u": 0.028, "v": 0.0098, "w": 0.024, "x": 0.0015, "y": 0.02,
    "z": 0.00074, " ": 0.13,
}


def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("hamming_distance requires equal-length buffers")
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def _english_score(text: bytes) -> float:
    if not text:
        return 0.0
    lowered = text.lower()
    score = 0.0
    for b in lowered:
        ch = chr(b)
        if ch in ENGLISH_FREQ:
            score += ENGLISH_FREQ[ch]
        elif b < 32 and b not in (9, 10, 13):
            score -= 0.5
    return score / len(text)


def _best_single_byte_xor_key(column: bytes) -> Tuple[int, bytes, float]:
    best_key, best_out, best_score = 0, b"", float("-inf")
    for key in range(256):
        out = bytes(b ^ key for b in column)
        score = _english_score(out)
        if score > best_score:
            best_key, best_out, best_score = key, out, score
    return best_key, best_out, best_score


def guess_xor_key_lengths(data: Bytes, min_key: int = 2, max_key: int = 40, top_n: int = 3) -> List[Tuple[int, float]]:
    """Normalized Hamming-distance ranking of candidate repeating-key lengths."""
    blob = _as_bytes(data)
    ranked = []
    for keysize in range(min_key, min(max_key, len(blob) // 2) + 1):
        blocks = [blob[i:i + keysize] for i in range(0, keysize * 4, keysize)]
        blocks = [b for b in blocks if len(b) == keysize]
        if len(blocks) < 2:
            continue
        distances = [
            hamming_distance(blocks[i], blocks[i + 1]) / keysize
            for i in range(len(blocks) - 1)
        ]
        ranked.append((keysize, sum(distances) / len(distances)))
    ranked.sort(key=lambda row: row[1])
    return ranked[:top_n]


def break_repeating_key_xor(
    data: Bytes,
    key_length: Optional[int] = None,
) -> dict:
    """Recover a plausible repeating XOR key via per-column frequency
    analysis. This is identification / teaching assistance for a blob the
    learner already has, not a live-system attack."""
    blob = _as_bytes(data)
    if key_length is None:
        guesses = guess_xor_key_lengths(blob)
        if not guesses:
            raise ValueError("not enough data to guess a repeating XOR key length")
        key_length = guesses[0][0]
    key_bytes = []
    for offset in range(key_length):
        column = blob[offset::key_length]
        key, _out, _score = _best_single_byte_xor_key(column)
        key_bytes.append(key)
    key = bytes(key_bytes)
    plaintext = xor_bytes(blob, key)
    return {
        "key": key,
        "key_hex": key.hex(),
        "plaintext": plaintext,
        "key_length": key_length,
        "printable_ratio": (
            sum(1 for b in plaintext if 32 <= b < 127) / len(plaintext) if plaintext else 0
        ),
    }


# --- recipes: chain named operations like a CyberChef recipe ---------------

OPERATIONS = {
    "to_base64": to_base64,
    "from_base64": from_base64,
    "to_hex": to_hex,
    "from_hex": from_hex,
    "to_url": to_url,
    "from_url": from_url,
    "rot13": rot13,
    "gunzip": gunzip_bytes,
    "gzip": gzip_bytes,
    "zlib_inflate": zlib_inflate,
    "zlib_deflate": zlib_deflate,
}


def run_recipe(data: Bytes, steps: List[str]) -> Bytes:
    """Apply a chain of named operations in order, e.g.
    run_recipe(blob, ["from_base64", "gunzip"]). Raises ValueError naming
    the unknown step if `steps` references an operation not in OPERATIONS,
    and lets the underlying decode error (binascii.Error, zlib errors, etc.)
    propagate with the step name attached so a failing link in the chain is
    obvious rather than a bare traceback."""
    result = data
    for step in steps:
        if step not in OPERATIONS:
            raise ValueError(f"Unknown recipe step '{step}'. Known steps: {', '.join(sorted(OPERATIONS))}")
        try:
            result = OPERATIONS[step](result)
        except Exception as e:
            raise ValueError(f"Recipe step '{step}' failed: {e}") from e
    return result


# --- magic: try the likely candidates automatically -------------------------

def magic_decode(data: Bytes, max_depth: int = 3) -> List[dict]:
    """
    CyberChef's "Magic" wand, minus the ML: heuristically detect which
    common encodings the input plausibly is, try decoding through up to
    `max_depth` chained layers (e.g. base64-of-hex-of-gzip), and return
    every successful, mostly-printable-ASCII result found, best guess
    first. This is a heuristic helper for a human or LLM to skim, not a
    guaranteed answer -- always sanity check the output.
    """
    results = []
    _magic_search(_as_bytes(data), [], results, max_depth)
    # prefer shorter recipes, then higher printable ratio
    results.sort(key=lambda r: (len(r["recipe"]), -r["printable_ratio"]))
    return results


def _looks_printable(data: bytes, threshold: float = 0.9) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data) >= threshold


def _magic_search(data: bytes, recipe_so_far: List[str], results: List[dict], depth_left: int) -> None:
    if _looks_printable(data) and recipe_so_far:
        printable = sum(1 for b in data if 32 <= b < 127)
        results.append({
            "recipe": list(recipe_so_far),
            "output": data,
            "printable_ratio": printable / len(data) if data else 0,
        })
    if depth_left <= 0:
        return

    text = data.decode("latin-1")
    candidates = []
    entropy = shannon_entropy(data)

    # High entropy: prefer compression/encryption-shaped candidates first.
    # Low entropy: prefer substitution (ROT13) before treating the blob as
    # encoded binary.
    if entropy >= 6.5 or data[:2] == b"\x1f\x8b" or data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
        if data[:2] == b"\x1f\x8b":
            try:
                candidates.append(("gunzip", gunzip_bytes(data)))
            except Exception:
                pass
        if data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            try:
                candidates.append(("zlib_inflate", zlib_inflate(data)))
            except Exception:
                pass

    if entropy < 5.0 and text.isalpha() and len(text) >= 8:
        rotated = rot13(data)
        if rotated != text:
            candidates.append(("rot13", rotated.encode("latin-1")))

    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", text) and len(text.strip()) >= 4:
        try:
            candidates.append(("from_base64", from_base64(data)))
        except (binascii.Error, ValueError):
            pass
    if re.fullmatch(r"[0-9a-fA-F\s]+", text) and len(re.sub(r"\s", "", text)) >= 4:
        try:
            candidates.append(("from_hex", from_hex(data)))
        except ValueError:
            pass
    if "%" in text:
        try:
            candidates.append(("from_url", from_url(data).encode()))
        except Exception:
            pass
    if entropy < 6.5:
        if data[:2] == b"\x1f\x8b":
            try:
                candidates.append(("gunzip", gunzip_bytes(data)))
            except Exception:
                pass
        if data[:2] in (b"\x78\x01", b"\x78\x9c", b"\x78\xda"):
            try:
                candidates.append(("zlib_inflate", zlib_inflate(data)))
            except Exception:
                pass

    for name, decoded in candidates:
        if decoded == data:
            continue  # no-op decode, avoid infinite loops on self-mapping input
        _magic_search(decoded, recipe_so_far + [name], results, depth_left - 1)

    # Repeating-key XOR: a distinct technique from the single-byte
    # XOR/base64/hex/rot13 candidates above, so it's tried once against
    # the raw input rather than folded into the chained-recipe search --
    # unlike those steps it isn't meant to compose arbitrarily deep, it's
    # a standalone ranked guess (see tools/xor_crack.py). Only attempted
    # at the top of the search (recipe_so_far empty, i.e. against the
    # original blob, not already-decoded intermediate output) and only on
    # payload-sized input: repeating-key keysize detection needs several
    # blocks to be statistically reliable, and this avoids the cost (and
    # false-positive risk) of running a 256-way-per-column search against
    # every short/no-op blob magic_decode() is handed.
    if not recipe_so_far and len(data) >= 40:
        try:
            # Cap the keysize search relative to input length, not just at
            # the CryptoPals-standard 40: each candidate keysize needs
            # several samples per column for the per-column English-score
            # search to converge on the true key rather than overfitting
            # noise in a too-short column (see tests/test_decode_toolkit.py
            # for a worked example of this failure mode at keysize:data
            # ratios beyond roughly 1:8).
            xor_guesses = crack_repeating_xor(
                data, max_keysize=min(40, max(2, len(data) // 8)), candidates=1
            )
        except (TypeError, ValueError):
            xor_guesses = []
        for key, plaintext, _score in xor_guesses:
            if len(key) > 1 and _looks_printable(plaintext, threshold=0.85):
                printable = sum(1 for b in plaintext if 32 <= b < 127)
                results.append({
                    "recipe": [f"repeating_xor(key={key!r})"],
                    "output": plaintext,
                    "printable_ratio": printable / len(plaintext) if plaintext else 0,
                })


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m tools.decode_toolkit \"<blob>\"")
        print("       python -m tools.decode_toolkit --recipe from_base64,gunzip \"<blob>\"")
        sys.exit(1)

    if sys.argv[1] == "--recipe":
        recipe_steps = sys.argv[2].split(",")
        blob = sys.argv[3]
        output = run_recipe(blob, recipe_steps)
        print(output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output)
    else:
        blob = sys.argv[1]
        found = magic_decode(blob)
        if not found:
            print("[no confident decode found -- try tools.decode_toolkit's individual "
                  "functions by hand, or widen max_depth]")
        for i, r in enumerate(found[:10]):
            text = r["output"].decode("utf-8", errors="replace")
            print(f"[{i}] recipe={r['recipe']} printable={r['printable_ratio']:.2f}\n    {text}\n")
