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

SECURITY: Decompression operations are protected against decompression bombs
by a configurable size cap (default 50MB). Attempting to decompress data that
would exceed this cap raises ValueError.
"""

import base64
import binascii
import gzip
import re
import zlib
from typing import List, Union
from urllib.parse import quote, unquote

Bytes = Union[str, bytes]

# Maximum decompressed size to prevent decompression bomb DoS.
# 50MB is large enough for legitimate CTF challenges, small enough to prevent
# accidental/malicious memory exhaustion.
MAX_DECOMPRESSED_SIZE = 50 * 1024 * 1024


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


# --- gzip / zlib (with decompression bomb protection) -----------------------

def gunzip_bytes(data: Bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Decompress gzip data with size cap protection against decompression bombs.
    Raises ValueError if decompressed output would exceed max_size.
    """
    data_b = _as_bytes(data)
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = decompressor.decompress(data_b, max_size)
        if decompressor.unconsumed_tail:
            raise ValueError(
                f"decompressed output exceeds size cap ({max_size} bytes) — "
                "possible decompression bomb"
            )
        return output
    except zlib.error as e:
        raise ValueError(f"gzip decompression failed: {e}") from e


def gzip_bytes(data: Bytes) -> bytes:
    return gzip.compress(_as_bytes(data))


def zlib_inflate(data: Bytes, max_size: int = MAX_DECOMPRESSED_SIZE) -> bytes:
    """
    Decompress zlib data with size cap protection against decompression bombs.
    Raises ValueError if decompressed output would exceed max_size.
    """
    data_b = _as_bytes(data)
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(data_b, max_size)
        if decompressor.unconsumed_tail:
            raise ValueError(
                f"decompressed output exceeds size cap ({max_size} bytes) — "
                "possible decompression bomb"
            )
        return output
    except zlib.error as e:
        raise ValueError(f"zlib decompression failed: {e}") from e


def zlib_deflate(data: Bytes) -> bytes:
    return zlib.compress(_as_bytes(data))


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
