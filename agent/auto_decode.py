"""
agent/auto_decode.py

Ciphey-inspired layered auto-decode (local, fast, pure Python).

Peels base64 / hex / URL / gzip / zlib / single-byte XOR layers with:
  - depth limit
  - wall-clock timeout
  - size caps
  - flag-pattern early exit

Inspired by community tools (Ciphey, CyberChef Magic) but dependency-free
and safe for the agent loop.
"""

from __future__ import annotations

import base64
import binascii
import re
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote


FLAG_RE = re.compile(
    r"(?:flag|ctf|htb|picoctf|fh|lactf|ductf|uiuctf)\s*\{[^\n\r]{3,120}\}",
    re.I,
)
PRINTABLE_RE = re.compile(rb"^[\x09\x0a\x0d\x20-\x7e]{8,}$")


@dataclass
class Layer:
    op: str
    preview: str


@dataclass
class DecodeResult:
    success: bool
    layers: List[Layer] = field(default_factory=list)
    final_text: str = ""
    flags: List[str] = field(default_factory=list)
    elapsed_ms: int = 0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "layers": [{"op": L.op, "preview": L.preview} for L in self.layers],
            "final_text": self.final_text[:2000],
            "flags": self.flags,
            "elapsed_ms": self.elapsed_ms,
            "notes": self.notes,
        }


def find_flags(text: str) -> List[str]:
    return list({m.group(0) for m in FLAG_RE.finditer(text or "")})


def _try_b64(data: bytes) -> Optional[bytes]:
    try:
        s = data.decode("ascii", errors="ignore").strip()
        if len(s) < 8 or not re.fullmatch(r"[A-Za-z0-9+/=\s]+", s):
            return None
        # pure hex is not base64 — let hex handler own it
        s_nospace = re.sub(r"\s+", "", s)
        if re.fullmatch(r"[0-9a-fA-F]+", s_nospace) and len(s_nospace) % 2 == 0:
            return None
        s_nospace += "=" * (-len(s_nospace) % 4)
        out = base64.b64decode(s_nospace, validate=False)
        if not out or out == data:
            return None
        return out
    except Exception:
        return None


def _try_hex(data: bytes) -> Optional[bytes]:
    try:
        s = re.sub(r"[^0-9a-fA-F]", "", data.decode("ascii", errors="ignore"))
        if len(s) < 8 or len(s) % 2:
            return None
        out = bytes.fromhex(s)
        return out if out and out != data else None
    except Exception:
        return None


def _try_url(data: bytes) -> Optional[bytes]:
    try:
        s = data.decode("utf-8", errors="ignore")
        if "%" not in s:
            return None
        out = unquote(s).encode("utf-8", errors="replace")
        return out if out != data else None
    except Exception:
        return None


def _try_zlib(data: bytes) -> Optional[bytes]:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 16):
        try:
            out = zlib.decompress(data, wbits)
            if out and len(out) < 5_000_000:
                return out
        except Exception:
            continue
    return None


def _try_xor_single(data: bytes) -> Optional[Tuple[bytes, int]]:
    """Fast English-ish single-byte XOR guess."""
    if not data or len(data) > 50_000:
        return None
    best = None
    best_score = -1.0
    # common spaces XOR
    for key in range(256):
        out = bytes(b ^ key for b in data)
        # score: printable + spaces
        printable = sum(1 for b in out if 32 <= b < 127)
        spaces = out.count(32)
        ratio = printable / len(out)
        if ratio < 0.85:
            continue
        score = ratio + 0.15 * (spaces / len(out))
        if score > best_score:
            best_score = score
            best = (out, key)
    if best and best_score >= 0.9:
        return best
    return None


def auto_decode(
    data: str | bytes,
    *,
    max_depth: int = 8,
    timeout_sec: float = 2.0,
) -> DecodeResult:
    t0 = time.time()
    if isinstance(data, str):
        cur: bytes = data.encode("utf-8", errors="replace")
    else:
        cur = data

    layers: List[Layer] = []
    notes: List[str] = []
    flags: List[str] = []

    for depth in range(max_depth):
        if time.time() - t0 > timeout_sec:
            notes.append("stopped: timeout")
            break
        if len(cur) > 2_000_000:
            notes.append("stopped: size cap")
            break

        text_try = cur.decode("utf-8", errors="replace")
        found = find_flags(text_try)
        if found:
            flags = found
            layers.append(Layer("flag_hit", found[0][:80]))
            break

        progressed = False
        for name, fn in (
            ("from_hex", _try_hex),
            ("from_base64", _try_b64),
            ("url_decode", _try_url),
            ("zlib_inflate", _try_zlib),
        ):
            out = fn(cur)
            if out is not None and out != cur:
                layers.append(Layer(name, out[:60].decode("utf-8", errors="replace")))
                cur = out
                progressed = True
                break
        if progressed:
            continue

        xor = _try_xor_single(cur)
        if xor is not None:
            out, key = xor
            layers.append(Layer(f"xor_single_byte(key={key})", out[:60].decode("utf-8", errors="replace")))
            cur = out
            continue

        break  # no more transforms

    final = cur.decode("utf-8", errors="replace")
    if not flags:
        flags = find_flags(final)

    return DecodeResult(
        success=bool(layers) or bool(flags),
        layers=layers,
        final_text=final[:4000],
        flags=flags,
        elapsed_ms=int((time.time() - t0) * 1000),
        notes=notes,
    )


def scan_for_flags(text: str) -> List[str]:
    return find_flags(text)
