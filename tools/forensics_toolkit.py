"""
tools/forensics_toolkit.py

Extends binwalk/exiftool coverage: pcap summaries, stego detectors, and
carving/memory tools when they are installed. Read-only; no live capture.
"""

import shutil
import subprocess
from typing import Optional


def _run(cmd: list, timeout: int = 20) -> str:
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"[{exe} not installed -- skip this check]"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout or "").strip()
        if result.stderr and result.stderr.strip():
            output += f"\n[stderr] {result.stderr.strip()[:1500]}"
        return output or "[no output]"
    except subprocess.TimeoutExpired:
        return f"[{exe} timed out after {timeout}s]"
    except Exception as e:
        return f"[{exe} failed: {e}]"


def summarize_pcap(path: str) -> str:
    if shutil.which("tshark"):
        proto = _run(["tshark", "-r", path, "-q", "-z", "io,phs"], timeout=30)
        dns = _run(["tshark", "-r", path, "-T", "fields", "-e", "dns.qry.name"], timeout=30)
        http = _run(["tshark", "-r", path, "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri"], timeout=30)
        return f"protocol hierarchy:\n{proto}\n\nDNS names:\n{dns[:2000]}\n\nHTTP requests:\n{http[:2000]}"
    return "[tshark not installed -- skip pcap summary]"


def _png_lsb_hint(path: str) -> str:
    """Lightweight LSB / bitplane hint without external tools (vision-adjacent).

    Reports whether low-order bitplanes look non-random enough to warrant a
    dedicated stego tool. Does not extract payloads — teaching-oriented only.
    """
    try:
        import struct
        import zlib
    except ImportError:
        return ""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return f"[lsb hint: cannot read file: {e}]"
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return ""
    # Parse IHDR for dimensions; stop at first IDAT stream sample.
    width = height = None
    idat = bytearray()
    pos = 8
    while pos + 8 <= len(data) and len(idat) < 200_000:
        length = struct.unpack(">I", data[pos:pos+4])[0]
        ctype = data[pos+4:pos+8]
        chunk = data[pos+8:pos+8+length]
        pos += 12 + length
        if ctype == b"IHDR" and length >= 13:
            width, height = struct.unpack(">II", chunk[:8])
        elif ctype == b"IDAT":
            idat.extend(chunk)
        elif ctype == b"IEND":
            break
    if not width or not height or not idat:
        return "[lsb hint: PNG header present but no sampleable IDAT]"
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error:
        return "[lsb hint: could not decompress IDAT sample]"
    # Estimate fraction of set LSBs in a sample of bytes (skip filter bytes roughly).
    sample = raw[1: min(len(raw), 50_000)]
    if not sample:
        return ""
    set_bits = sum(b & 1 for b in sample)
    ratio = set_bits / len(sample)
    # Near 0.5 is noise-like; strong bias can indicate structured embedding.
    note = "near-random" if 0.45 <= ratio <= 0.55 else ("biased low" if ratio < 0.45 else "biased high")
    return (
        f"lsb hint (PNG {width}x{height}): LSB set-ratio≈{ratio:.3f} ({note}); "
        "if zsteg/steghide are available, run them for channel extraction"
    )


def stego_info(path: str) -> str:
    chunks = []
    if shutil.which("zsteg"):
        chunks.append("zsteg:\n" + _run(["zsteg", path], timeout=25)[:3000])
    if shutil.which("steghide"):
        chunks.append("steghide --info:\n" + _run(["steghide", "info", path], timeout=15)[:2000])
    lsb = _png_lsb_hint(path)
    if lsb:
        chunks.append(lsb)
    if not chunks:
        return "[zsteg/steghide not installed -- skip stego checks]"
    return "\n\n".join(chunks)


def carve_hint(path: str) -> str:
    if shutil.which("foremost"):
        return (
            "[foremost is installed -- run it yourself in an isolated workspace if you want "
            "carved files written out. This wrapper will not auto-extract to disk.]"
        )
    if shutil.which("photorec"):
        return "[photorec is installed -- use it manually; not auto-run]"
    return "[foremost/photorec not installed]"


def volatility_hint(path: str) -> str:
    if shutil.which("vol") or shutil.which("volatility3"):
        return (
            "volatility3 appears installed. Suggested next step (manual): "
            "`vol -f <dump> windows.info` -- not auto-run because a full memory "
            "pass is slow and writes analysis artifacts."
        )
    return "[volatility3 not installed -- skip memory-forensics hint]"


def gather_forensics_evidence(path: Optional[str]) -> dict:
    if not path:
        return {}
    lower = path.lower()
    evidence = {}
    if lower.endswith((".pcap", ".pcapng", ".cap")):
        evidence["pcap_summary"] = summarize_pcap(path)
    if lower.endswith((".png", ".bmp", ".jpg", ".jpeg", ".gif", ".wav")):
        evidence["stego"] = stego_info(path)
    if lower.endswith((".raw", ".dmp", ".mem", ".vmem")):
        evidence["volatility"] = volatility_hint(path)
    if lower.endswith((".dd", ".img", ".e01", ".bin")):
        evidence["carving"] = carve_hint(path)
    return evidence
