"""
tools/crypto_toolkit.py

Evidence-gathering for crypto challenges: identify hash *type*, inspect
keys/certs with openssl, optionally confirm a John the Ripper format name.
Does not crack hashes or run RSA attacks that recover plaintext/flags.
"""

import re
import shutil
import subprocess
from typing import Optional


def _run(cmd: list, timeout: int = 15) -> str:
    exe = cmd[0]
    if shutil.which(exe) is None:
        return f"[{exe} not installed -- skip this check]"
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (result.stdout or "").strip()
        if result.stderr and result.stderr.strip():
            output += f"\n[stderr] {result.stderr.strip()}"
        return output or "[no output]"
    except subprocess.TimeoutExpired:
        return f"[{exe} timed out after {timeout}s]"
    except Exception as e:
        return f"[{exe} failed: {e}]"


def identify_hash(blob: str) -> str:
    """Heuristic hash-family identification from hex/modular-crypt strings.
    Names a likely algorithm so the decomposer has evidence; it does not
    attempt to invert the hash."""
    text = blob.strip()
    notes = []
    if text.startswith("$2a$") or text.startswith("$2b$") or text.startswith("$2y$"):
        notes.append("looks like bcrypt (modular crypt)")
    elif text.startswith("$argon2"):
        notes.append("looks like Argon2")
    elif text.startswith("$6$"):
        notes.append("looks like sha512crypt")
    elif text.startswith("$5$"):
        notes.append("looks like sha256crypt")
    elif text.startswith("$1$"):
        notes.append("looks like md5crypt")
    else:
        hex_only = re.fullmatch(r"[0-9a-fA-F]+", text)
        if hex_only:
            length = len(text)
            mapping = {
                32: "MD5 / MD4 / NTLM (32 hex chars)",
                40: "SHA-1 (40 hex chars)",
                56: "SHA-224 (56 hex chars)",
                64: "SHA-256 (64 hex chars)",
                96: "SHA-384 (96 hex chars)",
                128: "SHA-512 (128 hex chars)",
            }
            notes.append(mapping.get(length, f"unrecognized hex digest length {length}"))
        else:
            notes.append("not a familiar modular-crypt or hex digest shape")
    if shutil.which("hashid"):
        notes.append("hashid: " + _run(["hashid", text])[:500])
    elif shutil.which("hash-identifier"):
        notes.append("hash-identifier is installed but interactive -- skipped")
    return "\n".join(notes)


def openssl_inspect(path: str) -> str:
    """Describe a PEM/DER cert or key without extracting private material
    beyond what `openssl ... -text -noout` already prints locally."""
    chunks = []
    lower = path.lower()
    if lower.endswith((".crt", ".pem", ".cer", ".cert")):
        chunks.append(_run(["openssl", "x509", "-in", path, "-text", "-noout"]))
    if lower.endswith((".pem", ".key", ".pub")):
        chunks.append(_run(["openssl", "rsa", "-in", path, "-text", "-noout", "-pubin"]))
        chunks.append(_run(["openssl", "rsa", "-in", path, "-text", "-noout"]))
    if not chunks:
        chunks.append(_run(["openssl", "x509", "-in", path, "-text", "-noout"]))
        chunks.append(_run(["openssl", "rsa", "-in", path, "-pubin", "-in", path, "-text", "-noout"]))
    return "\n---\n".join(chunks)


def john_list_matching_formats(sample: str) -> str:
    """Ask John which format *names* exist. Does not start a crack."""
    listing = _run(["john", "--list=formats"])
    if listing.startswith("["):
        return listing
    text = sample.lower()
    hints = []
    for fmt in ("raw-md5", "raw-sha1", "raw-sha256", "bcrypt", "descrypt"):
        if fmt.replace("raw-", "") in text or fmt in listing.lower():
            hints.append(fmt)
    preview = listing.splitlines()[:8]
    return "john formats available (truncated):\n" + "\n".join(preview) + (
        f"\nheuristic matches for this sample: {', '.join(hints) or 'none'}"
    )


def rsa_public_properties(path: str) -> str:
    """Inspect a public key: modulus size and public exponent. Does not
    attempt Wiener/Fermat/common-modulus recovery."""
    text = _run(["openssl", "rsa", "-pubin", "-in", path, "-text", "-noout"])
    extras = []
    e_match = re.search(r"Exponent:\s+(\d+)", text)
    if e_match:
        exponent = int(e_match.group(1))
        if exponent in (3, 17):
            extras.append(
                f"small public exponent e={exponent} -- classic CTF lesson "
                "(cube-root / Hastad), inspect conceptually; this tool will not recover d."
            )
    bits = re.search(r"Private-Key:\s+\((\d+) bit\)", text) or re.search(r"Public-Key:\s+\((\d+) bit\)", text)
    if bits:
        extras.append(f"key size: {bits.group(1)} bits")
    extras.append(
        "RsaCtfTool is intentionally not auto-run (it recovers plaintext). "
        "If you have it installed, use it yourself in an isolated VM."
    )
    return text + ("\n" + "\n".join(extras) if extras else "")


def gather_crypto_evidence(path: Optional[str], strings_blob: str = "") -> dict:
    evidence = {}
    sample = strings_blob[:4000]
    hexish = re.findall(r"\b[0-9a-fA-F]{32,128}\b", sample)
    cryptish = re.findall(r"\$2[aby]\$[^\s]+|\$[156]\$[^\s]+", sample)
    candidates = cryptish + hexish[:5]
    if candidates:
        evidence["hash_id"] = "\n\n".join(
            f"{c[:80]} -> {identify_hash(c)}" for c in candidates[:5]
        )
        evidence["john_format_hint"] = john_list_matching_formats(candidates[0])
    if path:
        evidence["openssl"] = openssl_inspect(path)
        if path.lower().endswith((".pem", ".pub", ".key")):
            evidence["rsa_properties"] = rsa_public_properties(path)
    return evidence
