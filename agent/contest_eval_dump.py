"""
Build and expand evaluation dumps from public-contest-style challenge text.

Sources are rewritten descriptions grounded in commonly published practice
challenges (picoCTF-style, generic contest prompts). They are not verbatim
copies of proprietary contest text, and they are not generated from this
project's indicator table — so they remain usable as a blind eval set.

Usage:
  python -m agent.contest_eval_dump --write
  python -m agent.contest_eval_dump --merge-eval
  python main.py eval --public
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
DUMP_PATH = ROOT / "data" / "eval" / "contest_text_dump.jsonl"
PUBLIC_EVAL = ROOT / "data" / "eval" / "public_contest_grounded.json"

# Expanded public-contest-style prompts. Attribution is thematic, not a claim
# of ownership of any specific contest's wording.
DUMP_CASES: List[Dict[str, Any]] = [
    # --- pwn ---
    {
        "id": "dump-pwn-gets-crash",
        "description": "Smash the stack. Can you overflow the correct buffer? Input is read with gets; a SIGSEGV handler may print the flag.",
        "expected_category": "pwn",
        "expected_techniques": ["stack-buffer-overflow"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "picoCTF-style buffer overflow 0 theme",
    },
    {
        "id": "dump-pwn-ret2win",
        "description": "Control the return address. Overflow a small stack buffer and redirect execution to a win function already present in the binary.",
        "expected_category": "pwn",
        "expected_techniques": ["stack-buffer-overflow"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "picoCTF-style buffer overflow 1 theme",
    },
    {
        "id": "dump-pwn-canary",
        "description": "A stack canary protects against buffer overflows. Leak or brute the canary, then overwrite the return address.",
        "expected_category": "pwn",
        "expected_techniques": ["canary-bypass", "stack-buffer-overflow"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "picoCTF-style canary / buffer overflow 3 theme",
    },
    {
        "id": "dump-pwn-heap-adj",
        "description": "Two heap chunks sit next to each other. Overflowing the first overwrites a neighbouring safe variable used as a gate.",
        "expected_category": "pwn",
        "expected_techniques": ["heap-overflow"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "picoCTF-style heap-0 theme",
    },
    {
        "id": "dump-pwn-fmt-got",
        "description": "The program prints user input with printf. Using format specifiers, leak addresses and overwrite a GOT entry.",
        "expected_category": "pwn",
        "expected_techniques": ["format-string"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common format-string contest theme",
    },
    {
        "id": "dump-pwn-nx-ret2libc",
        "description": "NX is enabled so stack shellcode will not run. Divert control flow into libc to obtain a shell.",
        "expected_category": "pwn",
        "expected_techniques": ["ret2libc", "stack-buffer-overflow"],
        "difficulty": "hard",
        "source_style": "public-contest-grounded",
        "attribution": "common ret2libc contest theme",
    },
    {
        "id": "dump-pwn-rop-chain",
        "description": "Build a ROP chain from gadgets in the binary to call system with /bin/sh. ASLR is off for this instance.",
        "expected_category": "pwn",
        "expected_techniques": ["rop-chain"],
        "difficulty": "hard",
        "source_style": "public-contest-grounded",
        "attribution": "common ROP contest theme",
    },
    # --- web ---
    {
        "id": "dump-web-jwt-none",
        "description": "After login a cookie named jwt appears. The site blocks username admin at the form but trusts the token role field.",
        "expected_category": "web",
        "expected_techniques": ["jwt-none-bypass", "auth-bypass"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "picoCTF JaWT / JAuth family theme",
    },
    {
        "id": "dump-web-sqli-login",
        "description": "The login form concatenates username into SQL. A single quote changes the error. Log in as admin without the password.",
        "expected_category": "web",
        "expected_techniques": ["sql-injection"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "common SQLi login theme",
    },
    {
        "id": "dump-web-ssti",
        "description": "A greeting page renders your name through a server-side template engine. Template expressions in the name field are evaluated.",
        "expected_category": "web",
        "expected_techniques": ["ssti"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common SSTI contest theme",
    },
    {
        "id": "dump-web-lfi",
        "description": "A page loads files via a path query parameter. Directory traversal may reach /etc/passwd or the application source.",
        "expected_category": "web",
        "expected_techniques": ["path-traversal", "lfi"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common LFI / path traversal theme",
    },
    {
        "id": "dump-web-xss-cookie",
        "description": "A search box reflects input without encoding. Steal an admin session cookie via a crafted payload the bot will visit.",
        "expected_category": "web",
        "expected_techniques": ["xss-reflected", "xss-stored"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common XSS contest theme",
    },
    {
        "id": "dump-web-smuggle",
        "description": "Front-end and back-end disagree on Content-Length versus Transfer-Encoding. A crafted request can desync and smuggle a second request.",
        "expected_category": "web",
        "expected_techniques": ["http-request-smuggling"],
        "difficulty": "hard",
        "source_style": "public-contest-grounded",
        "attribution": "common request-smuggling theme",
    },
    # --- crypto ---
    {
        "id": "dump-crypto-caesar",
        "description": "The ciphertext looks like English with shifted alphabet positions. Frequency analysis should recover the motto.",
        "expected_category": "crypto",
        "expected_techniques": ["classical-caesar"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "common classical crypto theme",
    },
    {
        "id": "dump-crypto-xor-single",
        "description": "The flag was XOR-encrypted with one repeated byte. Ciphertext is hex. Recover the key and plaintext.",
        "expected_category": "crypto",
        "expected_techniques": ["xor-single-byte"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "common single-byte XOR theme",
    },
    {
        "id": "dump-crypto-xor-repeating",
        "description": "A long ciphertext was produced by XORing plaintext with a short repeating key. Kasiski-style analysis reveals the key length.",
        "expected_category": "crypto",
        "expected_techniques": ["xor-repeating-key"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common repeating-XOR theme",
    },
    {
        "id": "dump-crypto-rsa-e3",
        "description": "Textbook RSA with public exponent three and no padding. The message is short enough that cubing does not wrap the modulus.",
        "expected_category": "crypto",
        "expected_techniques": ["rsa-small-e"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common RSA small-e theme",
    },
    {
        "id": "dump-crypto-rsa-common-mod",
        "description": "The same message was encrypted under two RSA public keys that share a modulus. Recover the plaintext without factoring.",
        "expected_category": "crypto",
        "expected_techniques": ["rsa-common-modulus"],
        "difficulty": "hard",
        "source_style": "public-contest-grounded",
        "attribution": "common RSA common-modulus theme",
    },
    {
        "id": "dump-crypto-ecdsa-nonce",
        "description": "Two ECDSA signatures were produced with the same ephemeral nonce. Recover the private key from the pair of signatures.",
        "expected_category": "crypto",
        "expected_techniques": ["ecdsa-nonce-reuse"],
        "difficulty": "hard",
        "source_style": "public-contest-grounded",
        "attribution": "common ECDSA nonce-reuse theme",
    },
    # --- forensics ---
    {
        "id": "dump-forensics-pcap",
        "description": "Investigate this packet capture. Extract the file transferred over HTTP and open it for the flag.",
        "expected_category": "forensics",
        "expected_techniques": ["pcap-carving"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common pcap forensics theme",
    },
    {
        "id": "dump-forensics-disk",
        "description": "You are given a USB disk image. Recover a deleted document from unallocated space.",
        "expected_category": "forensics",
        "expected_techniques": ["disk-image-analysis", "file-carving"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common disk-image forensics theme",
    },
    {
        "id": "dump-forensics-lsb",
        "description": "An ordinary-looking PNG hides a bitstream in the lowest bit of each colour channel.",
        "expected_category": "forensics",
        "expected_techniques": ["steganography"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common LSB stego theme",
    },
    {
        "id": "dump-forensics-exif",
        "description": "Someone forgot to strip metadata from this JPEG. Photographer and camera model remain embedded.",
        "expected_category": "forensics",
        "expected_techniques": ["image-metadata"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "common EXIF forensics theme",
    },
    # --- rev ---
    {
        "id": "dump-rev-crackme",
        "description": "Reverse engineer this crackme. Enter the correct serial for your name to print the flag. The check is local in the binary.",
        "expected_category": "rev",
        "expected_techniques": ["keygen", "algorithm-recovery"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common keygen/crackme theme",
    },
    {
        "id": "dump-rev-packed",
        "description": "The sample's entry point jumps to a stub that unpacks the real code into memory and rebuilds the import table.",
        "expected_category": "rev",
        "expected_techniques": ["packed-binary"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common packer/unpack theme",
    },
    {
        "id": "dump-rev-go",
        "description": "A stripped binary written in Google's language. Recover function names from the remaining metadata tables.",
        "expected_category": "rev",
        "expected_techniques": ["go-reversing"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common Go reverse-engineering theme",
    },
    # --- misc / osint / blockchain ---
    {
        "id": "dump-misc-nested-zip",
        "description": "Try start. Nested password-protected archives form a chain; one archive comment channel encodes bits of the final password.",
        "expected_category": "misc",
        "expected_techniques": ["nested-archive"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "SSCTF-style nested archive theme",
    },
    {
        "id": "dump-misc-encoding",
        "description": "The challenge text looks like base64 but fails until you notice it is hex that was then base64-encoded.",
        "expected_category": "misc",
        "expected_techniques": ["multilayer-encoding", "encoding-recognition"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "common multilayer encoding theme",
    },
    {
        "id": "dump-osint-photo",
        "description": "Find where this photo was taken. The image may still contain location metadata from the camera.",
        "expected_category": "osint",
        "expected_techniques": ["osint-geolocation", "image-metadata"],
        "difficulty": "easy",
        "source_style": "public-contest-grounded",
        "attribution": "common OSINT geolocation theme",
    },
    {
        "id": "dump-blockchain-reentrancy",
        "description": "A Solidity contract pays out before updating balances. Call the withdraw function recursively to drain the contract.",
        "expected_category": "blockchain",
        "expected_techniques": ["reentrancy"],
        "difficulty": "medium",
        "source_style": "public-contest-grounded",
        "attribution": "common reentrancy theme",
    },
]


def write_dump(path: Path = DUMP_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for case in DUMP_CASES:
            f.write(json.dumps(case, ensure_ascii=False) + "\n")
    return path


def load_dump(path: Path = DUMP_PATH) -> List[Dict[str, Any]]:
    if not path.exists():
        return list(DUMP_CASES)
    out: List[Dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def merge_into_public_eval(
    dump: List[Dict[str, Any]] | None = None,
    eval_path: Path = PUBLIC_EVAL,
) -> Dict[str, int]:
    """Merge dump cases into the public eval JSON (dedupe by id)."""
    dump = dump if dump is not None else load_dump()
    existing: List[Dict[str, Any]] = []
    if eval_path.exists():
        existing = json.loads(eval_path.read_text(encoding="utf-8"))
    by_id = {c["id"]: c for c in existing}
    added = 0
    for case in dump:
        if case["id"] not in by_id:
            by_id[case["id"]] = case
            added += 1
        else:
            by_id[case["id"]] = case  # refresh text
    merged = list(by_id.values())
    eval_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return {"total": len(merged), "added": added, "from_dump": len(dump)}


def score_dump(dump: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge

    dump = dump if dump is not None else load_dump()
    ok = 0
    misses = []
    for case in dump:
        pred = classify_challenge(case["description"]).category
        if pred == case["expected_category"]:
            ok += 1
        else:
            misses.append({"id": case["id"], "pred": pred, "exp": case["expected_category"]})
    return {
        "n": len(dump),
        "ok": ok,
        "accuracy": (ok / len(dump)) if dump else 0.0,
        "misses": misses,
    }


def main(argv: List[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--write", action="store_true", help="write JSONL dump file")
    p.add_argument("--merge-eval", action="store_true", help="merge dump into public_contest_grounded.json")
    p.add_argument("--score", action="store_true", help="score dump with formal classifier")
    args = p.parse_args(argv)

    if not any([args.write, args.merge_eval, args.score]):
        args.write = args.merge_eval = args.score = True

    if args.write:
        path = write_dump()
        print(f"wrote {len(DUMP_CASES)} cases -> {path}")
    if args.merge_eval:
        stats = merge_into_public_eval()
        print(f"public eval: total={stats['total']} added={stats['added']}")
    if args.score:
        report = score_dump()
        print(f"accuracy {report['ok']}/{report['n']} = {report['accuracy']:.3f}")
        for m in report["misses"]:
            print(f"  MISS {m['id']}: pred={m['pred']} exp={m['exp']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
