"""
crypto_toolkit.py

Passive reconnaissance toolkit for cryptography challenges. Analyzes files
and ciphertext to identify hash types, RSA key properties, and common
crypto vulnerabilities without actually solving them.

All analysis is passive — no brute-force, no actual decryption, just
structural and vulnerability classification.
"""

import re
import json
from typing import Optional, Dict, List, Tuple


def _safe_read(path: str, max_size: int = 1024 * 1024) -> Optional[str]:
    """Safely read a file without blowing up the process on huge files."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_size)
    except Exception:
        return None


# Common hash signatures by length and format
HASH_SIGNATURES = {
    # Length-based identification
    32: [
        ("MD5", r"^[a-f0-9]{32}$"),
        ("MD4", r"^[a-f0-9]{32}$"),  # Same length, need more context
    ],
    40: [
        ("SHA-1", r"^[a-f0-9]{40}$"),
    ],
    56: [
        ("SHA-224", r"^[a-f0-9]{56}$"),
    ],
    64: [
        ("SHA-256", r"^[a-f0-9]{64}$"),
        ("BLAKE2b-256", r"^[a-f0-9]{64}$"),
    ],
    96: [
        ("SHA-384", r"^[a-f0-9]{96}$"),
    ],
    128: [
        ("SHA-512", r"^[a-f0-9]{128}$"),
        ("BLAKE2b", r"^[a-f0-9]{128}$"),
    ],
}

# Hash format prefixes (common in system files and applications)
HASH_FORMAT_PREFIXES = {
    "$1$": "MD5 (Unix crypt)",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt (fixed)",
    "$2y$": "bcrypt (PHP)",
    "$5$": "SHA-256 (Unix crypt)",
    "$6$": "SHA-512 (Unix crypt)",
    "$argon2i$": "Argon2i",
    "$argon2d$": "Argon2d",
    "$argon2id$": "Argon2id",
    "$scrypt$": "scrypt",
    "$pbkdf2-": "PBKDF2",
}


def identify_hash(hash_string: str) -> Dict[str, any]:
    """
    Identify hash type from a hash string or file containing hashes.
    Returns dict with 'type', 'confidence', 'analysis' keys.
    """
    hash_string = hash_string.strip()
    
    # Check format prefixes first (highest confidence)
    for prefix, hash_type in HASH_FORMAT_PREFIXES.items():
        if hash_string.startswith(prefix):
            return {
                "type": hash_type,
                "confidence": "high",
                "analysis": f"Format prefix '{prefix}' indicates {hash_type}",
                "raw_sample": hash_string[:60],
            }
    
    # Check length-based signatures
    length = len(hash_string)
    if length in HASH_SIGNATURES:
        candidates = []
        for hash_type, pattern in HASH_SIGNATURES[length]:
            if re.match(pattern, hash_string):
                candidates.append(hash_type)
        
        if candidates:
            return {
                "type": candidates[0],
                "confidence": "medium" if len(candidates) > 1 else "high",
                "analysis": f"Length {length} and hex pattern match(es): {', '.join(candidates)}",
                "candidates": candidates,
                "raw_sample": hash_string[:60],
            }
    
    return {
        "type": "unknown",
        "confidence": "low",
        "analysis": f"Could not identify (length={length}, hex={bool(re.match(r'^[a-f0-9]+$', hash_string))})",
        "raw_sample": hash_string[:60],
    }


def identify_hashes_in_file(path: str) -> List[Dict]:
    """
    Scan a file for hash strings and identify each.
    Returns list of identified hashes with context.
    """
    content = _safe_read(path)
    if not content:
        return []
    
    results = []
    lines = content.split("\n")
    
    for line_num, line in enumerate(lines[:100], 1):  # Scan first 100 lines
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Extract potential hashes (long hex strings or prefixed formats)
        candidates = re.findall(r"(?:\$[a-z0-9_\-]+\$[a-zA-Z0-9\./\$]+|[a-f0-9]{32,128})", line)
        
        for candidate in candidates:
            identified = identify_hash(candidate)
            if identified["type"] != "unknown":
                results.append({
                    "line": line_num,
                    "context": line[:100],
                    **identified,
                })
    
    return results[:10]  # Limit to first 10 to avoid spam


def analyze_rsa_key(path: str) -> Dict:
    """
    Analyze an RSA public/private key file for properties relevant to CTF.
    Looks for key size, exponent, modulus properties.
    """
    content = _safe_read(path)
    if not content:
        return {"error": "Could not read file"}
    
    analysis = {
        "is_rsa_key": False,
        "key_type": None,
        "properties": [],
    }
    
    # Check for PEM markers
    if "-----BEGIN RSA PRIVATE KEY-----" in content or "-----BEGIN PRIVATE KEY-----" in content:
        analysis["key_type"] = "private"
        analysis["is_rsa_key"] = True
    elif "-----BEGIN PUBLIC KEY-----" in content or "-----BEGIN RSA PUBLIC KEY-----" in content:
        analysis["key_type"] = "public"
        analysis["is_rsa_key"] = True
    elif "-----BEGIN CERTIFICATE-----" in content:
        analysis["key_type"] = "certificate"
        analysis["is_rsa_key"] = True
    
    if not analysis["is_rsa_key"]:
        # Try to parse as raw hex/base64 RSA components
        if re.search(r"modulus|exponent|prime", content, re.IGNORECASE):
            analysis["is_rsa_key"] = True
            analysis["key_type"] = "components"
    
    # Extract key size from modulus if present
    modulus_match = re.search(r"modulus\s*:\s*(\d+)\s*bit", content, re.IGNORECASE)
    if modulus_match:
        key_size = int(modulus_match.group(1))
        analysis["key_size"] = key_size
        if key_size < 1024:
            analysis["properties"].append("⚠️  Key size < 1024 bits (potentially weak)")
        elif key_size == 1024:
            analysis["properties"].append("⚠️  Key size = 1024 bits (deprecated, should be ≥2048)")
        elif key_size == 2048:
            analysis["properties"].append("ℹ️  Key size = 2048 bits (standard)")
        elif key_size >= 4096:
            analysis["properties"].append("ℹ️  Key size ≥ 4096 bits (strong)")
    
    # Check for common RSA vulnerabilities
    if "common modulus" in content.lower():
        analysis["properties"].append("⚠️  Common modulus attack possible")
    if re.search(r"small.*exponent|e\s*=\s*[0-9]\s", content, re.IGNORECASE):
        analysis["properties"].append("⚠️  Small public exponent detected (possible small-e attack)")
    if re.search(r"weak.*prime|small.*prime", content, re.IGNORECASE):
        analysis["properties"].append("⚠️  Weak prime factor indicated")
    
    return analysis


def scan_crypto_patterns(path: str) -> Dict:
    """
    Scan source code for cryptographic usage patterns.
    Identifies cipher modes, padding schemes, key derivation functions.
    """
    content = _safe_read(path)
    if not content:
        return {}
    
    patterns = {
        "Cipher Modes": {
            "ECB": r"ECB|electronic.?codebook",
            "CBC": r"CBC|cipher.?block.?chaining",
            "GCM": r"GCM|galois",
            "CTR": r"CTR|counter",
            "OFB": r"OFB",
            "CFB": r"CFB",
        },
        "Algorithms": {
            "AES": r"AES|Rijndael",
            "DES": r"\bDES\b|TripleDES|3DES",
            "RSA": r"RSA|rsa",
            "ECC": r"ECC|elliptic",
            "SHA": r"SHA-?[0-9]|SHA\([0-9]\)",
            "MD5": r"MD5|md5",
            "XOR": r"XOR|xor|\s\^\s",
        },
        "Padding": {
            "PKCS7": r"PKCS[#7]|PKCS.?7",
            "PKCS1": r"PKCS[#1]|OAEP",
            "No Padding": r"no.?padding|padding.?false|NoPadding",
        },
        "Key Derivation": {
            "PBKDF2": r"PBKDF2",
            "bcrypt": r"bcrypt",
            "scrypt": r"scrypt",
            "Argon2": r"argon2",
        },
    }
    
    found = {}
    for category, category_patterns in patterns.items():
        found[category] = {}
        for name, pattern in category_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                found[category][name] = "detected"
    
    # Remove empty categories
    return {k: v for k, v in found.items() if v}


def analyze_ciphertext(ciphertext: str) -> Dict:
    """
    Analyze a ciphertext or encrypted blob for properties.
    Returns info about encoding, entropy, likely algorithm.
    """
    ciphertext = ciphertext.strip()
    
    analysis = {
        "length": len(ciphertext),
        "encoding": None,
        "entropy_estimate": None,
        "block_size_hints": [],
    }
    
    # Check encoding
    if re.match(r"^[a-f0-9]+$", ciphertext, re.IGNORECASE):
        analysis["encoding"] = "hex"
    elif re.match(r"^[A-Za-z0-9+/]*={0,2}$", ciphertext):
        analysis["encoding"] = "base64"
    elif re.match(r"^[A-Za-z0-9_-]*={0,2}$", ciphertext):
        analysis["encoding"] = "base64url"
    
    # Estimate entropy (simple: ratio of unique chars to length)
    unique_chars = len(set(ciphertext))
    analysis["entropy_estimate"] = f"{100 * unique_chars / len(ciphertext):.1f}% (unique chars / length)"
    
    # Check for block size patterns (AES is 16-byte / 32-char hex blocks)
    if analysis["encoding"] == "hex":
        if len(ciphertext) % 32 == 0:
            block_size = len(ciphertext) // 32
            analysis["block_size_hints"].append(f"Length is multiple of 32 hex chars ({block_size} AES blocks?)")
    elif analysis["encoding"] and analysis["encoding"].startswith("base64"):
        if len(ciphertext) % 24 == 0:
            analysis["block_size_hints"].append("Length is multiple of 24 base64 chars (18 bytes = multiple of AES?)")
    
    return analysis


def analyze_crypto_file(path: str) -> Dict:
    """
    Comprehensive passive analysis of a crypto-related file.
    """
    content = _safe_read(path)
    if not content:
        return {"error": "Could not read file"}
    
    return {
        "file_type": "crypto",
        "hashes_found": identify_hashes_in_file(path),
        "rsa_key_analysis": analyze_rsa_key(path),
        "crypto_patterns": scan_crypto_patterns(path),
        "ciphertext_samples": [
            analyze_ciphertext(sample)
            for sample in re.findall(r"[a-f0-9]{32,256}|[A-Za-z0-9+/]{32,256}={0,2}", content)[:3]
        ],
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m tools.crypto_toolkit <file_or_hash>")
        sys.exit(1)
    
    path_or_hash = sys.argv[1]
    
    # Try as file first, then as a hash string
    try:
        result = analyze_crypto_file(path_or_hash)
    except Exception:
        result = identify_hash(path_or_hash)
    
    print(json.dumps(result, indent=2))
