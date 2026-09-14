"""
web_recon.py

Passive reconnaissance toolkit for web challenges. Extracts evidence from
source code files, HTTP responses, or static analysis that helps the
decomposer understand the challenge structure.

All checks are passive — no actual requests/exploitation, just analysis of
local files or provided content.
"""

import json
import re
from typing import Optional, Dict, List


def _safe_read(path: str, max_size: int = 1024 * 1024) -> Optional[str]:
    """Safely read a file without blowing up the process on huge files."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_size)
    except Exception:
        return None


def decode_jwt(token: str) -> Dict[str, any]:
    """
    Decode a JWT token into its header and payload (no signature verification).
    Returns a dict with 'header', 'payload', 'valid', 'issues' keys.
    
    This is educational only — always verify signatures server-side.
    """
    import base64
    
    result = {"header": None, "payload": None, "valid": False, "issues": []}
    
    parts = token.split(".")
    if len(parts) != 3:
        result["issues"].append(f"JWT has {len(parts)} parts, expected 3")
        return result
    
    def decode_part(part: str) -> Optional[dict]:
        try:
            # Add padding if needed
            padding = 4 - len(part) % 4
            if padding and padding != 4:
                part += "=" * padding
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception as e:
            return None
    
    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    
    if not header:
        result["issues"].append("Could not decode header")
    if not payload:
        result["issues"].append("Could not decode payload")
    
    result["header"] = header or {}
    result["payload"] = payload or {}
    result["valid"] = header is not None and payload is not None
    
    # Check for common issues
    if header:
        alg = header.get("alg", "").lower()
        if alg == "none":
            result["issues"].append("⚠️  Algorithm is 'none' — signature can be stripped")
        if alg.startswith("hs") and header.get("typ", "").lower() == "jwt":
            result["issues"].append("⚠️  Uses HMAC (symmetric) — secret key needed for verification")
        if alg.startswith("rs") or alg.startswith("es"):
            result["issues"].append("ℹ️  Uses asymmetric signing (RSA/ECDSA)")
    
    return result


def scan_jwt_in_source(path: str) -> List[Dict]:
    """
    Scan source code for JWT tokens (base64-like patterns with 3 dot-separated parts).
    Returns list of found tokens with decoded info.
    """
    content = _safe_read(path)
    if not content:
        return []
    
    # Regex for JWT-like patterns: xxx.yyy.zzz (base64url characters)
    jwt_pattern = r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
    matches = re.findall(jwt_pattern, content)
    
    results = []
    for token in matches[:5]:  # Limit to first 5 to avoid spam
        decoded = decode_jwt(token)
        results.append({"token": token[:50] + "..." if len(token) > 50 else token, "decoded": decoded})
    
    return results


def scan_headers_in_source(path: str) -> Dict[str, str]:
    """
    Scan source code for common security-relevant HTTP headers or header patterns.
    Looks for things like CORS, CSP, Authorization, etc.
    """
    content = _safe_read(path)
    if not content:
        return {}
    
    headers_found = {}
    
    # Common patterns in Flask/Django/Node.js code
    header_patterns = {
        "Authorization": r"(?:Authorization|auth\s*[:=])\s*['\"]?Bearer",
        "CORS": r"(?:Access-Control|CORS|cors)",
        "CSP": r"(?:Content-Security-Policy|CSP)",
        "X-Frame-Options": r"X-Frame-Options",
        "Strict-Transport-Security": r"(?:HSTS|Strict-Transport-Security)",
        "X-Content-Type-Options": r"X-Content-Type-Options",
        "Set-Cookie": r"Set-Cookie|cookie\s*[:=]",
    }
    
    for header_name, pattern in header_patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            headers_found[header_name] = "Found in code"
    
    return headers_found


def detect_framework(path: str) -> Dict[str, str]:
    """
    Detect web framework hints from source code.
    Returns dict with framework names and confidence indicators.
    """
    content = _safe_read(path)
    if not content:
        return {}
    
    frameworks = {}
    
    framework_indicators = {
        "Flask": [r"from flask import", r"@app\.route", r"Flask(__name__)"],
        "Django": [r"from django", r"django\.conf", r"models\.Model"],
        "FastAPI": [r"from fastapi import", r"@app\.get", r"@app\.post"],
        "Express.js": [r"require\(['\"]express", r"app\.get\(", r"app\.post\("],
        "Spring": [r"@SpringBootApplication", r"@RestController", r"org\.springframework"],
        "Laravel": [r"<?php.*Route::", r"Illuminate\\", r"artisan"],
        "Rails": [r"Rails\.application", r"ActiveRecord", r"erb"],
        "ASP.NET": [r"using System\.", r"public class.*Controller", r"[Cc]ontroller\s*:"],
    }
    
    for framework, patterns in framework_indicators.items():
        match_count = sum(1 for p in patterns if re.search(p, content, re.MULTILINE))
        if match_count > 0:
            frameworks[framework] = f"{match_count} indicator(s)"
    
    return frameworks


def scan_authentication_patterns(path: str) -> Dict[str, List[str]]:
    """
    Scan for common authentication/authorization patterns.
    Useful for identifying auth-bypass or privilege-escalation angles.
    """
    content = _safe_read(path)
    if not content:
        return {}
    
    patterns = {
        "Basic Auth": [r"Authorization.*Basic", r"base64.*decode"],
        "JWT": [r"jwt\.", r"JWT", r"decode.*token"],
        "OAuth": [r"oauth", r"access_token", r"refresh_token"],
        "Session": [r"session\[", r"req\.session", r"SESSION_ID"],
        "API Key": [r"api[_-]?key", r"API[_-]?KEY", r"x-api-key"],
        "Password Hash": [r"bcrypt", r"argon2", r"sha256", r"hash"],
    }
    
    found = {}
    for auth_type, auth_patterns in patterns.items():
        matches = []
        for p in auth_patterns:
            if re.search(p, content, re.IGNORECASE):
                matches.append(p)
        if matches:
            found[auth_type] = matches
    
    return found


def analyze_source_file(path: str) -> Dict:
    """
    Comprehensive passive analysis of a web source file.
    Returns a dict with all discovered evidence.
    """
    return {
        "file_type": "web source",
        "framework": detect_framework(path),
        "jwt_tokens": scan_jwt_in_source(path),
        "headers": scan_headers_in_source(path),
        "auth_patterns": scan_authentication_patterns(path),
    }


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m tools.web_recon <source_file>")
        sys.exit(1)
    
    path = sys.argv[1]
    result = analyze_source_file(path)
    print(json.dumps(result, indent=2))
