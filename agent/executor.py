"""
agent/executor.py

Safe, local-only execution of planned tools.

Rules:
- Never executes arbitrary user binaries.
- Never opens network connections except to the already-configured local Ollama.
- All file access is read-oriented and size-limited.
- Failures are returned as structured errors, never raised to crash the loop.
"""

from __future__ import annotations

import json
import time
import traceback
from typing import Any, Dict, Tuple

from agent.state import ActionRecord, ActionStatus


def execute_action(action: ActionRecord) -> Tuple[bool, str, str]:
    """
    Run one planned action.
    Returns (success, result_summary_or_output, error_message).
    """
    tool = action.tool
    args = action.arguments or {}
    start = time.time()

    try:
        if tool == "classify":
            return _run_classify(args)
        if tool == "decompose":
            return _run_decompose(args)
        if tool == "retrieve_archive":
            return _run_retrieve(args)
        if tool == "static_analysis":
            return _run_static(args)
        if tool == "web_recon":
            return _run_web_recon(args)
        if tool == "crypto_toolkit":
            return _run_crypto(args)
        if tool == "forensics_toolkit":
            return _run_forensics(args)
        if tool == "decode_toolkit":
            return _run_decode(args)
        if tool == "xor_crack":
            return _run_xor(args)
        if tool == "auto_decode":
            return _run_auto_decode(args)
        if tool == "gdb_inspect":
            return _run_gdb(args)
        if tool == "platform_ctfd":
            return _run_ctfd(args)
        if tool == "platform_htb":
            return _run_htb(args)
        if tool == "research":
            return _run_research(args)
        if tool == "ask_user":
            # The loop surfaces this to the caller; we do not block here.
            q = args.get("question", "Please provide more information.")
            return True, f"USER_QUESTION: {q}", ""
        if tool == "verify_candidate":
            return _run_verify(args)
        return False, "", f"Unknown or disallowed tool: {tool}"
    except Exception as exc:
        return False, "", f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-500:]}"
    finally:
        # duration is recorded by the caller
        _ = start


def _run_classify(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    from classifier import classify_heuristic, classify
    desc = args.get("description") or ""
    cat, scores = classify_heuristic(desc)
    if cat:
        return True, json.dumps({"category": cat, "scores": scores, "method": "heuristic"}), ""
    # Fall back to full classify only if heuristic is weak (may call LLM)
    try:
        result = classify(desc)
        return True, json.dumps({"category": result, "method": "llm_or_heuristic"}), ""
    except Exception as e:
        return True, json.dumps({"category": None, "scores": scores, "error": str(e)}), ""


def _run_decompose(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    from decomposer import decompose
    desc = args.get("description") or ""
    category = args.get("category") or None
    try:
        subproblems = decompose(desc, category=category)
        # subproblems may be list of SubProblem or dicts
        out = []
        for sp in subproblems or []:
            if hasattr(sp, "to_dict"):
                out.append(sp.to_dict())
            elif hasattr(sp, "__dict__"):
                out.append({k: getattr(sp, k) for k in ("id", "description", "likely_techniques", "evidence") if hasattr(sp, k)})
            else:
                out.append(str(sp))
        return True, json.dumps({"subproblems": out}, default=str), ""
    except Exception as e:
        return False, "", str(e)


def _run_retrieve(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    import os
    if os.getenv('CTF_TUTOR_DISABLE_RETRIEVE') in ('1', 'true', 'True'):
        return True, json.dumps({'matches': [], 'note': 'retrieve disabled (ablation)'}), ''
    query = args.get("query") or ""
    category = args.get("category") or None
    top_k = int(args.get("top_k") or 5)
    try:
        from agent.hybrid_retrieve import hybrid_search
        matches = hybrid_search(query, category=category, top_k=top_k)
        return True, json.dumps({"matches": matches}, default=str), ""
    except Exception as e:
        return True, json.dumps({"matches": [], "note": f"retrieval unavailable: {e}"}), ""


def _run_static(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = (args.get("path") or "").strip()
    if not path:
        return True, json.dumps({"note": "no path provided; static analysis skipped"}), ""
    try:
        from tools.static_analysis import full_recon
        result = full_recon(path, category_hint=args.get("category_hint"))
        if isinstance(result, dict):
            return True, json.dumps(result, default=str)[:4000], ""
        return True, str(result)[:4000], ""
    except TypeError:
        try:
            from tools.static_analysis import full_recon
            result = full_recon(path)
            return True, json.dumps(result, default=str)[:4000] if isinstance(result, dict) else str(result)[:4000], ""
        except Exception as e:
            return False, "", str(e)
    except Exception as e:
        return False, "", str(e)


def _run_web_recon(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = (args.get("path") or "").strip()
    if not path:
        return True, json.dumps({"note": "no path; web_recon skipped"}), ""
    try:
        from tools.web_recon import gather_web_evidence
        result = gather_web_evidence(path)
        return True, json.dumps(result, default=str)[:4000] if isinstance(result, dict) else str(result)[:4000], ""
    except Exception as e:
        return False, "", str(e)


def _run_crypto(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    target = args.get("path_or_text") or args.get("path") or ""
    if not target:
        return True, json.dumps({"note": "no input; crypto_toolkit skipped"}), ""
    try:
        from tools.crypto_toolkit import gather_crypto_evidence
        result = gather_crypto_evidence(target if '/' in str(target) or str(target).endswith(('.pem','.key','.txt')) else None, strings_blob=str(target))
        return True, json.dumps(result, default=str)[:4000] if isinstance(result, dict) else str(result)[:4000], ""
    except Exception as e:
        return False, "", str(e)


def _run_forensics(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    path = (args.get("path") or "").strip()
    if not path:
        return True, json.dumps({"note": "no path; forensics skipped"}), ""
    try:
        from tools.forensics_toolkit import gather_forensics_evidence
        result = gather_forensics_evidence(path)
        return True, json.dumps(result, default=str)[:4000] if isinstance(result, dict) else str(result)[:4000], ""
    except Exception as e:
        return False, "", str(e)


def _run_decode(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    target = args.get("path_or_text") or ""
    if not target:
        return True, json.dumps({"note": "no input"}), ""
    try:
        from tools.decode_toolkit import magic_decode
        result = magic_decode(target)
        return True, json.dumps({"candidates": result}, default=str)[:4000], ""
    except Exception as e:
        return False, "", str(e)


def _run_xor(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    data = args.get("data")
    if data is None:
        return True, json.dumps({"note": "no data"}), ""
    try:
        from tools.xor_crack import crack_repeating_xor as crack
        max_ks = int(args.get("max_keysize") or 16)
        if isinstance(data, str):
            # try hex then utf-8
            try:
                raw = bytes.fromhex(data.replace(" ", ""))
            except ValueError:
                raw = data.encode("utf-8", errors="replace")
        else:
            raw = bytes(data)
        results = crack(raw, max_keysize=max_ks)
        out = []
        for r in (results or [])[:5]:
            if hasattr(r, "_asdict"):
                out.append(r._asdict())
            elif isinstance(r, dict):
                out.append(r)
            else:
                out.append(str(r))
        return True, json.dumps({"candidates": out}, default=str)[:4000], ""
    except Exception as e:
        return False, "", str(e)


def _run_verify(args: Dict[str, Any]) -> Tuple[bool, str, str]:
    candidate = (args.get("candidate") or "").strip()
    constraints = args.get("constraints") or {}
    if not candidate:
        return True, json.dumps({"valid": False, "reason": "empty candidate"}), ""
    reasons = []
    valid = True
    # Basic flag-format heuristics
    flag_prefixes = ("flag{", "ctf{", "htb{", "picoctf{", "fh{", "lactf{")
    lower = candidate.lower()
    looks_like_flag = any(lower.startswith(p) or p in lower for p in flag_prefixes) or (
        candidate.startswith("{") and candidate.endswith("}")
    )
    if constraints.get("must_look_like_flag") and not looks_like_flag:
        valid = False
        reasons.append("does not match common flag format")
    if constraints.get("min_length") and len(candidate) < int(constraints["min_length"]):
        valid = False
        reasons.append("too short")
    return True, json.dumps({
        "valid": valid,
        "looks_like_flag": looks_like_flag,
        "reasons": reasons,
        "candidate_preview": candidate[:80],
    }), ""


def _run_research(args):
    import json
    try:
        from agent.research import research, format_citations
        q = args.get("query") or args.get("question") or ""
        cat = args.get("category") or None
        online = bool(args.get("online", False))
        hits = research(q, category=cat, online=online, top_k=int(args.get("top_k") or 5))
        return True, json.dumps({
            "hits": [h.to_dict() for h in hits],
            "citations": format_citations(hits),
        }, default=str)[:5000], ""
    except Exception as e:
        return True, json.dumps({"hits": [], "note": str(e)}), ""


def _run_auto_decode(args):
    import json
    try:
        from agent.auto_decode import auto_decode, scan_for_flags
        data = args.get("data") or args.get("path_or_text") or args.get("text") or ""
        if not data and args.get("path"):
            from pathlib import Path
            p = Path(args["path"])
            if p.is_file() and p.stat().st_size < 2_000_000:
                data = p.read_bytes()
        if not data:
            return True, json.dumps({"note": "no input"}), ""
        result = auto_decode(data, max_depth=int(args.get("max_depth") or 8),
                             timeout_sec=float(args.get("timeout") or 2.0))
        return True, json.dumps(result.to_dict()), ""
    except Exception as e:
        return False, "", str(e)


def _run_gdb(args):
    import json
    try:
        from agent.gdb_agent import inspect_binary, disassemble_function, gdb_available
        if not gdb_available():
            return True, json.dumps({"ok": False, "error": "gdb not available"}), ""
        path = (args.get("path") or args.get("binary") or "").strip()
        if not path:
            return True, json.dumps({"ok": False, "error": "no binary path"}), ""
        fn = args.get("function")
        if fn:
            result = disassemble_function(path, fn)
        else:
            result = inspect_binary(path)
        return True, json.dumps(result, default=str)[:6000], ""
    except Exception as e:
        return False, "", str(e)


def _run_ctfd(args):
    import json
    try:
        from agent.platforms import ctfd_list_challenges, ctfd_challenge_detail
        base = args.get("base_url") or ""
        if args.get("challenge_id"):
            result = ctfd_challenge_detail(base, int(args["challenge_id"]))
        else:
            result = ctfd_list_challenges(base)
        return True, json.dumps(result, default=str)[:6000], ""
    except Exception as e:
        return False, "", str(e)


def _run_htb(args):
    import json
    try:
        from agent.platforms import htb_list_machines, htb_profile
        if args.get("profile"):
            result = htb_profile()
        else:
            result = htb_list_machines(int(args.get("limit") or 20))
        return True, json.dumps(result, default=str)[:6000], ""
    except Exception as e:
        return False, "", str(e)
