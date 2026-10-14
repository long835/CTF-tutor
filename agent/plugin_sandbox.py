from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Defaults; resolved at call time when timeout is None
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_OUTPUT = 64_000
MAX_TOOLS = 50
TOOL_NAME_RE = r"^[A-Za-z0-9_-]+$"


def _repo_root() -> Path:
    # agent/plugin_sandbox.py -> repo_root/agent/plugin_sandbox.py
    return Path(__file__).resolve().parent.parent


def _allow_env() -> Dict[str, str]:
    env: Dict[str, str] = {}
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    env["LANG"] = os.environ.get("LANG", "C.UTF-8")
    env["PYTHONUNBUFFERED"] = "1"
    if "PYTHONPATH" in os.environ:
        env["PYTHONPATH"] = os.environ["PYTHONPATH"]
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def _start_proc(cmd: List[str]):
    # Use process-group semantics so we can kill entire group on timeout
    if os.name == "nt":
        # CREATE_NEW_PROCESS_GROUP lets us send CTRL_BREAK_EVENT to the group if needed
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_allow_env(),
            cwd=str(_repo_root()),
            creationflags=creationflags,
        )
    else:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_allow_env(),
            cwd=str(_repo_root()),
            start_new_session=True,
        )
    return proc


def _kill_proc(proc: subprocess.Popen) -> None:
    try:
        if os.name != "nt":
            try:
                os.killpg(proc.pid, 9)
            except Exception:
                pass
        else:
            try:
                proc.send_signal(subprocess.signal.CTRL_BREAK_EVENT)  # type: ignore[attr-defined]
            except Exception:
                pass
    except Exception:
        pass
    try:
        proc.kill()
    except Exception:
        pass


def _validate_tool_entry(t: Any) -> Optional[str]:
    # returns None if ok or error string
    if not isinstance(t, dict):
        return "tool entry must be an object"
    name = t.get("name")
    if not isinstance(name, str) or not name:
        return "tool.name must be a non-empty string"
    import re

    if not re.match(TOOL_NAME_RE, name):
        return f"invalid tool name: {name!r}"
    desc = t.get("description")
    if desc is not None and not isinstance(desc, str):
        return "tool.description must be a string"
    perm = t.get("permission")
    if perm is not None and not isinstance(perm, str):
        return "tool.permission must be a string"
    tags = t.get("category_tags")
    if tags is not None:
        if not isinstance(tags, list):
            return "tool.category_tags must be a list"
        for x in tags:
            if not isinstance(x, str):
                return "tool.category_tags must be a list of strings"
    return None


def _read_one_line_with_cap(proc: subprocess.Popen, cap: int, timeout: float) -> (str, str, int):
    """
    Read a single line from proc.stdout up to cap bytes. On POSIX this uses select
    to avoid unbounded blocking. Returns (stdout_str, stderr_str, returncode)
    If the cap is exceeded, the function attempts to kill the process group and
    returns what was read up to that point.
    """
    stdout_collected = []
    total = 0
    start = time.time()
    stderr = ""
    # POSIX iterative non-blocking read using select
    if os.name != "nt":
        import select

        fd = proc.stdout.fileno()
        while True:
            remaining = max(0.01, timeout - (time.time() - start))
            if remaining <= 0:
                _kill_proc(proc)
                try:
                    _, stderr = proc.communicate(timeout=1)
                except Exception:
                    stderr = ""
                return "".join(stdout_collected), stderr, proc.returncode if proc.returncode is not None else -1
            rlist, _, _ = select.select([fd], [], [], remaining)
            if not rlist:
                # timeout slice, loop again
                continue
            # data available
            line = proc.stdout.readline()
            if line == "":
                # EOF
                break
            stdout_collected.append(line)
            total += len(line.encode("utf-8", errors="replace"))
            if total > cap:
                # exceeded cap: kill and return what we have
                _kill_proc(proc)
                try:
                    _, stderr = proc.communicate(timeout=1)
                except Exception:
                    stderr = ""
                return "".join(stdout_collected), stderr, proc.returncode if proc.returncode is not None else -1
            # stop after first newline (we expect single-line JSON)
            if line.endswith("\n"):
                break
        try:
            # also collect stderr
            _, stderr = proc.communicate(timeout=0.1)
        except Exception:
            stderr = ""
        return "".join(stdout_collected), stderr, proc.returncode if proc.returncode is not None else 0
    else:
        # Windows fallback: use communicate with timeout; cannot stream safely here
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_proc(proc)
            try:
                stdout, stderr = proc.communicate(timeout=1)
            except Exception:
                stdout, stderr = "", ""
            return stdout, stderr, proc.returncode if proc.returncode is not None else -1
        return stdout, stderr, proc.returncode if proc.returncode is not None else 0


def list_plugin_tools(plugin_path: str, timeout: Optional[float] = None, max_tools: Optional[int] = None, max_output: Optional[int] = None) -> Dict[str, Any]:
    """
    Discover plugin tools by launching the worker with --list. Validates the returned
    metadata and enforces a max tool count.
    Returns: {ok: bool, plugin:, version:, description:, tools: [...], error: str}
    """
    t = float(timeout) if timeout is not None else float(os.getenv("CTF_TUTOR_PLUGIN_WORKER_TIMEOUT", DEFAULT_TIMEOUT))
    cap = int(max_output) if max_output is not None else int(os.getenv("CTF_TUTOR_PLUGIN_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT))
    max_tools = int(max_tools) if max_tools is not None else int(os.getenv("CTF_TUTOR_PLUGIN_MAX_TOOLS", MAX_TOOLS))

    cmd = [sys.executable, "-m", "agent.plugin_worker", "--module", str(plugin_path), "--list"]
    proc = _start_proc(cmd)
    stdout_text, stderr_text, rc = _read_one_line_with_cap(proc, cap, t)
    if rc != 0:
        return {"ok": False, "error": stderr_text or f"worker exit {rc}"}
    if not stdout_text.strip():
        return {"ok": False, "error": "worker produced no output"}
    try:
        payload = json.loads(stdout_text.strip())
    except Exception:
        return {"ok": False, "error": "invalid-json-from-worker"}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "worker returned non-object JSON"}
    tools = payload.get("tools")
    if not isinstance(tools, list):
        return {"ok": False, "error": "worker listing missing tools list"}
    if len(tools) > max_tools:
        return {"ok": False, "error": f"tool count {len(tools)} exceeds max {max_tools}"}
    validated_tools: List[Dict[str, Any]] = []
    for tentry in tools:
        err = _validate_tool_entry(tentry)
        if err:
            return {"ok": False, "error": f"invalid tool entry: {err}"}
        validated_tools.append({
            "name": str(tentry.get("name")),
            "description": str(tentry.get("description") or ""),
            "permission": str(tentry.get("permission") or ""),
            "category_tags": list(tentry.get("category_tags") or []),
        })
    return {
        "ok": True,
        "plugin": str(payload.get("plugin") or Path(plugin_path).name),
        "version": str(payload.get("version") or ""),
        "description": str(payload.get("description") or ""),
        "tools": validated_tools,
    }


def call_plugin_tool(plugin_path: str, tool: str, args: Optional[Dict[str, Any]] = None, timeout: Optional[float] = None, max_output: Optional[int] = None) -> Dict[str, Any]:
    """
    Call a single tool by launching the worker, sending one JSON request line,
    and reading one JSON response. Returns normalized {ok, output, error}.
    """
    t = float(timeout) if timeout is not None else float(os.getenv("CTF_TUTOR_PLUGIN_WORKER_TIMEOUT", DEFAULT_TIMEOUT))
    cap = int(max_output) if max_output is not None else int(os.getenv("CTF_TUTOR_PLUGIN_MAX_OUTPUT_BYTES", DEFAULT_MAX_OUTPUT))

    cmd = [sys.executable, "-m", "agent.plugin_worker", "--module", str(plugin_path)]
    proc = _start_proc(cmd)
    if proc.stdin is None:
        _kill_proc(proc)
        return {"ok": False, "output": "", "error": "worker stdin not available"}

    req = json.dumps({"tool": tool, "args": args or {}}) + "\n"
    try:
        # write request
        proc.stdin.write(req)
        proc.stdin.flush()
    except Exception:
        _kill_proc(proc)
        return {"ok": False, "output": "", "error": "failed to write to worker stdin"}

    stdout_text, stderr_text, rc = _read_one_line_with_cap(proc, cap, t)
    if rc != 0:
        return {"ok": False, "output": stdout_text, "error": stderr_text or f"worker exit {rc}"}
    if not stdout_text.strip():
        return {"ok": False, "output": "", "error": "worker produced no output"}
    try:
        payload = json.loads(stdout_text.strip())
    except Exception:
        return {"ok": False, "output": stdout_text, "error": "invalid-json-output"}
    if not isinstance(payload, dict):
        return {"ok": False, "output": stdout_text, "error": "worker returned non-object JSON"}
    return {"ok": bool(payload.get("ok")), "output": payload.get("output", ""), "error": payload.get("error", "")}
