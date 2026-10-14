"""Out-of-process plugin worker with listing and single-request JSON dispatch.

Usage:
  python -m agent.plugin_worker --module path/to/plugin.py --list
    -> prints JSON: {"ok": True, "plugin": "plugin.py", "description": "...", "version": "x.y", "tools": [{"name": "check", "description": "...", "permission": "ANALYSIS", "category_tags": [...]}, ...]}

  python -m agent.plugin_worker --module path/to/plugin.py
    -> read exactly one JSON line {"tool": "name", "args": {...}}, call the tool, print exactly one JSON reply {"ok": bool, "output": any, "error": string} and exit.

Security: while importing the plugin module, calling its register(api), and executing the tool handler,
all plugin writes to sys.stdout are redirected to sys.stderr so the worker's protocol (original stdout)
remains a clean JSON channel.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class WorkerPluginAPI:
    """API provided to plugins inside the worker process.

    Mirrors agent.plugins.PluginAPI: describe(version, description)
    and register_tool(name, handler, description, permission, category_tags).
    The worker collects tool handlers and metadata for listing and invocation.
    """

    def __init__(self):
        self._tools: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._version: str = "0.0.0"
        self._description: str = ""

    def describe(self, version: str = "", description: str = "") -> None:
        if version:
            self._version = str(version)
        if description:
            self._description = str(description)

    def register_tool(
        self,
        name: str,
        handler: Callable[[Dict[str, Any]], Any],
        description: str = "",
        permission: Optional[object] = None,
        category_tags: Optional[List[str]] = None,
    ) -> str:
        if not callable(handler):
            raise TypeError(f"handler for {name!r} is not callable")
        safe_name = str(name)
        self._tools[safe_name] = handler
        self._meta[safe_name] = {
            "name": safe_name,
            "description": str(description or ""),
            "permission": str(permission) if permission is not None else "",
            "category_tags": list(category_tags or []),
        }
        return safe_name

    @property
    def tools(self) -> Dict[str, Callable[[Dict[str, Any]], Any]]:
        return dict(self._tools)

    @property
    def tools_meta(self) -> List[Dict[str, Any]]:
        return [dict(v) for v in self._meta.values()]

    @property
    def version(self) -> str:
        return self._version

    @property
    def description(self) -> str:
        return self._description


def _call_tool(tool_name: str, tool_map: Dict[str, Callable[[Dict[str, Any]], Any]], args: Dict[str, Any]) -> Dict[str, Any]:
    handler = tool_map.get(tool_name)
    if handler is None:
        return {"ok": False, "output": "", "error": f"unknown tool: {tool_name}"}
    # Redirect plugin's stdout to stderr during execution to protect protocol
    orig_stdout = sys.stdout
    try:
        sys.stdout = sys.stderr
        result = handler(args or {})
    except Exception as exc:
        return {"ok": False, "output": "", "error": f"plugin raised: {type(exc).__name__}: {exc}"}
    finally:
        sys.stdout = orig_stdout
    if not isinstance(result, tuple) or len(result) != 3:
        return {"ok": False, "output": "", "error": f"tool {tool_name} returned malformed result"}
    ok, output, error = result
    return {"ok": bool(ok), "output": output, "error": str(error) if error else ""}


def _write_json_and_exit(obj: Dict[str, Any], out_stream) -> int:
    try:
        out_stream.write(json.dumps(obj, ensure_ascii=False) + "\n")
        out_stream.flush()
    except Exception:
        # If we cannot write to the original stdout, still exit nonzero
        pass
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--module", required=True)
    p.add_argument("--list", action="store_true")
    args = p.parse_args(argv)

    path = Path(args.module)
    orig_stdout = sys.stdout
    # Ensure plugin import errors and other diagnostics that go to stderr remain on stderr.
    if not path.exists():
        orig_stdout.write(json.dumps({"ok": False, "error": "module not found"}) + "\n")
        orig_stdout.flush()
        return 1

    spec = importlib.util.spec_from_file_location("plugin_mod", path)
    if not spec or not spec.loader:
        orig_stdout.write(json.dumps({"ok": False, "error": "load failed"}) + "\n")
        orig_stdout.flush()
        return 1

    module = importlib.util.module_from_spec(spec)

    # Import and register the plugin while redirecting plugin stdout to stderr
    try:
        sys.stdout = sys.stderr
        try:
            spec.loader.exec_module(module)
        finally:
            sys.stdout = orig_stdout
    except Exception as exc:
        orig_stdout.write(json.dumps({"ok": False, "error": f"import failed: {type(exc).__name__}: {exc}"}) + "\n")
        orig_stdout.flush()
        return 1

    api = WorkerPluginAPI()
    register = getattr(module, "register", None)
    if not callable(register):
        orig_stdout.write(json.dumps({"ok": False, "error": "no callable register(api) found"}) + "\n")
        orig_stdout.flush()
        return 1

    # Call register(api) with stdout redirected to stderr to avoid protocol pollution
    try:
        sys.stdout = sys.stderr
        try:
            register(api)
        finally:
            sys.stdout = orig_stdout
    except Exception as exc:
        orig_stdout.write(json.dumps({"ok": False, "error": f"register failed: {type(exc).__name__}: {exc}"}) + "\n")
        orig_stdout.flush()
        return 1

    # Prepare listing response
    if args.list:
        out = {
            "ok": True,
            "plugin": path.name,
            "description": api.description,
            "version": api.version,
            "tools": api.tools_meta,
        }
        return _write_json_and_exit(out, orig_stdout)

    # Call mode: read exactly one JSON line from stdin and respond with one JSON object
    line = sys.stdin.readline()
    if not line:
        orig_stdout.write(json.dumps({"ok": False, "error": "no input"}) + "\n")
        orig_stdout.flush()
        return 1

    try:
        msg = json.loads(line)
    except Exception:
        orig_stdout.write(json.dumps({"ok": False, "error": "bad json"}) + "\n")
        orig_stdout.flush()
        return 1

    tool_name = str(msg.get("tool", "")).strip()
    try:
        req_args = dict(msg.get("args") or {})
    except Exception:
        req_args = {}

    if not tool_name:
        orig_stdout.write(json.dumps({"ok": False, "error": "missing tool name"}) + "\n")
        orig_stdout.flush()
        return 1

    # Execute the tool with plugin stdout redirected to stderr
    result_obj = _call_tool(tool_name, api.tools, req_args)
    return _write_json_and_exit(result_obj, orig_stdout)


if __name__ == "__main__":
    raise SystemExit(main())
