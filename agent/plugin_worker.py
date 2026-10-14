"""Out-of-process plugin worker with listing and JSON dispatch.

Usage:
  python -m agent.plugin_worker --module path/to/plugin.py --list
    -> prints JSON: {"ok": True, "plugin": "plugin.py", "tools": [{"name": "check", "description": "...", "permission": "ANALYSIS"}, ...], "version": "x.y"}

  python -m agent.plugin_worker --module path/to/plugin.py
    -> interactive loop: read JSON lines {"tool": "name", "args": {...}} and print JSON responses {"ok": bool, "output": any, "error": string}

This runs the plugin entirely in the child process: import-time side effects and register(api)
are executed in the worker and are not visible to the parent process.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class WorkerPluginAPI:
    def __init__(self):
        # map of tool name -> (handler, metadata)
        self._tools: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}

    def describe(self, version: str = "", description: str = "") -> None:
        # worker can capture metadata via returned listing
        # not stored globally here; caller will inspect meta per-tool
        return None

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


def _call_tool(tool_name: str, tool_map: Dict[str, Callable[[Dict[str, Any]], Any]], args: Dict[str, Any]) -> Dict[str, Any]:
    handler = tool_map.get(tool_name)
    if handler is None:
        return {"ok": False, "output": "", "error": f"unknown tool: {tool_name}"}
    try:
        result = handler(args or {})
    except Exception as exc:
        return {"ok": False, "output": "", "error": f"plugin raised: {type(exc).__name__}: {exc}"}
    if not isinstance(result, tuple) or len(result) != 3:
        return {"ok": False, "output": "", "error": f"tool {tool_name} returned malformed result"}
    ok, output, error = result
    return {"ok": bool(ok), "output": output, "error": str(error) if error else ""}


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--module", required=True, help="Path to plugin .py file")
    p.add_argument("--list", action="store_true", help="List tools and exit")
    args = p.parse_args(argv)

    path = Path(args.module)
    if not path.exists():
        print(json.dumps({"ok": False, "error": "module not found"}))
        return 1

    spec = importlib.util.spec_from_file_location("plugin_mod", path)
    if not spec or not spec.loader:
        print(json.dumps({"ok": False, "error": "load failed"}))
        return 1

    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"import failed: {type(exc).__name__}: {exc}"}))
        return 1

    api = WorkerPluginAPI()
    register = getattr(mod, "register", None)
    if not callable(register):
        print(json.dumps({"ok": False, "error": "no callable register(api) found"}))
        return 1

    try:
        register(api)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"register failed: {type(exc).__name__}: {exc}"}))
        return 1

    tool_names = list(api.tools.keys())

    if args.list:
        out = {
            "ok": True,
            "plugin": path.name,
            "tools": api.tools_meta,
            "version": getattr(mod, "__version__", "0.0.0"),
        }
        print(json.dumps(out), flush=True)
        return 0

    # Interactive loop: read JSON lines describing tool calls and respond per-line.
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                print(json.dumps({"ok": False, "error": "bad json"}), flush=True)
                continue
            tool_name = str(msg.get("tool", "")).strip()
            try:
                req_args = dict(msg.get("args") or {})
            except Exception:
                req_args = {}
            if not tool_name:
                print(json.dumps({"ok": False, "error": "missing tool name"}), flush=True)
                continue
            res = _call_tool(tool_name, api.tools, req_args)
            print(json.dumps(res), flush=True)
    except BrokenPipeError:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
