"""
agent/plugins.py

Third-party toolkit loading (Phase 7).

`tools_registry` already lets code register a tool. The missing half was a
way to add a tool *without editing this repository* — which is what turns a
registry into an ecosystem.

A plugin is a Python file in `plugins/` exporting a `register(api)`
function. It receives a small API object rather than the raw registry, so
the loader can enforce three things the registry cannot:

  permission clamping   a plugin cannot grant itself more capability than
                        the session policy allows
  namespacing           tools are prefixed with the plugin name, so two
                        plugins cannot silently shadow each other or a
                        built-in
  failure isolation     a plugin that raises on import is reported and
                        skipped; it does not take the agent down

Plugins are ordinary local code running with your privileges. The loader is
opt-in via `CTF_TUTOR_ENABLE_PLUGINS=1` and prints what it loaded, because
"drop a file in a folder and it runs" should never be silent.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from agent.permissions import DEFAULT_MAX_PERMISSION, Permission

PLUGIN_DIR = os.getenv("CTF_TUTOR_PLUGIN_DIR", "plugins")
ENABLE_ENV = "CTF_TUTOR_ENABLE_PLUGINS"

# Capability a plugin may request at most, regardless of what it asks for.
# Deliberately below the session default: third-party code gets less rope
# than the built-in toolkits.
MAX_PLUGIN_PERMISSION = Permission.ANALYSIS

_PERMISSION_RANK = {
    Permission.READ_ONLY: 0,
    Permission.ANALYSIS: 1,
    Permission.SANDBOX_EXEC: 2,
    Permission.FULL_APPROVAL: 3,
}


def plugins_enabled() -> bool:
    return os.getenv(ENABLE_ENV, "0").strip().lower() in ("1", "true", "yes", "on")


def _clamp(requested: Optional[Permission]) -> Permission:
    """Never let a plugin exceed the plugin ceiling or the session policy."""
    want = requested or Permission.READ_ONLY
    ceiling = MAX_PLUGIN_PERMISSION
    if _PERMISSION_RANK[DEFAULT_MAX_PERMISSION] < _PERMISSION_RANK[ceiling]:
        ceiling = DEFAULT_MAX_PERMISSION
    return want if _PERMISSION_RANK[want] <= _PERMISSION_RANK[ceiling] else ceiling


@dataclass
class PluginInfo:
    name: str
    path: str
    version: str = "0.0.0"
    description: str = ""
    tools: List[str] = field(default_factory=list)
    loaded: bool = False
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "version": self.version,
            "description": self.description,
            "tools": list(self.tools),
            "loaded": self.loaded,
            "error": self.error,
        }


class PluginAPI:
    """
    What a plugin is handed. Intentionally small.

    A plugin sees `register_tool`, some read-only context, and nothing else
    — no direct registry handle, no way to unregister a built-in.
    """

    def __init__(self, plugin_name: str, info: PluginInfo):
        self._plugin = plugin_name
        self._info = info

    def describe(self, version: str = "", description: str = "") -> None:
        if version:
            self._info.version = str(version)
        if description:
            self._info.description = str(description)

    def register_tool(
        self,
        name: str,
        handler: Callable[[Dict[str, Any]], tuple],
        description: str = "",
        permission: Optional[Permission] = None,
        category_tags: Optional[List[str]] = None,
    ) -> str:
        """
        Add a tool. Returns the namespaced name it was registered under.

        The handler must return `(ok, output, error)` like every built-in
        executor helper, so plugin tools are indistinguishable from native
        ones at the planner level.
        """
        from agent import tools_registry

        if not callable(handler):
            raise TypeError(f"handler for {name!r} is not callable")

        safe = "".join(c if (c.isalnum() or c in "_-") else "_" for c in str(name)).strip("_")
        if not safe:
            raise ValueError("tool name must contain at least one alphanumeric character")
        namespaced = f"{self._plugin}.{safe}"

        granted = _clamp(permission)

        def guarded(args: Dict[str, Any]) -> tuple:
            """Contain plugin exceptions so one bad tool cannot end a run."""
            try:
                result = handler(args or {})
            except Exception as exc:  # noqa: BLE001 - isolation is the point
                return False, "", f"plugin {self._plugin} raised: {exc}"
            if not (isinstance(result, tuple) and len(result) == 3):
                return False, "", f"plugin {self._plugin}.{safe} returned a malformed result"
            return result

        tools_registry.register(
            namespaced,
            guarded,
            description=description or f"{self._plugin} plugin tool",
            permission=granted,
            category_tags=list(category_tags or []),
        )
        self._info.tools.append(namespaced)
        return namespaced

    @property
    def plugin_name(self) -> str:
        return self._plugin

    @property
    def max_permission(self) -> Permission:
        return _clamp(Permission.FULL_APPROVAL)


def discover(plugin_dir: str = PLUGIN_DIR) -> List[Path]:
    """List candidate plugin files, skipping private and dunder names."""
    root = Path(plugin_dir)
    if not root.is_dir():
        return []
    out: List[Path] = []
    for fp in sorted(root.glob("*.py")):
        if fp.name.startswith("_"):
            continue
        out.append(fp)
    for sub in sorted(root.iterdir()):
        if sub.is_dir() and not sub.name.startswith("_") and (sub / "__init__.py").is_file():
            out.append(sub / "__init__.py")
    return out


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot build a module spec for {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_plugin(path: Path) -> PluginInfo:
    """Load one plugin file. Never raises — errors land on the PluginInfo."""
    name = path.parent.name if path.name == "__init__.py" else path.stem
    info = PluginInfo(name=name, path=str(path))
    try:
        module = _load_module(path, f"ctf_tutor_plugin_{name}")
        register = getattr(module, "register", None)
        if not callable(register):
            info.error = "no callable register(api) found"
            return info
        info.description = (getattr(module, "__doc__", "") or "").strip().splitlines()[0][:200] if getattr(module, "__doc__", None) else ""
        info.version = str(getattr(module, "__version__", "0.0.0"))
        register(PluginAPI(name, info))
        info.loaded = True
    except Exception as exc:  # noqa: BLE001 - isolation is the point
        info.error = f"{type(exc).__name__}: {exc}"
        info.loaded = False
        if os.getenv("CTF_TUTOR_PLUGIN_DEBUG", "0") == "1":
            traceback.print_exc()
    return info


_LOADED: Optional[List[PluginInfo]] = None


def load_all(plugin_dir: str = PLUGIN_DIR, force: bool = False) -> List[PluginInfo]:
    """
    Load every discovered plugin once.

    Returns a report rather than printing, so callers decide how loud to be.
    """
    global _LOADED
    if _LOADED is not None and not force:
        return _LOADED
    _LOADED = [load_plugin(p) for p in discover(plugin_dir)]
    return _LOADED


def activate(plugin_dir: str = PLUGIN_DIR, verbose: bool = True) -> List[PluginInfo]:
    """
    Entry point for the CLI: honour the opt-in flag, then load and announce.
    """
    if not plugins_enabled():
        return []
    infos = load_all(plugin_dir, force=True)
    if verbose and infos:
        for info in infos:
            if info.loaded:
                print(f"  plugin loaded: {info.name} v{info.version} ({len(info.tools)} tool(s))")
            else:
                print(f"  plugin skipped: {info.name} — {info.error}")
    return infos


def status(plugin_dir: str = PLUGIN_DIR) -> Dict[str, Any]:
    """Describe plugin state for `python main.py plugins`."""
    candidates = discover(plugin_dir)
    infos = load_all(plugin_dir, force=True) if candidates else []
    return {
        "enabled": plugins_enabled(),
        "directory": str(Path(plugin_dir).resolve()) if Path(plugin_dir).is_dir() else str(plugin_dir),
        "directory_exists": Path(plugin_dir).is_dir(),
        "max_permission": _clamp(Permission.FULL_APPROVAL).value,
        "discovered": len(candidates),
        "loaded": sum(1 for i in infos if i.loaded),
        "failed": sum(1 for i in infos if not i.loaded),
        "plugins": [i.to_dict() for i in infos],
    }


def render_status(report: Dict[str, Any]) -> str:
    lines = ["# Plugins", ""]
    if not report.get("enabled"):
        lines.append("Plugins are off. Enable with `CTF_TUTOR_ENABLE_PLUGINS=1`.")
        lines.append("")
    lines.append(f"Directory: {report.get('directory')}")
    if not report.get("directory_exists"):
        lines.append("(directory does not exist yet — create it and drop in a .py file)")
    lines.append(
        f"Discovered: {report.get('discovered', 0)} · "
        f"loaded: {report.get('loaded', 0)} · failed: {report.get('failed', 0)} · "
        f"permission ceiling: {report.get('max_permission')}"
    )

    plugins = report.get("plugins") or []
    if plugins:
        lines.append("")
        for p in plugins:
            mark = "ok " if p.get("loaded") else "err"
            lines.append(f"[{mark}] {p.get('name')} v{p.get('version')}")
            if p.get("description"):
                lines.append(f"      {p['description']}")
            if p.get("tools"):
                lines.append(f"      tools: {', '.join(p['tools'])}")
            if p.get("error"):
                lines.append(f"      error: {p['error']}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_status(status()))
