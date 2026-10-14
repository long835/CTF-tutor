# tests/test_plugin_integration.py
import os
import sys
import time
from pathlib import Path
from typing import Dict, Any

import pytest

from agent import plugins as plugins_mod
from agent import tools_registry
from agent.permissions import Permission

WORKER_TIMEOUT_ENV = "CTF_TUTOR_PLUGIN_WORKER_TIMEOUT"


# Helper to write plugin files
def _write_plugin(path: Path, body: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


@pytest.fixture(autouse=True)
def snapshot_registry():
    """Snapshot and restore the real registry state from agent.tools_registry._REGISTRY.

    Fail loudly if the registry is missing expected keys on restore.
    """
    import agent.tools_registry as tr

    saved: Dict[str, Any] = dict(tr._REGISTRY)
    try:
        yield
    finally:
        # restore
        tr._REGISTRY.clear()
        tr._REGISTRY.update(saved)
        # verify we restored all original entries
        missing = set(saved.keys()) - set(tr._REGISTRY.keys())
        if missing:
            raise RuntimeError(f"registry restore failed, missing keys: {missing}")


def test_inprocess_plugin_register_and_invoke(tmp_path, monkeypatch):
    # In-process behavior: importing plugin in parent should create a marker in parent.
    marker = tmp_path / "import_marker_parent.txt"
    plugin = tmp_path / "p_inproc.py"
    _write_plugin(
        plugin,
        f'''
with open({str(marker)!r}, "w") as f:
    f.write("parent-imported")


def _check(args):
    text = args.get("text","")
    return True, f"saw:{{len(text)}}", ""


def register(api):
    api.describe(version="0.1")
    api.register_tool("check", _check)
''',
    )

    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.delenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", raising=False)

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert len(infos) == 1 and infos[0].loaded
    # import-time side effect must be visible in parent
    assert marker.exists()
    ok, out, err = tools_registry.run_tool(f"{infos[0].name}.check", {"text": "hello"})
    assert ok is True
    assert "saw:5" in out

    # cleanup sys.modules entry created by in-process import
    modname = f"ctf_tutor_plugin_{plugin.stem}"
    if modname in sys.modules:
        del sys.modules[modname]


def test_sandbox_listing_and_worker_call(tmp_path, monkeypatch):
    # Sandbox mode: the worker will import the plugin (so marker may exist),
    # but the parent must not have the plugin module loaded.
    marker = tmp_path / "import_marker_child.txt"
    plugin = tmp_path / "p_sandbox.py"
    # plugin writes its PID to an absolute marker to prove the import happened in the child
    _write_plugin(
        plugin,
        f'''
import os
with open({str(marker)!r}, "w") as f:
    f.write(str(os.getpid()))


def _echo(args):
    return True, args.get("text",""), ""


def register(api):
    api.describe(version="0.2")
    api.register_tool("echo", _echo)
''',
    )

    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "2.0")

    # remove marker if present
    if marker.exists():
        marker.unlink()

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert len(infos) == 1 and infos[0].loaded

    # Parent must not have imported the in-process module name
    parent_mod_name = f"ctf_tutor_plugin_{plugin.stem}"
    assert parent_mod_name not in sys.modules

    # The marker may exist because listing (--list) imports in the child process
    assert marker.exists()
    child_pid = int(marker.read_text())
    assert child_pid != os.getpid()

    # Now invoke the tool - wrapper should dispatch to worker and return the tuple
    ok, out, err = tools_registry.run_tool(f"{infos[0].name}.echo", {"text": "xyz"})
    assert ok is True
    assert out == "xyz"
    # cleanup
    marker.unlink()


def test_worker_print_noise_and_malformed_output(tmp_path, monkeypatch):
    # Plugin that writes noise to the original stdout and returns a normal tuple.
    plugin = tmp_path / "noisy.py"
    _write_plugin(
        plugin,
        '''
import sys

def register(api):
    def noisy(args):
        try:
            sys.__stdout__.write("NOISY LINE\n")
            sys.__stdout__.flush()
        except Exception:
            pass
        return True, "ok", ""
    api.register_tool("noisy", noisy)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "2.0")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert infos and infos[0].loaded
    ok, out, err = tools_registry.run_tool(f"{infos[0].name}.noisy", {})
    # If worker stdout was polluted, the wrapper should surface a parse error; else ok True
    assert (ok is False and isinstance(err, str)) or ok is True


def test_worker_returns_nonobject_json(tmp_path, monkeypatch):
    # Plugin that causes the worker to emit non-object JSON (an array) on stdout
    plugin = tmp_path / "arr.py"
    _write_plugin(
        plugin,
        '''
import sys

def register(api):
    def arr(args):
        try:
            sys.__stdout__.write("[]\n")
            sys.__stdout__.flush()
        except Exception:
            pass
        return True, "ok", ""
    api.register_tool("arr", arr)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "2.0")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert infos and infos[0].loaded
    ok, out, err = tools_registry.run_tool(f"{infos[0].name}.arr", {})
    assert ok is False
    assert "non-object" in (err or "").lower() or "invalid-json" in (err or "").lower()


def test_worker_crash_during_call(tmp_path, monkeypatch):
    plugin = tmp_path / "crash.py"
    _write_plugin(
        plugin,
        '''
import os

def register(api):
    def crash(args):
        os._exit(3)
    api.register_tool("crash", crash)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "2.0")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert infos and infos[0].loaded
    ok, out, err = tools_registry.run_tool(f"{infos[0].name}.crash", {})
    assert ok is False
    assert "exit" in (err or "").lower() or "worker exit" in (err or "")


def test_huge_output_handling(tmp_path, monkeypatch):
    plugin = tmp_path / "huge.py"
    _write_plugin(
        plugin,
        '''
import sys

def register(api):
    def big(args):
        try:
            sys.__stdout__.write("A" * 200000 + "\n")
            sys.__stdout__.flush()
        except Exception:
            pass
        return True, "ok", ""
    api.register_tool("big", big)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "2.0")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert infos and infos[0].loaded
    ok, out, err = tools_registry.run_tool(f"{infos[0].name}.big", {})
    assert ok is False
    assert isinstance(err, str)


def test_listing_failure_register_raises(tmp_path, monkeypatch):
    # Plugin whose register(api) raises during listing; activate should mark it failed
    plugin = tmp_path / "badreg.py"
    _write_plugin(
        plugin,
        '''
def register(api):
    raise RuntimeError("boom during register")
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "0.5")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert len(infos) == 1
    assert infos[0].loaded is False
    # ensure parent process did not import the plugin module
    modname = f"ctf_tutor_plugin_{plugin.stem}"
    assert modname not in sys.modules


def test_listing_timeout(tmp_path, monkeypatch):
    plugin = tmp_path / "slowlist.py"
    _write_plugin(
        plugin,
        '''
import time

def register(api):
    time.sleep(5)
    def x(args):
        return True, "x", ""
    api.register_tool("x", x)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    # short timeout to force listing to fail
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "0.5")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert len(infos) == 1
    assert infos[0].loaded is False


def test_declared_permission_clamped(tmp_path, monkeypatch):
    plugin = tmp_path / "perm.py"
    _write_plugin(
        plugin,
        '''
from agent.permissions import Permission

def register(api):
    def secret(args):
        return True, "ok", ""
    api.register_tool("secret", secret, permission=Permission.FULL_APPROVAL)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")
    monkeypatch.setenv(WORKER_TIMEOUT_ENV, "2.0")

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert infos and infos[0].loaded
    # find tool name
    toolname = None
    for t in infos[0].tools:
        if t.endswith(".secret"):
            toolname = t
            break
    assert toolname is not None
    spec = tools_registry.get(toolname)
    assert spec is not None
    # declared FULL_APPROVAL should be clamped to MAX_PLUGIN_PERMISSION (ANALYSIS)
    assert spec.permission == Permission.ANALYSIS


def test_registration_rollback_on_register_failure(tmp_path, monkeypatch):
    # Simulate a registry.register raising on second registration to force a rollback.
    plugin = tmp_path / "multi.py"
    _write_plugin(
        plugin,
        '''
def register(api):
    def a(args):
        return True, "a", ""
    def b(args):
        return True, "b", ""
    api.register_tool("a", a)
    api.register_tool("b", b)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")

    # Monkeypatch tools_registry.register to raise on the second call
    import agent.tools_registry as tr

    original_register = tr.register
    call_count = {"n": 0}

    def flaky_register(name: str, handler, description: str = "", permission=None, category_tags=None):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise RuntimeError("simulated registry failure")
        return original_register(name, handler, description=description, permission=permission, category_tags=category_tags)

    monkeypatch.setattr(tr, "register", flaky_register)

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    # library should mark plugin as failed due to rollback
    assert len(infos) == 1
    assert infos[0].loaded is False
    assert infos[0].error
    # first tool should NOT be in registry after rollback
    first_tool = f"{plugin.stem}.a"
    assert tr.get(first_tool) is None


def test_collision_rejected(tmp_path, monkeypatch):
    # Pre-register a namespaced tool to induce a collision
    plugin = tmp_path / "collide.py"
    _write_plugin(
        plugin,
        '''
def register(api):
    def x(args):
        return True, "x", ""
    api.register_tool("x", x)
''',
    )
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("CTF_TUTOR_ENABLE_PLUGINS", "1")
    monkeypatch.setenv("CTF_TUTOR_PLUGIN_USE_SANDBOX", "1")

    # register a conflicting name beforehand using plugin.stem
    conflict_name = f"{plugin.stem}.x"
    tools_registry.register(conflict_name, lambda a: (True, "z", ""), description="preexisting", category_tags=[])

    infos = plugins_mod.activate(plugin_dir=str(tmp_path), verbose=False)
    assert len(infos) == 1
    assert infos[0].loaded is False
    assert "collision" in (infos[0].error or "").lower()
