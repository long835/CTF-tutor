"""Multi-language local challenge sessions.

A session owns one workspace and a small JSON state record.  Source can be
compiled/run in Python, Rust, Java, or .NET without sharing process state;
metadata, notes, artifacts and language history are shared across switches.
Execution is deliberately local-only, bounded, and never uses a shell.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

SUPPORTED_LANGUAGES = ("python", "rust", "java", "dotnet")
DEFAULT_TIMEOUT = 10
MAX_OUTPUT = 20_000


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _slug(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_" else "-" for c in value).strip("-") or "session"


@dataclass
class ExecutionRecord:
    language: str
    source: str
    command: List[str]
    returncode: Optional[int]
    stdout: str
    stderr: str
    timed_out: bool = False
    timestamp: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class MultiLanguageSession:
    session_id: str
    challenge_name: str
    workspace: str
    current_language: str = "python"
    languages_used: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    artifacts: List[str] = field(default_factory=list)
    executions: List[ExecutionRecord] = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    @property
    def state_path(self) -> Path:
        return Path(self.workspace) / ".ctf-session.json"

    def __post_init__(self):
        if self.current_language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"unsupported language: {self.current_language}")
        Path(self.workspace).mkdir(parents=True, exist_ok=True)
        if self.current_language not in self.languages_used:
            self.languages_used.append(self.current_language)
        self.save()

    @classmethod
    def create(cls, challenge_name: str, root: str = "data/sessions", language: str = "python") -> "MultiLanguageSession":
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"unsupported language: {language}")
        session_id = f"{_slug(challenge_name)[:32]}-{uuid.uuid4().hex[:8]}"
        workspace = str(Path(root) / session_id)
        return cls(session_id=session_id, challenge_name=challenge_name, workspace=workspace, current_language=language)

    @classmethod
    def load(cls, workspace: str) -> "MultiLanguageSession":
        path = Path(workspace) / ".ctf-session.json"
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        executions = [ExecutionRecord(**x) for x in data.pop("executions", [])]
        return cls(executions=executions, **data)

    def save(self) -> None:
        payload = {
            "session_id": self.session_id,
            "challenge_name": self.challenge_name,
            "workspace": self.workspace,
            "current_language": self.current_language,
            "languages_used": self.languages_used,
            "notes": self.notes,
            "artifacts": self.artifacts,
            "executions": [x.to_dict() for x in self.executions[-100:]],
            "created_at": self.created_at,
        }
        tmp = self.state_path.with_suffix(".json.tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.state_path)

    def switch(self, language: str) -> None:
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(f"unsupported language: {language}")
        self.current_language = language
        if language not in self.languages_used:
            self.languages_used.append(language)
        self.save()

    def add_note(self, note: str) -> None:
        if note.strip():
            self.notes.append(note.strip())
            self.save()

    def record_artifact(self, path: str) -> None:
        p = str(Path(path).resolve())
        if p not in self.artifacts:
            self.artifacts.append(p)
            self.save()

    def run_source(self, source: str, language: Optional[str] = None, timeout: int = DEFAULT_TIMEOUT,
                   args: Optional[List[str]] = None) -> ExecutionRecord:
        lang = language or self.current_language
        if lang not in SUPPORTED_LANGUAGES:
            raise ValueError(f"unsupported language: {lang}")
        if timeout < 1 or timeout > 60:
            raise ValueError("timeout must be between 1 and 60 seconds")
        args = list(args or [])
        work = Path(self.workspace)
        src_path, cmd = _prepare(lang, source, work, args)
        record = _execute(cmd, work, lang, src_path.name, timeout)
        self.executions.append(record)
        self.record_artifact(str(src_path))
        self.save()
        return record


def _prepare(language: str, source: str, work: Path, args: List[str]):
    if language == "python":
        path = work / "main.py"
        path.write_text(source, encoding="utf-8")
        return path, ["python3", str(path), *args]

    if language == "rust":
        if not shutil.which("rustc"):
            raise RuntimeError("rustc is not installed")
        src = work / "main.rs"
        binary = work / "main-rust"
        src.write_text(source, encoding="utf-8")
        subprocess.run(["rustc", str(src), "-o", str(binary)], cwd=str(work),
                       capture_output=True, text=True, timeout=30, check=True)
        return src, [str(binary), *args]

    if language == "java":
        if not shutil.which("javac") or not shutil.which("java"):
            raise RuntimeError("javac/java are not installed")
        src = work / "Main.java"
        src.write_text(source, encoding="utf-8")
        subprocess.run(["javac", str(src)], cwd=str(work), capture_output=True, text=True,
                       timeout=30, check=True)
        return src, ["java", "-cp", str(work), "Main", *args]

    # .NET: source is a complete Program.cs; use a local project directory.
    if language == "dotnet":
        if not shutil.which("dotnet"):
            raise RuntimeError("dotnet is not installed")
        proj = work / "DotnetSession"
        proj.mkdir(exist_ok=True)
        csproj = proj / "DotnetSession.csproj"
        csproj.write_text(
            '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
            '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
            '<ImplicitUsings>enable</ImplicitUsings><Nullable>enable</Nullable>'
            '</PropertyGroup></Project>', encoding="utf-8")
        src = proj / "Program.cs"
        src.write_text(source, encoding="utf-8")
        return src, ["dotnet", "run", "--project", str(csproj), "--no-restore", "--", *args]

    raise AssertionError(language)


def _limits():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    except (ImportError, OSError, ValueError):
        pass


def _execute(cmd: List[str], cwd: Path, language: str, source_name: str, timeout: int) -> ExecutionRecord:
    try:
        kwargs = dict(cwd=str(cwd), capture_output=True, text=True, timeout=timeout, check=False)
        if os.name == "posix":
            kwargs["preexec_fn"] = _limits
        completed = subprocess.run(cmd, **kwargs)
        return ExecutionRecord(language, source_name, cmd, completed.returncode,
                               completed.stdout[:MAX_OUTPUT], completed.stderr[:MAX_OUTPUT])
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        return ExecutionRecord(language, source_name, cmd, None, stdout[:MAX_OUTPUT],
                               stderr[:MAX_OUTPUT], timed_out=True)


def list_sessions(root: str = "data/sessions") -> List[dict]:
    base = Path(root)
    if not base.exists():
        return []
    result = []
    for state in base.glob("*/.ctf-session.json"):
        try:
            with state.open("r", encoding="utf-8") as f:
                data = json.load(f)
            result.append({k: data.get(k) for k in ("session_id", "challenge_name", "current_language", "languages_used", "workspace")})
        except (OSError, json.JSONDecodeError):
            continue
    return result
