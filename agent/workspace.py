"""
agent/workspace.py

Per-challenge local workspace:

  workspace/<challenge_id>/
    ├── input/          # user-supplied files (copied or linked)
    ├── artifacts/      # agent-produced artifacts
    ├── logs/           # tool logs
    ├── state.json      # serialized AgentState
    ├── inventory.json  # triage inventory
    └── notes.md        # free-form learner notes
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Optional

from agent.state import AgentState


DEFAULT_ROOT = os.path.join("data", "workspaces")


class ChallengeWorkspace:
    def __init__(self, challenge_id: str, root: str = DEFAULT_ROOT):
        self.challenge_id = challenge_id
        self.root = Path(root) / challenge_id
        self.input_dir = self.root / "input"
        self.artifacts_dir = self.root / "artifacts"
        self.logs_dir = self.root / "logs"
        self.state_path = self.root / "state.json"
        self.inventory_path = self.root / "inventory.json"
        self.notes_path = self.root / "notes.md"

    def ensure(self) -> "ChallengeWorkspace":
        for d in (self.input_dir, self.artifacts_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)
        if not self.notes_path.exists():
            self.notes_path.write_text("# Notes\n\n", encoding="utf-8")
        return self

    def save_state(self, state: AgentState) -> None:
        self.ensure()
        self.state_path.write_text(state.to_json(), encoding="utf-8")

    def load_state(self) -> Optional[AgentState]:
        if not self.state_path.exists():
            return None
        try:
            return AgentState.from_json(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, KeyError):
            return None

    def save_inventory(self, inv_dict: dict) -> None:
        self.ensure()
        self.inventory_path.write_text(json.dumps(inv_dict, indent=2), encoding="utf-8")

    def import_path(self, src: str) -> str:
        """Copy a file or tree into input/. Returns destination path."""
        self.ensure()
        src_p = Path(src).resolve()
        if not src_p.exists():
            raise FileNotFoundError(src)
        dest = self.input_dir / src_p.name
        if src_p.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src_p, dest)
        else:
            shutil.copy2(src_p, dest)
        return str(dest)

    def append_note(self, text: str) -> None:
        self.ensure()
        with open(self.notes_path, "a", encoding="utf-8") as f:
            f.write(text.rstrip() + "\n\n")

    def write_log(self, name: str, content: str) -> str:
        self.ensure()
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:80]
        path = self.logs_dir / f"{safe}.log"
        path.write_text(content[:100_000], encoding="utf-8")
        return str(path)

    def import_lab(self, lab_id: str) -> dict:
        """Attach an experience lab artifact into workspace input/."""
        from agent.experience_labs import get_lab

        lab = get_lab(lab_id)
        if not lab:
            raise ValueError(f"unknown lab: {lab_id}")
        self.ensure()
        copied = []
        if lab.artifact_path and Path(lab.artifact_path).is_file():
            copied.append(self.import_path(lab.artifact_path))
        else:
            lab_dir = Path(lab.path)
            if lab_dir.is_dir():
                copied.append(self.import_path(str(lab_dir)))
        readme = Path(lab.path) / "README.md"
        if readme.is_file():
            try:
                copied.append(self.import_path(str(readme)))
            except Exception:
                pass
        self.append_note(
            "Experience lab attached: %s (%s)\nFiles: %s"
            % (lab.id, lab.category, ", ".join(copied))
        )
        return {
            "lab_id": lab.id,
            "category": lab.category,
            "techniques": list(lab.techniques),
            "copied": copied,
            "workspace": str(self.root),
        }
