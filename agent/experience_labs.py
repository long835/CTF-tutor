"""
First-class experience labs (Phase 6.5 / real CTF data path).

Loads data/samples/experience/manifest.json and turns each lab into a
challenge-shaped object the classifier, CLI, and API can use.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
LABS_DIR = ROOT / "data" / "samples" / "experience"
MANIFEST = LABS_DIR / "manifest.json"


@dataclass
class ExperienceLab:
    id: str
    category: str
    techniques: List[str]
    path: str
    artifact: Optional[str] = None
    description: str = ""
    readme: str = ""
    artifact_path: Optional[str] = None
    provenance: str = "synthetic-lab"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


    def challenge_text(self) -> str:
        """Text suitable for classify_challenge / agent triage."""
        parts = [self.description or self.id]
        if self.category == "pwn":
            parts.append("Local ELF binary with a stack buffer overflow and a win function.")
        elif self.category == "web":
            parts.append("Web application or HTTP service to inspect.")
        elif self.category == "crypto":
            parts.append("Ciphertext or cryptographic artifact to recover.")
        elif self.category == "forensics":
            parts.append("Forensic evidence file (pcap, image, or memory-related).")
        elif self.category == "misc":
            parts.append("Encoding layers or mixed puzzle artifact.")
        if self.artifact:
            parts.append("Artifact file: " + self.artifact)
        return "\n".join(parts)


def _load_manifest() -> Dict[str, Any]:
    if not MANIFEST.is_file():
        return {"items": []}
    try:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"items": []}


def list_labs() -> List[ExperienceLab]:
    man = _load_manifest()
    out: List[ExperienceLab] = []
    for item in man.get("items") or []:
        lab_path = LABS_DIR / (item.get("path") or item.get("id") or "")
        readme = ""
        rp = lab_path / "README.md"
        if rp.is_file():
            try:
                readme = rp.read_text(encoding="utf-8")
            except OSError:
                readme = ""
        # First non-empty paragraph as description
        desc = ""
        for line in readme.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("```"):
                desc = line
                break
        artifact = item.get("artifact")
        artifact_path = None
        if artifact:
            ap = lab_path / artifact
            if ap.is_file():
                artifact_path = str(ap)
        out.append(
            ExperienceLab(
                id=item.get("id") or lab_path.name,
                category=item.get("category") or "misc",
                techniques=list(item.get("techniques") or []),
                path=str(lab_path),
                artifact=artifact,
                description=desc,
                readme=readme[:2000],
                artifact_path=artifact_path,
                provenance=man.get("provenance") or "synthetic-lab",
            )
        )
    return out


def get_lab(lab_id: str) -> Optional[ExperienceLab]:
    lab_id = (lab_id or "").strip().lower()
    for lab in list_labs():
        if lab.id.lower() == lab_id:
            return lab
    return None


def classify_lab(lab_id: str) -> Dict[str, Any]:
    from agent.classify_challenge import classify_challenge

    lab = get_lab(lab_id)
    if not lab:
        return {"error": f"unknown lab: {lab_id}"}
    profile = classify_challenge(lab.challenge_text())
    return {
        "lab": lab.to_dict(),
        "classification": profile.to_dict(),
        "expected_category": lab.category,
        "category_match": profile.category == lab.category,
    }


def labs_summary() -> Dict[str, Any]:
    labs = list_labs()
    return {
        "count": len(labs),
        "labs": [
            {
                "id": l.id,
                "category": l.category,
                "techniques": l.techniques,
                "artifact": l.artifact,
                "artifact_path": l.artifact_path,
            }
            for l in labs
        ],
    }


def attach_lab_to_workspace(lab_id: str, challenge_id: str | None = None) -> dict:
    """Create/use a workspace and import the lab artifact."""
    from agent.workspace import ChallengeWorkspace

    cid = challenge_id or f"lab-{lab_id}"
    ws = ChallengeWorkspace(cid).ensure()
    return ws.import_lab(lab_id)
