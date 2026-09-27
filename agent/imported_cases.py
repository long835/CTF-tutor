"""Imported challenge cases with strict provenance (P1.5)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
IMPORTED_DIR = ROOT / "data" / "eval" / "imported"

REQUIRED_PROV = ("type", "source_url", "license", "attribution", "retrieved")


def load_imported(path: Path | None = None) -> List[Dict[str, Any]]:
    path = path or (IMPORTED_DIR / "public_literature.json")
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for row in data:
        prov = row.get("provenance") or {}
        missing = [k for k in REQUIRED_PROV if not prov.get(k)]
        if missing:
            raise ValueError(f"{row.get('id')}: missing provenance fields {missing}")
        if prov.get("type") != "imported":
            raise ValueError(f"{row.get('id')}: provenance.type must be 'imported'")
        out.append(row)
    return out


def validate_all() -> Dict[str, Any]:
    files = list(IMPORTED_DIR.glob("*.json"))
    total = 0
    for f in files:
        total += len(load_imported(f))
    return {"files": len(files), "cases": total}
