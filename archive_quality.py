"""Validation and duplicate checks for the CTF learning archive."""
from __future__ import annotations
import hashlib, json, os, re
from typing import Iterable, Optional
from schema import ArchiveEntry

VALID_CATEGORIES = {"pwn","rev","web","crypto","forensics","osint","misc","blockchain","mobile"}
VALID_DIFFICULTIES = {"easy","medium","hard","insane"}

def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")

def entry_fingerprint(entry: ArchiveEntry) -> str:
    refs = "\n".join(sorted(r.strip() for r in entry.references if r.strip()))
    payload = "\n".join([slugify(entry.challenge_name), entry.category, refs])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def validate_entry(entry: ArchiveEntry) -> list[str]:
    errors: list[str] = []
    if not entry.challenge_name.strip() or entry.challenge_name.strip().lower().startswith("unknown"):
        errors.append("challenge_name must be specific")
    if entry.category not in VALID_CATEGORIES:
        errors.append(f"unsupported category: {entry.category!r}")
    if entry.difficulty and entry.difficulty not in VALID_DIFFICULTIES:
        errors.append(f"unsupported difficulty: {entry.difficulty!r}")
    if not entry.techniques:
        errors.append("at least one technique is required")
    if not entry.description.strip():
        errors.append("description is required")
    if not entry.explanation.strip():
        errors.append("explanation is required")
    if not entry.solve_steps:
        errors.append("at least one high-level solve step is required")
    if not entry.references:
        errors.append("at least one source reference is required")
    return errors

def load_existing_fingerprints(output_dir: str) -> set[str]:
    seen: set[str] = set()
    if not os.path.isdir(output_dir):
        return seen
    for name in os.listdir(output_dir):
        if not name.endswith(".json"):
            continue
        try:
            seen.add(entry_fingerprint(ArchiveEntry.load(os.path.join(output_dir, name))))
        except Exception:
            continue
    return seen

def save_entry_checked(entry: ArchiveEntry, path: str, *, existing: Optional[set[str]] = None, dry_run: bool = False) -> bool:
    errors = validate_entry(entry)
    if errors:
        raise ValueError("invalid archive entry: " + "; ".join(errors))
    fingerprint = entry_fingerprint(entry)
    if existing is not None and fingerprint in existing:
        return False
    if dry_run:
        print(json.dumps(entry.to_dict(), indent=2, ensure_ascii=False))
    else:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        entry.save(path)
    if existing is not None:
        existing.add(fingerprint)
    return True
