"""
agent/provenance.py

Where did this knowledge come from, has it changed, and does it disagree
with itself? (Phase 6)

An archive that grows past a few dozen hand-written entries stops being
trustworthy by inspection. Three things start to matter:

  provenance     which source produced this entry, when, and under what
                 licence — so a bad source can be traced and pulled
  versioning     content-hash history, so an edit is visible instead of
                 silently overwriting what a learner studied last week
  contradiction  two entries that teach opposite things about the same
                 technique, which is worse than having neither

All state lives in a single sidecar file (data/provenance.json). Archive
entries themselves stay clean JSON so they remain readable and diffable.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

ARCHIVE_DIR = os.path.join("data", "archive")
PROVENANCE_PATH = os.path.join("data", "provenance.json")

# Source tiers, best first. Used to decide who wins a contradiction.
TRUST_TIERS: Dict[str, int] = {
    "curated": 5,  # hand-written and reviewed in this repo
    "official-writeup": 4,  # author's own published writeup
    "community-writeup": 3,  # third-party writeup
    "generated": 2,  # LLM-drafted, human-unchecked
    "synthetic": 1,  # deterministic template card
    "unknown": 0,
}

DEFAULT_SOURCE_TYPE = "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def content_hash(payload: Dict[str, Any]) -> str:
    """
    Stable hash of the teaching content only.

    Bookkeeping fields are excluded so that re-saving an entry without
    changing what it teaches does not create a spurious new version.
    """
    ignore = {"provenance", "version", "added_at", "updated_at"}
    trimmed = {k: v for k, v in sorted(payload.items()) if k not in ignore}
    blob = json.dumps(trimmed, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass
class Provenance:
    """Origin record for one archive entry."""

    entry_id: str
    source_type: str = DEFAULT_SOURCE_TYPE
    source_url: str = ""
    added_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)
    added_by: str = "unknown"
    license: str = "unspecified"
    version: int = 1
    content_hash: str = ""
    history: List[Dict[str, str]] = field(default_factory=list)
    verified: bool = False
    notes: str = ""

    @property
    def trust(self) -> int:
        return TRUST_TIERS.get(self.source_type, 0)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Provenance":
        fields = cls.__dataclass_fields__
        return cls(**{k: v for k, v in data.items() if k in fields})


class ProvenanceStore:
    """Sidecar index of provenance records, keyed by archive entry id."""

    def __init__(self, path: str = PROVENANCE_PATH):
        self.path = Path(path)
        self.records: Dict[str, Provenance] = {}
        self.load()

    def load(self) -> None:
        if not self.path.is_file():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for entry_id, raw in (data.get("records") or {}).items():
            try:
                self.records[entry_id] = Provenance.from_dict(raw)
            except (TypeError, ValueError):
                continue

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": 1,
            "updated_at": _now(),
            "records": {k: v.to_dict() for k, v in sorted(self.records.items())},
        }
        self.path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def get(self, entry_id: str) -> Optional[Provenance]:
        return self.records.get(entry_id)

    def record(
        self,
        entry_id: str,
        payload: Dict[str, Any],
        source_type: str = DEFAULT_SOURCE_TYPE,
        source_url: str = "",
        added_by: str = "unknown",
        license: str = "unspecified",
        notes: str = "",
    ) -> Provenance:
        """
        Register or update an entry.

        A changed content hash bumps the version and pushes the previous
        hash onto the history stack. An unchanged hash is a no-op, so this
        is safe to call on every ingest run.
        """
        digest = content_hash(payload)
        existing = self.records.get(entry_id)

        if existing is None:
            prov = Provenance(
                entry_id=entry_id,
                source_type=source_type,
                source_url=source_url,
                added_by=added_by,
                license=license,
                content_hash=digest,
                notes=notes,
            )
            self.records[entry_id] = prov
            return prov

        if existing.content_hash != digest:
            existing.history.append(
                {
                    "version": str(existing.version),
                    "content_hash": existing.content_hash,
                    "replaced_at": _now(),
                }
            )
            existing.history = existing.history[-20:]
            existing.version += 1
            existing.content_hash = digest
            existing.updated_at = _now()
            existing.verified = False  # content changed; re-verification needed

        if source_type != DEFAULT_SOURCE_TYPE:
            existing.source_type = source_type
        if source_url:
            existing.source_url = source_url
        if notes:
            existing.notes = notes
        return existing

    def mark_verified(self, entry_id: str, by: str = "human") -> bool:
        prov = self.records.get(entry_id)
        if not prov:
            return False
        prov.verified = True
        prov.added_by = by
        prov.updated_at = _now()
        return True

    def stats(self) -> Dict[str, Any]:
        by_source: Dict[str, int] = {}
        by_license: Dict[str, int] = {}
        for p in self.records.values():
            by_source[p.source_type] = by_source.get(p.source_type, 0) + 1
            by_license[p.license] = by_license.get(p.license, 0) + 1
        verified = sum(1 for p in self.records.values() if p.verified)
        revised = sum(1 for p in self.records.values() if p.version > 1)
        return {
            "tracked": len(self.records),
            "verified": verified,
            "unverified": len(self.records) - verified,
            "revised": revised,
            "by_source_type": dict(sorted(by_source.items())),
            "by_license": dict(sorted(by_license.items())),
        }


# ------------------------------------------------------------ contradictions

# Claim pairs that cannot both be true of the same technique. Each tuple is
# (regex A, regex B, human description).
CONTRADICTION_RULES: List[Tuple[str, str, str]] = [
    (
        r"\bis encrypt(?:ed|ion)\b",
        r"\b(is |only )?(signed|encoded)(?: only| not encrypted)?\b",
        "one entry calls it encrypted, another calls it signed/encoded",
    ),
    (
        r"\bnot exploitable\b|\bcannot be exploited\b",
        r"\bis exploitable\b|\bcan be exploited\b",
        "disagreement about exploitability",
    ),
    (
        r"\brequires? shellcode\b",
        r"\bno shellcode\b|\bwithout shellcode\b|\bcode reuse\b",
        "disagreement about whether shellcode is required",
    ),
    (
        r"\bpatched\b|\bfixed in\b",
        r"\bstill (?:works|vulnerable)\b|\bunpatched\b",
        "disagreement about whether the issue is fixed",
    ),
    (
        r"\bdeterministic\b",
        r"\brandomi[sz]ed\b|\bnon-deterministic\b",
        "disagreement about determinism",
    ),
]


@dataclass
class Contradiction:
    technique: str
    entry_a: str
    entry_b: str
    reason: str
    severity: str = "warning"  # warning | conflict
    winner: str = ""  # entry id favoured by source trust, if any

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _entry_text(payload: Dict[str, Any]) -> str:
    parts = [
        str(payload.get("description") or ""),
        str(payload.get("explanation") or ""),
        " ".join(str(s) for s in (payload.get("solve_steps") or [])),
        str(payload.get("notes") or ""),
    ]
    return " ".join(parts).lower()


def find_contradictions(
    entries: Dict[str, Dict[str, Any]],
    store: Optional[ProvenanceStore] = None,
) -> List[Contradiction]:
    """
    Compare entries that share a technique tag and flag opposing claims.

    Only entries sharing a technique are compared — two unrelated entries
    saying different things is not a contradiction, it is just coverage.
    """
    by_technique: Dict[str, List[str]] = {}
    for entry_id, payload in entries.items():
        for t in payload.get("techniques") or []:
            by_technique.setdefault(str(t).lower(), []).append(entry_id)

    compiled = [(re.compile(a), re.compile(b), why) for a, b, why in CONTRADICTION_RULES]
    found: List[Contradiction] = []
    seen_pairs: Set[Tuple[str, str, str]] = set()

    for technique, ids in by_technique.items():
        if len(ids) < 2:
            continue
        texts = {i: _entry_text(entries[i]) for i in ids}
        for i, a in enumerate(ids):
            for b in ids[i + 1 :]:
                ta, tb = texts[a], texts[b]
                for pat_a, pat_b, why in compiled:
                    a_says_a, a_says_b = bool(pat_a.search(ta)), bool(pat_b.search(ta))
                    b_says_a, b_says_b = bool(pat_a.search(tb)), bool(pat_b.search(tb))
                    # A holds one side exclusively, B holds the other.
                    opposed = (a_says_a and not a_says_b and b_says_b and not b_says_a) or (
                        a_says_b and not a_says_a and b_says_a and not b_says_b
                    )
                    if not opposed:
                        continue
                    key = (min(a, b), max(a, b), why)
                    if key in seen_pairs:
                        continue
                    seen_pairs.add(key)

                    winner = ""
                    if store:
                        pa, pb = store.get(a), store.get(b)
                        if pa and pb and pa.trust != pb.trust:
                            winner = a if pa.trust > pb.trust else b
                    found.append(
                        Contradiction(
                            technique=technique,
                            entry_a=a,
                            entry_b=b,
                            reason=why,
                            severity="conflict" if winner else "warning",
                            winner=winner,
                        )
                    )
    return found


# -------------------------------------------------------------------- audit


def load_archive_entries(archive_dir: str = ARCHIVE_DIR) -> Dict[str, Dict[str, Any]]:
    root = Path(archive_dir)
    out: Dict[str, Dict[str, Any]] = {}
    if not root.is_dir():
        return out
    for fp in sorted(root.glob("*.json")):
        try:
            out[fp.stem] = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
    return out


def infer_source_type(entry_id: str, payload: Dict[str, Any]) -> str:
    """Best guess at provenance for entries that predate this tracking."""
    source = str(payload.get("source") or "").lower()
    if entry_id.startswith("curated-") or "curated" in source:
        return "curated"
    if entry_id.startswith("synth") or "synthetic" in source or "pattern" in entry_id:
        return "synthetic"
    if entry_id.startswith("example"):
        return "curated"
    refs = payload.get("references") or []
    if any("github.com" in str(r) or "ctftime" in str(r) for r in refs):
        return "community-writeup"
    return DEFAULT_SOURCE_TYPE


def sync_archive(
    archive_dir: str = ARCHIVE_DIR,
    path: str = PROVENANCE_PATH,
    save: bool = True,
) -> Dict[str, Any]:
    """
    Bring the provenance sidecar in line with what is on disk.

    Reports newly tracked entries, revised entries, and entries that have
    a record but no longer exist on disk.
    """
    entries = load_archive_entries(archive_dir)
    store = ProvenanceStore(path)

    before = {k: (v.version, v.content_hash) for k, v in store.records.items()}
    added: List[str] = []
    revised: List[str] = []

    for entry_id, payload in entries.items():
        known = entry_id in store.records
        prov = store.record(
            entry_id,
            payload,
            source_type=store.records[entry_id].source_type
            if known and store.records[entry_id].source_type != DEFAULT_SOURCE_TYPE
            else infer_source_type(entry_id, payload),
            source_url=(payload.get("references") or [""])[0] if payload.get("references") else "",
        )
        if not known:
            added.append(entry_id)
        elif before.get(entry_id, (0, ""))[1] != prov.content_hash:
            revised.append(entry_id)

    orphaned = [k for k in store.records if k not in entries]

    if save:
        store.save()

    return {
        "tracked": len(store.records),
        "added": sorted(added),
        "revised": sorted(revised),
        "orphaned": sorted(orphaned),
        "stats": store.stats(),
    }


def audit_archive(archive_dir: str = ARCHIVE_DIR, path: str = PROVENANCE_PATH) -> Dict[str, Any]:
    """
    Full quality report: validation, provenance coverage, contradictions.

    This is what `python main.py audit` prints, and what CI can gate on.
    """
    entries = load_archive_entries(archive_dir)
    store = ProvenanceStore(path)

    invalid: List[Dict[str, Any]] = []
    try:
        from archive_quality import validate_entry
        from schema import ArchiveEntry

        for entry_id, payload in entries.items():
            try:
                errors = validate_entry(ArchiveEntry.from_dict(payload))
            except TypeError as exc:
                errors = [f"could not load entry: {exc}"]
            if errors:
                invalid.append({"entry": entry_id, "errors": errors})
    except Exception:
        pass

    untracked = [e for e in entries if e not in store.records]
    unverified = [e for e in entries if e in store.records and not store.records[e].verified]
    no_refs = [e for e, p in entries.items() if not (p.get("references") or [])]
    contradictions = find_contradictions(entries, store)

    coverage = (len(entries) - len(untracked)) / len(entries) if entries else 0.0

    return {
        "entries": len(entries),
        "provenance_coverage": round(coverage, 3),
        "untracked": sorted(untracked),
        "unverified": len(unverified),
        "missing_references": sorted(no_refs),
        "invalid": invalid,
        "contradictions": [c.to_dict() for c in contradictions],
        "stats": store.stats(),
        "clean": not invalid and not contradictions and not untracked,
    }


def render_audit(report: Dict[str, Any]) -> str:
    """Readable audit summary for the terminal."""
    lines = [
        "# Archive audit",
        "",
        f"Entries: {report.get('entries', 0)} · "
        f"provenance coverage: {report.get('provenance_coverage', 0) * 100:.0f}% · "
        f"unverified: {report.get('unverified', 0)}",
    ]

    stats = report.get("stats") or {}
    by_source = stats.get("by_source_type") or {}
    if by_source:
        lines.append("Sources: " + ", ".join(f"{k} x{v}" for k, v in by_source.items()))

    invalid = report.get("invalid") or []
    if invalid:
        lines += ["", f"## Failing validation ({len(invalid)})"]
        for row in invalid[:10]:
            lines.append(f"- {row['entry']}: {'; '.join(row['errors'])}")

    contradictions = report.get("contradictions") or []
    if contradictions:
        lines += ["", f"## Contradictions ({len(contradictions)})"]
        for c in contradictions[:10]:
            tail = f" — prefer {c['winner']}" if c.get("winner") else ""
            lines.append(f"- [{c['technique']}] {c['entry_a']} vs {c['entry_b']}: {c['reason']}{tail}")

    untracked = report.get("untracked") or []
    if untracked:
        lines += ["", f"## Untracked ({len(untracked)})", "Run `python main.py audit --sync` to register these."]
        for e in untracked[:10]:
            lines.append(f"- {e}")

    missing = report.get("missing_references") or []
    if missing:
        lines += ["", f"## Missing references ({len(missing)})"]
        for e in missing[:10]:
            lines.append(f"- {e}")

    if report.get("clean"):
        lines += ["", "Everything checks out."]
    return "\n".join(lines)


if __name__ == "__main__":
    print(render_audit(audit_archive()))
