"""Reverse-engineering workflow scaffold (static → dynamic)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


STAGES = [
    "file_triage",
    "strings_imports",
    "static_cfg",
    "identify_protections",
    "dynamic_debug",
    "unpack_if_needed",
    "recover_algorithm",
    "validate_solution",
]


@dataclass
class RevPlan:
    stage: str = STAGES[0]
    completed: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def advance(self, note: str = "") -> None:
        if self.stage not in self.completed:
            self.completed.append(self.stage)
        if note:
            self.notes.append(note)
        i = STAGES.index(self.stage)
        if i + 1 < len(STAGES):
            self.stage = STAGES[i + 1]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def next_rev_actions(plan: RevPlan) -> List[str]:
    return {
        "file_triage": ["file", "detect language runtime (Go/Rust/.NET)"],
        "strings_imports": ["strings", "imports/exports"],
        "static_cfg": ["Ghidra/headless decompile entry"],
        "identify_protections": ["anti-debug, packing, obfuscation markers"],
        "dynamic_debug": ["gdb breakpoints on strcmp/crypt"],
        "unpack_if_needed": ["dump unpacked image after OEP"],
        "recover_algorithm": ["reimplement transform offline"],
        "validate_solution": ["confirm flag / serial"],
    }.get(plan.stage, ["continue"])
