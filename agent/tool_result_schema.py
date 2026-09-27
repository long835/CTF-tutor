"""Normalize tool outcomes: success vs failure vs empty-success."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


@dataclass
class ToolResult:
    status: str  # success | failure | timeout | denied | unavailable
    evidence_quality: str  # direct | indirect | none
    coverage: str  # full | partial | none
    output: str = ""
    error: str = ""
    tool: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def normalize_tool_result(
    tool: str,
    success: bool,
    output: str = "",
    error: str = "",
    *,
    timeout: bool = False,
    denied: bool = False,
    unavailable: bool = False,
) -> ToolResult:
    if denied:
        return ToolResult(tool=tool, status="denied", evidence_quality="none", coverage="none", error=error or "denied")
    if unavailable:
        return ToolResult(tool=tool, status="unavailable", evidence_quality="none", coverage="none", error=error or "unavailable")
    if timeout:
        return ToolResult(tool=tool, status="timeout", evidence_quality="none", coverage="none", error=error or "timeout")
    if not success:
        return ToolResult(tool=tool, status="failure", evidence_quality="none", coverage="none", output=output or "", error=error or "failed")
    out = (output or "").strip()
    if not out:
        # success with empty output = negative evidence (looked, found nothing)
        return ToolResult(tool=tool, status="success", evidence_quality="direct", coverage="partial", output="", error="")
    return ToolResult(tool=tool, status="success", evidence_quality="direct", coverage="full", output=out, error="")
