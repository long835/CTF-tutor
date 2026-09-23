"""
agent/tool_capabilities.py

Which tools could produce the evidence that is missing (item 6).

A large toolkit makes a small model worse, not better. Offered fifteen
tools and a vague situation, a 4B model picks the one whose name most
resembles the challenge text. The fix is not a better prompt; it is a
shorter menu, chosen before the model is asked.

The selection rule here is deliberately backwards from the usual one.
Instead of asking "what tool suits a web challenge", it asks:

    which required signal is still missing  →  which tool can observe it

That inversion is what makes the agent evidence-driven. `agent.evidence`
says a stack overflow claim needs an unbounded copy and a stack buffer;
`agent.evidence_graph` says which of those is still unobserved; this module
says `static_analysis` can observe it and `retrieve_archive` cannot. The
model is then asked to choose among three plausible actions rather than to
invent a plan.

`produces` entries are phrases, matched against rubric signals with the
same matcher the rubrics use, so a signal added to `agent.evidence` is
automatically routable — and `uncovered_signals()` reports the ones that
are not, which is how a capability gap becomes visible instead of becoming
an agent that quietly cannot finish a proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from agent.evidence import REQUIREMENTS, _matches, requirements_for


@dataclass
class ToolCapability:
    """What one tool can take, what it can see, and what it costs."""

    name: str
    summary: str
    accepts: Set[str] = field(default_factory=set)       # artifact kinds
    categories: Set[str] = field(default_factory=set)    # challenge categories
    produces: List[str] = field(default_factory=list)    # observable signals
    args: List[str] = field(default_factory=list)
    cost: str = "cheap"                                  # cheap|moderate|expensive
    requires: str = ""                                   # external dependency
    offline: bool = True
    destructive: bool = False

    def can_observe(self, signal: str) -> bool:
        """Whether any capability phrase matches a rubric signal."""
        return any(_matches(signal, phrase) for phrase in self.produces)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "summary": self.summary,
            "accepts": sorted(self.accepts),
            "categories": sorted(self.categories),
            "produces": list(self.produces),
            "args": list(self.args),
            "cost": self.cost,
            "requires": self.requires,
            "offline": self.offline,
        }


# Artifact kinds mirror agent/triage.py's classification vocabulary.
CAPABILITIES: Dict[str, ToolCapability] = {
    "static_analysis": ToolCapability(
        name="static_analysis",
        summary="Category-aware static analysis of a local file or source tree",
        accepts={"binary", "source", "archive", "text"},
        categories={"pwn", "rev", "web", "misc"},
        produces=[
            "nx", "no canary", "canary", "pie disabled", "pie enabled", "relro",
            "statically linked", "dynamically linked", "libc",
            "gets", "strcpy", "sprintf", "unbounded copy", "read into", "fixed buffer",
            "printf", "fprintf", "snprintf", "format string is a literal",
            "non-literal format", "variable format", "user-controlled format argument",
            "input passed as argument not format",
            "win function", "buffer", "stack", "local array", "no bounds",
            "imports", "symbols", "puts|printf plt", "standard sections",
            "unusual section name", "rwx section", "few imports", "normal import table",
            "query|select|insert|where|sql", "concat|interpolat|format|f-string",
            "parameterised|prepared statement|placeholder|orm binding",
            "template|render|jinja|twig", "path|filename|file", "join|concat|open|read",
            "bounds checked", "fgets with size", "length validated",
            "rust|go|java|python source", "input escaped",
        ],
        args=["path", "category_hint"],
        cost="moderate",
    ),
    "web_recon": ToolCapability(
        name="web_recon",
        summary="Passive web pattern scan over local source (auth, JWT, framework markers)",
        accepts={"source", "text", "archive"},
        categories={"web"},
        produces=[
            "jwt|json web token", "alg|algorithm", "none", "hs256|rs256", "jwks",
            "header honoured", "verify without allowlist", "decode without verify",
            "algorithm allowlist", "alg pinned", "signature required", "algorithms=",
            "public key reachable", "generic verify", "hs256 accepted", "key type checked",
            "rs256|asymmetric|public key",
            "query|select|insert|where|sql", "concat|interpolat|format|f-string|\\+ user",
            "parameterised|prepared statement|placeholder|orm binding",
            "template|render|jinja|twig|freemarker|handlebars", "autoescape",
            "user input in template string", "input passed as context variable",
            "path|filename|file", "no normalisation", "prefix check only",
            "normalised then validated", "allowlist of filenames", "basename only",
            "session", "cookie", "csrf", "cors", "redirect",
        ],
        args=["path"],
        cost="cheap",
    ),
    "crypto_toolkit": ToolCapability(
        name="crypto_toolkit",
        summary="Hash, cipher and RSA pattern detection over a file or text",
        accepts={"text", "source", "binary"},
        categories={"crypto"},
        produces=[
            "xor|ciphertext|encoded bytes", "aes|rsa|block cipher", "ecb", "cbc",
            "padding", "hash", "md5|sha", "key length", "short key", "repeating byte",
            "modulus", "public exponent", "small exponent", "nonce", "iv reuse",
            "frequency match", "high entropy", "entropy|packed|compressed section",
        ],
        args=["path_or_text"],
        cost="cheap",
    ),
    "forensics_toolkit": ToolCapability(
        name="forensics_toolkit",
        summary="File magic, metadata, embedded-data and strings signals",
        accepts={"image", "pcap", "archive", "binary", "document", "audio"},
        categories={"forensics", "misc", "osint"},
        produces=[
            "magic", "file type", "image|audio|media file", "metadata", "exif",
            "embedded", "appended data", "size mismatch", "extra chunk", "lsb anomaly",
            "data appended after eof", "file is a plain archive",
            "entropy|packed|compressed section", "readable strings", "steg", "lsb",
            "thumbnail", "timestamps", "an embedded media asset",
            "ordinary compressed data such as an embedded archive",
        ],
        args=["path"],
        cost="cheap",
    ),
    "decode_toolkit": ToolCapability(
        name="decode_toolkit",
        summary="Identify and safely decode common encodings and nested archives",
        accepts={"text", "archive", "binary"},
        categories={"crypto", "misc", "forensics"},
        produces=[
            "base64", "hex", "rot", "url encoding", "printable after xor",
            "nested archive", "encoded bytes", "compressed data",
        ],
        args=["path_or_text"],
        cost="cheap",
    ),
    "xor_crack": ToolCapability(
        name="xor_crack",
        summary="Single-byte and repeating-key XOR recovery",
        accepts={"text", "binary"},
        categories={"crypto"},
        produces=[
            "xor|ciphertext|encoded bytes", "short key", "repeating byte",
            "printable after xor", "frequency match", "key length > 1 established",
            "a repeating multi-byte key, which needs a different approach",
        ],
        args=["data", "max_keysize"],
        cost="moderate",
    ),
    "auto_decode": ToolCapability(
        name="auto_decode",
        summary="Layered encoding peel with a timeout, plus flag scanning",
        accepts={"text", "binary", "archive"},
        categories={"crypto", "misc", "forensics"},
        produces=["base64", "hex", "printable after xor", "nested encoding", "flag pattern"],
        args=["data", "path", "max_depth", "timeout"],
        cost="cheap",
    ),
    "gdb_inspect": ToolCapability(
        name="gdb_inspect",
        summary="Sandboxed GDB batch inspection and disassembly",
        accepts={"binary"},
        categories={"pwn", "rev"},
        produces=[
            "crash", "segfault", "controllable rip", "control.{0,15}(rip|eip|return)",
            "overflow|control", "stack values leaked", "unexpected output",
            "disassembly", "register state", "offset", "breakpoint",
        ],
        args=["path", "function"],
        cost="expensive",
        requires="gdb",
    ),
    "retrieve_archive": ToolCapability(
        name="retrieve_archive",
        summary="Query the local knowledge archive for similar challenges and techniques",
        accepts={"none"},
        categories={"web", "pwn", "rev", "crypto", "forensics", "osint", "misc"},
        # Retrieval supplies candidate techniques, never observations about
        # *this* challenge. Keeping `produces` empty is what stops the agent
        # from treating a knowledge card as an observed signal.
        produces=[],
        args=["query", "category", "top_k"],
        cost="cheap",
    ),
    "research": ToolCapability(
        name="research",
        summary="Local archive plus concept cards, optionally online documentation",
        accepts={"none"},
        categories={"web", "pwn", "rev", "crypto", "forensics", "osint", "misc"},
        produces=[],
        args=["query", "category", "online"],
        cost="moderate",
        offline=False,
    ),
    "classify": ToolCapability(
        name="classify",
        summary="Re-classify the challenge description into a category",
        accepts={"none"},
        categories={"misc"},
        produces=[],
        args=["description"],
        cost="cheap",
    ),
    "decompose": ToolCapability(
        name="decompose",
        summary="Break the challenge into sub-problems and technique seeds",
        accepts={"none"},
        categories={"misc"},
        produces=[],
        args=["description", "category"],
        cost="moderate",
    ),
    "ask_user": ToolCapability(
        name="ask_user",
        summary="Request a file, command output, or clarification the agent cannot obtain",
        accepts={"none"},
        categories={"web", "pwn", "rev", "crypto", "forensics", "osint", "misc"},
        # The user can answer anything, which is exactly why this must be
        # last resort rather than a cheap way to look productive.
        produces=["*"],
        args=["question"],
        cost="expensive",
    ),
    "verify_candidate": ToolCapability(
        name="verify_candidate",
        summary="Check a candidate solution or flag against known constraints",
        accepts={"none"},
        categories={"web", "pwn", "rev", "crypto", "forensics", "osint", "misc"},
        produces=["flag pattern", "format", "length", "prefix"],
        args=["candidate", "constraints"],
        cost="cheap",
    ),
}

COST_PENALTY = {"cheap": 0.0, "moderate": 0.08, "expensive": 0.25}


@dataclass
class Candidate:
    """One shortlisted tool, with the reason it is on the list."""

    tool: str
    score: float
    reason: str
    closes: List[str] = field(default_factory=list)   # signals it could observe

    def to_dict(self) -> Dict[str, Any]:
        return {"tool": self.tool, "score": round(self.score, 3),
                "reason": self.reason, "closes": list(self.closes)}


def capability(name: str) -> Optional[ToolCapability]:
    return CAPABILITIES.get((name or "").strip())


def tools_for_signal(signal: str, exclude: Optional[Iterable[str]] = None) -> List[str]:
    """
    Which tools could observe this signal.

    `ask_user` is excluded from the direct answer: it can technically supply
    anything, and including it would make every gap look closeable without
    doing any work.
    """
    skip = {str(x) for x in (exclude or [])}
    return [
        cap.name for cap in CAPABILITIES.values()
        if cap.name not in skip and cap.name != "ask_user" and cap.can_observe(signal)
    ]


def tools_for_technique(technique: str) -> List[str]:
    """Tools that can observe at least one signal the technique requires."""
    req = requirements_for(technique)
    if req is None:
        return []
    out: List[str] = []
    for signal in req.required + req.supporting:
        for name in tools_for_signal(signal):
            if name not in out:
                out.append(name)
    return out


def candidates(
    category: str = "",
    artifact_kinds: Optional[Iterable[str]] = None,
    missing_signals: Optional[Iterable[str]] = None,
    exclude: Optional[Iterable[str]] = None,
    limit: int = 4,
) -> List[Candidate]:
    """
    The shortlist the model is allowed to choose from.

    Scoring is dominated by whether a tool can close a currently missing
    signal, because that is the only thing that changes the assessment.
    Category fit and artifact fit act as filters and tie-breakers; cost is a
    mild penalty so an expensive tool has to be clearly better to win.
    """
    kinds = {str(k).lower() for k in (artifact_kinds or [])}
    gaps = [str(s) for s in (missing_signals or [])]
    skip = {str(x) for x in (exclude or [])}
    cat = (category or "").strip().lower()

    scored: List[Candidate] = []
    for cap in CAPABILITIES.values():
        if cap.name in skip:
            continue
        # An analysis tool with nothing to analyse is not a candidate.
        needs_artifact = bool(cap.accepts) and "none" not in cap.accepts
        if needs_artifact and kinds and not (cap.accepts & kinds):
            continue
        if needs_artifact and not kinds:
            continue

        closes = [signal for signal in gaps if cap.can_observe(signal)]
        score = 0.0
        reasons: List[str] = []
        if closes:
            score += 0.5 + min(0.4, 0.12 * len(closes))
            reasons.append(f"can observe {len(closes)} missing signal(s)")
        if cat and cat in cap.categories:
            score += 0.2
            reasons.append(f"suits {cat}")
        elif cat and cap.categories and cat not in cap.categories:
            score -= 0.15
        if needs_artifact and kinds & cap.accepts:
            score += 0.15
            reasons.append(f"accepts {', '.join(sorted(kinds & cap.accepts))}")
        if not cap.offline:
            score -= 0.1
            reasons.append("needs network")
        score -= COST_PENALTY.get(cap.cost, 0.1)

        if cap.name == "ask_user":
            # Always available, never attractive: it only wins when the
            # shortlist would otherwise be empty.
            score = min(score, 0.05)
            reasons = ["last resort: no local tool can produce this evidence"]

        if score <= 0 and cap.name != "ask_user":
            continue
        scored.append(Candidate(
            tool=cap.name, score=score,
            reason="; ".join(reasons) or "generally applicable",
            closes=closes,
        ))

    scored.sort(key=lambda c: -c.score)
    shortlist = [c for c in scored if c.tool != "ask_user"][:limit]
    if not shortlist:
        fallback = [c for c in scored if c.tool == "ask_user"]
        return fallback[:1]
    return shortlist


def candidates_for_state(state: Any, graph: Any = None, limit: int = 4) -> List[Candidate]:
    """Shortlist for the current investigation, honouring recovery bans."""
    from agent.recovery import banned_actions

    kinds: Set[str] = set()
    for path in getattr(state, "discovered_artifacts", None) or []:
        kinds.add(_kind_of(str(path)))

    gaps: List[str] = []
    if graph is not None:
        try:
            gaps = list(graph.missing_signals())
        except Exception:
            gaps = []
    if not gaps:
        top = None
        try:
            top = state.top_hypothesis()
        except Exception:
            top = None
        req = requirements_for(getattr(top, "technique", "") or "")
        if req:
            gaps = list(req.required)

    already = {str(getattr(a, "tool", "")) for a in (getattr(state, "actions", None) or [])
               if str(getattr(a, "status", "")) == "succeeded"}
    return candidates(
        category=str(getattr(state, "category", "") or ""),
        artifact_kinds=kinds,
        missing_signals=gaps,
        exclude=banned_actions(state) | already,
        limit=limit,
    )


_EXT_KIND = {
    ".py": "source", ".js": "source", ".php": "source", ".rb": "source",
    ".go": "source", ".java": "source", ".c": "source", ".cpp": "source",
    ".ts": "source", ".rs": "source", ".cs": "source", ".html": "source",
    ".txt": "text", ".md": "text", ".json": "text", ".log": "text", ".csv": "text",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image", ".bmp": "image",
    ".pcap": "pcap", ".pcapng": "pcap",
    ".zip": "archive", ".tar": "archive", ".gz": "archive", ".7z": "archive",
    ".pdf": "document", ".docx": "document",
    ".wav": "audio", ".mp3": "audio",
    ".exe": "binary", ".elf": "binary", ".so": "binary", ".dll": "binary", ".bin": "binary",
}


def _kind_of(path: str) -> str:
    lowered = (path or "").lower()
    for ext, kind in _EXT_KIND.items():
        if lowered.endswith(ext):
            return kind
    return "binary" if "." not in lowered.rsplit("/", 1)[-1] else "text"


def candidate_prompt_block(shortlist: Sequence[Candidate], max_tools: int = 4) -> str:
    """
    Render the shortlist for a prompt.

    Only the shortlisted tools and their arguments appear, so the model
    never sees the full toolkit and cannot propose something the situation
    does not support.
    """
    if not shortlist:
        return "No applicable tool. Ask the user for the missing material."
    lines = ["Available actions (choose exactly one):"]
    for cand in list(shortlist)[:max_tools]:
        cap = capability(cand.tool)
        if cap is None:
            continue
        args = ", ".join(cap.args) or "no arguments"
        lines.append(f"  {cap.name}({args})")
        lines.append(f"      {cap.summary}")
        lines.append(f"      why offered: {cand.reason}")
        if cand.closes:
            lines.append(f"      would close: {'; '.join(cand.closes[:3])}")
    return "\n".join(lines)


def uncovered_signals() -> Dict[str, List[str]]:
    """
    Rubric signals no tool claims to observe.

    A diagnostic, not a runtime path: a required signal with no tool behind
    it is a technique the agent can never finish proving, and it is better
    to see that in a report than to discover it as a stalled investigation.
    """
    out: Dict[str, List[str]] = {}
    for technique, req in REQUIREMENTS.items():
        missing = [signal for signal in req.required if not tools_for_signal(signal)]
        if missing:
            out[technique] = missing
    return out
