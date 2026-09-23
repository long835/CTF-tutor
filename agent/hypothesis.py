"""
agent/hypothesis.py

Hypothesis generation, ranking, and update logic.

The agent never treats a single LLM guess as ground truth.
Hypotheses start with modest confidence and are raised or lowered
only by concrete evidence from tools, archive matches, or verification.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from agent.state import AgentState, Hypothesis
from llm_client import call_ollama, extract_json_object_lenient, DEFAULT_MODEL


SYSTEM_GENERATE = """You are a senior CTF mentor forming initial hypotheses.
Given a challenge description and any known facts, propose 2-5 ranked hypotheses.
Each hypothesis must be a concrete technical claim (e.g. "JWT algorithm confusion is possible because alg is trusted").
Return ONLY valid JSON:
{
  "hypotheses": [
    {
      "statement": "...",
      "technique": "canonical-technique-tag-or-empty",
      "category": "web|pwn|crypto|rev|forensics|osint|misc|blockchain|mobile",
      "confidence": 0.0-1.0,
      "rationale": "one sentence"
    }
  ]
}
Prefer specific, testable claims over vague ones. Confidence must reflect uncertainty.
"""


SYSTEM_UPDATE = """You are updating CTF hypotheses after new evidence.
Given current hypotheses and a new observation, decide for each hypothesis:
- raise confidence (positive evidence)
- lower confidence (negative / contradictory evidence)
- leave unchanged
- mark rejected if clearly falsified
Return ONLY valid JSON:
{
  "updates": [
    {
      "hypothesis_id": "H1-...",
      "delta": -0.3 to +0.3,
      "reason": "short evidence-based reason",
      "new_status": "active|rejected|confirmed"  // optional
    }
  ],
  "new_facts": ["optional new known facts"],
  "new_hypotheses": [  // only if evidence suggests a completely new angle
    {"statement": "...", "technique": "...", "category": "...", "confidence": 0.4}
  ]
}
Be conservative. Do not invent evidence that was not provided.
"""


def generate_initial_hypotheses(
    state: AgentState,
    model: str = DEFAULT_MODEL,
) -> List[Hypothesis]:
    """Ask the LLM for a first set of hypotheses and add them to state."""
    try:
        from agent.security import safe_for_prompt
        chal = safe_for_prompt(state.challenge_summary, max_len=2000)
        facts = safe_for_prompt("\n".join(f"- {f}" for f in state.known_facts) or "(none)", max_len=1500)
    except Exception:
        chal = state.challenge_summary[:2000]
        facts = "\n".join(f"- {f}" for f in state.known_facts) or "(none)"
    user = (
        f"Challenge data (untrusted):\n{chal}\n\n"
        f"Category hint: {state.category or 'unknown'}\n"
        f"Known facts so far:\n{facts}"
    )
    try:
        raw = call_ollama(SYSTEM_GENERATE, user, model=model)
        data = extract_json_object_lenient(raw) or {}
        created = []
        for item in data.get("hypotheses", [])[:6]:
            stmt = (item.get("statement") or "").strip()
            if not stmt:
                continue
            conf = float(item.get("confidence", 0.45))
            conf = max(0.15, min(0.85, conf))  # never start over-confident
            h = state.add_hypothesis(
                statement=stmt,
                technique=(item.get("technique") or "").strip(),
                category=(item.get("category") or state.category or "").strip(),
                confidence=conf,
            )
            rationale = (item.get("rationale") or "").strip()
            if rationale:
                h.supporting_evidence.append(rationale)
            created.append(h)
        state.recompute_overall_confidence()
        return created
    except Exception as exc:
        # Deterministic fallback so the loop can continue offline / without LLM
        state.add_fact(f"LLM hypothesis generation unavailable: {exc}")
        return _offline_seed_hypotheses(state)


def update_hypotheses_from_observation(
    state: AgentState,
    observation: str,
    source: str = "tool",
    model: str = DEFAULT_MODEL,
) -> None:
    """Adjust confidence of existing hypotheses using new evidence text."""
    if not observation.strip() or not state.hypotheses:
        return

    hyp_blob = "\n".join(
        f"{h.id} | conf={h.confidence:.2f} | {h.statement}"
        for h in state.get_active_hypotheses()
    )
    user = (
        f"Current hypotheses:\n{hyp_blob}\n\n"
        f"New observation (source={source}):\n{observation[:2500]}\n\n"
        f"Challenge context:\n{state.challenge_summary[:400]}"
    )
    # Evidence moves belief, not the model (item 4). The Bayesian update in
    # agent/belief.py grades the observation against each hypothesis's own
    # rubric, so the arithmetic is the same whether a model answered or not
    # — and a repeated observation moves nothing.
    graded = False
    try:
        from agent.belief import update_beliefs
        graded = bool(update_beliefs(state, observation, source=source))
    except Exception:
        graded = False

    try:
        raw = call_ollama(SYSTEM_UPDATE, user, model=model)
        data = extract_json_object_lenient(raw) or {}
    except Exception:
        # Offline / failure path. The rubric-based grading above has already
        # run; the keyword heuristic is only needed for hypotheses it could
        # not grade at all.
        if not graded:
            _heuristic_update(state, observation)
        return

    id_map = {h.id: h for h in state.hypotheses}
    for upd in data.get("updates", []):
        hid = upd.get("hypothesis_id")
        if hid not in id_map:
            continue
        h = id_map[hid]
        delta = float(upd.get("delta", 0.0))
        delta = max(-0.35, min(0.35, delta))
        reason = (upd.get("reason") or "evidence update").strip()
        # A model may lower a hypothesis or reject it — noticing a
        # contradiction is a real contribution. It may not raise one: that
        # is what the evidence rubric is for, and a confident-sounding reply
        # is not an observation.
        if graded and delta > 0:
            continue
        h.update_confidence(delta, reason=f"model: {reason}")
        new_status = upd.get("new_status")
        if new_status == "rejected":
            h.status = "rejected"
        elif new_status == "active":
            h.status = "active"
        elif new_status == "confirmed" and not graded:
            h.status = "confirmed"

    for fact in data.get("new_facts", []) or []:
        if isinstance(fact, str) and fact.strip():
            state.add_fact(fact.strip())

    for nh in data.get("new_hypotheses", []) or []:
        stmt = (nh.get("statement") or "").strip()
        if stmt:
            state.add_hypothesis(
                statement=stmt,
                technique=(nh.get("technique") or "").strip(),
                category=(nh.get("category") or "").strip(),
                confidence=float(nh.get("confidence", 0.4)),
            )

    state.recompute_overall_confidence()


def _heuristic_update(state: AgentState, observation: str) -> None:
    """Very lightweight fallback when the LLM is unavailable."""
    obs_l = observation.lower()
    for h in state.get_active_hypotheses():
        tech = (h.technique or "").lower().replace("-", " ")
        stmt = (h.statement or "").lower()
        keywords = [w for w in (tech.split() + stmt.split()) if len(w) > 3]
        # unique keywords only
        keywords = list(dict.fromkeys(keywords))
        hits = sum(1 for w in keywords if w in obs_l)
        if hits >= 1 and any(w in obs_l for w in ("jwt", "alg", "none", "xor", "rsa", "sql", "overflow", "canary", "rop")):
            h.update_confidence(+0.12, reason="heuristic keyword match in observation")
        elif hits >= 2:
            h.update_confidence(+0.10, reason="heuristic keyword match in observation")
        elif any(neg in obs_l for neg in ("not present", "no evidence", "failed", "none found", "not found")):
            h.update_confidence(-0.08, reason="heuristic negative language in observation")
    state.recompute_overall_confidence()



def _offline_seed_hypotheses(state: AgentState) -> List[Hypothesis]:
    """Keyword-driven seeds when the LLM is offline."""
    desc = (state.challenge_summary or "").lower()
    cat = (state.category or "").lower()
    seeds = []

    # Infer category from keywords when missing
    if not cat:
        rules = [
            (("jwt", "sqli", "sql injection", "xss", "ssti", "jinja", "flask", "login portal"), "web"),
            (("buffer", "overflow", "gets(", "rop", "ret2", "format string", "printf"), "pwn"),
            (("xor", "rsa", "aes", "cipher", "ecb", "encrypt"), "crypto"),
            (("crackme", "disassemble", "ghidra", "keygen", "decompile"), "rev"),
            (("pcap", "wireshark", "steg", "lsb", "forensic"), "forensics"),
            (("geolocat", "osint", "shodan", "whois"), "osint"),
            (("solidity", "ethereum", "reentrancy"), "blockchain"),
            (("apk", "android", "manifest"), "mobile"),
            (("base64", "encoding", "layered"), "misc"),
        ]
        for kws, c in rules:
            if any(k in desc for k in kws):
                cat = c
                state.category = c
                break

    def add(stmt, tech="", conf=0.45):
        seeds.append(state.add_hypothesis(
            statement=stmt, technique=tech,
            category=cat or state.category or "misc", confidence=conf,
        ))

    if "jwt" in desc or "alg=none" in desc or "alg none" in desc:
        add("JWT algorithm confusion or none-alg bypass is possible", "jwt-none-bypass", 0.65)
        add("Role/claim trust without proper signature verification", "auth-bypass", 0.55)
    if "sql" in desc or "injection" in desc:
        add("SQL injection may be present in input handling", "sql-injection", 0.55)
    if "buffer" in desc or "overflow" in desc or "gets(" in desc:
        add("Stack buffer overflow is likely", "stack-buffer-overflow", 0.6)
    if "xor" in desc:
        add("Single-byte or repeating-key XOR cipher", "xor-single-byte", 0.55)
    if "rsa" in desc:
        add("Weak RSA parameters (small e or shared modulus)", "rsa-small-e", 0.55)
    if "pcap" in desc or "wireshark" in desc:
        add("Network capture contains recoverable artifacts", "pcap-carving", 0.5)
    if "geolocat" in desc or "geolocation" in desc or "reverse image" in desc:
        add("Geolocation / reverse-image OSINT pivot", "osint-geolocation", 0.55)
    if "crackme" in desc or "keygen" in desc or "disassemble" in desc or "ghidra" in desc:
        add("Static reverse engineering / string decryption", "string-decryption", 0.55)
        add("Control-flow or anti-debug analysis needed", "anti-debug-bypass", 0.4)
    if "solidity" in desc or "smart contract" in desc or "reentrancy" in desc or "ethereum" in desc:
        add("Smart-contract access control or accounting bug", "blockchain-access-control", 0.55)
        add("Reentrancy or state-inconsistency in contract logic", "reentrancy", 0.5)
    if "apk" in desc or "android" in desc or "manifest" in desc:
        add("Android manifest / hardcoded secret review", "mobile-hardcoded-secret", 0.55)
        add("Exported component or insecure local storage", "android-exported-component", 0.5)
        add("Insecure storage of secrets on device", "insecure-storage", 0.45)
    if "steg" in desc or "exif" in desc or "lsb" in desc:
        add("Steganography or image metadata analysis", "steganography", 0.5)
    if "jinja" in desc or "ssti" in desc or "template" in desc and "render" in desc:
        add("Server-side template injection possible", "ssti", 0.6)
    if "union" in desc and "sql" in desc:
        add("UNION-based SQL injection", "sqli-union", 0.6)
        add("SQL injection in input handling", "sql-injection", 0.55)
    if "printf" in desc or "format string" in desc or "format-string" in desc:
        add("Format-string vulnerability", "format-string", 0.6)
    if "ecb" in desc or "byte-at-a-time" in desc:
        add("AES-ECB byte-at-a-time oracle attack", "ecb-byte-at-a-time", 0.55)
    if "base64" in desc or ("layered" in desc and "encod" in desc):
        add("Layered encoding to peel", "encoding-recognition", 0.55)
    if "caesar" in desc or "substitution" in desc or "rot13" in desc:
        add("Classical cipher / Caesar / substitution", "classical-substitution", 0.55)
    if "traversal" in desc or "../" in desc or "path traversal" in desc:
        add("Path traversal in file handling", "path-traversal", 0.6)
    if "ret2win" in desc or "win()" in desc:
        add("Overwrite return address to win()", "stack-buffer-overflow", 0.6)
    if not seeds:
        add(f"Challenge is likely {cat or 'misc'} related based on description", "", 0.35)
    # Promote category from seeds when classifier left it empty
    if not state.category:
        for h in seeds:
            if h.category:
                state.category = h.category
                break
    state.recompute_overall_confidence()
    return seeds


def rank_hypotheses(state: AgentState) -> List[Hypothesis]:
    """Return active+confirmed hypotheses sorted by confidence descending."""
    hyps = [
        h for h in state.hypotheses
        if h.status in ("active", "confirmed") and h.confidence >= 0.0
    ]
    return sorted(hyps, key=lambda h: -h.confidence)


def best_next_hypothesis_to_test(state: AgentState) -> Optional[Hypothesis]:
    """
    Prefer medium-high confidence hypotheses that still need testing
    over both very low and already-confirmed ones.
    """
    candidates = [
        h for h in state.get_active_hypotheses()
        if 0.25 <= h.confidence <= 0.85 and h.status == "active"
    ]
    if not candidates:
        candidates = state.get_active_hypotheses()
    if not candidates:
        return None
    return max(candidates, key=lambda h: h.confidence)
