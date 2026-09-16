"""
agent/rerank.py

Second-stage reranking for archive retrieval (Phase 3).

First-stage retrieval (lexical BM25 + optional vectors) is recall-oriented:
it casts a wide net and often returns near-duplicates of the same pattern
card. This module re-scores those candidates with cheap, explainable
features and then diversifies the final list so a learner sees three
*different* ideas instead of three spellings of one idea.

Everything here is pure Python — no model download, no network — so the
reranker works in exactly the same offline conditions as the rest of the
agent.

Signals used
------------
base            normalised first-stage score
technique       query terms matching the entry's technique tags
category        entry category agrees with the (predicted) category
difficulty      entry difficulty close to the learner's current level
vocab           query expanded through data/technique_vocab.json synonyms
prereq          entry teaches a prerequisite the learner has not mastered
novelty         penalty for entries the learner has already seen a lot

Then Maximal Marginal Relevance (MMR) trades relevance against redundancy.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

VOCAB_PATH = os.path.join("data", "technique_vocab.json")

DIFFICULTY_ORDER = ["easy", "medium", "hard", "insane"]

# Relative weight of each signal. Tuned to keep `base` dominant: reranking
# should reorder a good candidate list, not invent a new one.
DEFAULT_WEIGHTS: Dict[str, float] = {
    "base": 1.00,
    "technique": 0.65,
    "category": 0.40,
    "difficulty": 0.25,
    "vocab": 0.30,
    "prereq": 0.20,
    "novelty": 0.15,
}


def _tokens(text: str) -> Set[str]:
    return set(re.findall(r"[a-z0-9]{2,}", (text or "").lower()))


def _tech_tokens(techniques: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for t in techniques or []:
        out |= _tokens(str(t).replace("-", " "))
    return out


def _difficulty_index(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    try:
        return DIFFICULTY_ORDER.index(str(value).strip().lower())
    except ValueError:
        return None


@dataclass
class RerankFeatures:
    """Per-candidate feature breakdown, kept so scores stay explainable."""

    base: float = 0.0
    technique: float = 0.0
    category: float = 0.0
    difficulty: float = 0.0
    vocab: float = 0.0
    prereq: float = 0.0
    novelty: float = 0.0

    def as_dict(self) -> Dict[str, float]:
        return {k: round(v, 4) for k, v in self.__dict__.items()}

    def total(self, weights: Optional[Dict[str, float]] = None) -> float:
        w = weights or DEFAULT_WEIGHTS
        return sum(w.get(k, 0.0) * v for k, v in self.__dict__.items())


@dataclass
class RerankContext:
    """Everything the reranker knows about *this* learner and *this* query."""

    category: Optional[str] = None
    difficulty: Optional[str] = None
    mastered: Set[str] = field(default_factory=set)
    weak: Set[str] = field(default_factory=set)
    seen_counts: Dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_memory(
        cls,
        memory: Any = None,
        category: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> "RerankContext":
        """Build a context from a LearnerMemory (or nothing at all)."""
        if memory is None:
            return cls(category=category, difficulty=difficulty)
        try:
            mastered = set(memory.mastered_techniques())
            weak = set(memory.weak_techniques())
            seen = {name: st.attempts for name, st in memory.techniques.items()}
        except Exception:
            return cls(category=category, difficulty=difficulty)
        return cls(
            category=category,
            difficulty=difficulty,
            mastered=mastered,
            weak=weak,
            seen_counts=seen,
        )


def load_vocab_synonyms(path: str = VOCAB_PATH) -> Dict[str, Set[str]]:
    """
    Map every vocabulary word to the other words that share a technique tag.

    'union' and 'sqli' both live inside `sqli-union`, so a query mentioning
    "union select" can still pull up entries tagged only `sqli-union`.
    """
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}

    tags: List[str] = []
    if isinstance(data, dict):
        for group in data.values():
            if isinstance(group, (list, tuple)):
                tags.extend(str(t) for t in group)
    elif isinstance(data, list):
        tags.extend(str(t) for t in data)

    syn: Dict[str, Set[str]] = {}
    for tag in tags:
        parts = _tokens(tag.replace("-", " "))
        for part in parts:
            syn.setdefault(part, set()).update(parts - {part})
            syn[part].add(tag)
    return syn


def expand_query(query: str, synonyms: Optional[Dict[str, Set[str]]] = None) -> Set[str]:
    """Query tokens plus one hop of vocabulary synonyms."""
    syn = synonyms if synonyms is not None else load_vocab_synonyms()
    base = _tokens(query)
    expanded = set(base)
    for tok in base:
        expanded |= syn.get(tok, set())
    return expanded


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def score_candidate(
    candidate: Dict[str, Any],
    query: str,
    ctx: Optional[RerankContext] = None,
    max_base: float = 1.0,
    synonyms: Optional[Dict[str, Set[str]]] = None,
) -> RerankFeatures:
    """Compute the explainable feature vector for one retrieval candidate."""
    ctx = ctx or RerankContext()
    feats = RerankFeatures()

    raw_base = float(candidate.get("score") or 0.0)
    feats.base = raw_base / max_base if max_base > 0 else 0.0

    q_tokens = _tokens(query)
    techniques = candidate.get("techniques") or []
    tech_tokens = _tech_tokens(techniques)

    if q_tokens and tech_tokens:
        overlap = len(q_tokens & tech_tokens)
        feats.technique = min(1.0, overlap / max(1, min(len(tech_tokens), 4)))

    cand_cat = str(candidate.get("category") or "").lower()
    if ctx.category and cand_cat:
        feats.category = 1.0 if cand_cat == ctx.category.lower() else -0.5

    want = _difficulty_index(ctx.difficulty)
    got = _difficulty_index(candidate.get("difficulty"))
    if want is not None and got is not None:
        # 1.0 for an exact match, decaying by one step of distance.
        feats.difficulty = max(0.0, 1.0 - abs(want - got) / 3.0)

    expanded = expand_query(query, synonyms)
    blob = " ".join(
        [
            str(candidate.get("name") or ""),
            str(candidate.get("snippet") or ""),
            " ".join(str(t) for t in techniques),
        ]
    )
    cand_tokens = _tokens(blob) | {str(t).lower() for t in techniques}
    if expanded and cand_tokens:
        feats.vocab = min(1.0, len(expanded & cand_tokens) / 6.0)

    tech_set = {str(t).lower() for t in techniques}
    if tech_set & ctx.weak:
        feats.prereq += 0.7
    if ctx.mastered:
        try:
            from agent.skill_graph import prerequisites_for

            for t in tech_set:
                needed = set(prerequisites_for(t))
                if needed and not needed.issubset(ctx.mastered):
                    feats.prereq += 0.3
                    break
        except Exception:
            pass
    feats.prereq = min(1.0, feats.prereq)

    seen = sum(ctx.seen_counts.get(t, 0) for t in tech_set)
    feats.novelty = 1.0 / (1.0 + seen)

    return feats


def rerank(
    candidates: Sequence[Dict[str, Any]],
    query: str,
    ctx: Optional[RerankContext] = None,
    top_k: int = 5,
    weights: Optional[Dict[str, float]] = None,
    diversity: float = 0.3,
    explain: bool = False,
) -> List[Dict[str, Any]]:
    """
    Re-score and diversify first-stage retrieval results.

    `diversity` is the MMR lambda complement: 0.0 is pure relevance,
    1.0 is pure novelty. 0.3 keeps the top hit stable while still pushing
    near-duplicates down the list.
    """
    rows = [dict(c) for c in candidates if c]
    if not rows:
        return []

    ctx = ctx or RerankContext()
    weights = weights or DEFAULT_WEIGHTS
    synonyms = load_vocab_synonyms()
    max_base = max((float(r.get("score") or 0.0) for r in rows), default=1.0) or 1.0

    scored: List[Dict[str, Any]] = []
    for row in rows:
        feats = score_candidate(row, query, ctx, max_base=max_base, synonyms=synonyms)
        row["rerank_score"] = round(feats.total(weights), 4)
        row["first_stage_score"] = float(row.get("score") or 0.0)
        if explain:
            row["rerank_features"] = feats.as_dict()
        scored.append(row)

    scored.sort(key=lambda r: -r["rerank_score"])

    if diversity <= 0 or len(scored) <= 1:
        return scored[:top_k]

    # MMR selection: repeatedly take the candidate with the best blend of
    # score and dissimilarity from what has already been chosen.
    def sig(row: Dict[str, Any]) -> Set[str]:
        return _tech_tokens(row.get("techniques") or []) | _tokens(str(row.get("name") or ""))

    lam = 1.0 - max(0.0, min(1.0, diversity))
    pool = list(scored)
    chosen: List[Dict[str, Any]] = [pool.pop(0)]
    while pool and len(chosen) < top_k:
        best_idx, best_val = 0, float("-inf")
        for i, row in enumerate(pool):
            redundancy = max((_jaccard(sig(row), sig(c)) for c in chosen), default=0.0)
            val = lam * row["rerank_score"] - (1 - lam) * redundancy
            if val > best_val:
                best_idx, best_val = i, val
        chosen.append(pool.pop(best_idx))

    return chosen[:top_k]


def explain_ranking(results: Sequence[Dict[str, Any]]) -> str:
    """Human-readable breakdown, for `--explain` output and debugging."""
    if not results:
        return "No results to explain."
    lines = ["Rerank breakdown:"]
    for i, r in enumerate(results, 1):
        lines.append(
            f"{i}. {r.get('name', '?')} "
            f"[{r.get('category', '?')}] "
            f"score={r.get('rerank_score', 0):.3f} "
            f"(first stage {r.get('first_stage_score', 0):.3f})"
        )
        feats = r.get("rerank_features")
        if feats:
            parts = [f"{k}={v:+.2f}" for k, v in feats.items() if abs(v) > 0.001]
            if parts:
                lines.append("     " + "  ".join(parts))
    return "\n".join(lines)
