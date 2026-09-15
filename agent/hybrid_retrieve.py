"""
agent/hybrid_retrieve.py

Lexical (BM25-style) + optional vector retrieval over the local archive.

When chromadb / embeddings are unavailable the agent still gets useful
matches from a pure Python TF-IDF/BM25-ish scorer over archive JSON.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ARCHIVE_DIR = os.path.join("data", "archive")


def _tokenize(text: str) -> List[str]:
    text = (text or "").lower()
    return re.findall(r"[a-z0-9]{2,}", text)


@dataclass
class LexMatch:
    name: str
    category: str
    techniques: List[str]
    score: float
    path: str
    snippet: str = ""


class LexicalArchiveIndex:
    """In-memory index over data/archive/*.json — no external deps."""

    def __init__(self, archive_dir: str = ARCHIVE_DIR):
        self.archive_dir = archive_dir
        self.docs: List[Dict[str, Any]] = []
        self._df: Counter = Counter()
        self._load()

    def _load(self) -> None:
        root = Path(self.archive_dir)
        if not root.is_dir():
            return
        for fp in sorted(root.glob("*.json")):
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                continue
            text_parts = [
                str(data.get("challenge_name") or data.get("name") or ""),
                str(data.get("category") or ""),
                str(data.get("description") or data.get("summary") or ""),
                " ".join(data.get("techniques") or data.get("tags") or []),
                str(data.get("approach") or ""),
                str(data.get("walkthrough") or "")[:500],
            ]
            blob = " ".join(text_parts)
            tokens = _tokenize(blob)
            entry = {
                "path": str(fp),
                "name": data.get("challenge_name") or data.get("name") or fp.stem,
                "category": data.get("category") or "",
                "techniques": data.get("techniques") or data.get("tags") or [],
                "tokens": tokens,
                "tf": Counter(tokens),
                "snippet": (data.get("description") or data.get("summary") or "")[:200],
                "raw": data,
            }
            self.docs.append(entry)
            for t in set(tokens):
                self._df[t] += 1
        self.n_docs = max(1, len(self.docs))

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 5,
    ) -> List[LexMatch]:
        q_tokens = _tokenize(query)
        if not q_tokens or not self.docs:
            return []

        q_tf = Counter(q_tokens)
        scores: List[Tuple[float, Dict[str, Any]]] = []
        for doc in self.docs:
            if category and doc["category"] and doc["category"].lower() != category.lower():
                # soft filter — still allow but penalize
                cat_penalty = 0.35
            else:
                cat_penalty = 1.0

            score = 0.0
            doc_len = max(1, len(doc["tokens"]))
            avgdl = 50.0  # rough prior
            k1, b = 1.5, 0.75
            for term, qf in q_tf.items():
                tf = doc["tf"].get(term, 0)
                if tf == 0:
                    continue
                df = self._df.get(term, 0)
                idf = math.log(1 + (self.n_docs - df + 0.5) / (df + 0.5))
                denom = tf + k1 * (1 - b + b * doc_len / avgdl)
                score += idf * (tf * (k1 + 1) / denom) * qf
            score *= cat_penalty
            if score > 0:
                scores.append((score, doc))

        scores.sort(key=lambda x: -x[0])
        out: List[LexMatch] = []
        for sc, doc in scores[:top_k]:
            out.append(LexMatch(
                name=doc["name"],
                category=doc["category"],
                techniques=list(doc["techniques"]),
                score=round(sc, 4),
                path=doc["path"],
                snippet=doc["snippet"],
            ))
        return out


_INDEX: Optional[LexicalArchiveIndex] = None


def get_lexical_index(archive_dir: str = ARCHIVE_DIR, force_reload: bool = False) -> LexicalArchiveIndex:
    global _INDEX
    if force_reload or _INDEX is None or _INDEX.archive_dir != archive_dir:
        _INDEX = LexicalArchiveIndex(archive_dir)
    return _INDEX


def hybrid_search(
    query: str,
    category: Optional[str] = None,
    top_k: int = 5,
) -> List[Dict[str, Any]]:
    """
    Prefer chromadb retriever when available; always fall back to lexical.
    Returns list of dicts: name, category, techniques, score, source.
    """
    results: List[Dict[str, Any]] = []

    # Try vector retriever
    try:
        from retriever import Retriever
        r = Retriever()
        matches = r.search(query, category=category, n_results=top_k)
        for m in matches or []:
            entry = getattr(m, "entry", m)
            results.append({
                "name": getattr(entry, "challenge_name", None) or getattr(entry, "name", ""),
                "category": getattr(entry, "category", ""),
                "techniques": getattr(entry, "techniques", []) or getattr(entry, "tags", []),
                "score": float(getattr(m, "score", 0) or 0),
                "source": "vector",
            })
    except Exception:
        pass

    # Lexical always runs; merge by name
    lex = get_lexical_index().search(query, category=category, top_k=top_k)
    seen = {r["name"] for r in results}
    for m in lex:
        if m.name in seen:
            # boost existing
            for r in results:
                if r["name"] == m.name:
                    r["score"] = r["score"] + 0.15 * m.score
                    r["source"] = r["source"] + "+lexical"
        else:
            results.append({
                "name": m.name,
                "category": m.category,
                "techniques": m.techniques,
                "score": m.score,
                "source": "lexical",
                "snippet": m.snippet,
            })

    results.sort(key=lambda x: -x["score"])
    return results[:top_k]
