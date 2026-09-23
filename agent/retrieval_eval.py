"""
agent/retrieval_eval.py

Judging retrieval on its own, and keeping the answers out of the test set
(items 18, 19).

Retrieval currently gets evaluated implicitly: a challenge is solved or it
is not, and whether the retriever helped is a matter of opinion. That hides
both failure modes. A retriever returning nothing looks the same as one
returning five irrelevant cards, and a retriever returning the exact
writeup for the evaluation challenge looks like brilliant performance.

So two things live here.

**Metrics (item 18).** Recall@K, Precision@K, MRR and nDCG@K, plus the one
that actually matters for an agent: `helpfulness`, which asks whether the
retrieved material mentioned the technique the challenge needed. A card can
be topically relevant and still useless.

**Contamination control (item 19).** `leakage` measures n-gram overlap
between an evaluation case and a corpus document, which catches the case
where the corpus contains the solution in almost the same words.
`split_by_family` groups challenges by technique family before splitting, so
"train on JWT alg=none, test on JWT alg=none with a different port number"
cannot be reported as generalisation.

nDCG uses binary relevance here, because that is the ground truth the
project has. Graded relevance would be better and is not worth faking.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


# ------------------------------------------------------------------ metrics


def recall_at_k(retrieved: Sequence[str], relevant: Iterable[str], k: int = 5) -> float:
    """Share of relevant documents that appear in the top K."""
    gold = {str(x) for x in relevant}
    if not gold:
        return 1.0
    top = {str(x) for x in list(retrieved)[:k]}
    return len(top & gold) / len(gold)


def precision_at_k(retrieved: Sequence[str], relevant: Iterable[str], k: int = 5) -> float:
    """Share of the top K that is relevant."""
    gold = {str(x) for x in relevant}
    top = [str(x) for x in list(retrieved)[:k]]
    if not top:
        return 0.0
    return len([x for x in top if x in gold]) / len(top)


def reciprocal_rank(retrieved: Sequence[str], relevant: Iterable[str]) -> float:
    """
    1/rank of the first relevant hit.

    The metric that matters most for a small model: it reads the first
    result or two carefully and skims the rest, so a relevant card at
    position 7 may as well not be there.
    """
    gold = {str(x) for x in relevant}
    for index, doc in enumerate(retrieved, start=1):
        if str(doc) in gold:
            return 1.0 / index
    return 0.0


def dcg_at_k(retrieved: Sequence[str], relevant: Iterable[str], k: int = 5) -> float:
    gold = {str(x) for x in relevant}
    total = 0.0
    for index, doc in enumerate(list(retrieved)[:k], start=1):
        if str(doc) in gold:
            total += 1.0 / math.log2(index + 1)
    return total


def ndcg_at_k(retrieved: Sequence[str], relevant: Iterable[str], k: int = 5) -> float:
    """DCG against the best achievable ordering. Binary relevance."""
    gold = {str(x) for x in relevant}
    if not gold:
        return 1.0
    ideal = sum(1.0 / math.log2(i + 1) for i in range(1, min(k, len(gold)) + 1))
    if ideal <= 0:
        return 0.0
    return dcg_at_k(retrieved, gold, k) / ideal


# ------------------------------------------------------------------- cases


@dataclass
class RetrievalCase:
    """One query with its known-relevant documents."""

    query: str
    relevant_ids: List[str] = field(default_factory=list)
    id: str = ""
    category: str = ""
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "query": self.query,
            "relevant_ids": list(self.relevant_ids),
            "category": self.category,
            "techniques": list(self.techniques),
        }


@dataclass
class RetrievalReport:
    """Aggregate retrieval quality over a case set."""

    k: int = 5
    cases: int = 0
    recall: float = 0.0
    precision: float = 0.0
    mrr: float = 0.0
    ndcg: float = 0.0
    helpfulness: float = 0.0
    empty_results: int = 0
    per_case: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "k": self.k,
            "cases": self.cases,
            f"recall@{self.k}": round(self.recall, 3),
            f"precision@{self.k}": round(self.precision, 3),
            "mrr": round(self.mrr, 3),
            f"ndcg@{self.k}": round(self.ndcg, 3),
            "helpfulness": round(self.helpfulness, 3),
            "empty_results": self.empty_results,
        }

    def render(self) -> str:
        return (
            f"Retrieval over {self.cases} case(s), K={self.k}:\n"
            f"  recall@{self.k}    {self.recall:.3f}\n"
            f"  precision@{self.k} {self.precision:.3f}\n"
            f"  MRR           {self.mrr:.3f}\n"
            f"  nDCG@{self.k}      {self.ndcg:.3f}\n"
            f"  helpfulness   {self.helpfulness:.3f}  "
            f"(retrieved text mentioned the needed technique)\n"
            f"  empty         {self.empty_results}"
        )


def evaluate_retrieval(
    cases: Sequence[RetrievalCase],
    search: Callable[[str, int], Sequence[Any]],
    k: int = 5,
    id_of: Optional[Callable[[Any], str]] = None,
    text_of: Optional[Callable[[Any], str]] = None,
) -> RetrievalReport:
    """
    Score a retrieval function over labelled cases.

    `search` is injected rather than imported so the same harness works for
    the vector store, the lexical index, the hybrid, and a reranked variant
    — which is the comparison worth making.
    """
    id_of = id_of or _default_id_of
    text_of = text_of or _default_text_of

    report = RetrievalReport(k=k, cases=len(cases))
    if not cases:
        return report

    recalls: List[float] = []
    precisions: List[float] = []
    rrs: List[float] = []
    ndcgs: List[float] = []
    helps: List[float] = []

    for case in cases:
        try:
            results = list(search(case.query, k) or [])
        except Exception as exc:
            # A retriever that raised is a failure, not a zero-relevance
            # result — recorded distinctly so an outage cannot be read as
            # poor ranking.
            report.per_case.append({"id": case.id, "error": str(exc)[:200]})
            recalls.append(0.0), precisions.append(0.0), rrs.append(0.0), ndcgs.append(0.0)
            helps.append(0.0)
            continue

        if not results:
            report.empty_results += 1
        ids = [id_of(r) for r in results]
        blob = " ".join(text_of(r) for r in results).lower()

        recall = recall_at_k(ids, case.relevant_ids, k)
        precision = precision_at_k(ids, case.relevant_ids, k)
        rr = reciprocal_rank(ids, case.relevant_ids)
        ndcg = ndcg_at_k(ids, case.relevant_ids, k)
        if case.techniques:
            hits = [t for t in case.techniques if t.lower().replace("-", " ") in
                    blob.replace("-", " ")]
            helpful = len(hits) / len(case.techniques)
        else:
            helpful = 1.0 if recall > 0 else 0.0

        recalls.append(recall), precisions.append(precision)
        rrs.append(rr), ndcgs.append(ndcg), helps.append(helpful)
        report.per_case.append({
            "id": case.id, "recall": round(recall, 3), "precision": round(precision, 3),
            "rr": round(rr, 3), "ndcg": round(ndcg, 3), "helpfulness": round(helpful, 3),
            "returned": len(ids),
        })

    report.recall = sum(recalls) / len(recalls)
    report.precision = sum(precisions) / len(precisions)
    report.mrr = sum(rrs) / len(rrs)
    report.ndcg = sum(ndcgs) / len(ndcgs)
    report.helpfulness = sum(helps) / len(helps)
    return report


def _default_id_of(result: Any) -> str:
    for attr in ("id", "entry_id", "doc_id"):
        value = getattr(result, attr, None)
        if value:
            return str(value)
    if isinstance(result, dict):
        for key in ("id", "entry_id", "doc_id", "name"):
            if result.get(key):
                return str(result[key])
    entry = getattr(result, "entry", None)
    if entry is not None:
        for attr in ("id", "name", "title"):
            value = getattr(entry, attr, None)
            if value:
                return str(value)
    return str(result)[:60]


def _default_text_of(result: Any) -> str:
    if isinstance(result, dict):
        return " ".join(str(v) for v in result.values())[:2000]
    parts = []
    for attr in ("title", "name", "description", "summary", "techniques", "text", "content"):
        value = getattr(result, attr, None)
        if value:
            parts.append(str(value))
    entry = getattr(result, "entry", None)
    if entry is not None:
        for attr in ("title", "name", "description", "techniques"):
            value = getattr(entry, attr, None)
            if value:
                parts.append(str(value))
    return (" ".join(parts) or str(result))[:2000]


# ------------------------------------------------------- contamination (19)

_WORD = re.compile(r"[a-z0-9]+")


def _shingles(text: str, n: int = 5) -> Set[str]:
    words = _WORD.findall((text or "").lower())
    if len(words) < n:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}


def leakage(case_text: str, document_text: str, n: int = 5) -> float:
    """
    How much of a case's wording already exists in a document.

    Shingle overlap rather than embedding similarity on purpose: the failure
    being detected is verbatim reuse of a writeup, and near-duplicate
    phrasing is exactly what shingles catch and embeddings blur.
    """
    case = _shingles(case_text, n)
    if not case:
        return 0.0
    doc = _shingles(document_text, n)
    if not doc:
        return 0.0
    return len(case & doc) / len(case)


@dataclass
class ContaminationReport:
    """Evaluation cases whose answers are already in the corpus."""

    threshold: float = 0.25
    checked: int = 0
    contaminated: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.contaminated

    @property
    def rate(self) -> float:
        return (len(self.contaminated) / self.checked) if self.checked else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threshold": self.threshold,
            "checked": self.checked,
            "contaminated": len(self.contaminated),
            "rate": round(self.rate, 3),
            "cases": self.contaminated[:20],
        }

    def render(self) -> str:
        if self.clean:
            return f"No contamination above {self.threshold:.0%} over {self.checked} case(s)."
        lines = [f"Contamination: {len(self.contaminated)}/{self.checked} "
                 f"case(s) overlap the corpus above {self.threshold:.0%}"]
        for item in self.contaminated[:10]:
            lines.append(f"  {item['case']} ← {item['document']} ({item['leakage']:.0%})")
        return "\n".join(lines)


def check_contamination(
    cases: Sequence[Dict[str, Any]],
    documents: Sequence[Dict[str, Any]],
    threshold: float = 0.25,
    text_key: str = "description",
) -> ContaminationReport:
    """Flag evaluation cases that overlap corpus documents too closely."""
    report = ContaminationReport(threshold=threshold, checked=len(cases))
    for case in cases:
        case_text = str(case.get(text_key) or case.get("query") or "")
        worst: Tuple[float, str] = (0.0, "")
        for doc in documents:
            doc_text = " ".join(str(v) for v in doc.values() if isinstance(v, (str, list)))
            score = leakage(case_text, doc_text)
            if score > worst[0]:
                worst = (score, str(doc.get("id") or doc.get("name") or "?"))
        if worst[0] >= threshold:
            report.contaminated.append({
                "case": str(case.get("id") or case_text[:40]),
                "document": worst[1],
                "leakage": round(worst[0], 3),
            })
    return report


# Families group variants of the same underlying task. Splitting on these
# rather than on individual ids is what stops "same bug, different port"
# from being counted as generalisation.
_FAMILY_RULES: List[Tuple[str, Tuple[str, ...]]] = [
    ("jwt", ("jwt", "json web token", "alg=none", "alg confusion")),
    ("sqli", ("sql injection", "sqli", "union select")),
    ("ssti", ("ssti", "template injection", "jinja")),
    ("path-traversal", ("path traversal", "directory traversal", "lfi")),
    ("stack-overflow", ("buffer overflow", "stack overflow", "gets(", "ret2win")),
    ("rop", ("rop", "ret2libc", "ret2csu", "gadget")),
    ("format-string", ("format string", "%n", "printf")),
    ("heap", ("heap", "tcache", "fastbin", "unsorted bin")),
    ("xor", ("xor",)),
    ("rsa", ("rsa", "modulus", "wiener", "franklin")),
    ("block-cipher", ("aes", "ecb", "cbc", "padding oracle", "ctr")),
    ("hash", ("md5", "sha1", "length extension", "collision")),
    ("stego", ("steg", "lsb", "hidden in image")),
    ("pcap", ("pcap", "wireshark", "network capture")),
    ("metadata", ("exif", "metadata")),
    ("packing", ("upx", "packed", "unpack")),
    ("osint", ("osint", "geolocat", "whois", "shodan")),
]


def family_of(case: Dict[str, Any]) -> str:
    """
    Which family a case belongs to.

    Technique labels are consulted before free text, since a label is a
    deliberate statement and a description is whatever someone typed.
    """
    techniques = " ".join(str(t) for t in (case.get("expected_techniques") or
                                           case.get("techniques") or [])).lower()
    for family, markers in _FAMILY_RULES:
        if any(marker in techniques for marker in markers) or family in techniques:
            return family
    text = f"{case.get('description', '')} {case.get('query', '')}".lower()
    for family, markers in _FAMILY_RULES:
        if any(marker in text for marker in markers):
            return family
    return str(case.get("expected_category") or case.get("category") or "unknown")


def split_by_family(
    cases: Sequence[Dict[str, Any]],
    holdout: float = 0.3,
    seed: int = 0,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Split so that no family appears on both sides.

    Deterministic given the seed, because a split that changes between runs
    makes two evaluation numbers incomparable — and comparing them anyway is
    the most common way to believe in an improvement that did not happen.
    """
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for case in cases:
        grouped.setdefault(family_of(case), []).append(case)

    families = sorted(grouped)
    if not families:
        return [], []
    # Rotate by seed rather than shuffling, so the split is stable and
    # inspectable instead of depending on a PRNG implementation.
    offset = seed % len(families)
    families = families[offset:] + families[:offset]
    target = max(1, int(round(len(cases) * holdout)))

    test: List[Dict[str, Any]] = []
    test_families: Set[str] = set()
    for family in families:
        if len(test) >= target:
            break
        test.extend(grouped[family])
        test_families.add(family)
    train = [c for f in families if f not in test_families for c in grouped[f]]
    return train, test


def family_overlap(train: Sequence[Dict[str, Any]], test: Sequence[Dict[str, Any]]) -> Set[str]:
    """Families present on both sides of a split. Should always be empty."""
    return {family_of(c) for c in train} & {family_of(c) for c in test}
