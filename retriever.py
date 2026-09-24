"""
retriever.py

ChromaDB-backed semantic search over your archive of past solved challenges
(data/archive/*.json). Embeds each entry's `to_embedding_text()` output with
a local Ollama embedding model (default: nomic-embed-text -- run
`ollama pull nomic-embed-text` once) so lookups happen entirely offline,
same as decomposer.py.

Design notes:
- The chromadb dependency is imported lazily, only when actually building
  the default collection. This keeps the module importable (and testable
  via `Retriever(collection=some_fake)`) even in an environment where
  chromadb isn't installed -- e.g. this sandbox.
- chromadb metadata values must be flat str/int/float/bool. Rather than
  hand-picking a per-field encoding (which gets fiddly for Optional[str]
  fields where None and "" need to stay distinguishable), every
  ArchiveEntry field is JSON-encoded into its own metadata string. That
  guarantees a lossless round trip through `_entry_to_metadata` /
  `_entry_from_metadata` for any value the schema can hold, at the cost of
  the raw metadata blob not being human-readable if you ever inspect the
  chroma store directly.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from schema import ArchiveEntry
from llm_client import call_ollama_embed, DEFAULT_EMBED_MODEL
try:
    from agent.embeddings import ChromaCompatibleEmbeddingFunction, get_embedding_backend
    _HAS_EMBED_SEP = True
except Exception:
    _HAS_EMBED_SEP = False


COLLECTION_NAME = "ctf_archive"
DEFAULT_PERSIST_DIR = "data/chroma"


@dataclass
class RetrievedMatch:
    """One archive entry retrieved for a query, with its similarity score."""
    entry: ArchiveEntry
    score: float       # higher = more similar, always > 0
    distance: float     # raw distance from the vector store (lower = closer)
    matched_on: str      # the query text that produced this match


class OllamaEmbeddingFunction:
    """
    Minimal chromadb-compatible embedding function backed by a local Ollama
    embedding model. Batches every document in a single call through
    call_ollama_embed rather than one HTTP round-trip per document.
    """

    def __init__(self, model: str = DEFAULT_EMBED_MODEL):
        self.model = model

    def __call__(self, input: List[str]) -> List[List[float]]:
        return call_ollama_embed(list(input), model=self.model)

    def name(self) -> str:
        return f"ollama-{self.model}"


def _entry_to_metadata(entry: ArchiveEntry) -> dict:
    """Flatten an ArchiveEntry into an all-string metadata dict (see module docstring)."""
    return {field: json.dumps(value) for field, value in entry.to_dict().items()}


def _entry_from_metadata(metadata: dict) -> ArchiveEntry:
    """Inverse of _entry_to_metadata."""
    data = {field: json.loads(value) for field, value in metadata.items()}
    return ArchiveEntry.from_dict(data)


def _default_id(entry: ArchiveEntry) -> str:
    """Deterministic doc id from an entry's category + slugified name, so
    re-indexing the same entry (e.g. re-running ingest.py) upserts in place
    instead of creating a duplicate."""
    slug = re.sub(r"[^a-z0-9]+", "-", entry.challenge_name.lower()).strip("-")
    return f"{entry.category}-{slug}"


def _sub_problem_query_text(sub_problem) -> str:
    """Build the text used to query the archive for a given SubProblem --
    its description plus any guessed techniques and evidence, so retrieval
    isn't relying on the description alone."""
    parts = [sub_problem.description]
    techniques = getattr(sub_problem, "likely_techniques", None)
    if techniques:
        parts.append("Likely techniques: " + ", ".join(techniques))
    evidence = getattr(sub_problem, "evidence", "")
    if evidence:
        parts.append(f"Evidence: {evidence}")
    return "\n".join(parts)


class Retriever:
    """
    Wraps a chromadb Collection (or any object satisfying the same tiny
    upsert/query/count/delete_all interface -- see tests/fakes.py) with
    ArchiveEntry-aware indexing and querying.
    """

    def __init__(
        self,
        collection=None,
        persist_dir: Optional[str] = None,
        embedding_model: str = DEFAULT_EMBED_MODEL,
    ):
        self.collection = collection or self._build_default_collection(
            persist_dir, embedding_model
        )

    @staticmethod
    def _build_default_collection(persist_dir: Optional[str], embedding_model: str):
        try:
            import chromadb
        except ImportError:
            raise RuntimeError(
                "chromadb isn't installed. Run:\n    pip install chromadb\n"
                "or construct Retriever(collection=...) with your own "
                "chromadb (or chromadb-compatible) collection directly."
            )
        client = chromadb.PersistentClient(path=persist_dir or DEFAULT_PERSIST_DIR)
        return client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=(
                ChromaCompatibleEmbeddingFunction(get_embedding_backend())
                if _HAS_EMBED_SEP else OllamaEmbeddingFunction(model=embedding_model)
            ),
        )

    def index_entry(self, entry: ArchiveEntry, doc_id: Optional[str] = None) -> str:
        """Embed and (up)store one archive entry. Returns the doc id used,
        so callers can pin/reuse it if they want (e.g. to force an update)."""
        doc_id = doc_id or _default_id(entry)
        self.collection.upsert(
            ids=[doc_id],
            documents=[entry.to_embedding_text()],
            metadatas=[_entry_to_metadata(entry)],
        )
        return doc_id

    def index_directory(self, dir_path: str) -> int:
        """Index every *.json ArchiveEntry file in a directory (non-recursive).
        Files that fail to parse are skipped with a printed warning rather
        than aborting the whole batch. Returns the count successfully
        indexed."""
        if not os.path.isdir(dir_path):
            return 0
        indexed = 0
        for filename in sorted(os.listdir(dir_path)):
            if not filename.lower().endswith(".json"):
                continue
            path = os.path.join(dir_path, filename)
            try:
                entry = ArchiveEntry.load(path)
            except Exception as e:
                print(f"  skipped {filename}: {e}")
                continue
            self.index_entry(entry)
            indexed += 1
        return indexed

    def count(self) -> int:
        return self.collection.count()

    def reset(self) -> None:
        self.collection.delete_all()

    def query(
        self, query_text: str, n_results: int = 5, category: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> List[RetrievedMatch]:
        where = {}
        if category:
            where["category"] = json.dumps(category)
        if difficulty:
            where["difficulty"] = json.dumps(difficulty)
        if not where:
            where = None
        raw = self.collection.query(
            query_texts=[query_text], n_results=n_results, where=where
        )
        ids = raw.get("ids", [[]])[0]
        distances = raw.get("distances", [[]])[0]
        metadatas = raw.get("metadatas", [[]])[0]

        matches = []
        for _doc_id, distance, metadata in zip(ids, distances, metadatas):
            entry = _entry_from_metadata(metadata)
            score = 1.0 / (1.0 + max(distance, 0.0))  # always > 0, decreasing in distance
            matches.append(
                RetrievedMatch(
                    entry=entry, score=score, distance=distance, matched_on=query_text
                )
            )
        return matches

    def query_sub_problem(
        self, sub_problem, n_results: int = 3, category: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> List[RetrievedMatch]:
        query_text = _sub_problem_query_text(sub_problem)
        return self.query(
            query_text, n_results=n_results, category=category, difficulty=difficulty
        )

    def suggest_tools(self, sub_problem, n_results: int = 3, category: Optional[str] = None,
                      difficulty: Optional[str] = None) -> List[dict]:
        """Recommend tools from the closest archived examples without executing them.

        Returns compact dictionaries with a tool name, source challenge, and a
        human-readable reason so callers can present suggestions without turning
        retrieval into automatic tool execution.
        """
        matches = self.query_sub_problem(
            sub_problem, n_results=n_results, category=category, difficulty=difficulty
        )
        suggestions = []
        seen = set()
        for match in matches:
            for tool in match.entry.tools_used:
                tool = str(tool).strip()
                key = tool.lower()
                if not tool or key in seen:
                    continue
                seen.add(key)
                suggestions.append({
                    "tool": tool,
                    "source_challenge": match.entry.challenge_name,
                    "score": match.score,
                    "reason": f"resembles {match.entry.challenge_name}, where {tool} was used",
                })
                if len(suggestions) >= n_results:
                    return suggestions
        return suggestions


if __name__ == "__main__":
    import sys

    archive_dir = sys.argv[1] if len(sys.argv) > 1 else "data/archive"
    retriever = Retriever()
    count = retriever.index_directory(archive_dir)
    print(f"indexed {count} entries from {archive_dir} ({retriever.count()} total in store)")
