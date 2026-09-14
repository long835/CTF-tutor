"""
tests/fakes.py

Shared test doubles so the rest of the suite can exercise retriever.py,
synthesizer.py, explainer.py, depth_guide.py, main.py, and ingest.py
WITHOUT a real Ollama server or a real ChromaDB collection -- this sandbox
can't reach the project's own Docker/Ollama setup, so every test that
would otherwise need it fakes it out instead.
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from typing import List, Optional


class FakeCollection:
    """In-memory stand-in for the small subset of chromadb's Collection API
    retriever.py actually uses (upsert / query / count / delete_all).

    "Similarity" is faked as word-overlap between the query text and each
    stored document -- good enough to exercise ranking/filtering/formatting
    logic without a real embedding model or chromadb installed.
    """

    def __init__(self):
        self._ids: List[str] = []
        self._documents: List[str] = []
        self._metadatas: List[dict] = []

    def upsert(self, ids, documents, metadatas):
        for doc_id, document, metadata in zip(ids, documents, metadatas):
            if doc_id in self._ids:
                idx = self._ids.index(doc_id)
                self._documents[idx] = document
                self._metadatas[idx] = metadata
            else:
                self._ids.append(doc_id)
                self._documents.append(document)
                self._metadatas.append(metadata)

    def count(self) -> int:
        return len(self._ids)

    def delete_all(self) -> None:
        self._ids, self._documents, self._metadatas = [], [], []

    def query(self, query_texts, n_results, where=None):
        query = query_texts[0].lower()
        query_words = set(query.split())

        scored = []
        for doc_id, document, metadata in zip(self._ids, self._documents, self._metadatas):
            if where and any(metadata.get(k) != v for k, v in where.items()):
                continue
            overlap = len(query_words & set(document.lower().split()))
            distance = 1.0 / (overlap + 1)  # more overlap -> smaller distance
            scored.append((distance, doc_id, document, metadata))

        scored.sort(key=lambda row: row[0])
        top = scored[:n_results]
        return {
            "ids": [[row[1] for row in top]],
            "distances": [[row[0] for row in top]],
            "documents": [[row[2] for row in top]],
            "metadatas": [[row[3] for row in top]],
        }


def fake_chat_response(content: str) -> dict:
    """Shape of a real Ollama /api/chat non-streaming response body."""
    return {"message": {"role": "assistant", "content": content}}


def fake_embed_response(vectors: List[List[float]]) -> dict:
    """Shape of a real Ollama /api/embed response body."""
    return {"embeddings": vectors}


class _FakeHTTPResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"fake HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeOllamaHTTP:
    """
    Drop-in side_effect for `requests.post` that fakes BOTH Ollama endpoints
    llm_client.py talks to (/api/chat and /api/embed), so tests exercise the
    real llm_client parsing/error-handling code instead of stubbing it out.
    """

    def __init__(self, chat_reply: Optional[str] = None, embed_dim: int = 8):
        self.chat_reply = chat_reply
        self.embed_dim = embed_dim
        self.calls: List[dict] = []

    def __call__(self, url, json=None, timeout=None):
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if url.endswith("/api/chat"):
            return _FakeHTTPResponse(fake_chat_response(self.chat_reply or "{}"))
        if url.endswith("/api/embed"):
            n = len(json["input"]) if isinstance(json.get("input"), list) else 1
            vectors = [[float(i)] * self.embed_dim for i in range(n)]
            return _FakeHTTPResponse(fake_embed_response(vectors))
        raise AssertionError(f"FakeOllamaHTTP got an unexpected URL: {url}")