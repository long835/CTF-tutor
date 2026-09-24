"""
agent/embeddings.py — embedding backend separation (item 31).

Retrievers and vector stores should not import Ollama or chromadb directly.
This module owns the embedding function contract and backend selection.

Backends:
  - ollama   (default): llm_client.call_ollama_embed
  - hash     (offline fallback): deterministic bag-of-char n-grams, no model
  - none     : raises if embeddings are requested
"""

from __future__ import annotations

import hashlib
import math
import os
from typing import List, Optional, Protocol, Sequence


class EmbeddingBackend(Protocol):
    name: str

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        ...


class OllamaEmbeddingBackend:
    name = "ollama"

    def __init__(self, model: Optional[str] = None) -> None:
        self.model = model or os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        from llm_client import call_ollama_embed
        return call_ollama_embed(list(texts), model=self.model)


class HashEmbeddingBackend:
    """Deterministic offline embedding for tests and chromadb-less installs."""

    name = "hash"

    def __init__(self, dims: int = 256) -> None:
        self.dims = dims

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        out: List[List[float]] = []
        for text in texts:
            vec = [0.0] * self.dims
            tokens = (text or "").lower().split()
            if not tokens:
                tokens = ["_empty_"]
            for tok in tokens:
                h = int(hashlib.sha256(tok.encode("utf-8")).hexdigest(), 16)
                idx = h % self.dims
                sign = 1.0 if (h >> 8) & 1 else -1.0
                vec[idx] += sign
            # L2 normalise
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            out.append([v / norm for v in vec])
        return out


class NoneEmbeddingBackend:
    name = "none"

    def embed(self, texts: Sequence[str]) -> List[List[float]]:
        raise RuntimeError(
            "embeddings backend is 'none' — set CTF_TUTOR_EMBED_BACKEND=ollama|hash"
        )


def get_embedding_backend(name: Optional[str] = None) -> EmbeddingBackend:
    choice = (name or os.getenv("CTF_TUTOR_EMBED_BACKEND") or "ollama").strip().lower()
    if choice == "ollama":
        return OllamaEmbeddingBackend()
    if choice == "hash":
        return HashEmbeddingBackend()
    if choice == "none":
        return NoneEmbeddingBackend()
    # unknown → hash offline rather than crash
    return HashEmbeddingBackend()


def embed_texts(texts: Sequence[str], backend: Optional[str] = None) -> List[List[float]]:
    return get_embedding_backend(backend).embed(texts)


def embedding_backend_info() -> dict:
    b = get_embedding_backend()
    return {
        "backend": b.name,
        "env": os.getenv("CTF_TUTOR_EMBED_BACKEND", "ollama"),
        "embed_model": os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"),
    }


# chromadb-compatible wrapper used by retriever.py
class ChromaCompatibleEmbeddingFunction:
    def __init__(self, backend: Optional[EmbeddingBackend] = None) -> None:
        self.backend = backend or get_embedding_backend()

    def __call__(self, input: List[str]) -> List[List[float]]:  # noqa: A002
        return self.backend.embed(input)

    def name(self) -> str:  # chromadb API
        return f"ctf-tutor-{self.backend.name}"
