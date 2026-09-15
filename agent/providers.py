"""
agent/providers.py

Thin LLM provider abstraction.

Default: Ollama (local). Optional stubs for other OpenAI-compatible
local servers (llama.cpp server, vLLM, LM Studio) via base URL only.
No paid API keys required for core operation.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from typing import List, Optional


class LLMProvider(ABC):
    @abstractmethod
    def chat(self, system: str, user: str, model: Optional[str] = None) -> str:
        ...

    @abstractmethod
    def embed(self, texts: List[str], model: Optional[str] = None) -> List[List[float]]:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


class OllamaProvider(LLMProvider):
    def chat(self, system: str, user: str, model: Optional[str] = None) -> str:
        from llm_client import call_ollama, DEFAULT_MODEL
        return call_ollama(system, user, model=model or DEFAULT_MODEL)

    def embed(self, texts: List[str], model: Optional[str] = None) -> List[List[float]]:
        from llm_client import call_ollama_embed, DEFAULT_EMBED_MODEL
        return call_ollama_embed(list(texts), model=model or DEFAULT_EMBED_MODEL)

    @property
    def name(self) -> str:
        return "ollama"


class OpenAICompatibleProvider(LLMProvider):
    """
    For local OpenAI-compatible endpoints (llama.cpp server, vLLM, LM Studio).
    Configure via:
      LLM_PROVIDER=openai_compatible
      LLM_BASE_URL=http://localhost:8080/v1
      LLM_MODEL=...
    """

    def __init__(self) -> None:
        self.base = os.getenv("LLM_BASE_URL", "http://localhost:8080/v1").rstrip("/")
        self.model = os.getenv("LLM_MODEL", "local-model")
        self.api_key = os.getenv("LLM_API_KEY", "local")  # often unused locally

    def chat(self, system: str, user: str, model: Optional[str] = None) -> str:
        import requests
        url = f"{self.base}/chat/completions"
        payload = {
            "model": model or self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        resp = requests.post(url, json=payload, headers=headers, timeout=180)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    def embed(self, texts: List[str], model: Optional[str] = None) -> List[List[float]]:
        # Many local servers lack embeddings — return empty to force lexical fallback
        return [[] for _ in texts]

    @property
    def name(self) -> str:
        return "openai_compatible"


def get_provider() -> LLMProvider:
    kind = os.getenv("LLM_PROVIDER", "ollama").lower().strip()
    if kind in ("openai", "openai_compatible", "vllm", "llamacpp", "lmstudio"):
        return OpenAICompatibleProvider()
    return OllamaProvider()
