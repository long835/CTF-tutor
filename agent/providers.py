"""
agent/providers.py

Thin LLM provider abstraction.

Default: Ollama (local). Optional stubs for other OpenAI-compatible
local servers (llama.cpp server, vLLM, LM Studio) via base URL only.
No paid API keys required for core operation.
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Sequence


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


class OfflineProvider(LLMProvider):
    """
    Last resort when no LLM is reachable.

    Rather than raising and taking the whole agent down, this returns an
    empty string. Every caller already treats an empty completion as "the
    model gave me nothing useful" and falls back to heuristics, so the
    offline path degrades into the keyword-seeded agent instead of a crash.
    """

    def chat(self, system: str, user: str, model: Optional[str] = None) -> str:
        return ""

    def embed(self, texts: List[str], model: Optional[str] = None) -> List[List[float]]:
        return [[] for _ in texts]

    @property
    def name(self) -> str:
        return "offline"


def _build_provider(kind: str) -> Optional[LLMProvider]:
    kind = (kind or "").lower().strip()
    if kind in ("openai", "openai_compatible", "vllm", "llamacpp", "lmstudio"):
        return OpenAICompatibleProvider()
    if kind == "ollama":
        return OllamaProvider()
    if kind in ("offline", "none", "null"):
        return OfflineProvider()
    return None


class FailoverProvider(LLMProvider):
    """
    Try providers in order; remember which one worked.

    A local Ollama that is still loading a model, or an llama.cpp server
    that was restarted, should degrade to the next option rather than
    ending the session. Once a provider fails it is skipped for
    `cooldown_seconds` so every subsequent call does not re-pay its timeout.
    """

    def __init__(self, providers: Sequence[LLMProvider], cooldown_seconds: float = 60.0):
        self.providers: List[LLMProvider] = [p for p in providers if p is not None]
        if not self.providers:
            self.providers = [OfflineProvider()]
        self.cooldown_seconds = cooldown_seconds
        self._failed_until: Dict[str, float] = {}
        self.last_used: str = ""
        self.last_errors: List[str] = []

    def _available(self) -> List[LLMProvider]:
        now = time.monotonic()
        live = [p for p in self.providers if self._failed_until.get(p.name, 0.0) <= now]
        # If everything is cooling down, try them all anyway — a stale
        # cooldown is worse than one extra timeout.
        return live or list(self.providers)

    def _mark_failed(self, provider: LLMProvider, exc: Exception) -> None:
        self._failed_until[provider.name] = time.monotonic() + self.cooldown_seconds
        self.last_errors.append(f"{provider.name}: {exc}")
        self.last_errors = self.last_errors[-10:]

    def chat(self, system: str, user: str, model: Optional[str] = None) -> str:
        self.last_errors = []
        for provider in self._available():
            try:
                result = provider.chat(system, user, model=model)
            except Exception as exc:
                self._mark_failed(provider, exc)
                continue
            if result and result.strip():
                self.last_used = provider.name
                self._failed_until.pop(provider.name, None)
                return result
            # An empty answer from a live provider still counts as a miss.
            self._mark_failed(provider, RuntimeError("empty completion"))
        self.last_used = "offline"
        return ""

    def embed(self, texts: List[str], model: Optional[str] = None) -> List[List[float]]:
        for provider in self._available():
            try:
                vectors = provider.embed(list(texts), model=model)
            except Exception as exc:
                self._mark_failed(provider, exc)
                continue
            if vectors and any(v for v in vectors):
                self.last_used = provider.name
                return vectors
        return [[] for _ in texts]

    def health(self) -> Dict[str, Any]:
        now = time.monotonic()
        return {
            "chain": [p.name for p in self.providers],
            "last_used": self.last_used,
            "cooling_down": {
                name: round(until - now, 1)
                for name, until in self._failed_until.items()
                if until > now
            },
            "recent_errors": list(self.last_errors),
        }

    @property
    def name(self) -> str:
        return "failover(" + ",".join(p.name for p in self.providers) + ")"


def get_provider() -> LLMProvider:
    """
    Build the active provider.

    `LLM_PROVIDER` picks the primary. `LLM_PROVIDER_FALLBACK` is an
    optional comma-separated chain tried in order when the primary fails,
    e.g.:

        LLM_PROVIDER=ollama
        LLM_PROVIDER_FALLBACK=openai_compatible,offline

    With no fallback configured the behaviour is unchanged: a single
    provider, returned directly.
    """
    primary = _build_provider(os.getenv("LLM_PROVIDER", "ollama")) or OllamaProvider()

    raw_chain = os.getenv("LLM_PROVIDER_FALLBACK", "").strip()
    if not raw_chain:
        return primary

    chain: List[LLMProvider] = [primary]
    seen = {primary.name}
    for kind in raw_chain.split(","):
        provider = _build_provider(kind)
        if provider and provider.name not in seen:
            chain.append(provider)
            seen.add(provider.name)

    cooldown = float(os.getenv("LLM_FAILOVER_COOLDOWN", "60") or 60)
    return FailoverProvider(chain, cooldown_seconds=cooldown)
