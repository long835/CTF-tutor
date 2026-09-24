"""
agent/app_config.py — central configuration (item 41).

Single place for runtime knobs. Values come from environment / .env.
`public_dict()` omits secrets.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict

from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


@dataclass
class AppConfig:
    # LLM
    ollama_base_url: str = field(default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "qwen3:8b"))
    ollama_embed_model: str = field(default_factory=lambda: os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text"))
    ollama_vision_model: str = field(default_factory=lambda: os.getenv("OLLAMA_VISION_MODEL", "llava"))
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "ollama"))

    # Safety / network
    network_enabled: bool = field(default_factory=lambda: _bool("CTF_TUTOR_NETWORK"))
    online_research: bool = field(default_factory=lambda: _bool("CTF_TUTOR_ONLINE_RESEARCH"))
    prefer_local: bool = field(default_factory=lambda: _bool("CTF_TUTOR_PREFER_LOCAL", "1"))
    allow_frontier: bool = field(default_factory=lambda: _bool("CTF_TUTOR_ALLOW_FRONTIER"))

    # Resources
    max_workers: int = field(default_factory=lambda: _int("CTF_TUTOR_MAX_WORKERS", 4))
    max_cost_per_task: float = field(default_factory=lambda: float(os.getenv("CTF_TUTOR_MAX_COST", "5.0")))
    embed_backend: str = field(default_factory=lambda: os.getenv("CTF_TUTOR_EMBED_BACKEND", "ollama"))

    # API
    api_host: str = field(default_factory=lambda: os.getenv("CTF_TUTOR_API_HOST", "127.0.0.1"))
    api_port: int = field(default_factory=lambda: _int("CTF_TUTOR_API_PORT", 8765))

    # Telemetry (74) — off by default
    telemetry_enabled: bool = field(default_factory=lambda: _bool("CTF_TUTOR_TELEMETRY"))
    telemetry_path: str = field(default_factory=lambda: os.getenv("CTF_TUTOR_TELEMETRY_PATH", "data/telemetry.jsonl"))

    def public_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # no secrets today; keep hook for redaction
        return d


_CONFIG: AppConfig | None = None


def get_config(reload: bool = False) -> AppConfig:
    global _CONFIG
    if _CONFIG is None or reload:
        _CONFIG = AppConfig()
    return _CONFIG
