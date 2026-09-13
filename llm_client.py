```python
"""
llm_client.py

Shared helper for talking to an Ollama server. Used by decomposer.py
and the source-ingestion scripts so there's one place that knows how to
call the model and parse its output.

Configuration is loaded from a local .env file.

Create a .env file in the project root:

    OLLAMA_BASE_URL=http://localhost:11434
    OLLAMA_MODEL=qwen3:8b
    OLLAMA_EMBED_MODEL=nomic-embed-text

Each user can set these values to their own Ollama server.
"""

import json
import os
import re
from typing import List, Union

import requests
from dotenv import load_dotenv


# Load variables from .env if the file exists.
load_dotenv()


# ---------------------------------------------------------------------------
# Ollama configuration
# ---------------------------------------------------------------------------

OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434",
).rstrip("/")

DEFAULT_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen3:8b",
)

DEFAULT_EMBED_MODEL = os.getenv(
    "OLLAMA_EMBED_MODEL",
    "nomic-embed-text",
)

OLLAMA_URL = f"{OLLAMA_BASE_URL}/api/chat"
OLLAMA_EMBED_URL = f"{OLLAMA_BASE_URL}/api/embed"


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

def call_ollama(
    system_prompt: str,
    user_prompt: str,
    model: str = DEFAULT_MODEL,
) -> str:
    """Send a chat request to an Ollama server and return the text response."""

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
    }

    try:
        resp = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=180,
        )
        resp.raise_for_status()

    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Could not reach Ollama at {OLLAMA_BASE_URL} -- "
            "is the Ollama server running and is the URL configured correctly? "
            f"Is the model pulled (`ollama pull {model}`)?"
        )

    except requests.exceptions.ReadTimeout:
        raise RuntimeError(
            f"Ollama took longer than 180s to respond for model '{model}'. "
            "This usually means it's running on CPU instead of GPU, "
            "the model is still cold-loading into memory, or the server "
            "is under heavy load. Try the same prompt again once warmed up, "
            "or increase the timeout if your hardware is slower."
        )

    data = resp.json()

    return data.get("message", {}).get("content", "")


# ---------------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------------

def call_ollama_embed(
    text: Union[str, List[str]],
    model: str = DEFAULT_EMBED_MODEL,
) -> List[List[float]]:
    """
    Send one or more strings to Ollama's /api/embed endpoint and return one
    embedding vector per input string, in order.

    A single string is normalized into a length-1 list. Multiple strings are
    sent as one batched HTTP request.
    """

    texts = [text] if isinstance(text, str) else list(text)

    if not texts:
        return []

    payload = {
        "model": model,
        "input": texts,
    }

    try:
        resp = requests.post(
            OLLAMA_EMBED_URL,
            json=payload,
            timeout=60,
        )
        resp.raise_for_status()

    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Could not reach Ollama at {OLLAMA_BASE_URL} -- "
            "is the Ollama server running and is the URL configured correctly? "
            "Is the embedding model pulled "
            f"(`ollama pull {model}`)?"
        )

    except requests.exceptions.ReadTimeout:
        raise RuntimeError(
            "Ollama took longer than 60s to respond to an embedding request "
            f"for model '{model}'. This usually means the model is still "
            "cold-loading into memory on the first call -- try again once "
            "warmed up."
        )

    data = resp.json()

    embeddings = data.get("embeddings")

    if embeddings is None:
        raise RuntimeError(
            "Ollama embed response didn't include an 'embeddings' key: "
            f"{data}"
        )

    return embeddings


# ---------------------------------------------------------------------------
# Model output parsing
# ---------------------------------------------------------------------------

def _strip_thinking(text: str) -> str:
    """
    Reasoning models (qwen3, deepseek-r1, etc.) may wrap their reasoning in
    <think>...</think> before the actual answer.

    Strip those blocks before attempting JSON extraction.
    """

    return re.sub(
        r"<think>.*?</think>",
        "",
        text,
        flags=re.DOTALL,
    ).strip()


def _extract_balanced(
    text: str,
    open_ch: str,
    close_ch: str,
) -> str:
    """
    Find the outermost balanced {...} or [...] block in text.

    The longest complete balanced span is selected so nested objects/arrays
    don't get mistaken for the complete JSON response.
    """

    best = ""

    for start, ch in enumerate(text):
        if ch != open_ch:
            continue

        depth = 0

        for i in range(start, len(text)):
            if text[i] == open_ch:
                depth += 1

            elif text[i] == close_ch:
                depth -= 1

                if depth == 0:
                    candidate = text[start : i + 1]

                    if len(candidate) > len(best):
                        best = candidate

                    break

    return best


def extract_json_object(text: str) -> dict:
    """Pull the last balanced {...} block out of possibly-messy model output."""

    cleaned = _strip_thinking(text)

    candidate = _extract_balanced(
        cleaned,
        "{",
        "}",
    )

    if not candidate:
        raise ValueError(
            f"No JSON object found in model output:\n{text}"
        )

    return json.loads(candidate)


def extract_json_array(text: str) -> list:
    """Pull the last balanced [...] block out of possibly-messy model output."""

    cleaned = _strip_thinking(text)

    candidate = _extract_balanced(
        cleaned,
        "[",
        "]",
    )

    if not candidate:
        raise ValueError(
            f"No JSON array found in model output:\n{text}"
        )

    return json.loads(candidate)


def extract_json_object_lenient(
    text: str,
    fallback_key: str = "value",
) -> dict:
    """
    Like extract_json_object, but never raises.

    If no valid JSON object can be found, fall back to wrapping the cleaned
    raw text under fallback_key instead.
    """

    cleaned = _strip_thinking(text)

    candidate = _extract_balanced(
        cleaned,
        "{",
        "}",
    )

    if candidate:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    return {
        fallback_key: cleaned
    }
```
