"""
llm_client.py

Shared helper for talking to a local Ollama server. Used by decomposer.py
and the source-ingestion scripts so there's one place that knows how to
call the model and parse its output.
"""

import json
import re
from typing import List, Union

import requests

OLLAMA_URL = "http://localhost:11434/api/chat"
OLLAMA_EMBED_URL = "http://localhost:11434/api/embed"
DEFAULT_MODEL = "qwen3:8b"
DEFAULT_EMBED_MODEL = "nomic-embed-text"


def call_ollama(system_prompt: str, user_prompt: str, model: str = DEFAULT_MODEL) -> str:
    """Send a chat request to a local Ollama server and return the text response."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
    }
    try:
        resp = requests.post(OLLAMA_URL, json=payload, timeout=180)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Could not reach Ollama at http://localhost:11434 -- "
            "is `ollama serve` running? Is the model pulled "
            f"(`ollama pull {model}`)?"
        )
    except requests.exceptions.ReadTimeout:
        raise RuntimeError(
            f"Ollama took longer than 180s to respond for model '{model}'. "
            "This usually means it's running on CPU instead of GPU (check "
            "`nvidia-smi` inside the container/host, or `ollama ps` to see "
            "if it reports a GPU), or the model is still cold-loading into "
            "memory on the first call. Try the same prompt again once "
            "warmed up, or raise this timeout if your hardware is just slow."
        )
    data = resp.json()
    return data.get("message", {}).get("content", "")


def call_ollama_embed(
    text: Union[str, List[str]], model: str = DEFAULT_EMBED_MODEL
) -> List[List[float]]:
    """
    Send one or more strings to Ollama's /api/embed endpoint and return one
    embedding vector per input string, in order. Used by retriever.py's
    OllamaEmbeddingFunction -- chromadb calls an embedding function with a
    batch of documents at once, so a single string is normalized into a
    length-1 list and multiple strings are sent as ONE batched HTTP call
    rather than one call per string (much faster, and keeps this friendly to
    a local model that has to cold-load into memory).
    """
    texts = [text] if isinstance(text, str) else list(text)
    if not texts:
        return []

    payload = {"model": model, "input": texts}
    try:
        resp = requests.post(OLLAMA_EMBED_URL, json=payload, timeout=60)
        resp.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            "Could not reach Ollama at http://localhost:11434 -- "
            "is `ollama serve` running? Is the embedding model pulled "
            f"(`ollama pull {model}`)?"
        )
    except requests.exceptions.ReadTimeout:
        raise RuntimeError(
            f"Ollama took longer than 60s to respond to an embedding request "
            f"for model '{model}'. This usually means it's still cold-loading "
            "into memory on the first call -- try again once warmed up."
        )
    data = resp.json()
    embeddings = data.get("embeddings")
    if embeddings is None:
        raise RuntimeError(
            f"Ollama embed response didn't include an 'embeddings' key: {data}"
        )
    return embeddings


def _strip_thinking(text: str) -> str:
    """
    Reasoning models (qwen3, deepseek-r1, etc.) wrap their chain-of-thought in
    <think>...</think> before the real answer. That reasoning text very often
    contains its own { } or [ ] characters (the model "rehearsing" the JSON
    it's about to produce), which breaks a naive greedy brace-to-brace regex
    over the *whole* response. Strip any <think> blocks first so extraction
    only ever looks at the actual answer.
    """
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _extract_balanced(text: str, open_ch: str, close_ch: str) -> str:
    """
    Find the outermost balanced {..} or [..] block in text, scanning by
    bracket depth instead of a greedy regex. This is what actually survives
    stray braces elsewhere in the output (e.g. inside a string value, or
    leftover reasoning that wasn't caught by _strip_thinking).

    Picking "the last opening bracket" doesn't work here: if the real JSON
    contains a nested array/object (e.g. a "techniques": [...] field inside
    the outer object), that nested bracket can sit later in the string than
    the outer one and closes trivially, so a last-open-bracket search grabs
    the small nested piece instead of the whole thing. Instead, check every
    candidate start and keep whichever balanced span is LONGEST -- the true
    outermost structure always contains every nested one, so it's always the
    longest complete span.
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
    candidate = _extract_balanced(cleaned, "{", "}")
    if not candidate:
        raise ValueError(f"No JSON object found in model output:\n{text}")
    return json.loads(candidate)


def extract_json_array(text: str) -> list:
    """Pull the last balanced [...] block out of possibly-messy model output."""
    cleaned = _strip_thinking(text)
    candidate = _extract_balanced(cleaned, "[", "]")
    if not candidate:
        raise ValueError(f"No JSON array found in model output:\n{text}")
    return json.loads(candidate)


def extract_json_object_lenient(text: str, fallback_key: str = "value") -> dict:
    """
    Like extract_json_object, but never raises: if no valid JSON object can
    be found (small local models sometimes just answer in plain prose
    despite instructions), fall back to wrapping the cleaned raw text under
    `fallback_key` instead. Used by explainer.py/depth_guide.py so a
    malformed reply degrades into "here's the raw text" instead of crashing
    a whole run.
    """
    cleaned = _strip_thinking(text)
    candidate = _extract_balanced(cleaned, "{", "}")
    if candidate:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    return {fallback_key: cleaned}
