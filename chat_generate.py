"""Local Ollama chat and educational challenge generation helpers."""
import json
from llm_client import call_ollama, extract_json_object, DEFAULT_MODEL

CHAT_SYSTEM = """You are CTF-Tutor, a local educational CTF assistant. Explain concepts and guide learning. Do not provide flags, credential theft, persistence, or instructions for attacking real systems. Keep advice scoped to authorized CTF/lab environments."""
GENERATE_SYSTEM = """Generate a self-contained educational CTF challenge specification for a local practice lab. Return JSON only with keys: challenge_name, category, difficulty, description, learning_objectives, files, validation_notes. Do not include real credentials, real targets, flags, or instructions for attacking systems outside the lab. Files should describe safe local fixture files rather than destructive payloads."""

def chat(prompt: str, model: str = DEFAULT_MODEL) -> str:
    if not prompt.strip():
        raise ValueError("prompt must not be empty")
    return call_ollama(CHAT_SYSTEM, prompt.strip(), model=model)

def generate(prompt: str, model: str = DEFAULT_MODEL) -> dict:
    if not prompt.strip():
        raise ValueError("prompt must not be empty")
    raw = call_ollama(GENERATE_SYSTEM, prompt.strip(), model=model)
    try:
        obj = extract_json_object(raw)
    except ValueError as exc:
        raise RuntimeError("model returned invalid challenge JSON") from exc
    required = {"challenge_name", "category", "difficulty", "description", "learning_objectives", "files", "validation_notes"}
    missing = required - set(obj)
    if missing:
        raise RuntimeError("generated challenge is missing: " + ", ".join(sorted(missing)))
    return obj
