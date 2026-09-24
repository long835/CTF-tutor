"""
agent/vision.py — multimodal / image challenge path (item 32).

Local-first pipeline for image artifacts:
  1. Deterministic forensic hints (EXIF, PNG LSB ratio) — no model required.
  2. Optional Ollama vision model (llava, moondream, bakllava, qwen2-vl, …)
     when available, for free-form description and stego/UI transcription.

Does not solve challenges. Returns structured observations the tutor can
turn into Socratic hints.
"""

from __future__ import annotations

import base64
import mimetypes
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff", ".tif"}

VISION_SYSTEM = (
    "You are a CTF forensics tutor assistant. Describe what you see in the image "
    "for a student: visible text, UI elements, anomalies, possible steganography "
    "clues, and metadata-relevant details. Do NOT invent a flag. Be concise."
)


@dataclass
class VisionObservation:
    path: str
    kind: str = "image"
    forensic_hints: List[str] = field(default_factory=list)
    model_description: Optional[str] = None
    model_name: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def as_tutor_text(self) -> str:
        lines = [f"[vision] {self.path}"]
        for h in self.forensic_hints:
            lines.append(f"  · {h}")
        if self.model_description:
            lines.append(f"  · model ({self.model_name}): {self.model_description[:1200]}")
        if self.error:
            lines.append(f"  · note: {self.error}")
        return "\n".join(lines)


def is_image_path(path: str | Path) -> bool:
    return Path(path).suffix.lower() in IMAGE_SUFFIXES


def list_images(root: str | Path, limit: int = 20) -> List[Path]:
    root = Path(root)
    if root.is_file():
        return [root] if is_image_path(root) else []
    out: List[Path] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and is_image_path(p):
            out.append(p)
            if len(out) >= limit:
                break
    return out


def _forensic_hints(path: Path) -> List[str]:
    hints: List[str] = []
    try:
        from tools.forensics_toolkit import stego_info
        text = stego_info(str(path))
        if text and "skip stego" not in text.lower():
            hints.append(text[:800])
        elif text:
            hints.append(text[:200])
    except Exception as e:
        hints.append(f"stego tools unavailable: {e}")

    # Lightweight size / magic
    try:
        size = path.stat().st_size
        head = path.read_bytes()[:16]
        hints.append(f"file size={size} magic={head[:8].hex()}")
    except OSError as e:
        hints.append(f"unreadable: {e}")
    return hints


def _encode_image_b64(path: Path, max_bytes: int = 4_000_000) -> Optional[str]:
    data = path.read_bytes()
    if len(data) > max_bytes:
        return None
    return base64.b64encode(data).decode("ascii")


def _ollama_vision_available(model: str) -> bool:
    """Best-effort: does the configured host list this model?"""
    try:
        import requests
        from llm_client import OLLAMA_BASE_URL
        r = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5)
        if r.status_code != 200:
            return False
        names = [m.get("name", "") for m in r.json().get("models", [])]
        return any(model in n or n.startswith(model.split(":")[0]) for n in names)
    except Exception:
        return False


def describe_with_vision_model(
    path: Path,
    model: Optional[str] = None,
    prompt: Optional[str] = None,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Returns (description, model_name, error).
    Uses Ollama /api/chat with images[] when a vision-capable model is set.
    """
    model = model or os.getenv("OLLAMA_VISION_MODEL") or os.getenv("CTF_TUTOR_VISION_MODEL") or "llava"
    b64 = _encode_image_b64(path)
    if b64 is None:
        return None, model, "image too large or unreadable for vision model"

    # Skip remote call if model clearly absent (offline-friendly).
    if os.getenv("CTF_TUTOR_VISION_FORCE", "").lower() not in ("1", "true", "yes"):
        if not _ollama_vision_available(model):
            return None, model, f"vision model {model!r} not available on Ollama (set OLLAMA_VISION_MODEL or pull llava)"

    try:
        import requests
        from llm_client import OLLAMA_BASE_URL
        mime = mimetypes.guess_type(str(path))[0] or "image/png"
        payload = {
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": VISION_SYSTEM},
                {
                    "role": "user",
                    "content": prompt or "Describe this CTF challenge image for a student learning forensics.",
                    "images": [b64],
                },
            ],
            "options": {"temperature": 0.1},
        }
        r = requests.post(f"{OLLAMA_BASE_URL}/api/chat", json=payload, timeout=180)
        r.raise_for_status()
        content = (r.json().get("message") or {}).get("content") or ""
        return content.strip() or None, model, None
    except Exception as e:
        return None, model, str(e)


def observe_image(
    path: str | Path,
    *,
    use_model: bool = True,
    model: Optional[str] = None,
) -> VisionObservation:
    path = Path(path)
    obs = VisionObservation(path=str(path))
    if not path.is_file():
        obs.error = "file not found"
        return obs
    if not is_image_path(path):
        obs.error = f"not a recognised image suffix: {path.suffix}"
        return obs

    obs.forensic_hints = _forensic_hints(path)

    if use_model:
        # Honour model profile if caller set a non-vision model as default.
        try:
            from agent.model_profile import get_profile
            profile = get_profile(model)
            if not profile.supports_vision and model is None:
                # Still try explicit vision model env; otherwise skip quietly.
                if not (os.getenv("OLLAMA_VISION_MODEL") or os.getenv("CTF_TUTOR_VISION_MODEL")):
                    obs.error = obs.error or "no vision model configured (set OLLAMA_VISION_MODEL)"
                    return obs
        except Exception:
            pass
        desc, used, err = describe_with_vision_model(path, model=model)
        obs.model_description = desc
        obs.model_name = used
        if err and not desc:
            obs.error = err
    return obs


def observe_path(
    root: str | Path,
    *,
    use_model: bool = True,
    model: Optional[str] = None,
    limit: int = 5,
) -> List[VisionObservation]:
    return [
        observe_image(p, use_model=use_model, model=model)
        for p in list_images(root, limit=limit)
    ]
