"""
agent/model_profile.py

Knowing what the model in front of you can actually do (items 1, 29, 30).

A 4B quantized model on a laptop and a frontier API model are both "the
LLM" to the rest of this codebase, and that assumption quietly breaks
things. The small model needs shorter context, simpler plans, more
verification and more deterministic prompts. Asking it for a twelve-step
plan in strict JSON produces confident nonsense; asking it one narrow
question at a time produces something usable.

So the agent should not ask "what model is this?" but "how much can I ask
of it in one go?" — which is what `ModelProfile` answers.

Profiles are matched by name pattern, so an unknown model still gets a
conservative estimate rather than an exception. Conservative is the right
default: under-asking a capable model wastes a little headroom, while
over-asking a small one produces wrong answers that look right.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ModelTier(str, Enum):
    """Rough capability bands. Behaviour keys off these, not model names."""

    TINY = "tiny"        # <= 4B: single-step questions, heavy scaffolding
    SMALL = "small"      # 5-9B: the local default
    MEDIUM = "medium"    # 10-30B
    LARGE = "large"      # 30B+ local
    FRONTIER = "frontier"  # hosted API models

    @property
    def rank(self) -> int:
        return ["tiny", "small", "medium", "large", "frontier"].index(self.value)


@dataclass
class ModelProfile:
    """What a given model can be trusted to do."""

    name: str
    provider: str = "ollama"
    tier: ModelTier = ModelTier.SMALL

    context_length: int = 8192
    supports_tool_calling: bool = False
    supports_structured_output: bool = False   # reliable JSON without repair
    supports_vision: bool = False
    supports_embeddings: bool = False
    supports_streaming: bool = True
    emits_thinking_blocks: bool = False

    quantization: str = "unknown"              # Q4 | Q5 | Q6 | Q8 | FP16
    min_ram_gb: float = 8.0
    min_vram_gb: float = 0.0                   # 0 means CPU-viable

    # Behavioural budgets derived from the tier.
    max_plan_steps: int = 4
    max_retrieval_docs: int = 5
    verification_passes: int = 1
    temperature: float = 0.2

    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tier"] = self.tier.value
        return d

    @property
    def context_budget(self) -> int:
        """Usable prompt tokens, leaving room for the reply."""
        return max(1024, int(self.context_length * 0.7))

    @property
    def needs_json_repair(self) -> bool:
        return not self.supports_structured_output

    def describe(self) -> str:
        bits = [f"{self.name} ({self.provider}, {self.tier.value})",
                f"context {self.context_length}"]
        caps = [n for n, on in (
            ("tools", self.supports_tool_calling),
            ("json", self.supports_structured_output),
            ("vision", self.supports_vision),
            ("embed", self.supports_embeddings),
        ) if on]
        bits.append("caps: " + (", ".join(caps) if caps else "text only"))
        return " · ".join(bits)


# Tier defaults. These are the behavioural knobs the agent actually reads.
_TIER_DEFAULTS: Dict[ModelTier, Dict[str, Any]] = {
    ModelTier.TINY:     {"max_plan_steps": 2, "max_retrieval_docs": 3, "verification_passes": 2, "temperature": 0.1},
    ModelTier.SMALL:    {"max_plan_steps": 4, "max_retrieval_docs": 5, "verification_passes": 1, "temperature": 0.2},
    ModelTier.MEDIUM:   {"max_plan_steps": 6, "max_retrieval_docs": 8, "verification_passes": 1, "temperature": 0.3},
    ModelTier.LARGE:    {"max_plan_steps": 8, "max_retrieval_docs": 10, "verification_passes": 1, "temperature": 0.3},
    ModelTier.FRONTIER: {"max_plan_steps": 12, "max_retrieval_docs": 12, "verification_passes": 1, "temperature": 0.3},
}

# Known models, matched by regex against the model string.
KNOWN_PROFILES: List[Tuple[str, Dict[str, Any]]] = [
    (r"qwen3[:\-]?(?:8b)", {
        "tier": ModelTier.SMALL, "context_length": 32768, "emits_thinking_blocks": True,
        "supports_structured_output": False, "min_ram_gb": 10.0,
        "notes": "Repo default. Emits <think> blocks — strip before parsing JSON.",
    }),
    (r"qwen3[:\-]?(?:14b|32b)", {
        "tier": ModelTier.MEDIUM, "context_length": 32768, "emits_thinking_blocks": True,
        "min_ram_gb": 20.0, "min_vram_gb": 12.0,
    }),
    (r"qwen.*(?:0\.5b|1\.5b|3b|4b)", {
        "tier": ModelTier.TINY, "context_length": 32768, "min_ram_gb": 4.0,
    }),
    # Specific sizes must precede the generic family pattern, or the
    # generic one shadows them and a 70B gets treated as an 8B.
    (r"llama3.*(?:70b|405b)", {
        "tier": ModelTier.LARGE, "context_length": 8192, "supports_tool_calling": True,
        "min_ram_gb": 48.0, "min_vram_gb": 40.0,
    }),
    (r"llama3.*(?:1b|3b)", {
        "tier": ModelTier.TINY, "context_length": 8192, "min_ram_gb": 4.0,
    }),
    (r"llama3[.\-]?[12]?[:\-]?(?:8b)?", {
        "tier": ModelTier.SMALL, "context_length": 8192, "supports_tool_calling": True,
    }),
    (r"mistral|mixtral", {
        "tier": ModelTier.SMALL, "context_length": 32768, "supports_tool_calling": True,
    }),
    (r"deepseek.*(?:coder|r1)", {
        "tier": ModelTier.MEDIUM, "context_length": 16384, "emits_thinking_blocks": True,
    }),
    (r"phi[\-]?[34]", {"tier": ModelTier.TINY, "context_length": 4096, "min_ram_gb": 4.0}),
    (r"gemma[23]?", {"tier": ModelTier.SMALL, "context_length": 8192}),
    (r"codellama", {"tier": ModelTier.SMALL, "context_length": 16384}),
    (r"nomic-embed|mxbai-embed|all-minilm|bge-", {
        "tier": ModelTier.TINY, "context_length": 2048,
        "supports_embeddings": True, "supports_streaming": False,
        "notes": "Embedding model — not for generation.",
    }),
    (r"llava|bakllava|moondream|.*-vision", {
        "tier": ModelTier.SMALL, "context_length": 4096, "supports_vision": True,
    }),
    (r"gpt-4|gpt-5|o[13]-|claude-|gemini-", {
        "tier": ModelTier.FRONTIER, "context_length": 128000,
        "supports_tool_calling": True, "supports_structured_output": True,
        "supports_vision": True, "min_ram_gb": 0.0,
        "notes": "Hosted. No local resources required.",
    }),
]

# Matches q4, q4_0, q4_k_m, q8_0, fp16, bf16, int8 ...
_QUANT_PATTERN = re.compile(
    r"(?<![a-z0-9])(q[2-8](?:_[0-9a-z]+)*|fp16|f16|bf16|int8|int4)(?![a-z0-9])",
    re.IGNORECASE,
)


def _detect_quantization(name: str) -> str:
    match = _QUANT_PATTERN.search(name or "")
    return match.group(1).upper() if match else "unknown"


def _infer_tier_from_size(name: str) -> Optional[ModelTier]:
    """Fall back to the parameter count baked into most model names."""
    match = re.search(r"(\d+(?:\.\d+)?)\s*b\b", (name or "").lower())
    if not match:
        return None
    try:
        billions = float(match.group(1))
    except ValueError:
        return None
    if billions <= 4:
        return ModelTier.TINY
    if billions <= 9:
        return ModelTier.SMALL
    if billions <= 30:
        return ModelTier.MEDIUM
    return ModelTier.LARGE


def get_profile(model: Optional[str] = None, provider: Optional[str] = None) -> ModelProfile:
    """
    Build a profile for a model name.

    Unknown models get a conservative SMALL profile rather than an
    exception, because refusing to run on an unrecognised model would make
    the "bring your own local model" promise false.
    """
    name = (model or os.getenv("OLLAMA_MODEL") or "qwen3:8b").strip()
    provider = (provider or os.getenv("LLM_PROVIDER") or "ollama").strip()
    lowered = name.lower()

    attrs: Dict[str, Any] = {}
    for pattern, values in KNOWN_PROFILES:
        if re.search(pattern, lowered):
            attrs = dict(values)
            break

    if not attrs:
        tier = _infer_tier_from_size(lowered) or ModelTier.SMALL
        attrs = {"tier": tier, "notes": "Unrecognised model — conservative defaults applied."}
    else:
        # A known family whose name still carries a larger size wins on size:
        # "mixtral:8x22b" should not inherit the plain mistral profile.
        inferred = _infer_tier_from_size(lowered)
        if inferred and inferred.rank > attrs.get("tier", ModelTier.SMALL).rank:
            attrs["tier"] = inferred

    tier: ModelTier = attrs.pop("tier", ModelTier.SMALL)
    profile = ModelProfile(name=name, provider=provider, tier=tier, **attrs)

    for key, value in _TIER_DEFAULTS[tier].items():
        setattr(profile, key, value)

    profile.quantization = _detect_quantization(name)

    # Explicit overrides always win — the user knows their setup better
    # than a regex does.
    if os.getenv("CTF_TUTOR_MODEL_CONTEXT"):
        try:
            profile.context_length = int(os.environ["CTF_TUTOR_MODEL_CONTEXT"])
        except ValueError:
            pass
    if os.getenv("CTF_TUTOR_MODEL_TIER"):
        try:
            override = ModelTier(os.environ["CTF_TUTOR_MODEL_TIER"].lower())
            profile.tier = override
            for key, value in _TIER_DEFAULTS[override].items():
                setattr(profile, key, value)
        except ValueError:
            pass

    return profile


# ------------------------------------------------------ hardware (29, 30)


@dataclass
class Hardware:
    """What this machine can actually run."""

    ram_gb: float = 0.0
    cpu_count: int = 0
    gpu: str = ""
    vram_gb: float = 0.0
    platform: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def can_run(self, profile: ModelProfile) -> Tuple[bool, str]:
        if profile.provider not in ("ollama", "openai_compatible", "vllm", "llamacpp", "lmstudio"):
            return True, "hosted model — no local resources needed"
        if profile.min_ram_gb and self.ram_gb and self.ram_gb < profile.min_ram_gb:
            return False, f"needs ~{profile.min_ram_gb:.0f}GB RAM, this machine reports {self.ram_gb:.1f}GB"
        if profile.min_vram_gb and profile.min_vram_gb > 0:
            if not self.vram_gb:
                return True, f"no GPU detected — will run on CPU, expect it to be slow"
            if self.vram_gb < profile.min_vram_gb:
                return True, f"only {self.vram_gb:.1f}GB VRAM — will partially offload to CPU"
        return True, "looks fine"


def detect_hardware() -> Hardware:
    """Best-effort local capability detection. Never raises."""
    import platform as _platform

    hw = Hardware(platform=f"{_platform.system()} {_platform.machine()}")

    try:
        hw.cpu_count = os.cpu_count() or 0
    except Exception:
        pass

    # RAM: prefer a real API, fall back to /proc, then give up quietly.
    try:
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        hw.ram_gb = round(pages * page_size / (1024 ** 3), 1)
    except (ValueError, OSError, AttributeError):
        try:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        hw.ram_gb = round(int(line.split()[1]) / (1024 ** 2), 1)
                        break
        except OSError:
            pass

    # GPU: nvidia-smi if present. Absence is normal, not an error.
    if shutil.which("nvidia-smi"):
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=5, check=False,
            ).stdout.strip()
            if out:
                first = out.splitlines()[0].split(",")
                hw.gpu = first[0].strip()
                if len(first) > 1:
                    hw.vram_gb = round(float(first[1].strip()) / 1024, 1)
        except (subprocess.SubprocessError, ValueError, OSError):
            pass
    elif _platform.system() == "Darwin" and "arm" in _platform.machine().lower():
        hw.gpu = "Apple Silicon (unified memory)"
        hw.vram_gb = hw.ram_gb * 0.6

    return hw


def recommend_models(hw: Optional[Hardware] = None) -> List[Dict[str, Any]]:
    """Suggest models this machine can realistically run."""
    hw = hw or detect_hardware()
    candidates = ["phi-3", "qwen3:8b", "mistral", "qwen3:14b", "llama3:70b"]
    out = []
    for name in candidates:
        profile = get_profile(name)
        ok, note = hw.can_run(profile)
        out.append({
            "model": name,
            "tier": profile.tier.value,
            "context": profile.context_length,
            "runnable": ok,
            "note": note,
        })
    return out


def render_profile(profile: ModelProfile, hw: Optional[Hardware] = None) -> str:
    """Human-readable summary for `python main.py doctor`."""
    lines = [f"# Model profile", "", profile.describe(), ""]
    lines.append(f"Tier          {profile.tier.value}")
    lines.append(f"Context       {profile.context_length} tokens (budget {profile.context_budget})")
    lines.append(f"Quantization  {profile.quantization}")
    lines.append(f"Plan steps    max {profile.max_plan_steps}")
    lines.append(f"Retrieval     max {profile.max_retrieval_docs} docs")
    lines.append(f"JSON repair   {'required' if profile.needs_json_repair else 'not needed'}")
    if profile.emits_thinking_blocks:
        lines.append("Note          emits reasoning blocks; stripped before JSON parsing")
    if profile.notes:
        lines.append(f"Note          {profile.notes}")

    if hw:
        lines += ["", "# Hardware", ""]
        lines.append(f"Platform      {hw.platform}")
        lines.append(f"CPU           {hw.cpu_count} cores")
        lines.append(f"RAM           {hw.ram_gb or 'unknown'} GB")
        lines.append(f"GPU           {hw.gpu or 'none detected'}")
        if hw.vram_gb:
            lines.append(f"VRAM          {hw.vram_gb} GB")
        ok, note = hw.can_run(profile)
        lines += ["", f"Verdict       {'OK' if ok else 'PROBLEM'} — {note}"]
    return "\n".join(lines)
