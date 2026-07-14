"""Provider-agnostic LLM inference layer.

Purpose
-------
Give NivXRay one call-site (`llm_provider.llm_json`) that automatically:

    1. Tries the ONLINE provider first (Claude Sonnet 4.5 via Emergent LLM Key).
    2. On failure, falls back to any registered OFFLINE provider
       (planned: fine-tuned Qwen 2.5 7B "NivX Cognis" served via Ollama).

Every provider must respect the SAME JSON contract that the caller's system
prompt defines — the strict citation/anti-hallucination validators (in
`training.validator` and `knowledge_base.synthesizer._verify_citations`) do
NOT care which model produced the JSON, so swapping providers is safe.

Adding a new provider later
---------------------------
```
from llm_provider import register_provider, LLMProvider

class OllamaQwenProvider(LLMProvider):
    name = "ollama-qwen-2.5-7b"
    async def json(self, session_id, system, user, retries=1): ...

register_provider(OllamaQwenProvider(), priority=10)   # lower = tried first
```

The KB synthesizer, Process-Tree predictor, and every other AI call-site can
transparently benefit — no code changes needed at the call-site.
"""
from __future__ import annotations
import logging
from typing import Any, Dict, List, Optional, Protocol

from fastapi import HTTPException

log = logging.getLogger("nivxray")


class LLMProvider(Protocol):
    """Every provider must implement this contract."""
    name: str
    kind: str            # "online" | "offline"
    async def json(self, session_id: str, system: str, user: str,
                   retries: int = 1) -> Dict[str, Any]: ...


# --- Built-in provider: Claude Sonnet 4.5 via Emergent Universal Key -- #
class EmergentClaudeProvider:
    """Online provider — delegates to the existing deps.llm_json helper."""
    name = "emergent-claude-sonnet-4-5"
    kind = "online"

    async def json(self, session_id: str, system: str, user: str, retries: int = 1) -> Dict[str, Any]:
        # Local import to avoid circulars
        from deps import llm_json as _emergent_llm_json
        return await _emergent_llm_json(session_id, system, user, retries=retries)


# --- Stub for the future Qwen 2.5 7B provider (Task 3 / Task 4) ------- #
class OllamaQwenStub:
    """Placeholder for the offline NivX Cognis provider.

    Enable later by pointing at a running `ollama serve` instance and swapping
    the body of `json()` to call it. Until then, this stub always raises so
    the automatic failover simply skips it.
    """
    name = "ollama-qwen-2.5-7b (stub)"
    kind = "offline"

    async def json(self, session_id: str, system: str, user: str, retries: int = 1) -> Dict[str, Any]:
        raise NotImplementedError("NivX Cognis (Qwen 2.5 7B) not yet deployed")


# --- Registry ---------------------------------------------------------- #
# priority: LOWER is tried FIRST. Online tried before offline.
_REGISTRY: List[Dict[str, Any]] = [
    {"priority": 10,  "provider": EmergentClaudeProvider()},
    {"priority": 100, "provider": OllamaQwenStub()},
]


def register_provider(provider: LLMProvider, priority: int = 50) -> None:
    """Insert a new provider into the failover chain."""
    _REGISTRY.append({"priority": priority, "provider": provider})
    _REGISTRY.sort(key=lambda x: x["priority"])


def list_providers() -> List[Dict[str, str]]:
    """Return the current failover chain (for /api/system/llm-providers)."""
    return [{
        "name":     p["provider"].name,
        "kind":     getattr(p["provider"], "kind", "unknown"),
        "priority": p["priority"],
    } for p in sorted(_REGISTRY, key=lambda x: x["priority"])]


# --- Unified call-site ------------------------------------------------- #
async def llm_json(session_id: str, system: str, user: str,
                   retries: int = 1) -> Dict[str, Any]:
    """Try each provider in priority order; return the first successful JSON.

    Any provider that raises (LLM down, quota exceeded, NotImplementedError…)
    is skipped. If ALL providers fail, we re-raise the last error as a 502.
    """
    last_err: Optional[Exception] = None
    for slot in sorted(_REGISTRY, key=lambda x: x["priority"]):
        prov: LLMProvider = slot["provider"]
        try:
            data = await prov.json(session_id, system, user, retries=retries)
            if not isinstance(data, dict):
                raise ValueError(f"{prov.name} returned non-dict")
            return data
        except NotImplementedError:
            continue   # stub — just skip
        except HTTPException as e:
            last_err = e
            log.warning("llm_provider: %s failed (%s) — trying next", prov.name, e.detail)
            continue
        except Exception as e:
            last_err = e
            log.warning("llm_provider: %s failed (%s) — trying next", prov.name, e)
            continue

    raise HTTPException(status_code=502, detail=f"all LLM providers failed: {last_err}")
