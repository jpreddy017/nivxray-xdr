"""Provider-agnostic LLM inference layer.

Purpose
-------
Give NivXRay one call-site (`llm_provider.llm_json`) that automatically:

    1. Tries the ONLINE provider first (Claude Sonnet 4.5 via Emergent LLM Key).
    2. On failure, falls back to any registered OFFLINE provider
       (fine-tuned Qwen 2.5 7B "NivX Cognis" served via Ollama).

Every provider must respect the SAME JSON contract that the caller's system
prompt defines — the strict citation/anti-hallucination validators (in
`training.validator` and `knowledge_base.synthesizer._verify_citations`) do
NOT care which model produced the JSON, so swapping providers is safe.

Enabling the offline provider
-----------------------------
Set these environment variables in `backend/.env`:

    OLLAMA_HOST=http://ollama:11434     # or http://127.0.0.1:11434
    OLLAMA_MODEL=nivx-cognis:latest     # tag of your fine-tuned Qwen model

When both are set, `OllamaQwenProvider` is auto-registered at priority 100
(below Emergent Claude). Otherwise the stub is registered and simply skipped
during failover.
"""
from __future__ import annotations
import json
import logging
import os
from typing import Any, Dict, List, Optional, Protocol

import httpx
from fastapi import HTTPException

log = logging.getLogger("nivxray")


class LLMProvider(Protocol):
    name: str
    kind: str            # "online" | "offline"
    async def json(self, session_id: str, system: str, user: str,
                   retries: int = 1) -> Dict[str, Any]: ...


# --- Built-in provider: Claude Sonnet 4.5 via Emergent Universal Key -- #
class EmergentClaudeProvider:
    name = "emergent-claude-sonnet-4-5"
    kind = "online"

    async def json(self, session_id: str, system: str, user: str, retries: int = 1) -> Dict[str, Any]:
        from deps import llm_json as _emergent_llm_json
        return await _emergent_llm_json(session_id, system, user, retries=retries)


# --- Real Ollama provider (fine-tuned NivX Cognis / Qwen 2.5 7B) ------ #
class OllamaQwenProvider:
    """Offline provider — hits Ollama's /api/generate with JSON mode."""
    kind = "offline"

    def __init__(self, host: str, model: str):
        self.host = host.rstrip("/")
        self.model = model
        self.name = f"ollama:{model}"

    async def json(self, session_id: str, system: str, user: str, retries: int = 1) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "system": system,
            "prompt": user,
            "stream": False,
            "format": "json",              # Ollama JSON-mode — clean structured output
            "options": {
                "temperature": 0.2,
                "num_predict": 4096,
            },
        }
        last_err: Optional[Exception] = None
        for _ in range(retries + 1):
            try:
                async with httpx.AsyncClient(timeout=60.0) as client:
                    r = await client.post(f"{self.host}/api/generate", json=payload)
                    r.raise_for_status()
                    body = r.json()
                    raw = body.get("response") or ""
                    if not raw:
                        raise ValueError("empty Ollama response")
                    return json.loads(raw)
            except Exception as e:
                last_err = e
                continue
        raise HTTPException(status_code=502, detail=f"ollama provider error: {last_err}")


# --- Stub — used when OLLAMA_HOST / OLLAMA_MODEL not configured ------- #
class OllamaQwenStub:
    name = "ollama-qwen-2.5-7b (stub · configure OLLAMA_HOST + OLLAMA_MODEL)"
    kind = "offline"

    async def json(self, session_id: str, system: str, user: str, retries: int = 1) -> Dict[str, Any]:
        raise NotImplementedError("NivX Cognis (Qwen 2.5 7B) not yet deployed — set OLLAMA_HOST / OLLAMA_MODEL")


# --- Registry --------------------------------------------------------- #
def _build_offline_provider() -> LLMProvider:
    host = os.environ.get("OLLAMA_HOST")
    model = os.environ.get("OLLAMA_MODEL")
    if host and model:
        log.info("llm_provider: registering OllamaQwenProvider host=%s model=%s", host, model)
        return OllamaQwenProvider(host, model)
    return OllamaQwenStub()


_REGISTRY: List[Dict[str, Any]] = [
    {"priority": 10,  "provider": EmergentClaudeProvider()},
    {"priority": 100, "provider": _build_offline_provider()},
]


def register_provider(provider: LLMProvider, priority: int = 50) -> None:
    _REGISTRY.append({"priority": priority, "provider": provider})
    _REGISTRY.sort(key=lambda x: x["priority"])


def list_providers() -> List[Dict[str, str]]:
    return [{
        "name":     p["provider"].name,
        "kind":     getattr(p["provider"], "kind", "unknown"),
        "priority": p["priority"],
    } for p in sorted(_REGISTRY, key=lambda x: x["priority"])]


async def llm_json(session_id: str, system: str, user: str,
                   retries: int = 1) -> Dict[str, Any]:
    last_err: Optional[Exception] = None
    for slot in sorted(_REGISTRY, key=lambda x: x["priority"]):
        prov: LLMProvider = slot["provider"]
        try:
            data = await prov.json(session_id, system, user, retries=retries)
            if not isinstance(data, dict):
                raise ValueError(f"{prov.name} returned non-dict")
            return data
        except NotImplementedError:
            continue
        except HTTPException as e:
            last_err = e
            log.warning("llm_provider: %s failed (%s) — trying next", prov.name, e.detail)
            continue
        except Exception as e:
            last_err = e
            log.warning("llm_provider: %s failed (%s) — trying next", prov.name, e)
            continue

    raise HTTPException(status_code=502, detail=f"all LLM providers failed: {last_err}")
