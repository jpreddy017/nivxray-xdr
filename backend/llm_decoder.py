"""NivXRay · L3 LLM decoder fallback (Zero-Miss architecture · v1.5.0)

Purpose
-------
When both L1 (`smart_decode`) and L2 (`magic_decode`) return an Undecoded
verdict on a novel payload, escalate to L3: hand the raw payload to
Claude Sonnet 4.5 (via emergentintegrations) with a STRICT decoding
prompt and parse a structured JSON verdict.

This closes the "Undecoded" gap for novel wrappers the deterministic
engine hasn't been taught yet. L3 is the safety net BEFORE L4 sandbox
detonation.

Guarantees
----------
* Time-boxed: cancels after 10 s. Falls back to deterministic empty output.
* Cost-gated: skipped when EMERGENT_LLM_KEY is absent — L3 becomes a no-op.
* Non-recursive: L3 cannot call itself, cannot re-enter smart/magic.
* Idempotent: pure function, no DB writes.

Return shape mirrors `deterministic_best_decode` so the caller can drop
it into the same downstream analysis pipeline.
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional

log = logging.getLogger("nivxray.llm_decoder")

# Guardrails — L3 is opt-in. Only fires when both L1 & L2 gave up AND we
# have a valid LLM key.  Set NIVX_L3_DISABLE=1 to force-off.
_DISABLE = os.environ.get("NIVX_L3_DISABLE") == "1"
_TIMEOUT_S = 10.0


_SYSTEM = (
    "You are the L3 decoder-fallback for NivXRay. The deterministic L1/L2 decoders "
    "gave up on this payload. Your job: peel every layer of encoding and return the "
    "final plaintext + every layer name in order + all extractable IOCs + MITRE IDs.\n\n"
    "Encoding layers you must handle: base64 (utf-8 & utf-16-LE variants), hex, url, "
    "gzip, zlib, xor (with single-byte or short-key brute), rot13/rot-N, string reverse, "
    "ascii-decimal, base32, base85, PowerShell -EncodedCommand, certutil -decode, "
    "String.fromCharCode(...), format-operator obfuscation, backtick / caret filler, "
    "String::Concat / -f operator obfuscation.\n\n"
    "Return STRICT JSON only (no prose, no markdown fence). Schema:\n"
    "{\n"
    '  "output":       "<final decoded plaintext>",\n'
    '  "chain":        ["<op1>", "<op2>", ...],\n'
    '  "confidence":   <0-1 float>,\n'
    '  "iocs":         {"urls": [], "domains": [], "ips": [], "hashes": []},\n'
    '  "mitre":        ["T1059.001", ...],\n'
    '  "family":       "<best guess>",\n'
    '  "why":          "<1-3 sentence rationale citing decoded tokens>"\n'
    "}\n\n"
    "If a payload is legitimately not decodable (random noise, encrypted opaque blob "
    "with no key), return output=\"\" and confidence=0. Never invent IOCs."
)


async def _call_claude(payload: str, key: str) -> Optional[Dict[str, Any]]:
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
    except Exception as e:
        log.warning("L3: emergentintegrations import failed: %s", e)
        return None
    chat = (
        LlmChat(api_key=key, session_id=f"l3-{int(time.time()*1000)}", system_message=_SYSTEM)
        .with_model("anthropic", "claude-sonnet-4-5")
        .with_params(max_tokens=2000)
    )
    try:
        resp = await asyncio.wait_for(
            chat.send_message(UserMessage(text=f"PAYLOAD:\n{payload[:8000]}")),
            timeout=_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        log.warning("L3: timed out after %ss", _TIMEOUT_S)
        return None
    except Exception as e:
        log.warning("L3: LLM error: %s", e)
        return None
    text = resp if isinstance(resp, str) else str(resp)
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def llm_decode_fallback(payload: str) -> Optional[Dict[str, Any]]:
    """Sync wrapper — called from `deterministic_best_decode`.

    Returns a dict shaped like `deterministic_best_decode` output, or None
    if L3 is disabled / unavailable / gave up.
    """
    if _DISABLE:
        return None
    if not payload or len(payload) < 4:
        return None
    key = os.environ.get("EMERGENT_LLM_KEY")
    if not key:
        return None
    try:
        # asyncio.run inside a sync caller — safe because we're not in an
        # existing event loop (`deterministic_best_decode` is invoked from
        # sync FastAPI request paths after `await` returns).
        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop and loop.is_running():
            # We are inside an async request handler — schedule + block.
            fut = asyncio.run_coroutine_threadsafe(_call_claude(payload, key), loop)
            parsed = fut.result(timeout=_TIMEOUT_S + 2)
        else:
            parsed = asyncio.run(_call_claude(payload, key))
    except Exception as e:
        log.warning("L3: dispatch failed: %s", e)
        return None
    if not parsed or not isinstance(parsed, dict):
        return None
    # Shape adaptor — return `deterministic_best_decode`-compatible dict.
    chain = parsed.get("chain") or []
    return {
        "output":      parsed.get("output") or "",
        "steps":       [{"op": op, "args": {}, "reason": f"L3 LLM decoded: {op}"} for op in chain],
        "engine":      "llm-l3",
        "score":       float(parsed.get("confidence") or 0.5),
        "notes":       [f"L3 LLM fallback fired — {parsed.get('why', '')[:280]}"],
        "l3_metadata": {
            "iocs":       parsed.get("iocs") or {},
            "mitre":      parsed.get("mitre") or [],
            "family":     parsed.get("family") or "unknown",
            "confidence": parsed.get("confidence"),
            "why":        parsed.get("why"),
        },
    }
