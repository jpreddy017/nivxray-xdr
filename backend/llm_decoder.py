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
import threading
import time


def _run_async_on_dedicated_loop(coro, hard_timeout_s: float = 20.0):
    """v1.5.7 · Run an async coroutine on a fresh event loop in a dedicated
    thread and return its result synchronously.

    Why: L3 fallback is called from sync request paths that may or may not
    already be inside a running event loop (Starlette threadpool workers).
    Using `asyncio.run_coroutine_threadsafe(...).result()` on the caller's
    loop deadlocks the threadpool under sustained load. Spawning a
    dedicated loop in its own daemon thread sidesteps that entirely — the
    caller's loop keeps handling requests, and this helper cleanly bails
    on `hard_timeout_s`.
    """
    box: dict = {"value": None, "error": None}

    def _worker():
        loop = asyncio.new_event_loop()
        try:
            box["value"] = loop.run_until_complete(coro)
        except BaseException as e:            # noqa: BLE001 — propagate everything
            box["error"] = e
        finally:
            try: loop.close()
            except Exception: pass

    t = threading.Thread(target=_worker, daemon=True, name="l3-llm-decoder")
    t.start()
    t.join(timeout=hard_timeout_s)
    if t.is_alive():
        raise TimeoutError(f"L3 dispatch exceeded hard_timeout={hard_timeout_s}s")
    if box["error"] is not None:
        raise box["error"]
    return box["value"]
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
        # v1.5.7 · Deadlock fix.
        # PRIOR bug: when a caller was already inside a running event loop
        # AND executing on a threadpool worker (Starlette's default), the
        # old code did:
        #     fut = asyncio.run_coroutine_threadsafe(coro, loop)
        #     fut.result(timeout=…)   # ← blocks the worker thread
        # Under sustained decode traffic every threadpool worker parked on
        # `.result()` → threadpool exhausted → `/api/health` and every
        # sync request queued behind Starlette's threadpool → backend
        # appeared to "hang" and only `sudo supervisorctl restart backend`
        # recovered it.
        #
        # FIX: always run the Claude coroutine on a DEDICATED asyncio loop
        # inside its own thread. This never touches the caller's loop,
        # never occupies a Starlette threadpool worker for the full LLM
        # round-trip, and cleanly bails after `_TIMEOUT_S + 3s`.
        parsed = _run_async_on_dedicated_loop(
            _call_claude(payload, key), hard_timeout_s=_TIMEOUT_S + 3
        )
    except Exception as e:
        log.warning("L3: dispatch failed: %r", e)   # repr, so exception type is visible
        return None
    if not parsed or not isinstance(parsed, dict):
        return None
    # Shape adaptor — return `deterministic_best_decode`-compatible dict.
    # v1.5.8 — Filter/alias Claude-invented op names against the real
    # OPERATIONS registry. Prior bug: Claude returned chain steps like
    # `case-obfuscation-normalization` / `case_obfuscation_normalization`
    # that don't map to any registered op → the frontend Recipe replay
    # errored with `Unknown operation: …` and analysts saw a red 🔴 ERROR
    # on the final step even though the decode itself succeeded.
    raw_chain = parsed.get("chain") or []
    try:
        from operations import OPERATIONS as _OPS
    except Exception:
        _OPS = {}
    # Common LLM synonyms → real registered ops
    _ALIASES = {
        "case-obfuscation-normalization":  "cmd-deobfuscate",
        "case_obfuscation_normalization":  "cmd-deobfuscate",
        "cmd-caret-normalization":         "strip-carets",
        "caret-strip":                     "strip-carets",
        "b64-decode":                      "base64-decode",
        "b64":                             "base64-decode",
        "utf16-decode":                    "utf16le-decode",
        "utf16le":                         "utf16le-decode",
        "url-percent-decode":              "url-decode",
        "env-var-expand":                  "env-expand",
        "reverse-string":                  "reverse",
    }
    chain: list[str] = []
    dropped: list[str] = []
    for op in raw_chain:
        if not isinstance(op, str) or not op.strip():
            continue
        canonical = _ALIASES.get(op.strip(), op.strip())
        if _OPS and canonical not in _OPS:
            dropped.append(op)
            continue
        chain.append(canonical)
    steps = [{"op": op, "args": {}, "reason": f"L3 LLM decoded: {op}"} for op in chain]
    notes = [f"L3 LLM fallback fired — {parsed.get('why', '')[:280]}"]
    if dropped:
        notes.append(f"L3 dropped {len(dropped)} unknown op(s): {dropped[:5]!r}")
    return {
        "output":      parsed.get("output") or "",
        "steps":       steps,
        "engine":      "llm-l3",
        "score":       float(parsed.get("confidence") or 0.5),
        "notes":       notes,
        "l3_metadata": {
            "iocs":       parsed.get("iocs") or {},
            "mitre":      parsed.get("mitre") or [],
            "family":     parsed.get("family") or "unknown",
            "confidence": parsed.get("confidence"),
            "why":        parsed.get("why"),
        },
    }
