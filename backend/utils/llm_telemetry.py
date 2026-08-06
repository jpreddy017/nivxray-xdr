"""
Lightweight in-memory LLM telemetry (observability, NOT architectural).

Provides:

  1. ``track(caller)`` — an async context manager any LLM call site can
     wrap around its request for accurate per-caller attribution.

  2. ``install_litellm_hook()`` — monkeypatches ``litellm.completion`` /
     ``litellm.acompletion`` at process start so **every** completion
     is counted even when the calling code doesn't use ``track()``.
     Caller identity is inferred from the Python stack — enough to
     pinpoint runaway loops when the process-wide totals climb while
     the UI is idle.

Records:

  • ``in_flight``        — concurrent completions right now
  • ``peak_in_flight``   — max seen since process start
  • ``started_total``    — completions started since process start
  • ``completed_total``  — completions completed normally
  • ``failed_total``     — completions raised an exception
  • ``timeout_total``    — completions killed by ``asyncio.TimeoutError``
  • ``last_latency_ms``  — latency of the most recent completion
  • ``avg_latency_ms``   — rolling avg over the last 200 completions

Deliberately zero deps, single-process only. Not persisted. Exposed by the
admin telemetry endpoint so a runaway loop or event-loop starvation event
can be spotted in one glance.
"""
from __future__ import annotations

import inspect
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from threading import Lock
from typing import Any, Dict, Optional

_LOCK = Lock()
_STATE: Dict[str, Any] = {
    "in_flight": 0,
    "peak_in_flight": 0,
    "started_total": 0,
    "completed_total": 0,
    "failed_total": 0,
    "timeout_total": 0,
    "last_latency_ms": None,
    "started_at_epoch": time.time(),
    "litellm_hook_installed": False,
}
_RECENT_LATENCIES: deque = deque(maxlen=200)
_BY_CALLER: Dict[str, Dict[str, int]] = {}


def _bump_caller(caller: str, key: str) -> None:
    row = _BY_CALLER.setdefault(caller, {"started": 0, "completed": 0, "failed": 0, "timeout": 0})
    row[key] = row.get(key, 0) + 1


@asynccontextmanager
async def track(caller: str = "unknown"):
    """Wrap an LLM call: ``async with track("moe_panel:malware_analyst"): ...``"""
    import asyncio
    t0 = time.time()
    with _LOCK:
        _STATE["in_flight"] += 1
        _STATE["started_total"] += 1
        if _STATE["in_flight"] > _STATE["peak_in_flight"]:
            _STATE["peak_in_flight"] = _STATE["in_flight"]
        _bump_caller(caller, "started")
    try:
        yield
        with _LOCK:
            _STATE["completed_total"] += 1
            _bump_caller(caller, "completed")
    except asyncio.TimeoutError:
        with _LOCK:
            _STATE["timeout_total"] += 1
            _STATE["failed_total"] += 1
            _bump_caller(caller, "timeout")
        raise
    except Exception:
        with _LOCK:
            _STATE["failed_total"] += 1
            _bump_caller(caller, "failed")
        raise
    finally:
        dt_ms = int((time.time() - t0) * 1000)
        with _LOCK:
            _STATE["in_flight"] = max(0, _STATE["in_flight"] - 1)
            _STATE["last_latency_ms"] = dt_ms
            _RECENT_LATENCIES.append(dt_ms)


def _infer_caller_from_stack() -> str:
    """Walk the stack for the first frame outside litellm / this module.

    Returns ``"<pkg>/<module>:<function>:<line>"`` — enough to fingerprint
    a runaway loop without dragging heavy context.
    """
    skip = ("litellm", "utils.llm_telemetry", "utils/llm_telemetry",
            "emergentintegrations", "site-packages/anyio", "asyncio/",
            "concurrent/futures", "threading.py", "backend/llm_decoder.py")
    for frame in inspect.stack()[2:]:
        mod = frame.filename.replace("\\", "/")
        if any(s in mod for s in skip):
            continue
        # Strip everything before /backend/ for readability
        idx = mod.rfind("/backend/")
        short = mod[idx + 1:] if idx >= 0 else os.path.basename(mod)
        return f"{short}:{frame.function}:{frame.lineno}"
    return "unknown"


def install_litellm_hook() -> None:
    """Monkeypatch litellm.completion / acompletion once per process.

    Safe to call from FastAPI startup: idempotent, defensive against
    missing SDK. If ``litellm`` isn't imported this is a no-op.
    """
    with _LOCK:
        if _STATE["litellm_hook_installed"]:
            return
    try:
        import litellm  # type: ignore
    except Exception:
        return

    orig_completion  = getattr(litellm, "completion",  None)
    orig_acompletion = getattr(litellm, "acompletion", None)

    if callable(orig_completion) and not getattr(orig_completion, "_llm_tel", False):
        def _wrapped_completion(*args, **kwargs):
            caller = _infer_caller_from_stack()
            t0 = time.time()
            with _LOCK:
                _STATE["in_flight"] += 1
                _STATE["started_total"] += 1
                if _STATE["in_flight"] > _STATE["peak_in_flight"]:
                    _STATE["peak_in_flight"] = _STATE["in_flight"]
                _bump_caller(caller, "started")
            try:
                out = orig_completion(*args, **kwargs)
                with _LOCK:
                    _STATE["completed_total"] += 1
                    _bump_caller(caller, "completed")
                return out
            except Exception:
                with _LOCK:
                    _STATE["failed_total"] += 1
                    _bump_caller(caller, "failed")
                raise
            finally:
                dt_ms = int((time.time() - t0) * 1000)
                with _LOCK:
                    _STATE["in_flight"] = max(0, _STATE["in_flight"] - 1)
                    _STATE["last_latency_ms"] = dt_ms
                    _RECENT_LATENCIES.append(dt_ms)
        _wrapped_completion._llm_tel = True  # type: ignore[attr-defined]
        litellm.completion = _wrapped_completion

    if callable(orig_acompletion) and not getattr(orig_acompletion, "_llm_tel", False):
        async def _wrapped_acompletion(*args, **kwargs):
            import asyncio
            caller = _infer_caller_from_stack()
            t0 = time.time()
            with _LOCK:
                _STATE["in_flight"] += 1
                _STATE["started_total"] += 1
                if _STATE["in_flight"] > _STATE["peak_in_flight"]:
                    _STATE["peak_in_flight"] = _STATE["in_flight"]
                _bump_caller(caller, "started")
            try:
                out = await orig_acompletion(*args, **kwargs)
                with _LOCK:
                    _STATE["completed_total"] += 1
                    _bump_caller(caller, "completed")
                return out
            except asyncio.TimeoutError:
                with _LOCK:
                    _STATE["timeout_total"] += 1
                    _STATE["failed_total"] += 1
                    _bump_caller(caller, "timeout")
                raise
            except Exception:
                with _LOCK:
                    _STATE["failed_total"] += 1
                    _bump_caller(caller, "failed")
                raise
            finally:
                dt_ms = int((time.time() - t0) * 1000)
                with _LOCK:
                    _STATE["in_flight"] = max(0, _STATE["in_flight"] - 1)
                    _STATE["last_latency_ms"] = dt_ms
                    _RECENT_LATENCIES.append(dt_ms)
        _wrapped_acompletion._llm_tel = True  # type: ignore[attr-defined]
        litellm.acompletion = _wrapped_acompletion

    with _LOCK:
        _STATE["litellm_hook_installed"] = True


def snapshot() -> Dict[str, Any]:
    """Return a copy of the current telemetry state (safe for JSON)."""
    with _LOCK:
        avg = (
            round(sum(_RECENT_LATENCIES) / len(_RECENT_LATENCIES), 1)
            if _RECENT_LATENCIES else None
        )
        return {
            **_STATE,
            "avg_latency_ms": avg,
            "recent_samples": len(_RECENT_LATENCIES),
            "uptime_seconds": int(time.time() - _STATE["started_at_epoch"]),
            "by_caller": {k: dict(v) for k, v in _BY_CALLER.items()},
        }


def reset() -> None:
    """Test-only helper: reset counters."""
    with _LOCK:
        _STATE.update({
            "in_flight": 0,
            "peak_in_flight": 0,
            "started_total": 0,
            "completed_total": 0,
            "failed_total": 0,
            "timeout_total": 0,
            "last_latency_ms": None,
            "started_at_epoch": time.time(),
        })
        _RECENT_LATENCIES.clear()
        _BY_CALLER.clear()
