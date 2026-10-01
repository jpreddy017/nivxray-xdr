"""Offload CPU-bound decoder work off the FastAPI event loop.

v1.5.6 · Feb-2026 · SME/deployer directive
============================================

The NivXRay backend runs CPU-bound decoders (`xor-brute`, `L3`,
`magic_decode`, the recipe replay loop) synchronously inside async
FastAPI handlers. On tier_0's 250 mCPU cap a single heavy decode
monopolises the CPU quota and blocks the asyncio event loop for
17-21 seconds. During that window `/api/health` cannot answer within
nginx's 1s proxy timeout, so k8s liveness probes fail 9× and the
container is killed → Cloudflare fronts an empty response → **520**.

This helper moves the sync CPU work into asyncio's default thread
executor. Python still holds the GIL inside pure-Python decoder
loops (e.g. `_xor_bruteforce_256`) but releases it every ~5ms, which
is enough headroom for the event loop to service `/api/health` in
well under 1s. A hard wall-clock budget via `asyncio.wait_for`
prevents any single decode from running forever and starving the
executor pool.

Usage
-----

    from routers.helpers.decode_offload import run_offloaded

    @router.post("/decode/smart")
    async def decode_smart(body: AutoIn, ...):
        result = await run_offloaded(
            deterministic_best_decode,
            body.input,
            analysis_mode=body.analysis_mode or "balanced",
            timeout_s=25.0,     # per-request wall-clock budget
        )

The helper does NOT change the decoder's own return contract —
callers see the same dict/tuple/etc. they always did.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable

from fastapi import HTTPException

log = logging.getLogger("nivx.routers.helpers.decode_offload")

# Default per-request budget. `xor-brute` was observed at 21500 ms
# on 845 B in production (RC5); 25 s gives a small safety margin
# above the worst observed decode while still bounded enough that a
# stuck decoder never accumulates in the executor pool.
DEFAULT_DECODE_TIMEOUT_S = 25.0


async def run_offloaded(
    fn: Callable[..., Any],
    *args: Any,
    timeout_s: float = DEFAULT_DECODE_TIMEOUT_S,
    **kwargs: Any,
) -> Any:
    """Run a sync CPU-bound function in the default thread executor,
    bounded by a hard wall-clock ``timeout_s``.

    On timeout: raises ``HTTPException(504, ...)`` with a machine-
    parseable ``code=decode_timeout``. The FastAPI handler contract
    is preserved (never surface the raw ``asyncio.TimeoutError``).

    On exception inside ``fn``: re-raises unchanged so existing
    handler error mapping still applies.
    """
    loop = asyncio.get_running_loop()

    def _invoke():
        return fn(*args, **kwargs)

    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _invoke),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        # Structured log so on-call can grep budget breaches.
        log.warning(
            "decode_timeout fn=%s timeout_s=%.1f args_len=%s",
            getattr(fn, "__qualname__", getattr(fn, "__name__", str(fn))),
            timeout_s,
            _safe_arg_len(args),
        )
        raise HTTPException(
            status_code=504,
            detail={
                "code": "decode_timeout",
                "message": (
                    f"Decode operation exceeded {timeout_s:.0f}s wall-clock "
                    "budget. Payload may be adversarially crafted to stall "
                    "the decoder or the recipe chain is genuinely too long."
                ),
                "budget_s": timeout_s,
            },
        )


def _safe_arg_len(args: tuple[Any, ...]) -> int | None:
    """Best-effort input length for observability."""
    if not args:
        return None
    first = args[0]
    try:
        return len(first)
    except Exception:
        return None
