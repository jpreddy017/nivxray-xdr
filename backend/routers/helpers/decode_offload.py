"""Run server-owned decoder callables in killable bounded workers.

The thread only supervises child lifecycle. A timeout joins/terminates/reaps the
child before returning 504; it never abandons ongoing decoding in an executor.
"""
import asyncio
import functools
from services.decoder.isolated import invoke

DEFAULT_DECODE_TIMEOUT_S = 25.0

async def run_offloaded(fn, *args, timeout_s=DEFAULT_DECODE_TIMEOUT_S, **kwargs):
    # Importable functions only. Do not accept names from a request body.
    if '<locals>' in fn.__qualname__:
        raise TypeError('Offloaded decoder functions must be module-level')
    task = asyncio.create_task(asyncio.to_thread(
        invoke, fn.__module__, fn.__qualname__, args, kwargs,
        min(timeout_s, DEFAULT_DECODE_TIMEOUT_S),
    ))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # Keep admission occupied until supervision has reaped the child.
        # Decode work remains bounded even when the client disconnects.
        try:
            await asyncio.shield(task)
        except Exception:
            pass
        raise
