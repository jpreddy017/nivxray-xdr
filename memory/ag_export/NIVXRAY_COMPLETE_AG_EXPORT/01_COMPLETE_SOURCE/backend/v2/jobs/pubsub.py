"""In-memory per-job pub/sub for AUTO INVESTIGATE progress streaming.

One `asyncio.Queue` per active subscriber per job. Publishers fan-out
non-blockingly — if a subscriber is slow, its queue backs up but the
publisher never blocks the worker.

Also keeps a ring buffer of the last N events per job so a late-joining
WebSocket subscriber immediately catches up on what already happened.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict, deque
from typing import Any

log = logging.getLogger("nivx.jobs.pubsub")

# Per-job list of subscriber queues.
_subs: dict[str, list[asyncio.Queue]] = defaultdict(list)
# Per-job ring buffer of the most recent events so late-joining WS
# clients can replay the timeline before receiving new updates.
_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=512))
# Guard subscribe/unsubscribe against concurrent publishes.
_lock = asyncio.Lock()


async def publish(job_id: str, event: dict[str, Any]) -> None:
    """Fan-out an event to every subscriber of `job_id`. Non-blocking on
    slow subscribers — a full queue simply drops the oldest item."""
    _history[job_id].append(event)
    async with _lock:
        subs = list(_subs.get(job_id, ()))
    for q in subs:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            try:
                q.get_nowait()
            except Exception:
                pass
            try:
                q.put_nowait(event)
            except Exception:
                log.warning("pubsub: dropped event for job=%s", job_id)


async def subscribe(job_id: str) -> asyncio.Queue:
    """Return a new subscriber queue pre-loaded with the event history."""
    q: asyncio.Queue = asyncio.Queue(maxsize=1024)
    for ev in list(_history.get(job_id, ())):
        try:
            q.put_nowait(ev)
        except asyncio.QueueFull:
            break
    async with _lock:
        _subs[job_id].append(q)
    return q


async def unsubscribe(job_id: str, q: asyncio.Queue) -> None:
    async with _lock:
        if job_id in _subs and q in _subs[job_id]:
            _subs[job_id].remove(q)
            if not _subs[job_id]:
                _subs.pop(job_id, None)


def close_job(job_id: str) -> None:
    """Drop the event history once the job has fully completed and
    no subscribers remain. Idempotent."""
    _history.pop(job_id, None)
