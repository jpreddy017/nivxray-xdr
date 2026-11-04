"""Renew live processing claims; downstream writes still need idempotency."""
import asyncio
from datetime import timedelta, timezone

class ProcessingLeaseLost(RuntimeError):
    pass

async def renew(db, *, tenant_id, raw_id, attempts, lease_seconds):
    from edr_plane.processing_queue import COLLECTION, PROCESSING, _now
    now = _now()
    result = await db[COLLECTION].update_one(
        {"tenant_id": tenant_id, "raw_id": raw_id, "state": PROCESSING,
         "attempts": attempts, "lease_until": {"$gt": now}},
        {"$set": {"lease_until": now + timedelta(seconds=max(1, lease_seconds)),
                  "updated_at": now}},
    )
    return bool(result.matched_count)

async def run_with_lease(db, job, work, *, lease_seconds):
    """Cancel and await work on renewal failure; never revive expired claims."""
    from edr_plane.processing_queue import _now
    try:
        deadline = job["lease_until"]
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
        remaining = (deadline - _now()).total_seconds()
    except BaseException:
        work.close()
        raise
    if remaining <= 0:
        work.close()
        raise ProcessingLeaseLost("processing lease expired before work started")
    interval = min(max(1, lease_seconds) / 3, remaining / 3)
    task = asyncio.create_task(work)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=interval)
            if done:
                return await task
            try:
                owned = await asyncio.wait_for(
                    renew(db, tenant_id=job["tenant_id"], raw_id=job["raw_id"],
                          attempts=job["attempts"], lease_seconds=lease_seconds),
                    timeout=interval,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                raise ProcessingLeaseLost("processing lease renewal failed") from exc
            if not owned:
                raise ProcessingLeaseLost("processing lease ownership lost")
            interval = max(1, lease_seconds) / 3
    finally:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
