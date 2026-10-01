"""Durable downstream-processing queue for authenticated EDR raw evidence.

The sensor may release its local copy only after:
  1. immutable raw evidence is durably retained, and
  2. durable downstream work exists for that raw event.

This queue is idempotent on (tenant_id, raw_id).  It deliberately stores
references to immutable raw evidence rather than copying telemetry payloads.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from pymongo import ReturnDocument

COLLECTION = "edr_processing_queue"

PENDING = "PENDING"
PROCESSING = "PROCESSING"
RETRY = "RETRY"
DONE = "DONE"


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def ensure_indexes(db: Any) -> None:
    """Create the indexes required for idempotency and worker claiming."""
    await db[COLLECTION].create_index(
        [("tenant_id", 1), ("raw_id", 1)],
        unique=True,
        name="uniq_tenant_raw",
    )
    await db[COLLECTION].create_index(
        [("state", 1), ("available_at", 1), ("created_at", 1)],
        name="claimable_work",
    )
    await db[COLLECTION].create_index(
        [("state", 1), ("lease_until", 1)],
        name="expired_leases",
    )


async def enqueue(
    db: Any,
    *,
    tenant_id: str,
    raw_id: str,
) -> dict[str, Any]:
    """Ensure exactly one durable downstream-work item exists.

    Re-delivery is harmless: an existing job is returned unchanged rather
    than creating duplicate downstream processing.
    """
    now = _now()

    result = await db[COLLECTION].update_one(
        {"tenant_id": tenant_id, "raw_id": raw_id},
        {
            "$setOnInsert": {
                "tenant_id": tenant_id,
                "raw_id": raw_id,
                "state": PENDING,
                "attempts": 0,
                "created_at": now,
                "updated_at": now,
                "available_at": now,
                "lease_until": None,
                "last_error": None,
                "completed_at": None,
            }
        },
        upsert=True,
    )

    return {
        "tenant_id": tenant_id,
        "raw_id": raw_id,
        "created": result.upserted_id is not None,
    }


async def claim(
    db: Any,
    *,
    lease_seconds: int = 60,
) -> dict[str, Any] | None:
    """Atomically claim one pending/retryable job.

    Expired PROCESSING leases are also reclaimable so a worker crash cannot
    permanently strand evidence.
    """
    now = _now()
    lease_until = now + timedelta(seconds=max(1, lease_seconds))

    return await db[COLLECTION].find_one_and_update(
        {
            "$or": [
                {
                    "state": {"$in": [PENDING, RETRY]},
                    "available_at": {"$lte": now},
                },
                {
                    "state": PROCESSING,
                    "lease_until": {"$lte": now},
                },
            ]
        },
        {
            "$set": {
                "state": PROCESSING,
                "lease_until": lease_until,
                "updated_at": now,
            },
            "$inc": {"attempts": 1},
        },
        sort=[("created_at", 1)],
        return_document=ReturnDocument.AFTER,
    )


async def mark_done(
    db: Any,
    *,
    tenant_id: str,
    raw_id: str,
) -> bool:
    """Mark successfully processed durable work complete."""
    now = _now()
    result = await db[COLLECTION].update_one(
        {
            "tenant_id": tenant_id,
            "raw_id": raw_id,
            "state": PROCESSING,
        },
        {
            "$set": {
                "state": DONE,
                "completed_at": now,
                "updated_at": now,
                "lease_until": None,
                "last_error": None,
            }
        },
    )
    return bool(result.modified_count)


async def mark_retry(
    db: Any,
    *,
    tenant_id: str,
    raw_id: str,
    error: str,
    retry_after_seconds: int = 30,
) -> bool:
    """Return failed work to the durable queue without losing evidence."""
    now = _now()
    available_at = now + timedelta(seconds=max(1, retry_after_seconds))

    result = await db[COLLECTION].update_one(
        {
            "tenant_id": tenant_id,
            "raw_id": raw_id,
            "state": PROCESSING,
        },
        {
            "$set": {
                "state": RETRY,
                "available_at": available_at,
                "updated_at": now,
                "lease_until": None,
                "last_error": str(error)[:1000],
            }
        },
    )
    return bool(result.modified_count)


# ---------------------------------------------------------------------------
# Durable downstream worker
# ---------------------------------------------------------------------------

DEFAULT_WORKER_LEASE_SECONDS = 600
DEFAULT_RETRY_SECONDS = 30


async def process_one(
    db: Any,
    *,
    lease_seconds: int = DEFAULT_WORKER_LEASE_SECONDS,
    retry_after_seconds: int = DEFAULT_RETRY_SECONDS,
) -> dict[str, Any]:
    """Claim and process one durable EDR work item.

    The HTTP ingest path never calls the canonical/XDR bridge.  This worker
    consumes the durable obligation after the endpoint has been ACKed.

    A claimed job reaches DONE only after the canonical bridge returns.
    Missing/malformed raw evidence or bridge exceptions remain durable RETRY
    work; they are never silently discarded.
    """
    from edr_plane import raw_events
    from edr_plane.canonical_bridge import bridge

    job = await claim(db, lease_seconds=lease_seconds)
    if not job:
        return {"processed": False, "reason": "no_work"}

    tenant_id = job["tenant_id"]
    raw_id = job["raw_id"]

    try:
        raw_doc = await raw_events.get(
            db,
            tenant_id=tenant_id,
            raw_id=raw_id,
        )

        if not raw_doc:
            raise RuntimeError(
                f"raw evidence missing for durable job {tenant_id}/{raw_id}"
            )

        authentication = raw_doc.get("authentication")
        if not isinstance(authentication, dict):
            raise RuntimeError(
                f"authenticated provenance missing for raw event {raw_id}"
            )

        endpoint_id = (
            authentication.get("endpoint_id")
            or raw_doc.get("endpoint_ref")
        )
        if not endpoint_id:
            raise RuntimeError(
                f"endpoint identity missing for raw event {raw_id}"
            )

        result = await bridge(
            db,
            raw_id=raw_id,
            tenant_id=tenant_id,
            payload=raw_doc["payload"],
            endpoint_id=endpoint_id,
            hostname=authentication.get("hostname"),
            authentication=authentication,
            source_kind=raw_doc.get("source_kind"),
            sensor_version=raw_doc.get("sensor_version"),
            nivx_received_at=raw_doc.get("ingest_time"),
        )

        completed = await mark_done(
            db,
            tenant_id=tenant_id,
            raw_id=raw_id,
        )
        if not completed:
            raise RuntimeError(
                f"lost processing lease before DONE for {tenant_id}/{raw_id}"
            )

        return {
            "processed": True,
            "tenant_id": tenant_id,
            "raw_id": raw_id,
            "state": DONE,
            "canonical": result,
        }

    except Exception as exc:
        retried = await mark_retry(
            db,
            tenant_id=tenant_id,
            raw_id=raw_id,
            error=str(exc),
            retry_after_seconds=retry_after_seconds,
        )

        return {
            "processed": False,
            "tenant_id": tenant_id,
            "raw_id": raw_id,
            "state": RETRY if retried else PROCESSING,
            "retry_recorded": retried,
            "error": str(exc)[:1000],
        }


async def reconcile_missing_jobs(
    db: Any,
    *,
    limit: int = 500,
) -> dict[str, int]:
    """Repair authenticated raw evidence missing a durable processing job.

    Mongo performs the anti-join against edr_processing_queue, so already
    covered historical rows cannot permanently hide a later missing job.
    enqueue() remains the final idempotent authority.
    """
    from edr_plane import raw_events

    limit = max(1, min(int(limit), 5000))

    pipeline = [
        {"$match": {"trust_state": "AUTHENTICATED"}},
        {"$lookup": {
            "from": COLLECTION,
            "let": {
                "tenant": "$tenant_id",
                "raw": "$raw_id",
            },
            "pipeline": [
                {"$match": {"$expr": {"$and": [
                    {"$eq": ["$tenant_id", "$$tenant"]},
                    {"$eq": ["$raw_id", "$$raw"]},
                ]}}},
                {"$limit": 1},
            ],
            "as": "_processing_job",
        }},
        {"$match": {"_processing_job": {"$eq": []}}},
        {"$sort": {"ingest_time": 1}},
        {"$limit": limit},
        {"$project": {
            "_id": 0,
            "tenant_id": 1,
            "raw_id": 1,
        }},
    ]

    cursor = db[raw_events.COLLECTION].aggregate(pipeline)

    scanned = 0
    created = 0
    already_present = 0

    async for raw_doc in cursor:
        tenant_id = raw_doc.get("tenant_id")
        raw_id = raw_doc.get("raw_id")

        if not tenant_id or not raw_id:
            continue

        scanned += 1

        result = await enqueue(
            db,
            tenant_id=tenant_id,
            raw_id=raw_id,
        )

        if result["created"]:
            created += 1
        else:
            # Another worker/reconciler may have repaired it after the
            # aggregation snapshot. That race is safe because enqueue()
            # is idempotent.
            already_present += 1

    return {
        "scanned": scanned,
        "created": created,
        "already_present": already_present,
    }


# ---------------------------------------------------------------------------
# Worker supervisor lifecycle
# ---------------------------------------------------------------------------

import asyncio

_supervisor_task: asyncio.Task | None = None
_stop_event: asyncio.Event | None = None


async def _worker_loop(
    db: Any,
    *,
    idle_seconds: float = 1.0,
) -> None:
    """Continuously consume durable work with bounded concurrency."""
    assert _stop_event is not None

    while not _stop_event.is_set():
        try:
            result = await process_one(
                db,
                lease_seconds=DEFAULT_WORKER_LEASE_SECONDS,
                retry_after_seconds=DEFAULT_RETRY_SECONDS,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # A transient claim/database failure must not permanently kill
            # this worker. Back off before retrying to avoid a hot failure
            # loop while the dependency is unavailable.
            try:
                await asyncio.wait_for(
                    _stop_event.wait(),
                    timeout=idle_seconds,
                )
            except asyncio.TimeoutError:
                pass
            continue

        if not result.get("processed") and result.get("reason") == "no_work":
            try:
                await asyncio.wait_for(
                    _stop_event.wait(),
                    timeout=idle_seconds,
                )
            except asyncio.TimeoutError:
                pass


async def _supervisor(
    db: Any,
    *,
    worker_count: int,
    reconcile_interval_seconds: int,
) -> None:
    """Run bounded workers plus periodic crash-window reconciliation."""
    assert _stop_event is not None

    workers = [
        asyncio.create_task(
            _worker_loop(db),
            name=f"edr-processing-worker-{i + 1}",
        )
        for i in range(worker_count)
    ]

    try:
        while not _stop_event.is_set():
            try:
                await reconcile_missing_jobs(db)
            except Exception:
                # Reconciliation failure must not kill delivery workers.
                pass

            try:
                await asyncio.wait_for(
                    _stop_event.wait(),
                    timeout=max(5, reconcile_interval_seconds),
                )
            except asyncio.TimeoutError:
                pass
    finally:
        for task in workers:
            task.cancel()

        await asyncio.gather(*workers, return_exceptions=True)


async def start_workers(
    db: Any,
    *,
    worker_count: int = 2,
    reconcile_interval_seconds: int = 60,
) -> bool:
    """Start exactly one bounded EDR processing supervisor per process."""
    global _supervisor_task, _stop_event

    if _supervisor_task is not None and not _supervisor_task.done():
        return False

    worker_count = max(1, min(int(worker_count), 8))

    _stop_event = asyncio.Event()
    _supervisor_task = asyncio.create_task(
        _supervisor(
            db,
            worker_count=worker_count,
            reconcile_interval_seconds=reconcile_interval_seconds,
        ),
        name="edr-processing-supervisor",
    )
    return True


async def stop_workers() -> None:
    """Stop the supervisor and wait for its bounded workers to exit."""
    global _supervisor_task, _stop_event

    task = _supervisor_task
    stop = _stop_event

    if task is None:
        return

    if stop is not None:
        stop.set()

    try:
        await asyncio.wait_for(task, timeout=15)
    except asyncio.TimeoutError:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    finally:
        _supervisor_task = None
        _stop_event = None
