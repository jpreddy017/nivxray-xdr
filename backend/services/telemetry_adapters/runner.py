"""
NivXRay XDR · Telemetry Ingestion Runner — Phase 2 operationalisation.

Owner rules baked in:

  * Never bypass the adapter boundary.  Vendor parsing lives
    only inside adapters registered with `TelemetryAdapterRegistry`.
  * Deterministic dedup: `CanonicalEvent.canonical_id` is the
    idempotency key.  Restart/resume never emits duplicates.
  * Preserve BOTH source_event_time (from the vendor) and
    ingested_at (stamped by the adapter).  We do not overwrite
    one with the other.
  * Never fabricate telemetry when a provider is unavailable.
    A poller that fails records the failure in ingestion health
    and moves on.
  * Never expose credentials in logs, health endpoints or exceptions.
  * Idempotency + provenance are the contract; everything else is
    replaceable.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Protocol


from .framework import (
    CanonicalEvent, TelemetryAdapter, get_registry,
)


log = logging.getLogger("nivxray.telemetry.runner")


# --------------------------------------------------------------------
# Poller protocol.  A poller is a vendor-facing IO adapter that
# fetches raw records from a source starting at `cursor`.  It
# returns `(raw_records, next_cursor)`.  The runner does NOT know
# what a cursor looks like — that's vendor-defined.
# --------------------------------------------------------------------
class SourcePoller(Protocol):
    async def fetch(self, cursor: str | None
                                    ) -> tuple[list[dict[str, Any]], str | None]: ...


# --------------------------------------------------------------------
@dataclass(frozen=True)
class IngestionJob:
    """One adapter + one poller + one persistence store.

    The runner never inspects `poller` beyond the `fetch()` call —
    keeping vendor logic strictly behind the adapter boundary."""
    name:         str                     # human-readable job id
    adapter_name: str                     # must exist in TelemetryAdapterRegistry
    poller:       SourcePoller
    interval_s:   float = 60.0
    batch_limit:  int   = 500


@dataclass
class IngestionHealth:
    """Public health snapshot.  No secrets, ever."""
    job:                str
    adapter:            str
    last_run_at:        str | None = None
    last_success_at:    str | None = None
    last_error_at:      str | None = None
    last_error_message: str | None = None       # scrubbed, never a credential
    lag_seconds:        float | None = None
    checkpoint_cursor:  str | None = None
    total_events_in:    int = 0
    total_events_out:   int = 0
    total_dedup_dropped: int = 0
    consecutive_failures: int = 0
    state:              str = "IDLE"            # IDLE|RUNNING|OK|DEGRADED|FAILED


# --------------------------------------------------------------------
# Checkpoint + dedup store contracts.  In production we back them
# with Mongo (`_MongoCheckpoint`); tests use in-memory
# `InMemoryCheckpoint` to keep the invariants deterministic and
# credential-free.
# --------------------------------------------------------------------
class CheckpointStore(Protocol):
    async def read (self, job: str) -> str | None: ...
    async def write(self, job: str, cursor: str | None) -> None: ...


class DedupStore(Protocol):
    async def seen(self, canonical_ids: list[str]) -> set[str]: ...
    async def remember(self, canonical_ids: list[str]) -> None: ...


class InMemoryCheckpoint(dict, CheckpointStore):
    async def read(self, job): return self.get(job)
    async def write(self, job, cursor):
        if cursor is None:
            self.pop(job, None)
        else:
            self[job] = cursor


class InMemoryDedup(set, DedupStore):
    async def seen(self, canonical_ids): return {c for c in canonical_ids if c in self}
    async def remember(self, canonical_ids):
        for c in canonical_ids:
            self.add(c)


# --------------------------------------------------------------------
class IngestionRunner:
    """Scheduled poller → adapter → dedup → sink.

    The runner is intentionally passive: it does NOT talk to
    Mongo directly, does NOT know vendor URLs and does NOT hold
    secrets.  Callers wire concrete `SourcePoller`, `CheckpointStore`,
    `DedupStore` and `sink` implementations at boot time.
    """
    def __init__(
        self,
        checkpoint_store: CheckpointStore,
        dedup_store:      DedupStore,
        sink:             Callable[[list[CanonicalEvent]], Awaitable[None]],
    ):
        self._ckp = checkpoint_store
        self._dd  = dedup_store
        self._sink = sink
        self._jobs: dict[str, IngestionJob] = {}
        self._health: dict[str, IngestionHealth] = {}
        self._tasks: dict[str, asyncio.Task] = {}

    def register(self, job: IngestionJob) -> None:
        if job.name in self._jobs:
            raise ValueError(f"job already registered: {job.name}")
        # Validate adapter exists NOW so misconfiguration fails fast.
        get_registry().get(job.adapter_name)
        self._jobs[job.name] = job
        self._health[job.name] = IngestionHealth(
            job=job.name, adapter=job.adapter_name)

    def health(self) -> list[dict[str, Any]]:
        return [
            {
                "job":                  h.job,
                "adapter":              h.adapter,
                "state":                h.state,
                "last_run_at":          h.last_run_at,
                "last_success_at":      h.last_success_at,
                "last_error_at":        h.last_error_at,
                "last_error_message":   h.last_error_message,
                "lag_seconds":          h.lag_seconds,
                "checkpoint_cursor":    h.checkpoint_cursor,
                "total_events_in":      h.total_events_in,
                "total_events_out":     h.total_events_out,
                "total_dedup_dropped":  h.total_dedup_dropped,
                "consecutive_failures": h.consecutive_failures,
            }
            for h in self._health.values()
        ]

    # ---------- single tick (public for tests + smoke) --------------
    async def tick(self, job_name: str) -> IngestionHealth:
        job = self._jobs[job_name]
        adapter: TelemetryAdapter = get_registry().get(job.adapter_name)
        h = self._health[job_name]
        h.state = "RUNNING"
        h.last_run_at = _now()
        try:
            cursor = await self._ckp.read(job.name)
            raw, next_cursor = await job.poller.fetch(cursor)
            raw = raw[:job.batch_limit]
            h.total_events_in += len(raw)
            events = await adapter.normalise(raw)
            ids    = [e.canonical_id for e in events]
            already = await self._dd.seen(ids)
            fresh  = [e for e in events if e.canonical_id not in already]
            h.total_dedup_dropped += len(events) - len(fresh)
            if fresh:
                await self._sink(fresh)
                await self._dd.remember([e.canonical_id for e in fresh])
            h.total_events_out += len(fresh)
            if next_cursor is not None:
                await self._ckp.write(job.name, next_cursor)
                h.checkpoint_cursor = next_cursor
            h.last_success_at = _now()
            h.consecutive_failures = 0
            h.last_error_at = None
            h.last_error_message = None
            h.state = "OK"
            h.lag_seconds = _lag_seconds(fresh)
            return h
        except Exception as e:                      # noqa: BLE001
            h.last_error_at = _now()
            # Scrub credentials — the exception string is bounded
            # to the first 240 chars and never emitted at DEBUG.
            h.last_error_message = _scrub(str(e))[:240]
            h.consecutive_failures += 1
            h.state = "DEGRADED" if h.consecutive_failures < 3 else "FAILED"
            log.warning("ingestion tick failed for %s (%s)",
                                job_name, h.last_error_message)
            return h


# ---- helpers -------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _lag_seconds(events: list[CanonicalEvent]) -> float | None:
    if not events:
        return None
    latest_source = None
    for e in events:
        p = e.provenance
        if p and p.source_event_time:
            try:
                t = datetime.fromisoformat(
                    p.source_event_time.replace("Z", "+00:00"))
                if latest_source is None or t > latest_source:
                    latest_source = t
            except ValueError:
                continue
    if latest_source is None:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (now - latest_source).total_seconds())


_SECRET_PATTERNS = (
    "authorization", "bearer", "api-key", "apikey", "x-api-key",
    "aws_access_key", "aws_secret", "client_secret",
    "password", "token=", "sessiontoken",
)

def _scrub(msg: str) -> str:
    low = msg.lower()
    for p in _SECRET_PATTERNS:
        if p in low:
            return "[redacted: contained a credential-shaped token]"
    return msg
