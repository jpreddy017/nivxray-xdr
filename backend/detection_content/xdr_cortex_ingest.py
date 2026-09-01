"""
Round 26 · Cortex Ingest Fabric — pipeline & audit.
====================================================

Consumes parsed canonical rows and **upserts** them into
``xdr_canonical_evidence`` deterministically.  Never promotes an
alert to an incident (that's Round 26.5).  Every ingest run writes
an audit envelope so replays / gaps are auditable.

Sources:
  · Push  → HMAC-verified webhook (`routes.xdr_cortex_ingest_routes`).
  · Pull  → Scheduled poller via `xdr_cortex_executor.ingest_cortex_alerts`.

Idempotency:
  · `event_id` is deterministic (see `xdr_cortex_parser._event_id`).
  · MongoDB upsert on `event_id` guarantees "same payload → same row".
  · Duplicate counts are reported honestly per run.

Checkpoint:
  · Stored per-integration in ``xdr_cortex_ingest_checkpoints`` keyed
    by ``integration_id``.  Contains ``last_modification_time`` (epoch
    ms) which is the Cortex-native cursor for the incidents endpoint.
"""
from __future__ import annotations

import datetime as _dt
import logging
from typing import Any, Optional

from .xdr_cortex_parser import parse_batch

log = logging.getLogger("nivxray.xdr.cortex_ingest")

CANONICAL       = "xdr_canonical_evidence"
INGEST_AUDIT    = "xdr_cortex_ingest_audit"
CHECKPOINT      = "xdr_cortex_ingest_checkpoints"


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


async def _upsert_rows(db, rows: list[dict]) -> dict:
    """Deterministic upsert on `event_id`.  Reports inserted vs
    duplicate counts honestly."""
    inserted = 0
    duplicates = 0
    for row in rows:
        eid = row.get("event_id")
        if not eid:
            continue
        result = await db[CANONICAL].update_one(
            {"event_id": eid},
            {
                "$setOnInsert": {
                    "event_id":              eid,
                    "vendor":                row.get("vendor"),
                    "source_integration_id": row.get("source_integration_id"),
                    "source_object_type":    row.get("source_object_type"),
                    "source_object_id":      row.get("source_object_id"),
                    "xdr_incident_id":       row.get("xdr_incident_id"),
                    "observed_at":           row.get("observed_at"),
                    "ingested_at":           row.get("ingested_at"),
                    "event_type":            row.get("event_type"),
                    "source":                row.get("source"),
                    "raw":                   row.get("raw"),
                },
                "$set": {
                    # Fields may evolve as vendor payloads update; the
                    # deterministic identity is `event_id`, not the
                    # fields.  We refresh non-identity fields on every
                    # ingest so late-arriving Cortex updates land.
                    "fields":                row.get("fields"),
                    "last_seen_at":          _iso_now(),
                },
            },
            upsert=True,
        )
        if result.upserted_id is not None:
            inserted += 1
        else:
            duplicates += 1
    return {"inserted": inserted, "duplicates": duplicates,
              "total": inserted + duplicates}


async def ingest_payload(db, *, integration_id: str, payload: Any,
                              source: str, principal: str) -> dict:
    """Parse + upsert.  Returns a per-run audit envelope."""
    rows = parse_batch(payload, integration_id=integration_id)
    stats = await _upsert_rows(db, rows) if rows \
                else {"inserted": 0, "duplicates": 0, "total": 0}
    envelope = {
        "integration_id": integration_id,
        "source":         source,     # "webhook" | "poller"
        "principal":      principal,
        "rows_parsed":    len(rows),
        "rows_inserted":  stats["inserted"],
        "rows_duplicate": stats["duplicates"],
        "at":             _iso_now(),
    }
    await db[INGEST_AUDIT].insert_one(dict(envelope))
    return envelope


# ── Checkpoint ──────────────────────────────────────────────
async def get_checkpoint(db, integration_id: str) -> Optional[int]:
    doc = await db[CHECKPOINT].find_one(
        {"integration_id": integration_id}, {"_id": 0})
    if doc is None:
        return None
    v = doc.get("last_modification_time")
    return int(v) if v is not None else None


async def set_checkpoint(db, integration_id: str,
                                last_modification_time: int) -> None:
    await db[CHECKPOINT].update_one(
        {"integration_id": integration_id},
        {"$set": {"integration_id": integration_id,
                     "last_modification_time": int(last_modification_time),
                     "updated_at": _iso_now()}},
        upsert=True,
    )


def latest_modification_time(rows: list[dict]) -> Optional[int]:
    """Compute the highest `modification_time` in an incident batch
    so the poller can advance its cursor deterministically."""
    best = None
    for row in rows:
        if row.get("source_object_type") != "incident":
            continue
        raw = row.get("raw") or {}
        mt = raw.get("modification_time")
        if isinstance(mt, (int, float)):
            v = int(mt)
            if best is None or v > best:
                best = v
    return best
