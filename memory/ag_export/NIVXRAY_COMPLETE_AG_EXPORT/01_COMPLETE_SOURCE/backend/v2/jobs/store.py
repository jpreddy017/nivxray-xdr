"""MongoDB-backed persistence for AUTO INVESTIGATE background jobs.

Collection: `v2_ai_jobs`
Document shape:
  {
    "_id":            <uuid>,
    "job_id":         <uuid>,
    "status":         "queued" | "running" | "complete" | "failed",
    "created_at":     ISO-8601 UTC,
    "updated_at":     ISO-8601 UTC,
    "created_by":     <user email>,
    "incident_bytes": int,
    "focus":          str | None,
    "progress": {
        "stage":   str,      # parsing | decoding | osint | aggregating | reporting | done
        "percent": int,      # 0..100
        "message": str,
        "steps":   [{stage, percent, message, ts}],  # append-only log
    },
    "decode_statuses": [ { binary, status, bytes, seconds, message } ],
    "result":         <FinalIncidentSummary payload> | None,
    "error":          <str> | None,
  }
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from deps import db


COLL = "v2_ai_jobs"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def create_job(*, incident_text: str, focus: str | None, user_email: str) -> dict:
    job_id = f"aij-{uuid.uuid4().hex[:16]}"
    doc = {
        "_id": job_id,
        "job_id": job_id,
        "status": "queued",
        "created_at": _now(),
        "updated_at": _now(),
        "created_by": user_email,
        "incident_bytes": len(incident_text.encode("utf-8", errors="ignore")),
        "focus": focus,
        "progress": {
            "stage": "queued",
            "percent": 0,
            "message": "Investigation queued",
            "steps": [{"stage": "queued", "percent": 0,
                       "message": "Investigation queued", "ts": _now()}],
        },
        "decode_statuses": [],
        "result": None,
        "error": None,
    }
    await db[COLL].insert_one(doc)
    return doc


async def get_job(job_id: str) -> dict | None:
    return await db[COLL].find_one({"_id": job_id})


async def set_progress(job_id: str, *, stage: str, percent: int, message: str) -> None:
    ts = _now()
    await db[COLL].update_one(
        {"_id": job_id},
        {
            "$set": {
                "progress.stage": stage,
                "progress.percent": percent,
                "progress.message": message,
                "updated_at": ts,
                "status": "running" if stage not in ("done", "failed") else "running",
            },
            "$push": {
                "progress.steps": {"stage": stage, "percent": percent,
                                   "message": message, "ts": ts},
            },
        },
    )


async def append_command_status(job_id: str, status: dict) -> None:
    await db[COLL].update_one(
        {"_id": job_id},
        {"$push": {"decode_statuses": status},
         "$set": {"updated_at": _now()}},
    )


async def mark_complete(job_id: str, result: dict[str, Any]) -> None:
    await db[COLL].update_one(
        {"_id": job_id},
        {"$set": {
            "status": "complete",
            "progress.stage": "done",
            "progress.percent": 100,
            "progress.message": "Investigation complete",
            "result": result,
            "updated_at": _now(),
        }},
    )


async def mark_failed(job_id: str, error: str) -> None:
    await db[COLL].update_one(
        {"_id": job_id},
        {"$set": {
            "status": "failed",
            "progress.stage": "failed",
            "progress.message": error[:500],
            "error": error[:2000],
            "updated_at": _now(),
        }},
    )
