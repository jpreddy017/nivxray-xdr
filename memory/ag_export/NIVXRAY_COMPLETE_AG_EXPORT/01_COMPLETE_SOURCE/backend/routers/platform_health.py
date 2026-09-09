"""Platform Health Dashboard — Phase A.5 · item 3.3.

Endpoints:
    GET  /api/platform/metrics       — current snapshot (8 sections)
    POST /api/platform/snapshot      — persist a snapshot for trend lines
    GET  /api/platform/timeseries    — last N persisted snapshots

Owner-locked scope (2026-02-16). Read-only consumer of the SSOT +
Golden Corpus baselines + NVKC descriptors.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from pymongo import MongoClient

from deps import get_current_user
from services.platform_metrics import (
    PLATFORM_METRICS_VERSION,
    compute_snapshot,
    snapshot_body_hash,
)

router = APIRouter(prefix="/platform", tags=["platform"])

# Dedicated sync pymongo client for this read-only aggregation.
# compute_snapshot() uses sync APIs so this stays simple; the
# dashboard's slow reads never block the async event loop's critical
# paths.
_SYNC_DB = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


@router.get("/metrics")
def get_metrics(user=Depends(get_current_user)):
    snap = compute_snapshot(_SYNC_DB)
    snap["body_hash"] = snapshot_body_hash(snap)
    return snap


@router.post("/snapshot")
def persist_snapshot(user=Depends(get_current_user)):
    """Persist a snapshot so trend lines accumulate. Idempotent within
    the same UTC day: repeated calls that produce the same body don't
    duplicate rows."""
    snap = compute_snapshot(_SYNC_DB)
    body_hash = snapshot_body_hash(snap)
    today = datetime.now(timezone.utc).date().isoformat()
    if _SYNC_DB.platform_metrics_snapshots.find_one(
            {"body_hash": body_hash, "date_bucket": today}):
        return {"stored": False, "reason": "duplicate_body_hash",
                "body_hash": body_hash, "date_bucket": today}
    email = user.get("email") if isinstance(user, dict) else getattr(user, "email", None)
    doc = {**snap, "body_hash": body_hash, "date_bucket": today,
           "actor": email}
    _SYNC_DB.platform_metrics_snapshots.insert_one(doc)
    return {"stored": True, "body_hash": body_hash, "date_bucket": today}


@router.get("/timeseries")
def get_timeseries(limit: int = 30, user=Depends(get_current_user)):
    if limit < 1 or limit > 365:
        raise HTTPException(status_code=400, detail="limit_out_of_range")
    cur = _SYNC_DB.platform_metrics_snapshots.find(
        {}, {"_id": 0, "computed_at": 1, "body_hash": 1, "date_bucket": 1,
             "pipeline_health.decode_success_rate": 1,
             "pipeline_health.investigation_success_rate": 1,
             "pipeline_health.total_cases": 1,
             "explainability.metrics": 1,
             "coverage.mitre_id_count": 1,
             "coverage.analyzer_type_count": 1,
             "fingerprint_stability.golden_corpus.coverage": 1,
             "nvkc.total_samples": 1}
    ).sort("computed_at", -1).limit(limit)
    items: List[Dict[str, Any]] = list(cur)
    items.reverse()   # oldest-first for charts
    return {"items": items, "count": len(items),
            "platform_metrics_version": PLATFORM_METRICS_VERSION}
