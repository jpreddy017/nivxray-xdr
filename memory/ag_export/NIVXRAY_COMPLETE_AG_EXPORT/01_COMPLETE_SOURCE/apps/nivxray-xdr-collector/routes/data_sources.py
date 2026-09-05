"""
Data-sources projection consumed by the XDR Admin > Data Sources UI.
"""
from __future__ import annotations

from fastapi import APIRouter, Request

router = APIRouter(tags=["data-sources"])


@router.get("/data-sources")
def list_data_sources(request: Request):
    store  = getattr(request.app.state, "store", None)
    instances = getattr(request.app.state, "instances", {})
    rows = []
    for rec in (store.list() if store else []):
        inst = instances.get(rec.id)
        d = inst.describe() if inst else {}
        rows.append({
            "source":          rec.label,
            "type":            rec.source_type,
            "tenant_id":       rec.tenant_id,
            "status":          d.get("health", "not_started"),
            "last_collection": (d.get("metrics") or {}).get("last_success"),
            "events":          (d.get("metrics") or {}).get("events_accepted", 0),
            "events_collected": (d.get("metrics") or {}).get("events_collected", 0),
            "events_duplicated": (d.get("metrics") or {}).get("events_duplicated", 0),
            "events_failed":   (d.get("metrics") or {}).get("events_failed", 0),
            "lag_seconds":     (d.get("metrics") or {}).get("collection_lag_seconds"),
            "connector_id":    rec.id,
            "capabilities":    d.get("capabilities", []),
            "created_at":      rec.created_at,
            "enabled":         rec.enabled,
        })
    return {"data_sources": rows, "count": len(rows), "phase": "B"}
