from fastapi import APIRouter, Request

router = APIRouter(tags=["data-sources"])


@router.get("/data-sources")
def list_data_sources(request: Request):
    """Data-sources projection consumed by the XDR Admin > Data Sources.

    Every row carries the exact fields the mockup shows:
      Source · Type · Tenant · Status · Last Collection · Events ·
      Lag · Connector · Capabilities.

    Phase A: registry is empty, so the response is an empty list —
    the UI surfaces `NO MATCHING EVIDENCE` honestly.  We do NOT
    seed placeholder CrowdStrike / Palo Alto / Okta rows.
    """
    reg = request.app.state.registry
    rows = []
    for c in reg.all():
        d = c.describe()
        rows.append({
            "source":          c.label,
            "type":            c.source_type,
            "tenant_id":       c.tenant_id,
            "status":          d["health"],
            "last_collection": d["metrics"].get("last_success"),
            "events":          d["metrics"].get("events_accepted", 0),
            "lag_seconds":     d["metrics"].get("collection_lag_seconds"),
            "connector":       d["identity"],
            "capabilities":    d["capabilities"],
        })
    return {"data_sources": rows, "phase": "A"}
