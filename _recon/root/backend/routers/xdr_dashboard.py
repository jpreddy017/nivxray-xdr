"""Analyst Operations · Operations Dashboard router.

Returns real, deterministic tile counts derived from live incident
data.  Never fabricates a count.  Every tile shares a Mongo predicate
with the corresponding Incident-Queue lens (see
``services/dashboard_lenses``) so the number the analyst sees on the
dashboard exactly matches the queue they land in when they click.

Phase 1 gate — this router MUST NOT invoke any investigation engine.
It is a pure query layer on top of ``workspace_cases``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from deps import get_current_user_optional, sync_collection
from services.dashboard_lenses import (
    LENSES,
    LENS_GROUPS,
    build_predicate,
    is_never_match,
)

router = APIRouter(prefix="/xdr/dashboard", tags=["xdr-dashboard"])

_col = sync_collection("workspace_cases")


# ── Tile counts ──────────────────────────────────────────────────────
@router.get("/tiles")
async def get_dashboard_tiles(user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    """Return the 10 operational lens tiles.

    The response shape:

        {
          "generated_at": ISO8601,
          "user_email":   str | null,
          "groups": [
            {"id": "triage",     "label": "TRIAGE",     "tiles": [tile, …]},
            {"id": "ownership",  "label": "OWNERSHIP",  "tiles": [tile, …]},
            {"id": "risk",       "label": "RISK",       "tiles": [tile, …]},
          ]
        }

    Each ``tile`` carries: ``id``, ``label``, ``description``, ``tone``,
    ``count`` (int), ``lens_href`` (queue deep-link) and, honestly,
    ``count_source`` = ``"live"`` when the query ran and ``"empty"``
    when the lens intentionally short-circuited to zero (e.g.
    ``in_progress_mine`` when no user is authenticated).

    NO fabricated counts.  NO cached zeros.
    """
    email = (user or {}).get("email")
    now_iso = datetime.now(timezone.utc).isoformat()

    # Build tiles in a stable order matching LENSES.
    tiles_by_group: Dict[str, List[Dict[str, Any]]] = {g: [] for g in LENS_GROUPS}
    for lens in LENSES:
        pred = build_predicate(lens["id"], email)
        if is_never_match(pred):
            count = 0
            source = "empty"
        else:
            count = _col.count_documents(pred)
            source = "live"
        tiles_by_group[lens["group"]].append({
            "id":           lens["id"],
            "label":        lens["label"],
            "description":  lens["description"],
            "tone":         lens["tone"],
            "count":        int(count),
            "count_source": source,
            "lens_href":    f"/xdr/incidents?lens={lens['id']}",
        })

    groups_response = [
        {
            "id":    gid,
            "label": gid.upper(),
            "tiles": tiles_by_group[gid],
        }
        for gid in LENS_GROUPS
    ]

    return {
        "generated_at": now_iso,
        "user_email":   email,
        "invariant":    "Dashboard tiles are pure projections of live "
                          "incident data · no cached counters · no "
                          "fabricated numbers · tile count == queue "
                          "count for the same lens.",
        "groups":       groups_response,
    }
