"""NivXForge EDR Wave 0 — the capability-truth API.

Directive §14: the console must not be able to claim a capability the
registry denies. That only works if the console can ASK, so the registry
is served here and the UI reads `effective_state`, never a hardcoded
assumption.

Read-only by design. The registry is graded in source, reviewed in
version control and served from there — it is not editable at runtime,
because a truth baseline that any caller can rewrite is not a baseline.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from deps import db as _db, get_current_user
from edr_plane import raw_events as raw
from edr_plane.capability import INVENTORY, SENSOR_REGISTRY, by_id, summary, taxonomy
from edr_plane.contracts import schema_export
from edr_plane.contracts.epistemic import (EPISTEMIC_GLYPH, EpistemicState,
                                     FORBIDDEN_EQUIVALENCES)

router = APIRouter(prefix="/edr/wave0", tags=["nivxforge-edr-wave0"])


def _tenant(user: dict) -> str:
    return (user or {}).get("customer") or "default"


@router.get("/capabilities")
async def list_capabilities(
    plane: Optional[str] = Query(None),
    gap_class: Optional[str] = Query(None),
    operational_only: bool = Query(False),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    rows = INVENTORY
    if plane:
        rows = [c for c in rows if c.plane == plane.upper()]
    if gap_class:
        rows = [c for c in rows if c.gap_class == gap_class.upper()]
    if operational_only:
        rows = [c for c in rows if c.is_operational]
    return {
        "capabilities": [c.model_dump() for c in rows],
        "count": len(rows),
        "summary": summary(),
        "authority": "docs/architecture/NIVXFORGE_EDR_MASTER_DIRECTIVE.md",
        "note": ("effective_state is authoritative. Where it differs from "
                 "declared_state, downgrade_reason states why the stronger "
                 "claim is not supported by evidence in this repository."),
    }


@router.get("/capabilities/summary")
async def capability_summary(
        user: dict = Depends(get_current_user)) -> dict[str, Any]:
    return summary()


@router.get("/capabilities/{capability_id}")
async def get_capability(capability_id: str,
                         user: dict = Depends(get_current_user)
                         ) -> dict[str, Any]:
    cap = by_id(capability_id)
    if not cap:
        raise HTTPException(
            status_code=404,
            detail={"code": "CAPABILITY_NOT_REGISTERED",
                    "capability_id": capability_id,
                    "reason": "This capability is not in the NivXForge EDR "
                              "inventory. An unregistered capability is not "
                              "an implemented one."})
    return cap.model_dump()


@router.get("/sensors")
async def list_sensors(user: dict = Depends(get_current_user)
                       ) -> dict[str, Any]:
    return {
        "sensors": [s.model_dump() for s in SENSOR_REGISTRY],
        "count": len(SENSOR_REGISTRY),
        "note": ("Zero registered sensors is the honest state: no NivXForge "
                 "agent is installed on any endpoint. Every endpoint field "
                 "therefore resolves NOT_SUPPORTED or NOT_COLLECTED, never "
                 "NOT_OBSERVED."),
    }


@router.get("/contracts")
async def list_contracts(user: dict = Depends(get_current_user)
                         ) -> dict[str, Any]:
    return {
        "manifest": schema_export.manifest(),
        "epistemic_states": {s.value: EPISTEMIC_GLYPH[s]
                             for s in EpistemicState},
        "forbidden_equivalences": [
            {"left": a, "right": b, "because": why}
            for a, b, why in FORBIDDEN_EQUIVALENCES],
    }


@router.get("/contracts/{name}/schema")
async def contract_schema(name: str,
                          user: dict = Depends(get_current_user)
                          ) -> dict[str, Any]:
    try:
        return schema_export.export_one(name)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "CONTRACT_NOT_DEFINED", "contract": name,
                    "available": sorted(schema_export.CONTRACTS)})


@router.get("/filter-taxonomy")
async def filter_taxonomy(user: dict = Depends(get_current_user)
                          ) -> dict[str, Any]:
    """The 43-item baseline status.

    Returns `complete: false` with a disclosure while the verbatim item
    list is pending owner input. A filter UI must render the disclosure
    rather than present a partial filter set as the mandatory baseline.
    """
    return taxonomy.status()


@router.get("/raw-events/stats")
async def raw_event_stats(user: dict = Depends(get_current_user)
                          ) -> dict[str, Any]:
    return await raw.stats(_db, tenant_id=_tenant(user))


@router.get("/raw-events/replay-candidates")
async def replay_candidates(
    parser_state: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    user: dict = Depends(get_current_user),
) -> dict[str, Any]:
    rows = await raw.replay_candidates(
        _db, tenant_id=_tenant(user), parser_state=parser_state, limit=limit)
    return {
        "candidates": rows, "count": len(rows),
        "note": ("These raw events are byte-preserved and can be re-reasoned "
                 "at a new replay_generation after a parser, normalizer, "
                 "detection or intelligence improvement. Re-reasoning "
                 "APPENDS a derivation; it never rewrites history."),
    }
