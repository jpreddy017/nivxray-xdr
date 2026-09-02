"""
Telemetry Adapter Framework HTTP surface — Phase 2.

    GET  /api/telemetry/adapters             — list registered adapters
    POST /api/telemetry/adapters/{name}/normalise
                                                — normalise a batch of raw
                                                  vendor records (dev/QA);
                                                  production ingestion is
                                                  driven by pipeline runners
                                                  not this endpoint.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user
from services.telemetry_adapters import get_registry


router = APIRouter()


class NormaliseIn(BaseModel):
    events: list[dict[str, Any]] = Field(default_factory=list)


def _serialise(ev):
    d = asdict(ev)
    d["source_kind"] = ev.source_kind.value
    return d


@router.get("/telemetry/adapters")
async def list_adapters(user = Depends(get_current_user)):
    reg = get_registry()
    return {"adapters": reg.list()}


@router.post("/telemetry/adapters/{name}/normalise")
async def normalise_via_adapter(
    name: str,
    payload: NormaliseIn,
    user = Depends(get_current_user),
):
    reg = get_registry()
    try:
        adapter = reg.get(name)
    except KeyError:
        raise HTTPException(status_code=404,
                                          detail=f"unknown adapter: {name}")
    events = await adapter.normalise(payload.events)
    return {
        "adapter":     name,
        "count_in":    len(payload.events),
        "count_out":   len(events),
        "events":      [_serialise(e) for e in events],
    }
