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
from services.telemetry_adapters import (
    get_registry, IngestionRunner, InMemoryCheckpoint, InMemoryDedup,
    correlate, build_verdict_inputs, build_evidence_graph_edges,
    bridge_to_dict, poller_configuration_status,
)


router = APIRouter()


# --------------------------------------------------------------------
# Process-level runner singleton.  In production the sink writes
# CanonicalEvents to Mongo; here we keep the last N in memory so
# ops/QA can inspect what an adapter emitted without touching the
# vendor.  Credentials never enter this module.
# --------------------------------------------------------------------
_RECENT_EVENTS: list[dict[str, Any]] = []
_RECENT_LIMIT  = 500


async def _memory_sink(events):
    global _RECENT_EVENTS
    for ev in events:
        _RECENT_EVENTS.append(_serialise(ev))
    # Keep only the most recent N.
    if len(_RECENT_EVENTS) > _RECENT_LIMIT:
        _RECENT_EVENTS = _RECENT_EVENTS[-_RECENT_LIMIT:]


_RUNNER = IngestionRunner(
    checkpoint_store = InMemoryCheckpoint(),
    dedup_store      = InMemoryDedup(),
    sink             = _memory_sink,
)


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




@router.get("/telemetry/runner/health")
async def runner_health(user = Depends(get_current_user)):
    return {"jobs": _RUNNER.health()}


@router.get("/telemetry/runner/recent")
async def runner_recent(user = Depends(get_current_user),
                                          limit: int = 100):
    return {"events": _RECENT_EVENTS[-max(1, min(limit, _RECENT_LIMIT)):]}


@router.post("/telemetry/correlate")
async def correlate_events(
    payload: dict,
    user = Depends(get_current_user),
):
    from services.telemetry_adapters import (
        CanonicalEvent, Provenance, SourceKind,
    )
    events_raw = payload.get("events") or []
    events = []
    for e in events_raw:
        if not isinstance(e, dict):
            continue
        prov = e.get("provenance") or {}
        events.append(CanonicalEvent(
            canonical_id  = e.get("canonical_id", ""),
            source_kind   = SourceKind(e.get("source_kind", "endpoint")),
            action        = e.get("action", ""),
            actor         = dict(e.get("actor") or {}),
            target        = dict(e.get("target") or {}),
            context       = dict(e.get("context") or {}),
            outcome       = e.get("outcome"),
            severity_hint = e.get("severity_hint"),
            tags          = tuple(e.get("tags") or ()),
            provenance    = Provenance(**prov) if prov else None,
        ))
    groups = correlate(events, window_minutes=payload.get("window_minutes") or 30)
    return {
        "count":  len(groups),
        "groups": [
            {
                "key":           g.key,
                "reasons":       list(g.reasons),
                "canonical_ids": list(g.canonical_ids),
                "lanes":         list(g.lanes),
                "actor_id":      g.actor_id,
                "first_seen":    g.first_seen,
                "last_seen":     g.last_seen,
                "confidence":    g.confidence,
            } for g in groups
        ],
    }




@router.get("/telemetry/pollers/status")
async def pollers_status(user = Depends(get_current_user)):
    """Report vendor poller configuration status — configured
    vs unconfigured, per provider — without leaking any values."""
    return {"pollers": poller_configuration_status()}


@router.post("/telemetry/verdict-inputs")
async def verdict_inputs(payload: dict,
                                              user = Depends(get_current_user)):
    """Build governed Verdict-Engine inputs from a batch of
    CanonicalEvent-shaped records.  The Verdict Engine remains
    the sole verdict authority; this endpoint just formats the
    correlation signals it may consume."""
    from services.telemetry_adapters import (
        CanonicalEvent, Provenance, SourceKind,
    )
    events = []
    for e in payload.get("events") or []:
        if not isinstance(e, dict): continue
        prov = e.get("provenance") or {}
        events.append(CanonicalEvent(
            canonical_id  = e.get("canonical_id", ""),
            source_kind   = SourceKind(e.get("source_kind", "endpoint")),
            action        = e.get("action", ""),
            actor         = dict(e.get("actor") or {}),
            target        = dict(e.get("target") or {}),
            context       = dict(e.get("context") or {}),
            outcome       = e.get("outcome"),
            severity_hint = e.get("severity_hint"),
            tags          = tuple(e.get("tags") or ()),
            provenance    = Provenance(**prov) if prov else None,
        ))
    groups = correlate(events,
                                    window_minutes=payload.get("window_minutes") or 30)
    inputs = build_verdict_inputs(groups)
    edges  = build_evidence_graph_edges(groups)
    return {
        "verdict_inputs": [bridge_to_dict(v) for v in inputs],
        "evidence_graph_edges": [bridge_to_dict(e) for e in edges],
        "correlation_group_count": len(groups),
    }
