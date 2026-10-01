"""
P1.10a · Spread Watchlist API — read/manage the evidence-watch plane.

Read-only by default.  The two write paths (analyst enrollment and
retirement) exist because an analyst must be able to watch something the
evidence gate did not admit — but neither can create an incident, assign
a score, or alter a verdict.  Promotion remains the sole authority of the
existing incident gate.

Every response says "observed across N endpoints", never "spread to N
endpoints": the first is evidence, the second is a conclusion.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from deps import db
from routers.xdr_rbac import require_permission
from detection_content.xdr_spread_watchlist import (
    HONESTY_NOTE, INDICATOR_TYPES, PLANE_ID, PLANE_VERSION,
    SIGHTINGS_COLLECTION, SPREAD_RULE_ID, THRESHOLDS, WATCHLIST_COLLECTION,
    cmdline_fingerprint)

router = APIRouter(prefix="/api/xdr/spread", tags=["xdr-spread-watchlist"])

CORRELATION_MATCHES_COLLECTION = "xdr_correlation_matches"


def _tenant(request: Request) -> str:
    ten = (request.headers.get("X-Tenant-Id") or "").strip()
    if not ten:
        raise HTTPException(400, detail="X-Tenant-Id header is required")
    return ten


def _principal(request: Request) -> str:
    return (request.headers.get("X-Principal-Id") or "").strip() or "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class AnalystWatchBody(BaseModel):
    indicator_type:  str
    indicator_value: str = Field(min_length=1, max_length=512)
    note:            str | None = None


class RetireBody(BaseModel):
    reason: str = Field(min_length=1, max_length=512)


@router.get("")
async def list_watchlist(request: Request,
                         status: str | None = Query(None),
                         indicator_type: str | None = Query(None),
                         min_endpoints: int = Query(0, ge=0),
                         spread_only: bool = Query(False),
                         limit: int = Query(100, ge=1, le=500),
                         _=Depends(require_permission("collectors.read"))):
    ten = _tenant(request)
    q: dict[str, Any] = {"tenant_id": ten}
    if status:
        q["status"] = status
    if indicator_type:
        q["indicator_type"] = indicator_type
    if min_endpoints:
        q["endpoint_count"] = {"$gte": min_endpoints}
    if spread_only:
        q["endpoint_count"] = {"$gte": 2}
    rows = await db[WATCHLIST_COLLECTION].find(q, {"_id": 0}).sort(
        [("endpoint_count", -1), ("last_seen", -1)]).to_list(limit)
    return {
        "watchlist": rows,
        "count": len(rows),
        "totals": {
            "watching": await db[WATCHLIST_COLLECTION].count_documents(
                {"tenant_id": ten, "status": "WATCHING"}),
            "observed_on_multiple_endpoints":
                await db[WATCHLIST_COLLECTION].count_documents(
                    {"tenant_id": ten, "endpoint_count": {"$gte": 2}}),
            "retired": await db[WATCHLIST_COLLECTION].count_documents(
                {"tenant_id": ten, "status": "RETIRED"}),
        },
        "plane_id": PLANE_ID,
        "plane_version": PLANE_VERSION,
        "honesty_note": HONESTY_NOTE,
    }


@router.get("/policy")
async def policy(_=Depends(require_permission("collectors.read"))):
    """The watch plane's own contract, stated rather than implied."""
    return {
        "plane_id": PLANE_ID,
        "plane_version": PLANE_VERSION,
        "is_engine": False,
        "role": "evidence / watch plane — records sightings and emits "
                "correlation evidence only",
        "correlation_engine": "nivxray::xdr::ice",
        "scoring_engine": "nivxray::xdr::veee",
        "promotion_authority": "existing incident gate "
                               "(detection_content.xdr_incident)",
        "indicator_types": list(INDICATOR_TYPES),
        "context_only_attributes": ["src_ip", "username", "hostname",
                                     "host_ip", "event_time"],
        "enrollment": {
            "mode": "evidence-gated",
            "admits": "a real detection match, OR a VEEE verdict strictly "
                      "above INCONCLUSIVE (score >= 25)",
            "note": "enrollment is NOT a malicious verdict — it means the "
                    "indicator is interesting enough to watch for recurrence",
        },
        "endpoint_identity": {
            "accepted": ["host.hostname", "host.host_id (when not an IP)"],
            "rejected": ["src_ip", "any IP literal"],
            "unknown_policy": "retained, displayed, provenance-preserving, "
                              "marked endpoint_identity_state=UNKNOWN, and "
                              "NEVER counted toward endpoint cardinality",
        },
        "thresholds": [{"distinct_real_endpoints": n, "status": s}
                        for n, s in THRESHOLDS],
        "scoring_note": "Spread emits evidence at each threshold. The score "
                        "contribution is bounded by the EXISTING VEEE "
                        "correlation cap; endpoint_count and the threshold "
                        "ledger preserve evidence progression beyond the cap.",
        "spread_is_not": ["lateral movement",
                           "compromise of every endpoint",
                           "patient zero"],
        "spread_is": "evidence that the same tracked indicator was observed "
                      "across distinct real endpoint identities",
        "honesty_note": HONESTY_NOTE,
    }


@router.get("/signals")
async def spread_signals(request: Request,
                         limit: int = Query(50, ge=1, le=200),
                         _=Depends(require_permission("collectors.read"))):
    """Correlation evidence this plane has emitted, newest first."""
    ten = _tenant(request)
    rows = await db[CORRELATION_MATCHES_COLLECTION].find(
        {"tenant_id": ten, "rule_id": SPREAD_RULE_ID},
        {"_id": 0}).sort("emitted_at", -1).to_list(limit)
    return {"signals": rows, "count": len(rows),
            "rule_id": SPREAD_RULE_ID,
            "honesty_note": HONESTY_NOTE}


@router.get("/{watch_id}")
async def get_watch(watch_id: str, request: Request,
                    sightings_limit: int = Query(200, ge=1, le=1000),
                    _=Depends(require_permission("collectors.read"))):
    ten = _tenant(request)
    doc = await db[WATCHLIST_COLLECTION].find_one(
        {"watch_id": watch_id, "tenant_id": ten}, {"_id": 0})
    if doc is None:
        raise HTTPException(404, detail="watch entry not found")
    sightings = await db[SIGHTINGS_COLLECTION].find(
        {"watch_id": watch_id, "tenant_id": ten},
        {"_id": 0}).sort("at", -1).to_list(sightings_limit)
    signals = await db[CORRELATION_MATCHES_COLLECTION].find(
        {"tenant_id": ten, "rule_id": SPREAD_RULE_ID,
         "spread.watch_id": watch_id}, {"_id": 0}).sort(
            "emitted_at", -1).to_list(50)
    return {
        "watch": doc,
        "sightings": sightings,
        "sightings_returned": len(sightings),
        "unknown_endpoint_sightings": [
            s for s in sightings
            if s.get("endpoint_identity_state") == "UNKNOWN"],
        "correlation_evidence": signals,
        "claim": (f"Indicator observed across "
                   f"{doc.get('endpoint_count', 0)} distinct endpoint "
                   f"identities."),
        "honesty_note": HONESTY_NOTE,
    }


@router.post("", status_code=201)
async def analyst_watch(body: AnalystWatchBody, request: Request,
                        _=Depends(require_permission("collectors.enroll"))):
    """Analyst enrollment — for indicators the evidence gate did not admit.

    Creates a watch entry with ZERO endpoints and ZERO sightings: adding
    something to the watchlist is not evidence that it was observed.
    """
    ten = _tenant(request)
    if body.indicator_type not in INDICATOR_TYPES:
        raise HTTPException(400, detail={
            "code": "UNSUPPORTED_INDICATOR_TYPE",
            "supported": list(INDICATOR_TYPES)})
    value = body.indicator_value.strip()
    display = value
    if body.indicator_type == "cmdline_fingerprint":
        fp = cmdline_fingerprint(value)
        if fp is None:
            raise HTTPException(400, detail={
                "code": "CMDLINE_NOT_FINGERPRINTABLE",
                "reason": "the normalized command line has fewer than 3 "
                          "tokens — process_identity already covers it"})
        value, display = fp
    else:
        value = value.lower()

    existing = await db[WATCHLIST_COLLECTION].find_one(
        {"tenant_id": ten, "indicator_type": body.indicator_type,
         "indicator_value": value}, {"_id": 0})
    if existing:
        return {"created": False, "watch": existing,
                "reason": "already watched"}

    import hashlib
    watch_id = "wl_" + hashlib.sha256(
        "|".join([ten, body.indicator_type, value]).encode()).hexdigest()[:20]
    now = _now()
    doc = {
        "watch_id": watch_id, "tenant_id": ten,
        "indicator_type": body.indicator_type,
        "indicator_value": value, "indicator_display": display,
        "match_basis": "analyst enrollment",
        "status": "WATCHING", "source": "analyst",
        "enrolled_at": now, "enrolled_by": _principal(request),
        "enrollment_basis": {"reason": "analyst enrollment",
                              "note": body.note,
                              "detection_rule_ids": [],
                              "verdict_label": None, "verdict_score": None},
        "first_seen": None, "last_seen": None,
        "endpoints": [], "endpoint_count": 0,
        "unknown_endpoint_sightings": 0,
        "sighting_count": 0, "duplicate_sightings": 0,
        "thresholds_emitted": [], "spread_evidence": [],
        "epistemic_state": {"endpoint_cardinality": "NOT_OBSERVED"},
        "honesty_note": HONESTY_NOTE,
    }
    await db[WATCHLIST_COLLECTION].insert_one(dict(doc))
    return {"created": True, "watch": doc}


@router.post("/{watch_id}/retire")
async def retire_watch(watch_id: str, body: RetireBody, request: Request,
                       _=Depends(require_permission("collectors.enroll"))):
    """Retire a watch entry.  Sightings and emitted evidence are NEVER
    deleted — retirement stops future evidence, it does not rewrite the
    past."""
    ten = _tenant(request)
    res = await db[WATCHLIST_COLLECTION].update_one(
        {"watch_id": watch_id, "tenant_id": ten},
        {"$set": {"status": "RETIRED",
                  "retired_at": _now(),
                  "retired_by": _principal(request),
                  "retired_reason": body.reason}})
    if res.matched_count == 0:
        raise HTTPException(404, detail="watch entry not found")
    doc = await db[WATCHLIST_COLLECTION].find_one(
        {"watch_id": watch_id}, {"_id": 0})
    return {"retired": True, "watch": doc,
            "note": "sightings and emitted correlation evidence are retained"}
