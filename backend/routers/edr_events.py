"""GATE 11 · the estate-wide Events Explorer.

Server-side filtering, sorting and cursor pagination over the EDR's own
authenticated endpoint event store (`edr_raw_events`). Every row is
tenant-stamped and endpoint-attributed at ingest, which is what makes an
estate-wide query safe: the tenant predicate is applied in the database,
never in the console.

Why this store and not the canonical observation store: a raw endpoint
event carries `tenant_id`, `endpoint_ref`, the verbatim payload, the
authentication provenance of the connector that produced it and the
appended derivations of every pass the pipeline made over it. That is
the complete, attributable answer to "what did this estate observe".

What is NOT here is stated rather than hidden: the released connector
does not observe files, network connections or the registry, so no
filter pretends those events exist.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from deps import db as _db, get_current_user
from edr_plane.enrollment import store as enrollment_store
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter(prefix="/edr/events", tags=["nivxforge-edr-events"])

RAW = "edr_raw_events"
MAX_LIMIT = 200

DETECTION_FILTERS = {
    "matched": "DETECTION_MATCHED",
    "evaluated_no_match": "DETECTION_EVALUATED_NO_MATCH",
    "not_evaluated": "DETECTION_NOT_EVALUATED",
}

COVERAGE_NOTE = (
    "These are the endpoint events the NivXForge connector actually "
    "delivered, authenticated and attributed. Collection coverage is "
    "REPORTED from what the estate delivered — see the `activity` facet — "
    "and is never claimed: an activity class with no events was either "
    "not observed or is not collected by the installed connector "
    "release, and those are different facts.")

#: Activity classes the sensors stamp onto the payload envelope. Used for
#: filtering and for the coverage facet; absence here is reported, not
#: interpreted.
ACTIVITY_CLASSES = ("PROCESS", "NETWORK", "FILE", "REGISTRY", "AUTH",
                    "MODULE", "DNS")


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


def _encode(row: Dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(
        {"t": row.get("ingest_time"), "r": row.get("raw_id")}).encode()
    ).decode().rstrip("=")


def _decode(cursor: str) -> Dict[str, Any]:
    try:
        pad = cursor + "=" * (-len(cursor) % 4)
        out = json.loads(base64.urlsafe_b64decode(pad.encode()).decode())
        if not isinstance(out, dict) or "t" not in out or "r" not in out:
            raise ValueError
        return out
    except Exception:
        raise HTTPException(422, detail={
            "code": "CURSOR_INVALID",
            "reason": "the cursor was not produced by this endpoint"}) from None


async def _endpoint_refs(tenant: str, endpoint_id: str) -> List[str]:
    """Every identifier the raw store can be addressed by for one
    endpoint. Resolution never widens authorisation: the lookup itself is
    tenant-scoped."""
    rec = await _db[enrollment_store.ENDPOINTS].find_one(
        {"tenant_id": tenant, "endpoint_id": endpoint_id}, {"_id": 0})
    if rec is None:
        raise HTTPException(404, detail={
            "code": "ENDPOINT_NOT_FOUND",
            "reason": ("no endpoint you are authorised for resolves to this "
                       "reference — an authorisation or identity outcome, "
                       "not a statement about the evidence")})
    return [str(v) for v in (rec.get("endpoint_id"), rec.get("device_iid"))
            if v]


def _detection(derivations: List[Dict[str, Any]]) -> Dict[str, Any]:
    det = [d for d in (derivations or [])
           if str(d.get("outcome") or "").startswith("DETECTION_")]
    if not det:
        return {"outcome": "NOT_RECORDED",
                "basis": ("no detection derivation is recorded for this "
                          "event; the deterministic plane did not run, which "
                          "is not a statement that it was benign")}
    latest = det[-1]
    return {"outcome": latest.get("outcome"),
            "reason": latest.get("reason"),
            "detection_content_version": latest.get(
                "detection_content_version"),
            "basis": "read from the derivation appended at ingest"}


def _row(doc: Dict[str, Any], hosts: Dict[str, str]) -> Dict[str, Any]:
    derivations = doc.get("derivations") or []
    payload = doc.get("payload") or ""
    canonical = next((d.get("event_id") for d in derivations
                      if d.get("event_id")), None)
    parser = next((d.get("parser_state") for d in reversed(derivations)
                   if d.get("parser_state")), None)
    activity = operation = None
    if payload.startswith("{"):
        try:
            env = json.loads(payload)
            if isinstance(env, dict):
                activity = env.get("activity")
                operation = env.get("operation")
        except ValueError:
            pass
    return {
        "raw_id": doc.get("raw_id"),
        "ingest_time": doc.get("ingest_time"),
        "event_time": doc.get("event_time"),
        "endpoint_ref": doc.get("endpoint_ref"),
        "hostname": hosts.get(str(doc.get("endpoint_ref"))),
        "activity": activity,
        "operation": operation,
        "source_kind": doc.get("source_kind"),
        "sensor_version": doc.get("sensor_version"),
        "trust_state": doc.get("trust_state"),
        "telemetry_quality": doc.get("telemetry_quality"),
        "payload_sha256": doc.get("payload_sha256"),
        "payload_preview": payload[:240],
        "payload_truncated": len(payload) > 240,
        "duplicate_count": doc.get("duplicate_count") or 0,
        "canonical_event_id": canonical,
        "parser_state": parser,
        "derivation_count": len(derivations),
        "detection": _detection(derivations),
    }


@router.get("")
async def list_events(
        endpoint_id: Optional[str] = Query(None),
        hostname: Optional[str] = Query(None),
        since: Optional[str] = Query(None, description="ISO-8601 inclusive"),
        until: Optional[str] = Query(None, description="ISO-8601 exclusive"),
        hours: Optional[int] = Query(None, ge=1, le=24 * 365),
        source_kind: Optional[str] = Query(None),
        activity: Optional[str] = Query(
            None, description="PROCESS | NETWORK | FILE | REGISTRY | AUTH "
                              "| MODULE | DNS"),
        trust_state: Optional[str] = Query(None),
        telemetry_quality: Optional[str] = Query(None),
        detection: Optional[str] = Query(
            None, description="matched | evaluated_no_match | not_evaluated "
                              "| not_recorded"),
        payload_sha256: Optional[str] = Query(None, min_length=8,
                                              max_length=64),
        q: Optional[str] = Query(None, min_length=2, max_length=200,
                                 description="Substring of the verbatim "
                                             "payload"),
        sort: str = Query("desc", pattern="^(asc|desc)$"),
        limit: int = Query(50, ge=1, le=MAX_LIMIT),
        cursor: Optional[str] = Query(None),
        user: dict = Depends(get_current_user),
        tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Estate-wide event query. Every filter is applied in the database."""
    tenant = _scoped(tenant_id, user)
    query: Dict[str, Any] = {"tenant_id": tenant}
    applied: Dict[str, Any] = {}

    if endpoint_id:
        refs = await _endpoint_refs(tenant, endpoint_id)
        query["endpoint_ref"] = {"$in": refs}
        applied["endpoint_id"] = endpoint_id
    elif hostname:
        ids = [e["endpoint_id"] async for e in
               _db[enrollment_store.ENDPOINTS].find(
                   {"tenant_id": tenant, "hostname": hostname},
                   {"_id": 0, "endpoint_id": 1})]
        query["endpoint_ref"] = {"$in": ids}
        applied["hostname"] = hostname

    time_filter: Dict[str, Any] = {}
    if hours and not since:
        since = (datetime.now(timezone.utc)
                 - timedelta(hours=hours)).isoformat()
        applied["hours"] = hours
    if since:
        time_filter["$gte"] = since
        applied["since"] = since
    if until:
        time_filter["$lt"] = until
        applied["until"] = until
    if time_filter:
        query["ingest_time"] = time_filter

    for field, value in (("source_kind", source_kind),
                         ("trust_state", trust_state),
                         ("telemetry_quality", telemetry_quality)):
        if value:
            query[field] = value
            applied[field] = value
    if payload_sha256:
        if len(payload_sha256) == 64:
            query["payload_sha256"] = payload_sha256.lower()
        else:
            query["payload_sha256"] = {
                "$regex": f"^{payload_sha256.lower()}"}
        applied["payload_sha256"] = payload_sha256
    if q:
        query["payload"] = {"$regex": q, "$options": "i"}
        applied["q"] = q
    if activity:
        act = activity.strip().upper()
        if act not in ACTIVITY_CLASSES:
            raise HTTPException(422, detail={
                "code": "ACTIVITY_INVALID",
                "allowed": list(ACTIVITY_CLASSES)})
        existing = query.pop("payload", None)
        pattern = f'"activity"\\s*:\\s*"{act}"'
        if existing:
            query["$and"] = query.get("$and", []) + [
                {"payload": existing}, {"payload": {"$regex": pattern}}]
        else:
            query["payload"] = {"$regex": pattern}
        applied["activity"] = act
    if detection:
        key = detection.strip().lower()
        if key in DETECTION_FILTERS:
            query["derivations.outcome"] = DETECTION_FILTERS[key]
        elif key == "not_recorded":
            query["derivations.outcome"] = {"$not": {
                "$regex": "^DETECTION_"}}
        else:
            raise HTTPException(422, detail={
                "code": "DETECTION_FILTER_INVALID",
                "allowed": list(DETECTION_FILTERS) + ["not_recorded"]})
        applied["detection"] = key

    direction = -1 if sort == "desc" else 1
    if cursor:
        c = _decode(cursor)
        op = "$lt" if direction == -1 else "$gt"
        keyed = {"$or": [{"ingest_time": {op: c["t"]}},
                         {"ingest_time": c["t"],
                          "raw_id": {op: c["r"]}}]}
        query = {"$and": [query, keyed]}

    projection = {"_id": 0, "raw_id": 1, "ingest_time": 1, "event_time": 1,
                  "endpoint_ref": 1, "source_kind": 1, "sensor_version": 1,
                  "trust_state": 1, "telemetry_quality": 1,
                  "payload_sha256": 1, "payload": 1, "duplicate_count": 1,
                  "derivations": 1}
    docs = [d async for d in _db[RAW].find(query, projection).sort(
        [("ingest_time", direction), ("raw_id", direction)]
    ).limit(limit + 1)]
    has_more = len(docs) > limit
    docs = docs[:limit]

    refs = sorted({str(d.get("endpoint_ref")) for d in docs
                   if d.get("endpoint_ref")})
    hosts = {e["endpoint_id"]: e.get("hostname")
             async for e in _db[enrollment_store.ENDPOINTS].find(
                 {"tenant_id": tenant, "endpoint_id": {"$in": refs}},
                 {"_id": 0, "endpoint_id": 1, "hostname": 1})}

    return {
        "tenant_id": tenant,
        "events": [_row(d, hosts) for d in docs],
        "count": len(docs),
        "has_more": has_more,
        "next_cursor": _encode(docs[-1]) if docs and has_more else None,
        "sort": sort,
        "limit": limit,
        "filters_applied": applied,
        "store": RAW,
        "pagination": ("keyset (ingest_time, raw_id) — stable under "
                       "concurrent ingest, unlike skip/limit"),
        "coverage": COVERAGE_NOTE,
    }


@router.get("/facets")
async def facets(hours: int = Query(24, ge=1, le=24 * 365),
                 user: dict = Depends(get_current_user),
                 tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Real counts for the filter bar, from one bounded aggregation."""
    tenant = _scoped(tenant_id, user)
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    match = {"tenant_id": tenant, "ingest_time": {"$gte": since}}
    pipeline = [
        {"$match": match},
        {"$facet": {
            "source_kind": [{"$group": {"_id": "$source_kind",
                                        "count": {"$sum": 1}}}],
            "trust_state": [{"$group": {"_id": "$trust_state",
                                        "count": {"$sum": 1}}}],
            "telemetry_quality": [{"$group": {"_id": "$telemetry_quality",
                                              "count": {"$sum": 1}}}],
            "endpoint": [{"$group": {"_id": "$endpoint_ref",
                                     "count": {"$sum": 1}}},
                         {"$sort": {"count": -1}}, {"$limit": 50}],
            "detection": [{"$unwind": {"path": "$derivations",
                                       "preserveNullAndEmptyArrays": True}},
                          {"$match": {"derivations.outcome": {
                              "$regex": "^DETECTION_"}}},
                          {"$group": {"_id": "$derivations.outcome",
                                      "count": {"$sum": 1}}}],
            "activity": [
                {"$project": {"a": {"$let": {
                    "vars": {"m": {"$regexFind": {
                        "input": {"$ifNull": ["$payload", ""]},
                        "regex": r'"activity"\s*:\s*"([A-Z_]+)"'}}},
                    "in": {"$arrayElemAt": [
                        {"$ifNull": ["$$m.captures", []]}, 0]}}}}},
                {"$group": {"_id": "$a", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}],
            "total": [{"$count": "events"}],
        }},
    ]
    out = [r async for r in _db[RAW].aggregate(pipeline)]
    raw = out[0] if out else {}

    def as_map(key: str) -> Dict[str, int]:
        return {str(r["_id"]): r["count"] for r in (raw.get(key) or [])
                if r.get("_id") is not None}

    refs = list(as_map("endpoint"))
    hosts = {e["endpoint_id"]: e.get("hostname")
             async for e in _db[enrollment_store.ENDPOINTS].find(
                 {"tenant_id": tenant, "endpoint_id": {"$in": refs}},
                 {"_id": 0, "endpoint_id": 1, "hostname": 1})}
    return {
        "tenant_id": tenant, "window_hours": hours,
        "total_events": ((raw.get("total") or [{}])[0] or {}).get("events", 0),
        "source_kind": as_map("source_kind"),
        "trust_state": as_map("trust_state"),
        "telemetry_quality": as_map("telemetry_quality"),
        "detection": as_map("detection"),
        "activity": as_map("activity"),
        "activity_classes_known": list(ACTIVITY_CLASSES),
        "activity_not_observed": [a for a in ACTIVITY_CLASSES
                                  if a not in as_map("activity")],
        "endpoints": [{"endpoint_ref": ref, "hostname": hosts.get(ref),
                       "count": count}
                      for ref, count in sorted(as_map("endpoint").items(),
                                               key=lambda kv: -kv[1])],
        "coverage": COVERAGE_NOTE,
    }


@router.get("/{raw_id}")
async def get_event(raw_id: str, user: dict = Depends(get_current_user),
                    tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """One event, verbatim, with every derivation the pipeline appended."""
    tenant = _scoped(tenant_id, user)
    doc = await _db[RAW].find_one({"tenant_id": tenant, "raw_id": raw_id},
                                  {"_id": 0})
    if doc is None:
        raise HTTPException(404, detail={
            "code": "EVENT_NOT_FOUND",
            "reason": "no such event in the tenant you are authorised for"})
    hosts = {}
    if doc.get("endpoint_ref"):
        ep = await _db[enrollment_store.ENDPOINTS].find_one(
            {"tenant_id": tenant, "endpoint_id": doc["endpoint_ref"]},
            {"_id": 0, "endpoint_id": 1, "hostname": 1, "platform": 1,
             "group_id": 1, "policy_id": 1})
        if ep:
            hosts[ep["endpoint_id"]] = ep.get("hostname")
    return {
        "tenant_id": tenant,
        "event": {**_row(doc, hosts),
                  "payload": doc.get("payload"),
                  "payload_encoding": doc.get("payload_encoding"),
                  "received_from_ip": doc.get("received_from_ip"),
                  "authentication": doc.get("authentication"),
                  "derivations": doc.get("derivations") or []},
        "immutability": ("the payload is retained byte-for-byte. Every "
                         "pipeline pass is APPENDED as a derivation and "
                         "never overwrites the original."),
        "coverage": COVERAGE_NOTE,
    }
