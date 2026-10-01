"""NivXForge EDR · the Audit surface.

This is an AGGREGATOR, not a new store. Every record is read from the
authoritative evidence that the operation itself wrote:

    edr_policy_audit                policy create / version / assign / ACK
    edr_exclusions.audit[]          exclusion create / approve / revoke
    edr_policy_endpoint_state       delivery, ACK, apply, verify per endpoint
    edr_connector_deployments       connector deployment administration
    edr_response_commands           response approval and execution
    edr_endpoints                   enrolment placement of a computer

Creating a second audit store for the console would mean the console
could disagree with the operation. It cannot, because there is nothing
to disagree with.

Entirely inside NivXForge EDR: no XDR audit store is read, and no EDR
record is written to one.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from deps import db as _db, get_current_user
from routers.edr_tenancy import edr_scope, edr_tenant

router = APIRouter(prefix="/edr/audit", tags=["nivxforge-edr-audit"])

#: Each source is read within the requested window and merged. The
#: per-source cap keeps one noisy source from starving the others; when
#: it bites, the response says so rather than silently truncating.
PER_SOURCE_CAP = 2000

CATEGORIES = ("POLICY", "EXCLUSION", "POLICY_DELIVERY", "CONNECTOR",
              "RESPONSE", "ENROLMENT")


def _scoped(tenant_id: str, user: dict) -> str:
    edr_scope(tenant_id, user)
    return tenant_id


def _rec(*, at, actor, action, category, target, target_type,
         previous_state=None, new_state=None, reason=None, approval=None,
         policy_version=None, endpoint_id=None, result=None,
         evidence_ref=None, source_store, detail=None) -> Dict[str, Any]:
    return {"at": at, "actor": actor, "action": action, "category": category,
            "target": target, "target_type": target_type,
            "previous_state": previous_state, "new_state": new_state,
            "reason": reason, "approval": approval,
            "policy_version": policy_version, "endpoint_id": endpoint_id,
            "result": result, "evidence_ref": evidence_ref,
            "source_store": source_store, "detail": detail,
            "record_id": f"{source_store}:{evidence_ref}:{action}:{at}"}


async def _policy(tenant: str, since: str) -> List[Dict[str, Any]]:
    out = []
    async for r in _db["edr_policy_audit"].find(
            {"tenant_id": tenant, "at": {"$gte": since}},
            {"_id": 0}).sort("at", -1).limit(PER_SOURCE_CAP):
        d = r.get("detail") or {}
        out.append(_rec(
            at=r.get("at"), actor=r.get("by"), action=r.get("action"),
            category=("POLICY" if not str(r.get("action")).endswith("ACK")
                      else "POLICY_DELIVERY"),
            target=d.get("policy_id") or d.get("group_id"),
            target_type=("GROUP" if d.get("group_id") and not d.get("policy_id")
                         else "POLICY"),
            new_state=d.get("outcome"), policy_version=d.get("version"),
            endpoint_id=(r.get("by") if str(r.get("action")) == "POLICY_ACK"
                         else None),
            result=("ACCEPTED" if d.get("accepted") is True
                    else "OUT_OF_SYNC" if d.get("accepted") is False else None),
            evidence_ref=d.get("policy_id") or d.get("group_id"),
            source_store="edr_policy_audit", detail=d))
    return out


async def _exclusion(tenant: str, since: str) -> List[Dict[str, Any]]:
    out = []
    async for e in _db["edr_exclusions"].find({"tenant_id": tenant},
                                              {"_id": 0}):
        for entry in (e.get("audit") or []):
            if str(entry.get("at") or "") < since:
                continue
            action = entry.get("action")
            out.append(_rec(
                at=entry.get("at"), actor=entry.get("by"),
                action=f"EXCLUSION_{action}", category="EXCLUSION",
                target=f"{e.get('type')} {e.get('match')} {e.get('value')}",
                target_type="EXCLUSION",
                previous_state=("PENDING_APPROVAL"
                                if action in ("APPROVED", "REJECTED") else None),
                new_state=action,
                reason=(e.get("reason") if action == "CREATED"
                        else entry.get("detail")),
                approval=(f"{action} by {entry.get('by')}"
                          if action in ("APPROVED", "REJECTED") else None),
                result=action, evidence_ref=e.get("exclusion_id"),
                source_store="edr_exclusions.audit",
                detail={"set_id": e.get("set_id"),
                        "affected_engines": e.get("affected_engines"),
                        "scope": e.get("scope")}))
    return out


async def _delivery(tenant: str, since: str) -> List[Dict[str, Any]]:
    """Delivery, acknowledgement, apply and verification are FOUR facts,
    so they are four audit records — never one 'policy updated'."""
    out = []
    async for s in _db["edr_policy_endpoint_state"].find(
            {"tenant_id": tenant}, {"_id": 0}):
        for field, action, state in (
                ("assigned_at", "POLICY_ASSIGNED_TO_ENDPOINT", "ASSIGNED"),
                ("delivered_at", "POLICY_DELIVERED", "DELIVERED"),
                ("acknowledged_at", "POLICY_ACKNOWLEDGED", "ACKNOWLEDGED"),
                ("applied_at", "POLICY_APPLIED", "APPLIED"),
                ("verified_at", "POLICY_VERIFIED", "VERIFIED"),
                ("failed_at", "POLICY_APPLY_FAILED", "FAILED")):
            at = s.get(field)
            if not at or str(at) < since:
                continue
            out.append(_rec(
                at=at,
                actor=(s.get("assigned_by") if state == "ASSIGNED"
                       else s.get("endpoint_id")),
                action=action, category="POLICY_DELIVERY",
                target=s.get("endpoint_id"), target_type="ENDPOINT",
                new_state=state, reason=s.get("failure_reason")
                if state == "FAILED" else None,
                policy_version=(s.get("applied_version")
                                or s.get("acknowledged_version")
                                or s.get("delivered_version")),
                endpoint_id=s.get("endpoint_id"),
                result=state,
                evidence_ref=(s.get("applied_config_digest")
                              or s.get("delivered_config_digest")),
                source_store="edr_policy_endpoint_state",
                detail={"connector_version": s.get("connector_version"),
                        "policy_id": s.get("assigned_policy_id")}))
    return out


async def _connector(tenant: str, since: str) -> List[Dict[str, Any]]:
    out = []
    async for d in _db["edr_connector_deployments"].find(
            {"tenant_id": tenant, "created_at": {"$gte": since}},
            {"_id": 0}).sort("created_at", -1).limit(PER_SOURCE_CAP):
        out.append(_rec(
            at=d.get("created_at"), actor=d.get("created_by"),
            action="CONNECTOR_DEPLOYMENT_CREATED", category="CONNECTOR",
            target=d.get("release_id"), target_type="CONNECTOR_RELEASE",
            new_state="DEPLOYMENT_CONTEXT_ISSUED",
            reason=d.get("label"), policy_version=d.get("policy_version"),
            result=("NO_REBUILD" if d.get("rebuilt_connector") is False
                    else None),
            evidence_ref=d.get("deployment_id"),
            source_store="edr_connector_deployments",
            detail={"group": d.get("group_name"),
                    "policy": d.get("policy_name"),
                    "artifact_identity": d.get("artifact_identity")}))
    return out


async def _response(tenant: str, since: str) -> List[Dict[str, Any]]:
    out = []
    async for c in _db["edr_response_commands"].find(
            {"tenant_id": tenant}, {"_id": 0}).sort(
                "issued_at", -1).limit(PER_SOURCE_CAP):
        for field, action in (("issued_at", "RESPONSE_ISSUED"),
                              ("approved_at", "RESPONSE_APPROVED"),
                              ("delivered_at", "RESPONSE_DELIVERED"),
                              ("executed_at", "RESPONSE_EXECUTED"),
                              ("verified_at", "RESPONSE_VERIFIED")):
            at = c.get(field)
            if not at or str(at) < since:
                continue
            out.append(_rec(
                at=at,
                actor=(c.get("approved_by") if field == "approved_at"
                       else c.get("issued_by") or c.get("endpoint_id")),
                action=action, category="RESPONSE",
                target=c.get("command") or c.get("action"),
                target_type="RESPONSE_COMMAND",
                new_state=c.get("state"), reason=c.get("reason"),
                approval=(f"approved by {c.get('approved_by')}"
                          if c.get("approved_by") else None),
                endpoint_id=c.get("endpoint_id"),
                result=c.get("result") or c.get("state"),
                evidence_ref=c.get("command_id") or c.get("id"),
                source_store="edr_response_commands",
                detail={"verification": c.get("verification")}))
    return out


async def _enrolment(tenant: str, since: str) -> List[Dict[str, Any]]:
    out = []
    async for e in _db["edr_endpoints"].find(
            {"tenant_id": tenant, "placement_at": {"$gte": since}},
            {"_id": 0}).sort("placement_at", -1).limit(PER_SOURCE_CAP):
        out.append(_rec(
            at=e.get("placement_at"), actor=e.get("endpoint_id"),
            action="ENDPOINT_PLACED", category="ENROLMENT",
            target=e.get("hostname") or e.get("endpoint_id"),
            target_type="ENDPOINT",
            new_state=e.get("placement_basis"),
            endpoint_id=e.get("endpoint_id"), result="PLACED",
            evidence_ref=e.get("endpoint_id"), source_store="edr_endpoints",
            detail={"group_id": e.get("group_id"),
                    "policy_id": e.get("policy_id"),
                    "deployment_id": e.get("deployment_id")}))
    # P0-PROD-2 · the enrolment-token lifecycle, read from the store the
    # operation itself wrote. Never contains token or credential material.
    async for a in _db["edr_enrollment_audit"].find(
            {"tenant_id": tenant, "at": {"$gte": since}},
            {"_id": 0}).sort("at", -1).limit(PER_SOURCE_CAP):
        out.append(_rec(
            at=a.get("at"), actor=a.get("actor"), action=a.get("event"),
            category="ENROLMENT",
            target=a.get("token_id") or a.get("endpoint_id") or "enrolment",
            target_type=("ENROLLMENT_TOKEN" if a.get("token_id")
                         else "ENDPOINT"),
            new_state=a.get("outcome"), reason=a.get("reason_code"),
            endpoint_id=a.get("endpoint_id"), result=a.get("outcome"),
            evidence_ref=(a.get("token_id") or a.get("secret_fingerprint")
                          or a.get("at")),
            source_store="edr_enrollment_audit",
            detail={**(a.get("detail") or {}),
                    "source_ip": a.get("source_ip"),
                    "secret_fingerprint": a.get("secret_fingerprint")}))
    return out


def _cursor_encode(rec: Dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(
        {"a": rec["at"], "r": rec["record_id"]}).encode()).decode().rstrip("=")


def _cursor_decode(cursor: str) -> Dict[str, Any]:
    try:
        pad = cursor + "=" * (-len(cursor) % 4)
        out = json.loads(base64.urlsafe_b64decode(pad.encode()).decode())
        return {"a": out["a"], "r": out["r"]}
    except Exception:
        raise HTTPException(422, detail={
            "code": "CURSOR_INVALID",
            "reason": "the cursor was not produced by this endpoint"}) from None


@router.get("")
async def audit(category: Optional[str] = Query(None),
                actor: Optional[str] = Query(None),
                action: Optional[str] = Query(None),
                endpoint_id: Optional[str] = Query(None),
                q: Optional[str] = Query(None, min_length=2, max_length=200),
                days: int = Query(30, ge=1, le=365),
                limit: int = Query(50, ge=1, le=200),
                cursor: Optional[str] = Query(None),
                user: dict = Depends(get_current_user),
                tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    """Auditable EDR operations, newest first, filtered and paginated."""
    tenant = _scoped(tenant_id, user)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    wanted = None
    if category:
        wanted = category.strip().upper()
        if wanted not in CATEGORIES:
            raise HTTPException(422, detail={"code": "CATEGORY_INVALID",
                                             "allowed": list(CATEGORIES)})

    sources = {"POLICY": _policy, "EXCLUSION": _exclusion,
               "POLICY_DELIVERY": _delivery, "CONNECTOR": _connector,
               "RESPONSE": _response, "ENROLMENT": _enrolment}
    records: List[Dict[str, Any]] = []
    read: Dict[str, int] = {}
    for name, fn in sources.items():
        # Every source is read, then filtered by category: the POLICY
        # store also emits POLICY_DELIVERY records (an endpoint ACK), so
        # skipping stores by name would silently lose them.
        rows = await fn(tenant, since)
        read[name] = len(rows)
        records.extend(rows)
    if wanted:
        records = [r for r in records if r["category"] == wanted]
    if actor:
        records = [r for r in records if str(r.get("actor") or "") == actor]
    if action:
        records = [r for r in records
                   if str(r.get("action") or "").upper() == action.upper()]
    if endpoint_id:
        records = [r for r in records if r.get("endpoint_id") == endpoint_id]
    if q:
        needle = q.lower()
        records = [r for r in records
                   if needle in json.dumps(r, default=str).lower()]

    records.sort(key=lambda r: (str(r.get("at") or ""), r["record_id"]),
                 reverse=True)
    if cursor:
        c = _cursor_decode(cursor)
        key = (c["a"], c["r"])
        records = [r for r in records
                   if (str(r.get("at") or ""), r["record_id"]) < key]
    page = records[:limit]
    has_more = len(records) > limit
    capped = [k for k, v in read.items() if v >= PER_SOURCE_CAP]
    return {
        "tenant_id": tenant, "audit": page, "count": len(page),
        "has_more": has_more,
        "next_cursor": _cursor_encode(page[-1]) if page and has_more else None,
        "window_days": days,
        "categories": list(CATEGORIES),
        "sources_read": read,
        "sources_capped": capped,
        "completeness": (
            "complete for this window" if not capped else
            f"TRUNCATED: {capped} returned the per-source cap of "
            f"{PER_SOURCE_CAP}; narrow the window or filter by category to "
            "see the rest. The records are not lost, only not shown."),
        "provenance": (
            "every record is read from the authoritative store the "
            "operation itself wrote. There is no separate audit copy for "
            "the console to disagree with."),
    }


@router.get("/facets")
async def facets(days: int = Query(30, ge=1, le=365),
                 user: dict = Depends(get_current_user),
                 tenant_id: str = Depends(edr_tenant)) -> Dict[str, Any]:
    tenant = _scoped(tenant_id, user)
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    records: List[Dict[str, Any]] = []
    for fn in (_policy, _exclusion, _delivery, _connector, _response,
               _enrolment):
        records.extend(await fn(tenant, since))
    cats: Dict[str, int] = {}
    actors: Dict[str, int] = {}
    actions: Dict[str, int] = {}
    for r in records:
        cats[r["category"]] = cats.get(r["category"], 0) + 1
        a = str(r.get("actor") or "UNATTRIBUTED")
        actors[a] = actors.get(a, 0) + 1
        actions[r["action"]] = actions.get(r["action"], 0) + 1
    return {"tenant_id": tenant, "window_days": days,
            "total": len(records), "category": cats,
            "actor": dict(sorted(actors.items(), key=lambda kv: -kv[1])[:40]),
            "action": dict(sorted(actions.items(), key=lambda kv: -kv[1])),
            "categories": list(CATEGORIES)}
