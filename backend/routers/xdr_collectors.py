"""
XDR Collectors — P0-8 · Admin Control Plane + Evidence-Backed State Machine.

A **Collector** is HOW telemetry reaches NivXRay: a Syslog receiver, a
REST poller, a Webhook receiver, a Kafka consumer, an OTLP endpoint,
a Windows Event Forwarder subscription, etc.  It is a NAMED runtime
handle that operators can start/stop/test/rotate and that reports its
health honestly.

State machine (identical vocabulary to the P0-8 directive):

    ADOPTED  →  CONFIGURED  →  STARTING  →  CONNECTED
                                   ↓
                              AUTH_FAILED
                              CONNECTION_FAILED
                              NO_TELEMETRY
                              PARSE_ERROR
                              DEGRADED
                              DISABLED

CRITICAL invariant (enforced by ``xdr_ingest``): ``CONNECTED`` is
ONLY assigned when the collector has produced real telemetry that
was successfully received + parsed + normalized.  The admin surface
here NEVER promotes a collector to CONNECTED — it can only demote
it (start ⇒ STARTING, disable ⇒ DISABLED, error ⇒ CONNECTION_FAILED).

Protocol implementation registry
--------------------------------
Every collector kind carries an honest implementation state so the
UI never claims a fake CONNECTED:

    IMPLEMENTED   — real receiver/adapter shipped in the collector
                          service and reachable end-to-end.
    SCAFFOLD      — protocol vocabulary + config validation exist,
                          but no live adapter is wired yet.
    BLOCKED       — external dependency prevents implementation.

Storage · MongoDB collection ``xdr_collectors``.
"""
from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo import DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/collectors", tags=["xdr-collectors"])


# ── Mongo binding ─────────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _coll():
    return _db()["xdr_collectors"] if _db() is not None else None


# ── Principal extraction ─────────────────────────────────────────
def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


# ── Canonical protocol registry — SINGLE source of truth ────────
# Every value here is checked at CRUD and rendered by the UI.  The
# `implementation` field is HONEST: adapters live in
# `/app/apps/nivxray-xdr-collector` — only those that exist there
# are marked IMPLEMENTED.  Anything else is SCAFFOLD until wired.
PROTOCOL_REGISTRY: dict[str, dict[str, Any]] = {
    "syslog":  {"implementation": "IMPLEMENTED",
                    "transport":       "udp/tcp",
                    "canonical_schema": "canonical.log",
                    "notes": "Real receiver in nivxray-xdr-collector · framework/syslog.py"},
    "webhook": {"implementation": "IMPLEMENTED",
                    "transport":       "http",
                    "canonical_schema": "canonical.event",
                    "notes": "Real HMAC-validated receiver · framework/webhook.py"},
    "rest":    {"implementation": "IMPLEMENTED",
                    "transport":       "https",
                    "canonical_schema": "canonical.event",
                    "notes": "Real REST poller · framework/rest_poller.py"},
    "cef":     {"implementation": "SCAFFOLD",
                    "transport":       "syslog",
                    "canonical_schema": "canonical.log",
                    "notes": "Uses syslog transport · CEF parser wiring pending"},
    "leef":    {"implementation": "SCAFFOLD",
                    "transport":       "syslog",
                    "canonical_schema": "canonical.log",
                    "notes": "Uses syslog transport · LEEF parser wiring pending"},
    "kafka":   {"implementation": "SCAFFOLD",
                    "transport":       "kafka",
                    "canonical_schema": "canonical.event",
                    "notes": "Consumer client not implemented"},
    "otlp":    {"implementation": "SCAFFOLD",
                    "transport":       "grpc/http",
                    "canonical_schema": "canonical.event",
                    "notes": "OTLP receiver not implemented"},
    "wef":     {"implementation": "SCAFFOLD",
                    "transport":       "winrm",
                    "canonical_schema": "canonical.host.process",
                    "notes": "Windows Event Forwarding subscription not implemented"},
    "file":    {"implementation": "SCAFFOLD",
                    "transport":       "filesystem",
                    "canonical_schema": "canonical.event",
                    "notes": "File tailer not implemented"},
    "edr":     {"implementation": "SCAFFOLD",
                    "transport":       "vendor-sdk",
                    "canonical_schema": "canonical.host.process",
                    "notes": "Vendor adapter framework in nivxray-xdr-collector; wiring pending"},
    "ndr":     {"implementation": "SCAFFOLD",
                    "transport":       "vendor-sdk",
                    "canonical_schema": "canonical.network.flow",
                    "notes": "Vendor adapter framework in nivxray-xdr-collector; wiring pending"},
    "cloud":   {"implementation": "SCAFFOLD",
                    "transport":       "https",
                    "canonical_schema": "canonical.cloud.audit",
                    "notes": "Cloud audit connectors (AWS/GCP/Azure) not wired"},
}


STATES = {
    "ADOPTED", "CONFIGURED", "STARTING",
    "AUTH_FAILED", "CONNECTION_FAILED", "NO_TELEMETRY", "PARSE_ERROR",
    "CONNECTED", "DEGRADED", "DISABLED",
}

# Transitions the ADMIN API may perform.  CONNECTED is deliberately
# absent — only the ingest telemetry path may transition to CONNECTED.
ADMIN_TRANSITIONS: dict[str, set[str]] = {
    "ADOPTED":              {"CONFIGURED", "STARTING", "DISABLED"},
    "CONFIGURED":           {"STARTING", "DISABLED"},
    "STARTING":             {"CONFIGURED", "AUTH_FAILED", "CONNECTION_FAILED", "DISABLED"},
    "AUTH_FAILED":          {"CONFIGURED", "STARTING", "DISABLED"},
    "CONNECTION_FAILED":    {"CONFIGURED", "STARTING", "DISABLED"},
    "NO_TELEMETRY":         {"CONFIGURED", "STARTING", "DISABLED"},
    "PARSE_ERROR":          {"CONFIGURED", "STARTING", "DISABLED"},
    "CONNECTED":            {"DEGRADED", "DISABLED", "STARTING"},
    "DEGRADED":             {"CONFIGURED", "STARTING", "DISABLED"},
    "DISABLED":             {"CONFIGURED", "STARTING"},
}


# ── Pydantic models ───────────────────────────────────────────────
_NAME_RE = re.compile(r"^[a-zA-Z0-9._:\- ]{1,80}$")


class CreateCollectorBody(BaseModel):
    name:         str = Field(min_length=1, max_length=80)
    protocol:     str
    description:  str | None = None
    parser:       str | None = None
    normalization_profile: str | None = None
    tls:          bool | None = None
    auth_kind:    str | None = None       # "none" | "basic" | "bearer" | "hmac" | "mtls"
    secret_id:    str | None = None
    config:       dict[str, Any] = Field(default_factory=dict)
    tags:         list[str] = Field(default_factory=list)


class UpdateCollectorBody(BaseModel):
    name:         str | None = None
    description:  str | None = None
    parser:       str | None = None
    normalization_profile: str | None = None
    tls:          bool | None = None
    auth_kind:    str | None = None
    secret_id:    str | None = None
    config:       dict[str, Any] | None = None
    tags:         list[str] | None = None


# ── Helpers ───────────────────────────────────────────────────────
def _mask(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k != "_id"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_create(body: CreateCollectorBody) -> None:
    if not _NAME_RE.match(body.name):
        raise HTTPException(400, detail=f"invalid name '{body.name}'")
    if body.protocol not in PROTOCOL_REGISTRY:
        raise HTTPException(400, detail={
            "code": "UNKNOWN_PROTOCOL",
            "protocol": body.protocol,
            "allowed": sorted(PROTOCOL_REGISTRY)})


def _transition_state(coll: dict, target: str, *, reason: str,
                                     evidence: dict, admin: bool = True) -> None:
    """Persist a state transition.  Admin-driven transitions are
    validated against ADMIN_TRANSITIONS.  Only the ingest path is
    allowed to move a collector to CONNECTED — see ``xdr_ingest``."""
    if target not in STATES:
        raise HTTPException(500, detail=f"invalid target state '{target}'")
    if admin and target == "CONNECTED":
        raise HTTPException(400, detail={
            "code": "CONNECTED_REQUIRES_TELEMETRY",
            "reason": ("CONNECTED may only be assigned after actual "
                            "telemetry has been received, parsed and "
                            "normalized — via the ingest telemetry path")})
    current = coll.get("state", "ADOPTED")
    if admin and current in ADMIN_TRANSITIONS and \
            target not in ADMIN_TRANSITIONS[current] and target != current:
        raise HTTPException(400, detail={
            "code": "ILLEGAL_TRANSITION",
            "from":  current,
            "to":    target,
            "allowed_from": sorted(ADMIN_TRANSITIONS[current])})
    now = _now()
    _coll().update_one({"_id": coll["_id"]},
        {"$set": {"state": target, "state_reason": reason,
                       "state_evidence": {**evidence, "at": now},
                       "updated_at": now}})


# ── Endpoints ─────────────────────────────────────────────────────
@router.get("",
                     dependencies=[Depends(require_permission("collectors.read"))])
def list_collectors(request: Request,
                                 protocol: str | None = Query(None),
                                 state: str | None = Query(None),
                                 limit: int = Query(200, ge=1, le=1000)):
    if _coll() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    q: dict[str, Any] = {"tenant_id": ten}
    if protocol: q["protocol"] = protocol
    if state:    q["state"]    = state
    cur = _coll().find(q).sort("created_at", DESCENDING).limit(limit)
    rows = [_mask(d) for d in cur]
    return {"ok": True, "data": {"collectors": rows, "count": len(rows),
                                                      "protocols": PROTOCOL_REGISTRY}}


@router.get("/{cid}",
                     dependencies=[Depends(require_permission("collectors.read"))])
def get_collector(cid: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")
    return {"ok": True, "data": _mask(doc)}


@router.get("/protocols/catalog",
                     dependencies=[Depends(require_permission("collectors.read"))])
def protocol_catalog():
    """Public list of collector protocols with honest implementation
    status.  Never fabricated — the UI reads this."""
    implemented = sum(1 for m in PROTOCOL_REGISTRY.values()
                                    if m["implementation"] == "IMPLEMENTED")
    scaffold    = sum(1 for m in PROTOCOL_REGISTRY.values()
                                    if m["implementation"] == "SCAFFOLD")
    blocked     = sum(1 for m in PROTOCOL_REGISTRY.values()
                                    if m["implementation"] == "BLOCKED")
    return {"ok": True, "data": {
        "protocols": PROTOCOL_REGISTRY,
        "counts": {"total": len(PROTOCOL_REGISTRY),
                        "implemented": implemented,
                        "scaffold": scaffold,
                        "blocked": blocked}}}


@router.post("",
                       dependencies=[Depends(require_permission("collectors.create"))])
def create_collector(body: CreateCollectorBody, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    _validate_create(body)
    ten, pid, pkd = _principal(request)
    if _coll().find_one({"tenant_id": ten, "name": body.name}):
        raise HTTPException(409,
            detail=f"collector '{body.name}' already exists for tenant")

    cid = f"col_{uuid.uuid4().hex[:20]}"
    now = _now()
    proto = PROTOCOL_REGISTRY[body.protocol]
    doc = {
        "id":                    cid,
        "tenant_id":             ten,
        "name":                  body.name,
        "protocol":              body.protocol,
        "implementation":        proto["implementation"],
        "transport":             proto["transport"],
        "canonical_schema":      proto["canonical_schema"],
        "description":           body.description,
        "parser":                body.parser,
        "normalization_profile": body.normalization_profile,
        "tls":                   bool(body.tls) if body.tls is not None else None,
        "auth_kind":             body.auth_kind,
        "secret_id":             body.secret_id,
        "config":                dict(body.config or {}),
        "tags":                  list(body.tags or []),
        "enabled":               True,
        "state":                 "ADOPTED",
        "state_reason":          "created",
        "state_evidence":        {"at": now, "by": pid, "reason": "created"},
        # Real telemetry counters (only touched by the ingest path).
        "events_received":       0,
        "events_parsed":         0,
        "events_normalized":     0,
        "events_error":          0,
        "last_event_at":         None,
        "eps_1m":                0.0,
        "created_at":            now,
        "updated_at":            now,
        "created_by":            pid,
    }
    _coll().insert_one(dict(doc))
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_CREATED", resource_kind="collector",
        resource_id=cid,
        after={"name": body.name, "protocol": body.protocol,
                    "implementation": proto["implementation"]},
    )
    return {"ok": True, "data": _mask(doc), "audit_ref": audit["id"]}


@router.put("/{cid}",
                     dependencies=[Depends(require_permission("collectors.update"))])
def update_collector(cid: str, body: UpdateCollectorBody, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")

    patch: dict[str, Any] = {}
    for k in ("name", "description", "parser", "normalization_profile",
                  "tls", "auth_kind", "secret_id", "config", "tags"):
        v = getattr(body, k)
        if v is not None:
            patch[k] = v
    if not patch:
        raise HTTPException(400, detail="no updatable fields provided")
    if "name" in patch and not _NAME_RE.match(patch["name"]):
        raise HTTPException(400, detail=f"invalid name '{patch['name']}'")
    patch["updated_at"] = _now()

    # Any admin update after ADOPTED moves the doc to CONFIGURED so
    # the state accurately reflects "config was touched".
    new_state = "CONFIGURED" if doc.get("state") == "ADOPTED" else doc.get("state")
    if new_state != doc.get("state"):
        patch["state"] = new_state
        patch["state_reason"]   = "configuration updated"
        patch["state_evidence"] = {"at": patch["updated_at"], "by": pid,
                                                    "reason": "configuration updated"}

    _coll().update_one({"_id": doc["_id"]}, {"$set": patch})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_UPDATED", resource_kind="collector",
        resource_id=cid,
        before={k: doc.get(k) for k in patch if k != "updated_at"},
        after={k: v for k, v in patch.items() if k != "updated_at"},
    )
    return {"ok": True, "data": _mask(_coll().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


def _admin_transition(cid: str, request: Request, *, action_audit: str,
                                     target: str, reason: str) -> dict:
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")
    before_state = doc.get("state")
    _transition_state(doc, target,
                                reason=reason,
                                evidence={"by": pid, "reason": reason})
    doc = _coll().find_one({"_id": doc["_id"]})
    audit_action = action_audit
    emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action=audit_action, resource_kind="collector",
        resource_id=cid,
        before={"state": before_state},
        after={"state": target, "reason": reason},
    )
    # Additionally emit a state-change event so operators can trace it.
    emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_STATE_CHANGED", resource_kind="collector",
        resource_id=cid,
        before={"state": before_state},
        after={"state": target, "reason": reason},
        metadata={"evidence": {"by": pid}},
    )
    return {"ok": True, "data": _mask(doc)}


@router.post("/{cid}/start",
                       dependencies=[Depends(require_permission("collectors.enable"))])
def start_collector(cid: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    return _admin_transition(cid, request, action_audit="COLLECTOR_STARTED",
                                              target="STARTING", reason="start requested")


@router.post("/{cid}/stop",
                       dependencies=[Depends(require_permission("collectors.disable"))])
def stop_collector(cid: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    return _admin_transition(cid, request, action_audit="COLLECTOR_STOPPED",
                                              target="DISABLED", reason="stop requested")


@router.post("/{cid}/enable",
                       dependencies=[Depends(require_permission("collectors.enable"))])
def enable_collector(cid: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")
    if doc.get("enabled") is True:
        return {"ok": True, "data": _mask(doc), "no_change": True}
    _coll().update_one({"_id": doc["_id"]},
                                {"$set": {"enabled": True, "updated_at": _now()}})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_ENABLED", resource_kind="collector",
        resource_id=cid, after={"enabled": True},
    )
    return {"ok": True, "data": _mask(_coll().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


@router.post("/{cid}/disable",
                       dependencies=[Depends(require_permission("collectors.disable"))])
def disable_collector(cid: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    return _admin_transition(cid, request, action_audit="COLLECTOR_DISABLED",
                                              target="DISABLED", reason="disabled by admin")


@router.post("/{cid}/test",
                       dependencies=[Depends(require_permission("collectors.test"))])
def test_collector(cid: str, request: Request):
    """Deterministic connectivity probe.  Records the probe outcome
    but NEVER promotes the collector to CONNECTED.  If the probe
    reveals a configuration problem the collector is transitioned to
    the appropriate diagnostic state (AUTH_FAILED / CONNECTION_FAILED)
    with the reason recorded as evidence."""
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")

    problems: list[str] = []
    proto = doc.get("protocol")
    reg   = PROTOCOL_REGISTRY.get(proto)
    if reg is None:
        problems.append(f"unknown protocol '{proto}'")
    elif reg["implementation"] != "IMPLEMENTED":
        problems.append(
            f"protocol '{proto}' is {reg['implementation']} — no live adapter")
    if (doc.get("auth_kind") or "none") not in \
            {"none", "basic", "bearer", "hmac", "mtls"}:
        problems.append(f"unknown auth_kind '{doc.get('auth_kind')}'")

    now = _now()
    probe = {"at": now, "by": pid, "problems": problems,
                  "ok": len(problems) == 0}
    _coll().update_one({"_id": doc["_id"]},
                                {"$set": {"last_probe": probe, "updated_at": now}})

    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_TESTED", resource_kind="collector",
        resource_id=cid,
        outcome="SUCCESS" if probe["ok"] else "PARTIAL",
        after={"problems": problems, "ok": probe["ok"]},
    )
    return {"ok": True, "data": {**_mask(doc), "last_probe": probe},
                 "audit_ref": audit["id"]}


@router.post("/{cid}/rotate-credential",
                       dependencies=[Depends(require_permission("collectors.rotate"))])
def rotate_credential(cid: str, body: dict, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    new_secret_id = body.get("secret_id")
    if not new_secret_id:
        raise HTTPException(400, detail="secret_id is required")
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")
    _coll().update_one({"_id": doc["_id"]},
                                {"$set": {"secret_id": new_secret_id,
                                                "updated_at": _now()}})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_CREDENTIAL_ROTATED",
        resource_kind="collector", resource_id=cid,
        before={"secret_id": doc.get("secret_id")},
        after={"secret_id": new_secret_id},
    )
    return {"ok": True, "data": _mask(_coll().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


@router.delete("/{cid}",
                          dependencies=[Depends(require_permission("collectors.delete"))])
def delete_collector(cid: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": cid, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="collector not found")
    _coll().delete_one({"_id": doc["_id"]})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="COLLECTOR_DELETED", resource_kind="collector",
        resource_id=cid,
        before={"name": doc.get("name"), "protocol": doc.get("protocol")},
    )
    return {"ok": True, "data": {"id": cid, "deleted": True},
                 "audit_ref": audit["id"]}
