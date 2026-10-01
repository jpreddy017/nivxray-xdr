"""
XDR Data Sources — P0-8 · Admin Control Plane.

A **Data Source** describes WHAT telemetry we want (a security tool,
a cloud tenant, an on-host agent).  It is bound to a **Collector**
that provides HOW the telemetry reaches NivXRay (Syslog receiver,
REST poller, Webhook, Kafka topic, OTLP endpoint, …).

Contract:
  * Tenant-scoped, RBAC-enforced, audit-emitted on every mutation.
  * Credentials MUST NOT be stored in the data-source doc; they live
    in the Secrets Store and the doc carries only the ``secret_id``.
  * No fabricated state.  Every transition is evidence-backed:
    creation is an admin act; enable/disable is an admin act; a
    connectivity ``test`` is only ever a probe, never a "CONNECTED".
    A source is only ``CONNECTED`` once its bound collector has
    received + parsed + normalized real telemetry (recorded via
    ``xdr_ingest``).

Storage · MongoDB collection ``xdr_data_sources``.
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

router = APIRouter(prefix="/api/xdr/data-sources", tags=["xdr-data-sources"])


# ── Mongo binding (sync pymongo — matches the other P0 routers) ───
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None


def _coll():
    return _db()["xdr_data_sources"] if _db() is not None else None


# ── Principal extraction (identical shape to sibling routers) ────
def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


# ── Canonical vocabularies ────────────────────────────────────────
# Every accepted source kind maps to a collector protocol.  This is
# the source of truth for the UI's "kind" dropdown.  Unknown values
# are rejected at validation time — no free-form kinds.
SOURCE_KINDS: dict[str, dict[str, Any]] = {
    # kind          →   default protocol / canonical schema hint
    "generic_syslog":       {"protocol": "syslog",   "canonical": "canonical.log"},
    "cef_syslog":           {"protocol": "syslog",   "canonical": "canonical.log"},
    "leef_syslog":          {"protocol": "syslog",   "canonical": "canonical.log"},
    "windows_event_fwd":    {"protocol": "wef",      "canonical": "canonical.host.process"},
    "sysmon_wef":           {"protocol": "wef",      "canonical": "canonical.host.process"},
    "generic_webhook":      {"protocol": "webhook",  "canonical": "canonical.event"},
    "generic_rest":         {"protocol": "rest",     "canonical": "canonical.event"},
    "aws_cloudtrail":       {"protocol": "rest",     "canonical": "canonical.cloud.audit"},
    "gcp_audit_logs":       {"protocol": "rest",     "canonical": "canonical.cloud.audit"},
    "azure_activity":       {"protocol": "rest",     "canonical": "canonical.cloud.audit"},
    "office365_activity":   {"protocol": "rest",     "canonical": "canonical.cloud.audit"},
    "kafka_topic":          {"protocol": "kafka",    "canonical": "canonical.event"},
    "otlp_logs":            {"protocol": "otlp",     "canonical": "canonical.event"},
    "file_ingest":          {"protocol": "file",     "canonical": "canonical.event"},
    "edr_stream":           {"protocol": "edr",      "canonical": "canonical.host.process"},
    "ndr_stream":           {"protocol": "ndr",      "canonical": "canonical.network.flow"},
}

# Data-source lifecycle (never confused with collector state machine):
LIFECYCLE_STATES = {"DRAFT", "ADOPTED", "ENABLED", "DISABLED", "ARCHIVED"}


# ── Pydantic models ───────────────────────────────────────────────
_NAME_RE = re.compile(r"^[a-zA-Z0-9._:\- ]{1,80}$")


class CreateDataSourceBody(BaseModel):
    name:                 str = Field(min_length=1, max_length=80)
    kind:                 str
    description:          str | None = None
    parser:               str | None = None
    normalization_profile: str | None = None
    collector_id:         str | None = None
    secret_id:            str | None = None
    tags:                 list[str] = Field(default_factory=list)
    config:               dict[str, Any] = Field(default_factory=dict)


class UpdateDataSourceBody(BaseModel):
    name:                 str | None = None
    description:          str | None = None
    parser:               str | None = None
    normalization_profile: str | None = None
    collector_id:         str | None = None
    secret_id:            str | None = None
    tags:                 list[str] | None = None
    config:               dict[str, Any] | None = None


# ── Helpers ───────────────────────────────────────────────────────
def _mask(doc: dict) -> dict:
    """Strip Mongo ``_id`` before returning to the caller.  Secrets
    live in the Secrets Store — only ``secret_id`` reference here."""
    d = {k: v for k, v in doc.items() if k != "_id"}
    return d


def _validate_create(body: CreateDataSourceBody) -> None:
    if not _NAME_RE.match(body.name):
        raise HTTPException(400, detail=f"invalid name '{body.name}' · "
                                                          "allowed: [A-Za-z0-9._: -] up to 80 chars")
    if body.kind not in SOURCE_KINDS:
        raise HTTPException(400, detail={"code": "INVALID_KIND",
                                                                  "kind": body.kind,
                                                                  "allowed": sorted(SOURCE_KINDS)})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Endpoints ─────────────────────────────────────────────────────
@router.get("",
                     dependencies=[Depends(require_permission("data_sources.read"))])
def list_data_sources(request: Request,
                                     kind: str | None = Query(None),
                                     enabled: bool | None = Query(None),
                                     limit: int = Query(200, ge=1, le=1000)):
    if _coll() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    q: dict[str, Any] = {"tenant_id": ten}
    if kind:              q["kind"] = kind
    if enabled is not None: q["enabled"] = enabled
    cur = _coll().find(q).sort("created_at", DESCENDING).limit(limit)
    rows = [_mask(d) for d in cur]
    return {"ok": True, "data": {"data_sources": rows, "count": len(rows),
                                                      "kinds": sorted(SOURCE_KINDS)}}


@router.get("/{ds_id}",
                     dependencies=[Depends(require_permission("data_sources.read"))])
def get_data_source(ds_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    doc = _coll().find_one({"id": ds_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="data source not found")
    return {"ok": True, "data": _mask(doc)}


@router.post("",
                       dependencies=[Depends(require_permission("data_sources.create"))])
def create_data_source(body: CreateDataSourceBody, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    _validate_create(body)
    ten, pid, pkd = _principal(request)
    if _coll().find_one({"tenant_id": ten, "name": body.name}):
        raise HTTPException(409,
            detail=f"data source '{body.name}' already exists for tenant")

    dsid = f"ds_{uuid.uuid4().hex[:20]}"
    now = _now()
    kind_meta = SOURCE_KINDS[body.kind]
    doc = {
        "id":                    dsid,
        "tenant_id":             ten,
        "name":                  body.name,
        "kind":                  body.kind,
        "protocol":              kind_meta["protocol"],
        "canonical_schema":      kind_meta["canonical"],
        "description":           body.description,
        "parser":                body.parser,
        "normalization_profile": body.normalization_profile,
        "collector_id":          body.collector_id,
        "secret_id":             body.secret_id,
        "tags":                  list(body.tags or []),
        "config":                dict(body.config or {}),
        "enabled":               True,
        "state":                 "ADOPTED",
        "state_reason":          "created",
        "state_evidence":        {"created_at": now, "created_by": pid},
        "last_telemetry_at":     None,
        "events_received":       0,
        "events_parsed":         0,
        "events_normalized":     0,
        "events_error":          0,
        "created_at":            now,
        "updated_at":            now,
        "created_by":            pid,
    }
    _coll().insert_one(dict(doc))
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="DATA_SOURCE_CREATED", resource_kind="data_source",
        resource_id=dsid,
        after={"name": body.name, "kind": body.kind,
                    "protocol": kind_meta["protocol"]},
    )
    return {"ok": True, "data": _mask(doc), "audit_ref": audit["id"]}


@router.put("/{ds_id}",
                     dependencies=[Depends(require_permission("data_sources.update"))])
def update_data_source(ds_id: str, body: UpdateDataSourceBody, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": ds_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="data source not found")

    patch: dict[str, Any] = {}
    for k in ("name", "description", "parser", "normalization_profile",
                  "collector_id", "secret_id", "tags", "config"):
        v = getattr(body, k)
        if v is not None:
            patch[k] = v
    if not patch:
        raise HTTPException(400, detail="no updatable fields provided")
    if "name" in patch and not _NAME_RE.match(patch["name"]):
        raise HTTPException(400, detail=f"invalid name '{patch['name']}'")
    patch["updated_at"] = _now()
    _coll().update_one({"_id": doc["_id"]}, {"$set": patch})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="DATA_SOURCE_UPDATED", resource_kind="data_source",
        resource_id=ds_id,
        before={k: doc.get(k) for k in patch if k != "updated_at"},
        after={k: v for k, v in patch.items() if k != "updated_at"},
    )
    updated = _coll().find_one({"_id": doc["_id"]})
    return {"ok": True, "data": _mask(updated), "audit_ref": audit["id"]}


def _toggle(ds_id: str, request: Request, *, enable: bool) -> dict:
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": ds_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="data source not found")
    if bool(doc.get("enabled")) == enable:
        return {"ok": True, "data": _mask(doc), "no_change": True}
    now = _now()
    new_state = "ADOPTED" if enable else "DISABLED"
    reason    = "enabled by admin" if enable else "disabled by admin"
    _coll().update_one(
        {"_id": doc["_id"]},
        {"$set": {"enabled": enable, "updated_at": now,
                       "state": new_state, "state_reason": reason,
                       "state_evidence": {"at": now, "by": pid}}},
    )
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action=("DATA_SOURCE_ENABLED" if enable else "DATA_SOURCE_DISABLED"),
        resource_kind="data_source", resource_id=ds_id,
        after={"enabled": enable, "state": new_state, "reason": reason},
    )
    return {"ok": True, "data": _mask(_coll().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


@router.post("/{ds_id}/enable",
                       dependencies=[Depends(require_permission("data_sources.enable"))])
def enable_data_source(ds_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    return _toggle(ds_id, request, enable=True)


@router.post("/{ds_id}/disable",
                       dependencies=[Depends(require_permission("data_sources.disable"))])
def disable_data_source(ds_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    return _toggle(ds_id, request, enable=False)


@router.post("/{ds_id}/test",
                       dependencies=[Depends(require_permission("data_sources.test"))])
def test_data_source(ds_id: str, request: Request):
    """Diagnostic probe.  DOES NOT change state to CONNECTED — only
    the ingest telemetry path can do that.  Records the probe outcome
    on the doc so operators can see the last diagnostic result."""
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": ds_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="data source not found")
    # Deterministic probe: verify config integrity + collector binding.
    problems: list[str] = []
    if not doc.get("collector_id"):
        problems.append("no collector bound")
    kind_meta = SOURCE_KINDS.get(doc.get("kind"))
    if kind_meta is None:
        problems.append(f"unknown kind '{doc.get('kind')}'")
    now = _now()
    probe = {"at": now, "by": pid, "problems": problems,
                  "ok": len(problems) == 0}
    _coll().update_one({"_id": doc["_id"]},
                                {"$set": {"last_probe": probe, "updated_at": now}})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="DATA_SOURCE_TESTED", resource_kind="data_source",
        resource_id=ds_id,
        outcome="SUCCESS" if probe["ok"] else "PARTIAL",
        after={"problems": problems, "ok": probe["ok"]},
    )
    return {"ok": True, "data": {**_mask(doc), "last_probe": probe},
                 "audit_ref": audit["id"]}


@router.post("/{ds_id}/rotate-credential",
                       dependencies=[Depends(require_permission("data_sources.rotate"))])
def rotate_credential(ds_id: str, body: dict, request: Request):
    """Point the data source at a new ``secret_id``.  Does NOT rotate
    the underlying secret — call ``POST /api/xdr/secrets/{id}/rotate``
    for that.  This endpoint only updates the reference and is an
    explicit audit event so the analyst can see a credential swap."""
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    new_secret_id = body.get("secret_id")
    if not new_secret_id:
        raise HTTPException(400, detail="secret_id is required")
    doc = _coll().find_one({"id": ds_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="data source not found")
    _coll().update_one({"_id": doc["_id"]},
                                {"$set": {"secret_id": new_secret_id,
                                                "updated_at": _now()}})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="DATA_SOURCE_CREDENTIAL_ROTATED",
        resource_kind="data_source", resource_id=ds_id,
        before={"secret_id": doc.get("secret_id")},
        after={"secret_id": new_secret_id},
    )
    return {"ok": True, "data": _mask(_coll().find_one({"_id": doc["_id"]})),
                 "audit_ref": audit["id"]}


@router.delete("/{ds_id}",
                          dependencies=[Depends(require_permission("data_sources.delete"))])
def delete_data_source(ds_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": ds_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="data source not found")
    _coll().delete_one({"_id": doc["_id"]})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="DATA_SOURCE_DELETED", resource_kind="data_source",
        resource_id=ds_id,
        before={"name": doc.get("name"), "kind": doc.get("kind")},
    )
    return {"ok": True, "data": {"id": ds_id, "deleted": True},
                 "audit_ref": audit["id"]}


@router.get("/kinds/catalog",
                     dependencies=[Depends(require_permission("data_sources.read"))])
def list_kinds():
    """Public catalog of accepted data-source kinds and the protocol
    each maps to.  Renders the Add-source dropdown honestly — no
    fabricated kinds."""
    return {"ok": True, "data": {
        "kinds": SOURCE_KINDS,
        "count": len(SOURCE_KINDS),
    }}
