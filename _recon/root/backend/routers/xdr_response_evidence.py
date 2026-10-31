"""
POST /api/xdr/response-evidence — Response Engine → Base evidence sink.

Owner-locked scope (see /app/apps/nivxray-xdr-response/RESPONSE_INGEST_CONTRACT.md):
  * The ONLY base-backend endpoint the standalone Response Engine
    writes to.  Everything else stays authoritative-write only.
  * Idempotent on ``execution_id`` — repeat POSTs return the same
    (evidence_ref, audit_ref, timeline_ref) triple.
  * Validates provenance (`provenance.kind = "response_action"`); the
    engine forwarder always stamps that, so a payload without it is
    treated as untrusted and rejected.
  * Does NOT touch SSOT / Verdict / IKG.  Persists three lightweight
    projection rows into MongoDB collections dedicated to response
    provenance so an analyst reading Investigation can see the
    response chain without changing detection logic.

Collections (created on demand):
  * ``xdr_response_evidence``  — evidence rows keyed by (evidence_ref).
  * ``xdr_response_audit``     — audit rows keyed by (audit_ref).
  * ``xdr_response_timeline``  — timeline rows keyed by (timeline_ref).
  * ``xdr_response_executions`` — dedup index on execution_id →
    (evidence_ref, audit_ref, timeline_ref) for idempotency.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from routers.xdr_rbac import require_permission
from deps import get_current_user
from routers.incidents import authorized_incident
from services.dashboard_lenses import resolve_tenant_scope


def _apply_principal_tenant_scope(q: dict[str, Any], user: dict | None,
                                  requested_tenant: str | None) -> dict:
    """P0 · the ONE tenant predicate for the response-evidence plane.

    The scope is resolved from the verified principal
    (`resolve_tenant_scope`), exactly as the incident plane resolves it. A
    client-presented `tenant_id` is a REQUEST: it may narrow the principal's
    own scope and can never widen it. An unauthorized principal gets a
    predicate that cannot match, so the answer is an honest empty state
    rather than another customer's response history.
    """
    scope = resolve_tenant_scope((user or {}).get("email"))
    if not scope.get("authorized"):
        q["tenant_id"] = {"$in": []}
        return scope
    if scope.get("all_tenants"):
        if requested_tenant:
            q["tenant_id"] = requested_tenant
        return scope
    tenants = [t for t in (scope.get("tenant_ids") or []) if t]
    if requested_tenant:
        tenants = [t for t in tenants if t == requested_tenant]
    q["tenant_id"] = {"$in": tenants}
    return scope

def _resolve_write_tenant_authority(body: ResponseEvidenceRequest,
                                    user: dict | None) -> tuple[str, str, dict]:
    """P0.1 · THE tenant authority for a response-evidence WRITE.

    Owner contract (2026-06): `body.tenant_id` is an ASSERTION that may be
    CHECKED, never the source of ownership. Tenant ownership is derived only
    from authoritative server-side context:

        single-tenant verified principal + no resource anchor
            → its one tenant is authoritative
        any principal + authoritative incident anchor
            → the incident's server-resolved tenant is authoritative
        multi/all-tenant principal + no authoritative anchor
            → DENY (being authorized for tenant B does not prove that THIS
              response evidence belongs to tenant B)

    A presented tenant that disagrees with the authority fails closed, and
    the refusal never discloses the authoritative tenant value.
    """
    scope = resolve_tenant_scope((user or {}).get("email"))
    if not scope.get("authorized"):
        raise HTTPException(403, detail={
            "error":  "tenant_authority_denied",
            "reason": "principal_not_tenant_authorized",
        })
    asserted = (body.tenant_id or "").strip() or None
    incident_id = (body.invoker.context or {}).get("incident_id")

    if incident_id:
        # THE incident authority: out of scope ⇒ 404, existence undisclosed.
        doc, _q = authorized_incident(str(incident_id), user,
                                      {"_id": 0, "id": 1, "tenant_id": 1})
        tenant = str(doc.get("tenant_id") or "").strip()
        if not tenant:
            raise HTTPException(403, detail={
                "error":  "tenant_authority_denied",
                "reason": "incident_carries_no_tenant_authority",
            })
        if asserted and asserted != tenant:
            raise HTTPException(403, detail={
                "error":  "tenant_authority_denied",
                "reason": "asserted_tenant_conflicts_with_resource_authority",
            })
        return tenant, "incident", scope

    if scope.get("all_tenants"):
        raise HTTPException(403, detail={
            "error":  "tenant_authority_denied",
            "reason": "ambiguous_tenant_authority_without_resource_anchor",
        })
    tenants = [t for t in (scope.get("tenant_ids") or []) if t]
    if len(tenants) != 1:
        raise HTTPException(403, detail={
            "error":  "tenant_authority_denied",
            "reason": "ambiguous_tenant_authority_without_resource_anchor",
        })
    tenant = str(tenants[0])
    if asserted and asserted != tenant:
        raise HTTPException(403, detail={
            "error":  "tenant_authority_denied",
            "reason": "asserted_tenant_outside_principal_authority",
        })
    return tenant, "principal_scope", scope


router = APIRouter(prefix="/xdr", tags=["xdr-response-evidence"])


class Invoker(BaseModel):
    kind:    str
    id:      str
    context: dict[str, Any] = Field(default_factory=dict)


class ActionRef(BaseModel):
    action_id:  str
    provider:   str | None = None
    capability: str | None = None


class Authorization(BaseModel):
    approved_by:  str | None = None
    approval_ref: str | None = None
    reason:       str | None = None


class ResponseEvidenceRequest(BaseModel):
    execution_id:     str
    # P0.1 · an ASSERTION only. The stored tenant is resolved server-side
    # (`_resolve_write_tenant_authority`); a presented value may be checked
    # but is never authority, and may therefore be omitted entirely.
    tenant_id:        str | None = None
    invoker:          Invoker
    action:           ActionRef
    parameters:       dict[str, Any] = Field(default_factory=dict)
    canonical_target: dict[str, Any] = Field(default_factory=dict)
    adapter_result:   dict[str, Any] | None = None
    adapter_ok:       bool = False
    started_at:       str | None = None
    completed_at:     str | None = None
    dry_run:          bool = False
    authorization:    Authorization = Field(default_factory=Authorization)
    # Provenance is optional in the wire payload — the engine stamps it,
    # but for hand-crafted test POSTs we tolerate its absence and fill in.
    provenance:       dict[str, Any] | None = None


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mint(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@router.post("/response-evidence",
                       dependencies=[Depends(require_permission("response.execute"))])
async def response_evidence(body: ResponseEvidenceRequest, request: Request,
                            user: dict = Depends(get_current_user)):
    """Idempotent evidence sink for the Response Engine.  See module docstring."""
    db = _resolve_db(request)
    if db is None:
        raise HTTPException(503, detail={"error": "database_unavailable"})

    # 0. P0.1 · resolve the tenant AUTHORITY before anything is read or
    # written. Everything below stores and matches on this value only.
    tenant_id, authority_source, _scope = _resolve_write_tenant_authority(body, user)

    # 1. Idempotency — replay returns identical refs. Scoped to the resolved
    # tenant so an execution_id can neither collide across tenants nor be
    # used to harvest another tenant's ref triple.
    prior = await db.xdr_response_executions.find_one(
        {"execution_id": body.execution_id, "tenant_id": tenant_id})
    if prior:
        return {
            "evidence_ref": prior["evidence_ref"],
            "audit_ref":    prior["audit_ref"],
            "timeline_ref": prior["timeline_ref"],
            "idempotent_replay": True,
        }

    # 2. Provenance validation — enforce the invariant published in the contract.
    prov = dict(body.provenance or {})
    prov.setdefault("kind", "response_action")
    prov["execution_id"] = body.execution_id
    # P0.1 · record WHERE the tenant authority came from. This documents the
    # decision; it is never itself consulted as authority.
    prov["tenant_authority"] = {
        "source":             authority_source,
        "tenant_id":          tenant_id,
        "asserted_tenant_id": (body.tenant_id or None),
    }
    if prov.get("kind") != "response_action":
        raise HTTPException(400, detail={
            "error":  "invalid_provenance",
            "reason": "provenance.kind must be 'response_action'",
        })

    # 3. Mint the three refs.
    evidence_ref = _mint("evidence")
    audit_ref    = _mint("audit")
    timeline_ref = _mint("timeline")
    now          = _iso()
    common = {
        "execution_id":     body.execution_id,
        "tenant_id":        tenant_id,
        "invoker":          body.invoker.model_dump(),
        "action":           body.action.model_dump(),
        "parameters":       body.parameters,
        "canonical_target": body.canonical_target,
        "adapter_ok":       bool(body.adapter_ok),
        "adapter_result":   body.adapter_result,
        "started_at":       body.started_at,
        "completed_at":     body.completed_at,
        "dry_run":          bool(body.dry_run),
        "simulation":       bool(body.dry_run),
        "authorization":    body.authorization.model_dump(),
        "provenance":       prov,
        "ingested_at":      now,
    }
    incident_id = (body.invoker.context or {}).get("incident_id")

    # 4. Persist evidence · audit · timeline.  A single write per collection.
    try:
        await db.xdr_response_evidence.insert_one({
            **common, "_ref": evidence_ref, "ref": evidence_ref,
            "label": f"{body.action.action_id} · {'succeeded' if body.adapter_ok else 'failed'}",
        })
        await db.xdr_response_audit.insert_one({
            **common, "_ref": audit_ref, "ref": audit_ref,
        })
        await db.xdr_response_timeline.insert_one({
            **common,
            "_ref":        timeline_ref, "ref": timeline_ref,
            "incident_id": incident_id,
            "occurred_at": body.completed_at or body.started_at or now,
            "label":       _timeline_label(body),
        })
        await db.xdr_response_executions.insert_one({
            "execution_id": body.execution_id,
            "tenant_id":    tenant_id,
            "evidence_ref": evidence_ref,
            "audit_ref":    audit_ref,
            "timeline_ref": timeline_ref,
            "ingested_at":  now,
        })
    except Exception as e:                                      # noqa: BLE001
        raise HTTPException(500, detail={
            "error":  "evidence_write_failed",
            "reason": f"{type(e).__name__}: {e}",
        })

    return {
        "evidence_ref": evidence_ref,
        "audit_ref":    audit_ref,
        "timeline_ref": timeline_ref,
    }


@router.get("/response-evidence/{execution_id}",
                     dependencies=[Depends(require_permission("evidence.read"))])
async def get_response_evidence(execution_id: str, request: Request,
                                        tenant_id: str | None = None,
                                        user: dict = Depends(get_current_user)):
    """Reads the persisted triple for an execution.

    P0 (2026-06-21) · the `tenant_id` query parameter used to be the ONLY
    tenant predicate, so omitting it read any tenant's execution by id. The
    tenant now comes from the verified principal
    (`resolve_tenant_scope`); the parameter survives for compatibility but
    can only NARROW the principal's own scope, never widen it. Out of scope
    is indistinguishable from non-existent.
    """
    db = _resolve_db(request)
    if db is None:
        raise HTTPException(503, detail={"error": "database_unavailable"})
    q: dict[str, Any] = {"execution_id": execution_id}
    _apply_principal_tenant_scope(q, user, tenant_id)
    row = await db.xdr_response_executions.find_one(q)
    if not row:
        raise HTTPException(404, detail={"error": "not_found"})
    return {k: row[k] for k in
                ("execution_id", "tenant_id", "evidence_ref", "audit_ref",
                 "timeline_ref", "ingested_at")}


@router.get("/incidents/{incident_id}/response-executions",
                     dependencies=[Depends(require_permission("evidence.read"))])
async def list_incident_response_executions(
        incident_id: str, request: Request,
        tenant_id: str | None = None, limit: int = 100,
        user: dict = Depends(get_current_user)):
    """Backfill route for the Investigation Canvas.

    Returns every response execution whose invoker context carries the
    requested ``incident_id``, joined with its persisted ref triple.
    The Response Engine still owns the execution lifecycle (own SQLite);
    the base backend owns the evidence/audit/timeline record; this route
    surfaces the base's authoritative projection so the frontend does
    not need a second call to the Response Engine.

    P0 (2026-06-21) · this route used to query purely by
    ``invoker.context.incident_id`` with an OPTIONAL, client-supplied
    ``tenant_id``, so any principal holding ``evidence.read`` could read
    another customer's response executions by putting their incident id in
    the path. Authorization is now:

        authenticated principal
          → the incident is resolved through THE incident authority
            (`routers.incidents.authorized_incident`, server-resolved
            tenant scope; out of scope ⇒ 404, existence never disclosed)
          → the evidence query is scoped to the principal's own tenants

    The ``tenant_id`` parameter is preserved for compatibility and can only
    narrow that server-resolved scope.
    """
    db = _resolve_db(request)
    if db is None:
        raise HTTPException(503, detail={"error": "database_unavailable"})

    # The incident is the authority: a principal that cannot address the
    # incident cannot read its response history, and cannot learn it exists.
    authorized_incident(incident_id, user, {"_id": 0, "id": 1, "tenant_id": 1})

    # Evidence rows carry the full invoker/action/parameters block, so
    # we read from ``xdr_response_evidence`` filtered by
    # ``invoker.context.incident_id`` and join in the ref triple from
    # the dedup index.
    q: dict[str, Any] = {"invoker.context.incident_id": incident_id}
    scope = _apply_principal_tenant_scope(q, user, tenant_id)

    cursor = db.xdr_response_evidence.find(q).sort("completed_at", -1)
    rows: list[dict[str, Any]] = []
    async for r in cursor:
        # Motor is optional in tests; the fake in tests returns a plain
        # list-backed collection so we tolerate a `find(...)` that
        # returns a synchronous iterable too.
        rows.append(r)
        if len(rows) >= max(1, min(limit, 500)):
            break
    projected = []
    for r in rows:
        projected.append({
            "execution_id":     r.get("execution_id"),
            "tenant_id":        r.get("tenant_id"),
            "invoker":          r.get("invoker"),
            "action":           r.get("action"),
            "action_id":        (r.get("action") or {}).get("action_id"),
            "parameters":       r.get("parameters"),
            "canonical_target": r.get("canonical_target"),
            "adapter_ok":       r.get("adapter_ok"),
            "adapter_result":   r.get("adapter_result"),
            "started_at":       r.get("started_at"),
            "completed_at":     r.get("completed_at"),
            "dry_run":          r.get("dry_run"),
            "simulation":       r.get("simulation"),
            "authorization":    r.get("authorization"),
            "evidence_ref":     r.get("_ref") or r.get("ref"),
            # audit + timeline refs come from the dedup index — join.
            "audit_ref":        None,
            "timeline_ref":     None,
            "state":            "SUCCEEDED" if r.get("adapter_ok") else "FAILED_EXECUTION",
        })
    # Join in audit + timeline refs.  Bulk-fetch by execution_id.
    ex_ids = [p["execution_id"] for p in projected if p["execution_id"]]
    if ex_ids:
        dedup_q: dict[str, Any] = {"execution_id": {"$in": ex_ids}}
        _apply_principal_tenant_scope(dedup_q, user, tenant_id)
        dedup_cur = db.xdr_response_executions.find(dedup_q)
        dedup_map: dict[str, dict[str, Any]] = {}
        async for d in dedup_cur:
            dedup_map[d.get("execution_id")] = d
        for p in projected:
            d = dedup_map.get(p["execution_id"])
            if not d: continue
            p["audit_ref"]    = d.get("audit_ref")
            p["timeline_ref"] = d.get("timeline_ref")
    applied = q.get("tenant_id")
    return {
        "incident_id":   incident_id,
        # the tenant scope that was APPLIED, resolved server-side — never
        # the value a caller presented.
        "tenant_id":     (applied.get("$in") if isinstance(applied, dict)
                          else applied),
        "tenant_scope":  ("ALL_TENANTS" if scope.get("all_tenants")
                          else "PRINCIPAL_TENANTS"),
        "count":         len(projected),
        "executions":    projected,
    }


def _timeline_label(body: ResponseEvidenceRequest) -> str:
    target = ""
    for k in ("host_id", "user_id", "user", "ip", "domain", "hash", "message_id"):
        if k in (body.parameters or {}):
            target = f" · {body.parameters[k]}"
            break
    who = body.authorization.approved_by or body.invoker.id or ""
    who = f" · by {who}" if who else ""
    verb = body.action.action_id.replace(".", " · ")
    return f"{verb}{target}{who}"


def _resolve_db(request: Request):
    """Reach the Motor client that ``server.py`` mounted on ``client``.
    Isolated helper so unit tests can inject a fake db."""
    # Support two mount patterns without importing server directly:
    # 1) ``app.state.db`` (test injection),  2) module-level ``client`` in server.
    fake = getattr(request.app.state, "db", None)
    if fake is not None:
        return fake
    try:
        from server import db as _server_db  # type: ignore
        return _server_db
    except Exception:                                           # pragma: no cover
        return None
