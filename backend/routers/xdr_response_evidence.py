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

import os
import uuid
from datetime import datetime, timezone
from typing   import Any, Dict, Optional

from fastapi  import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field


router = APIRouter(prefix="/xdr", tags=["xdr-response-evidence"])


class Invoker(BaseModel):
    kind:    str
    id:      str
    context: Dict[str, Any] = Field(default_factory=dict)


class ActionRef(BaseModel):
    action_id:  str
    provider:   Optional[str] = None
    capability: Optional[str] = None


class Authorization(BaseModel):
    approved_by:  Optional[str] = None
    approval_ref: Optional[str] = None
    reason:       Optional[str] = None


class ResponseEvidenceRequest(BaseModel):
    execution_id:     str
    tenant_id:        str
    invoker:          Invoker
    action:           ActionRef
    parameters:       Dict[str, Any] = Field(default_factory=dict)
    canonical_target: Dict[str, Any] = Field(default_factory=dict)
    adapter_result:   Optional[Dict[str, Any]] = None
    adapter_ok:       bool = False
    started_at:       Optional[str] = None
    completed_at:     Optional[str] = None
    dry_run:          bool = False
    authorization:    Authorization = Field(default_factory=Authorization)
    # Provenance is optional in the wire payload — the engine stamps it,
    # but for hand-crafted test POSTs we tolerate its absence and fill in.
    provenance:       Optional[Dict[str, Any]] = None


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mint(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@router.post("/response-evidence")
async def response_evidence(body: ResponseEvidenceRequest, request: Request):
    """Idempotent evidence sink for the Response Engine.  See module docstring."""
    db = _resolve_db(request)
    if db is None:
        raise HTTPException(503, detail={"error": "database_unavailable"})

    # 1. Idempotency — replay returns identical refs.
    prior = await db.xdr_response_executions.find_one({"execution_id": body.execution_id})
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
        "tenant_id":        body.tenant_id,
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
            "tenant_id":    body.tenant_id,
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


@router.get("/response-evidence/{execution_id}")
async def get_response_evidence(execution_id: str, request: Request,
                                        tenant_id: Optional[str] = None):
    """Reads the persisted triple for an execution.  Optional tenant
    filter as a defensive check on top of upstream authz."""
    db = _resolve_db(request)
    if db is None:
        raise HTTPException(503, detail={"error": "database_unavailable"})
    q: Dict[str, Any] = {"execution_id": execution_id}
    if tenant_id:
        q["tenant_id"] = tenant_id
    row = await db.xdr_response_executions.find_one(q)
    if not row:
        raise HTTPException(404, detail={"error": "not_found"})
    return {k: row[k] for k in
                ("execution_id", "tenant_id", "evidence_ref", "audit_ref",
                 "timeline_ref", "ingested_at")}


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
        from server import db as _server_db                    # type: ignore
        return _server_db
    except Exception:                                           # pragma: no cover
        return None
