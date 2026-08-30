"""
XDR Audit Log — P0-1 of the Admin Control-Plane Spec.

Append-only, tenant-aware, HMAC-signed audit chain.  Every subsequent
XDR admin write MUST emit an event through `emit_audit(...)`.

Storage: MongoDB collection `xdr_audit_log`.
Signing: per-tenant HMAC over deterministic canonical serialization; each
event carries `prev_sig` forming a tamper-evident chain per tenant.

NO fabrication.  NO synthetic events.  Empty result sets return `[]`.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pymongo import MongoClient, DESCENDING, ASCENDING
from pydantic import BaseModel, Field


router = APIRouter(prefix="/api/xdr/audit-log", tags=["xdr-audit-log"])

# ── Mongo binding (sync pymongo — audit log is not perf-critical and
# using sync eliminates event-loop mismatch under TestClient). ────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _get_coll():
    if _client is None:
        return None
    return _client[_DB_NAME]["xdr_audit_log"]


_coll = _get_coll()  # for tests that reference al._coll directly


# ── Signing key (per-tenant HMAC) ────────────────────────────────
# In production this is fetched from the platform KMS envelope.  For
# now we derive it deterministically from a platform master secret so
# the chain is verifiable in-process; rotation is a future concern.
_MASTER = (os.environ.get("XDR_AUDIT_MASTER_SECRET")
                 or "xdr-audit-master-do-not-use-in-prod").encode()


def _tenant_key(tenant_id: str) -> bytes:
    return hmac.new(_MASTER, tenant_id.encode(), hashlib.sha256).digest()


def _canonical(event: dict) -> bytes:
    """Deterministic serialization — used for signing."""
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"),
        default=str,
    ).encode()


def _sign(tenant_id: str, event: dict, prev_sig: str) -> str:
    payload = {**event, "prev_sig": prev_sig}
    return hmac.new(_tenant_key(tenant_id), _canonical(payload),
                             hashlib.sha256).hexdigest()


# ── Emit helper — the canonical write path ───────────────────────
def emit_audit(
    *, tenant_id: str, principal_id: str, principal_kind: str,
    action: str, resource_kind: str, resource_id: str,
    outcome: str = "SUCCESS",
    before: Optional[dict] = None, after: Optional[dict] = None,
    correlation_id: Optional[str] = None,
    source: str = "xdr-admin", metadata: Optional[dict] = None,
) -> dict:
    """Write one audit event.  Returns the persisted document.

    NEVER fabricates.  NEVER returns until the write has been
    acknowledged by Mongo (fail-close per spec §5)."""
    if _get_coll() is None:
        raise HTTPException(
            status_code=503,
            detail="audit-log unavailable · MONGO_URL not configured")

    now = datetime.now(timezone.utc).isoformat()
    event_id = f"aud_{uuid.uuid4().hex[:20]}"

    # Fetch prev_sig for this tenant (tamper-evident chain).
    last = _get_coll().find_one({"tenant_id": tenant_id},
                                                   sort=[("at", DESCENDING)])
    prev_sig = (last or {}).get("sig", "genesis")

    base = {
        "id": event_id, "tenant_id": tenant_id,
        "principal_id": principal_id, "principal_kind": principal_kind,
        "action": action, "resource_kind": resource_kind,
        "resource_id": resource_id, "outcome": outcome,
        "before": before, "after": after,
        "correlation_id": correlation_id or event_id,
        "source": source, "metadata": metadata or {},
        "at": now,
    }
    sig = _sign(tenant_id, base, prev_sig)
    doc = {**base, "prev_sig": prev_sig, "sig": sig}
    _get_coll().insert_one(doc)
    doc.pop("_id", None)
    return doc


# ── Public read endpoints ────────────────────────────────────────
class AuditEvent(BaseModel):
    id: str
    tenant_id: str
    principal_id: str
    principal_kind: str
    action: str
    resource_kind: str
    resource_id: str
    outcome: str
    before: Optional[dict] = None
    after:  Optional[dict] = None
    correlation_id: str
    source: str
    metadata: dict = Field(default_factory=dict)
    at: str
    prev_sig: str
    sig: str


def _principal(req: Request) -> tuple[str, str, str]:
    """Best-effort principal extraction.  Falls back to `demo` when
    no auth middleware has set the request state.  A future JWT
    verifier will replace this with real claim extraction."""
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


@router.get("")
def list_events(
    request: Request,
    tenant: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_kind: Optional[str] = Query(None),
    principal_id: Optional[str] = Query(None),
    outcome: Optional[str] = Query(None),
    since: Optional[str] = Query(None),
    until: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    if _get_coll() is None:
        return {"ok": False, "error": {
            "code": "STORAGE_UNAVAILABLE",
            "detail": "audit-log storage not configured"}}
    ten, _, _ = _principal(request)
    tenant = tenant or ten
    q: dict[str, Any] = {"tenant_id": tenant}
    if action:        q["action"] = action
    if resource_kind: q["resource_kind"] = resource_kind
    if principal_id:  q["principal_id"] = principal_id
    if outcome:       q["outcome"] = outcome
    if since or until:
        q["at"] = {}
        if since: q["at"]["$gte"] = since
        if until: q["at"]["$lte"] = until
    cur = _get_coll().find(q, {"_id": 0}).sort("at", DESCENDING).limit(limit)
    rows = list(cur)
    return {"ok": True, "data": {"events": rows, "count": len(rows)}}


@router.get("/{event_id}")
def get_event(event_id: str, request: Request):
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    doc = _get_coll().find_one({"id": event_id, "tenant_id": ten}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="audit event not found")
    return {"ok": True, "data": doc}


@router.get("/verify/chain")
def verify_chain(request: Request, limit: int = Query(500, ge=1, le=5000)):
    """Walk the tenant's chain from oldest to newest, recomputing each
    signature.  Returns the first break (if any) or 'valid'."""
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    cur = _get_coll().find({"tenant_id": ten}, {"_id": 0}).sort("at", ASCENDING).limit(limit)
    prev = "genesis"
    checked = 0
    for doc in cur:
        expected_prev = doc.get("prev_sig")
        if expected_prev != prev:
            return {"ok": True, "data": {"status": "chain_broken",
                                                          "at_event": doc["id"],
                                                          "reason": "prev_sig_mismatch",
                                                          "expected": prev,
                                                          "actual": expected_prev,
                                                          "checked": checked}}
        base = {k: v for k, v in doc.items() if k not in ("sig", "prev_sig")}
        recomputed = _sign(ten, base, prev)
        if recomputed != doc.get("sig"):
            return {"ok": True, "data": {"status": "chain_broken",
                                                          "at_event": doc["id"],
                                                          "reason": "signature_mismatch",
                                                          "checked": checked}}
        prev = doc["sig"]
        checked += 1
    return {"ok": True, "data": {"status": "valid", "checked": checked}}


# ── POST /emit — direct emit endpoint used by XDR UI + tests ─────
class EmitBody(BaseModel):
    action: str
    resource_kind: str
    resource_id: str
    outcome: str = "SUCCESS"
    before: Optional[dict] = None
    after:  Optional[dict] = None
    correlation_id: Optional[str] = None
    source: str = "xdr-admin"
    metadata: dict = Field(default_factory=dict)


@router.post("/emit")
def emit_endpoint(body: EmitBody, request: Request):
    ten, pid, pkd = _principal(request)
    doc = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action=body.action, resource_kind=body.resource_kind,
        resource_id=body.resource_id, outcome=body.outcome,
        before=body.before, after=body.after,
        correlation_id=body.correlation_id, source=body.source,
        metadata=body.metadata,
    )
    return {"ok": True, "data": doc, "audit_ref": doc["id"]}
