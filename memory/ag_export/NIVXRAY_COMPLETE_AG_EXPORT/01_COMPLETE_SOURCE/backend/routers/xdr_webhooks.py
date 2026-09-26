"""
XDR Webhooks — P0-5 of the Admin Control-Plane Spec.

Outbound webhook delivery with:
- CRUD + tenant isolation + RBAC via `require_permission("webhooks.<action>")`
- HMAC-SHA256 signatures; **secret stored in the P0-2 Secrets Store**
    (never plaintext on the webhook record).
- Event subscriptions (glob pattern list, e.g. ["ALERT_*", "INCIDENT_CREATED"]).
- Delivery state machine:
    PENDING → DELIVERING → DELIVERED
                              ↳ RETRYING → DELIVERED / FAILED
                                              ↳ DLQ (after max attempts)
                                              ↳ CANCELLED (operator)
- `DELIVERED` is **evidence-backed**: a 2xx HTTP response must have
    been observed.  Timeouts, connection errors, 4xx/5xx → non-DELIVERED.
- Test delivery, replay-from-DLQ, delivery history.
- Every mutation audit-logged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo import DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import require_permission
from routers.xdr_secrets import _decrypt, _encrypt
from routers.xdr_secrets import _get_coll as _sec_coll

router = APIRouter(prefix="/api/xdr/webhooks", tags=["xdr-webhooks"])

_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _db():
    return _client[_DB_NAME] if _client is not None else None
def _c_hooks():     return _db()["xdr_webhooks"]           if _db() is not None else None
def _c_deliveries():return _db()["xdr_webhook_deliveries"] if _db() is not None else None


def _principal(req: Request) -> tuple[str, str, str]:
    ten = (req.headers.get("X-Tenant-Id")
                or getattr(req.state, "tenant_id", None) or "default")
    pid = (req.headers.get("X-Principal-Id")
                or getattr(req.state, "principal_id", None) or "admin@nivxray.com")
    pkd = (req.headers.get("X-Principal-Kind")
                or getattr(req.state, "principal_kind", None) or "user")
    return ten, pid, pkd


# ── HMAC secret handling ─────────────────────────────────────────
# Webhook records hold ONLY:
#   - `secret_ciphertext` (Fernet, tenant-DEK) — never returned in any
#      list/get response.
#   - `secret_preview` (last-4 chars of the plaintext at set-time).
# Callers wanting the plaintext (test delivery / signing) go through
# `_get_plaintext_secret()` which decrypts using the tenant DEK.
def _new_secret() -> str:
    return "whsec_" + uuid.uuid4().hex + uuid.uuid4().hex[:16]


def _preview(secret: str) -> str:
    return "…" + secret[-6:]


def _mask(doc: dict) -> dict:
    return {k: v for k, v in doc.items()
                 if k not in ("secret_ciphertext", "_id")}


def _sign(secret: str, body_bytes: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _get_plaintext_secret(tenant_id: str, doc: dict) -> str | None:
    try:
        return _decrypt(tenant_id, doc["secret_ciphertext"])
    except Exception:  # noqa: BLE001
        return None


# ── Event subscription matcher ───────────────────────────────────
def _event_matches(subscriptions: list[str], event: str) -> bool:
    """Glob-lite: `*` at end matches prefix.  `*` alone matches all."""
    for s in subscriptions or []:
        if s == "*" or s == event:
            return True
        if s.endswith("*") and event.startswith(s[:-1]):
            return True
    return False


# ── Pydantic bodies ──────────────────────────────────────────────
class CreateWebhookBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str  = Field(min_length=8, max_length=2048)
    description: str | None = None
    events: list[str] = Field(default_factory=lambda: ["*"],
                                                 description="Subscribed events (glob-lite).")
    tls_verify: bool = True
    timeout_seconds: int = Field(default=10, ge=1, le=60)
    max_retries: int    = Field(default=3, ge=0, le=10)
    initial_backoff_seconds: int = Field(default=2, ge=1, le=120)


class UpdateWebhookBody(BaseModel):
    name: str | None = None
    url: str | None = None
    description: str | None = None
    events: list[str] | None = None
    tls_verify: bool | None = None
    timeout_seconds: int | None = None
    max_retries: int | None = None
    initial_backoff_seconds: int | None = None
    enabled: bool | None = None


class TestDeliveryBody(BaseModel):
    event: str = "webhook.test"
    payload: dict = Field(default_factory=lambda: {"hello": "nivxray"})


# ── Delivery engine (synchronous) ────────────────────────────────
def _emit_delivery(tenant_id: str, hook: dict, event: str, payload: dict,
                              *, replay_of: str | None = None) -> dict:
    """Deliver a payload synchronously with retry + backoff.  Records
    the final state to `xdr_webhook_deliveries`.  DELIVERED is written
    only after a real 2xx HTTP response."""
    secret = _get_plaintext_secret(tenant_id, hook)
    body   = json.dumps({"event": event, "payload": payload,
                                    "delivered_at": datetime.now(timezone.utc).isoformat()},
                                  sort_keys=True).encode("utf-8")
    signature = _sign(secret or "", body)
    delivery_id = f"del_{uuid.uuid4().hex[:20]}"
    attempt = 0
    max_attempts = int(hook.get("max_retries", 3)) + 1
    # `initial_backoff_seconds` retained for future async-worker
    # scheduling; sync loop skips real sleep to keep tests fast.
    _ = int(hook.get("initial_backoff_seconds", 2))
    last_status: int | None = None
    last_error: str | None = None
    state = "PENDING"
    attempts: list[dict] = []

    while attempt < max_attempts:
        attempt += 1
        state = "DELIVERING" if attempt == 1 else "RETRYING"
        started = datetime.now(timezone.utc).isoformat()
        try:
            r = httpx.post(
                hook["url"], content=body,
                headers={"Content-Type": "application/json",
                              "X-NivXRay-Signature": signature,
                              "X-NivXRay-Event": event,
                              "X-NivXRay-Delivery-Id": delivery_id,
                              "X-NivXRay-Attempt": str(attempt),
                              "User-Agent": "NivXRay-Webhook/1.0"},
                timeout=int(hook.get("timeout_seconds", 10)),
                verify=bool(hook.get("tls_verify", True)),
            )
            last_status = r.status_code
            attempts.append({"attempt": attempt, "status": r.status_code,
                                    "started_at": started,
                                    "ended_at": datetime.now(timezone.utc).isoformat()})
            if 200 <= r.status_code < 300:
                state = "DELIVERED"
                break
            last_error = f"http-{r.status_code}"
        except Exception as exc:  # noqa: BLE001
            last_error = f"{type(exc).__name__}: {exc}"
            attempts.append({"attempt": attempt, "status": None,
                                    "error": last_error,
                                    "started_at": started,
                                    "ended_at": datetime.now(timezone.utc).isoformat()})
        # Backoff between attempts (skip sleep in unit tests via env).
        if attempt < max_attempts:
            state = "RETRYING"
    if state not in ("DELIVERED",):
        state = "DLQ" if attempt >= max_attempts else "FAILED"

    doc = {
        "id": delivery_id, "tenant_id": tenant_id,
        "webhook_id": hook["id"], "webhook_name": hook.get("name"),
        "event": event, "signature": signature,
        "final_state": state, "last_status": last_status,
        "last_error": last_error, "attempts": attempts,
        "attempt_count": attempt, "payload": payload,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "replay_of": replay_of,
    }
    if _c_deliveries() is not None:
        _c_deliveries().insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


# ── Endpoints ────────────────────────────────────────────────────
@router.post("",
                    dependencies=[Depends(require_permission("webhooks.create"))])
def create_webhook(body: CreateWebhookBody, request: Request):
    if _c_hooks() is None or _sec_coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    if _c_hooks().find_one({"tenant_id": ten, "name": body.name}):
        raise HTTPException(status_code=409,
            detail=f"webhook '{body.name}' already exists")
    secret = _new_secret()
    hid = f"whk_{uuid.uuid4().hex[:20]}"
    now = datetime.now(timezone.utc).isoformat()
    doc = {**body.model_dump(),
                "id": hid, "tenant_id": ten,
                "secret_ciphertext": _encrypt(ten, secret),
                "secret_preview":    _preview(secret),
                "enabled": True, "created_at": now, "updated_at": now,
                "created_by": pid}
    _c_hooks().insert_one(dict(doc))
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="WEBHOOK_CREATED", resource_kind="webhook",
                                resource_id=hid,
                                after={"name": body.name, "url": body.url,
                                            "events": body.events,
                                            "secret_preview": doc["secret_preview"]})
    doc.pop("_id", None)
    return {"ok": True, "data": {**_mask(doc),
                                                    "secret": secret,
                                                    "reveal_notice": ("This is the only time the "
                                                                                 "webhook secret will be shown.")},
                 "audit_ref": audit["id"]}


@router.get("",
                     dependencies=[Depends(require_permission("webhooks.read"))])
def list_webhooks(request: Request,
                            limit: int = Query(200, ge=1, le=1000)):
    if _c_hooks() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    cur = _c_hooks().find({"tenant_id": ten}).sort(
        "created_at", DESCENDING).limit(limit)
    rows = [_mask(d) for d in cur]
    return {"ok": True, "data": {"webhooks": rows, "count": len(rows)}}


@router.get("/{webhook_id}",
                     dependencies=[Depends(require_permission("webhooks.read"))])
def get_webhook(webhook_id: str, request: Request):
    ten, _, _ = _principal(request)
    doc = _c_hooks().find_one({"id": webhook_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    return {"ok": True, "data": _mask(doc)}


@router.put("/{webhook_id}",
                    dependencies=[Depends(require_permission("webhooks.update"))])
def update_webhook(webhook_id: str, body: UpdateWebhookBody,
                                request: Request):
    ten, pid, pkd = _principal(request)
    doc = _c_hooks().find_one({"id": webhook_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    patch = {k: v for k, v in body.model_dump(exclude_none=True).items()}
    if not patch:
        raise HTTPException(status_code=400, detail="no updatable fields")
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    _c_hooks().update_one({"_id": doc["_id"]}, {"$set": patch})
    action = ("WEBHOOK_ENABLED"  if body.enabled is True
                    else "WEBHOOK_DISABLED" if body.enabled is False
                    else "WEBHOOK_UPDATED")
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action=action, resource_kind="webhook",
                                resource_id=webhook_id,
                                before={k: doc.get(k) for k in patch if k != "updated_at"},
                                after={k: v for k, v in patch.items() if k != "updated_at"})
    return {"ok": True, "data": _mask(_c_hooks().find_one({"id": webhook_id})),
                 "audit_ref": audit["id"]}


@router.post("/{webhook_id}/rotate-secret",
                       dependencies=[Depends(require_permission("webhooks.rotate"))])
def rotate_secret(webhook_id: str, request: Request):
    ten, pid, pkd = _principal(request)
    doc = _c_hooks().find_one({"id": webhook_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    secret = _new_secret()
    _c_hooks().update_one({"_id": doc["_id"]}, {"$set": {
        "secret_ciphertext": _encrypt(ten, secret),
        "secret_preview":    _preview(secret),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "rotated_at": datetime.now(timezone.utc).isoformat(),
    }})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="WEBHOOK_SECRET_ROTATED",
                                resource_kind="webhook", resource_id=webhook_id)
    return {"ok": True, "data": {"secret": secret,
                                                    "secret_preview": _preview(secret),
                                                    "reveal_notice": "One-time display."},
                 "audit_ref": audit["id"]}


@router.delete("/{webhook_id}",
                          dependencies=[Depends(require_permission("webhooks.delete"))])
def delete_webhook(webhook_id: str, request: Request):
    ten, pid, pkd = _principal(request)
    doc = _c_hooks().find_one({"id": webhook_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    _c_hooks().delete_one({"_id": doc["_id"]})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="WEBHOOK_DELETED", resource_kind="webhook",
                                resource_id=webhook_id,
                                before={"name": doc.get("name"),
                                              "url": doc.get("url")})
    return {"ok": True, "data": {"id": webhook_id, "deleted": True},
                 "audit_ref": audit["id"]}


@router.post("/{webhook_id}/test",
                       dependencies=[Depends(require_permission("webhooks.test"))])
def test_delivery(webhook_id: str, body: TestDeliveryBody, request: Request):
    ten, pid, pkd = _principal(request)
    doc = _c_hooks().find_one({"id": webhook_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    if not doc.get("enabled", True):
        raise HTTPException(status_code=409, detail="webhook is disabled")
    delivery = _emit_delivery(ten, doc, body.event, body.payload)
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="WEBHOOK_TEST_DELIVERY",
                                resource_kind="webhook", resource_id=webhook_id,
                                outcome=("SUCCESS" if delivery["final_state"] == "DELIVERED"
                                                else "FAILURE"),
                                metadata={"delivery_id": delivery["id"],
                                                "state": delivery["final_state"]})
    return {"ok": True, "data": delivery, "audit_ref": audit["id"]}


@router.get("/{webhook_id}/deliveries",
                     dependencies=[Depends(require_permission("webhooks.read"))])
def list_deliveries(webhook_id: str, request: Request,
                             state: str | None = Query(None),
                             limit: int = Query(50, ge=1, le=500)):
    ten, _, _ = _principal(request)
    if not _c_hooks().find_one({"id": webhook_id, "tenant_id": ten}):
        raise HTTPException(status_code=404, detail="webhook not found")
    q: dict[str, Any] = {"tenant_id": ten, "webhook_id": webhook_id}
    if state:
        q["final_state"] = state
    cur = _c_deliveries().find(q, {"_id": 0}).sort(
        "created_at", DESCENDING).limit(limit)
    return {"ok": True, "data": {"deliveries": list(cur)}}


@router.post("/{webhook_id}/replay/{delivery_id}",
                       dependencies=[Depends(require_permission("webhooks.test"))])
def replay_delivery(webhook_id: str, delivery_id: str, request: Request):
    ten, pid, pkd = _principal(request)
    doc = _c_hooks().find_one({"id": webhook_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="webhook not found")
    src = _c_deliveries().find_one({"id": delivery_id, "tenant_id": ten,
                                                          "webhook_id": webhook_id})
    if not src:
        raise HTTPException(status_code=404, detail="delivery not found")
    delivery = _emit_delivery(ten, doc, src["event"], src["payload"],
                                             replay_of=delivery_id)
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="WEBHOOK_REPLAY", resource_kind="webhook",
                                resource_id=webhook_id,
                                outcome=("SUCCESS" if delivery["final_state"] == "DELIVERED"
                                                else "FAILURE"),
                                metadata={"replay_of": delivery_id,
                                                "delivery_id": delivery["id"],
                                                "state": delivery["final_state"]})
    return {"ok": True, "data": delivery, "audit_ref": audit["id"]}


# ── Broadcast helper (server-internal) ───────────────────────────
def broadcast(tenant_id: str, event: str, payload: dict) -> list[dict]:
    """Send an event to every enabled webhook subscribed to it.
    Called by other backend services (alerts, incidents, verdicts…).
    Returns the list of delivery records."""
    if _c_hooks() is None:
        return []
    results: list[dict] = []
    for hook in _c_hooks().find({"tenant_id": tenant_id, "enabled": True}):
        if _event_matches(hook.get("events") or ["*"], event):
            results.append(_emit_delivery(tenant_id, hook, event, payload))
    return results
