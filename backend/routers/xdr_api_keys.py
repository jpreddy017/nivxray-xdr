"""
XDR API Keys — P0-4 of the Admin Control-Plane Spec.

Programmatic access tokens for the NivXRay XDR API.

Guarantees
==========
- **Only SHA-256 hashes** are persisted.  Plaintext is returned once at
    creation / rotation and NEVER again.
- **Scopes** are drawn from the same `permission` vocabulary that RBAC
    roles use, so an API key can express `secrets.read`, `alerts.ack`,
    `lolbas.sync`, `*.*`, etc.  Every request validated by
    `verify_api_key()` returns the resolved scope set.
- **Expiration + revocation** are enforced at verify time; expired /
    revoked / disabled keys never verify.
- **Every mutation is audit-logged** and RBAC-gated via
    `require_permission("api_keys.<action>")`.
- **`last_used_at` + `last_used_ip`** are stamped on verify — enabling
    the Admin UI to answer "which keys are still active?".

Storage: MongoDB collection `xdr_api_keys`.
"""
from __future__ import annotations

import hashlib
import os
import secrets as _secrets
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo import DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit
from routers.xdr_rbac import _valid_permission, require_permission
from services import tenant_registry

router = APIRouter(prefix="/api/xdr/api-keys", tags=["xdr-api-keys"])

# ── Mongo ─────────────────────────────────────────────────────────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _coll():
    if _client is None:
        return None
    return _client[_DB_NAME]["xdr_api_keys"]


# ── Principal ────────────────────────────────────────────────────
def _principal(req: Request) -> tuple[str, str, str]:
    """ONE tenancy authority — delegated, never re-implemented here.

    2026-06 DEFECT CLOSED (caught by `tests/test_p0_security_gate.py`): this
    resolved the tenant through the registry ONLY. That proves the tenant
    EXISTS; it never asked whether the caller is AUTHORIZED for it, so a
    principal holding `api_keys.read` in tenant A could read tenant B's credential inventory
    simply by naming B in `X-Tenant-Id`. It now delegates to
    `xdr_rbac.resolve_principal`, the single resolver that runs
    `authorize_requested_tenant()`.

    Naming a tenant is therefore a REQUEST, never an authorisation.
    """
    from routers.xdr_rbac import resolve_principal
    return resolve_principal(req)


def _verified_principal(req: Request) -> str:
    """A0.5 · T-RISK-2 · identity from VERIFIED authentication only.

    The previous body read `X-Principal-Id` and, when absent, substituted
    the literal `"admin@nivxray.com"`, so a credential could be minted and
    attributed to the platform administrator by a caller who proved no
    identity at all.
    """
    from fastapi import HTTPException

    from routers.xdr_rbac import verified_actor
    pid, _ = verified_actor(req)
    if not pid:
        raise HTTPException(status_code=403, detail={
            "code": "ACCESS_DENIED",
            "reason": ("no verified principal; a client-supplied identity "
                            "header is never an identity"),
            "risk": "T-RISK-2", "fail_closed": True})
    return str(pid)


# ── Key format / hashing ─────────────────────────────────────────
_KEY_PREFIX = "nvx_"


def _gen_plaintext() -> str:
    """Return a URL-safe 48-hex-char key with the `nvx_` prefix."""
    return _KEY_PREFIX + _secrets.token_hex(24)


def _hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _preview(plaintext: str) -> str:
    # First 12 chars: `nvx_` + first 8 hex chars, safe to display.
    return plaintext[:12]


def _mask(doc: dict) -> dict:
    return {k: v for k, v in doc.items() if k not in ("hash", "_id")}


_TENANT_EVIDENCE = ("xdr_users", "xdr_roles", "xdr_collectors", "xdr_api_keys")


def _tenant_is_known(tenant_id: str) -> bool:
    """True when the tenant already owns at least one control-plane object.

    Used to refuse minting a credential for a mistyped tenant id.
    """
    if _client is None:
        return False
    db = _client[_DB_NAME]
    for name in _TENANT_EVIDENCE:
        if db[name].find_one({"tenant_id": tenant_id}, {"_id": 1}):
            return True
    return False


# ── Pydantic bodies ──────────────────────────────────────────────
class CreateKeyBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    #: P1 issuance safeguard — the operator must restate the tenant the key
    #: will be bound to.  A typo in `X-Tenant-Id` can no longer silently mint
    #: a credential for the wrong (or a non-existent) tenant.
    confirm_tenant_id: str = Field(min_length=1, max_length=128)
    #: DEPRECATED (tenant registry) — tenancy is created only by
    #: `POST /api/xdr/tenants`. Kept for one release so nothing that still
    #: sends it breaks; with `NIVX_TENANT_REGISTRY_ENFORCE` on, sending
    #: `true` is refused instead of silently bootstrapping a tenant.
    allow_new_tenant: bool = False
    description: str | None = None
    scopes: list[str] = Field(default_factory=list,
                                                description="Permission strings, e.g. 'lolbas.sync'")
    expires_at: str | None = Field(
        default=None,
        description="ISO-8601 UTC.  Omit for never-expires.")


class UpdateKeyBody(BaseModel):
    name: str | None = None
    description: str | None = None
    scopes: list[str] | None = None
    enabled: bool | None = None
    expires_at: str | None = None


# ── Endpoints ────────────────────────────────────────────────────
@router.post("",
                       dependencies=[Depends(require_permission("api_keys.create"))])
def create_key(body: CreateKeyBody, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    # ── P1 · issuance confirmation ────────────────────────────────
    # The tenant a key is bound to is decided here and is immutable
    # afterwards, so it is confirmed twice and checked for existence.
    if body.confirm_tenant_id.strip() != ten:
        raise HTTPException(status_code=400, detail={
            "code": "TENANT_CONFIRMATION_MISMATCH",
            "resolved_tenant": ten,
            "confirm_tenant_id": body.confirm_tenant_id,
            "reason": ("confirm_tenant_id must exactly match the tenant the "
                            "key will be minted for")})
    if not _tenant_is_known(ten) and not body.allow_new_tenant:
        if tenant_registry.enforcing():
            # Unreachable in practice: `_principal()` already refused an
            # unregistered tenant. Kept so the failure can never invert into
            # "mint anyway" if the guard above is ever relaxed.
            raise HTTPException(status_code=403, detail={
                "code": "TENANT_NOT_FOUND",
                "resolved_tenant": ten,
                "reason": tenant_registry.IMPLICIT_TENANT_FORBIDDEN})
        raise HTTPException(status_code=400, detail={
            "code": "UNKNOWN_TENANT",
            "resolved_tenant": ten,
            "reason": ("no users, roles, collectors or keys exist for this "
                            "tenant — this is usually a typo.  Re-send with "
                            "allow_new_tenant=true to mint the first "
                            "credential for a genuinely new tenant.")})
    if body.allow_new_tenant and tenant_registry.enforcing():
        # DEPRECATED path. Creating tenancy while minting a credential is
        # exactly the implicit-tenancy defect B4 describes.
        raise HTTPException(status_code=400, detail={
            "code": "ALLOW_NEW_TENANT_DEPRECATED",
            "resolved_tenant": ten,
            "reason": ("allow_new_tenant is deprecated: " +
                            tenant_registry.IMPLICIT_TENANT_FORBIDDEN)})
    # Validate scopes against the canonical permission catalog.
    for s in body.scopes:
        if not _valid_permission(s):
            raise HTTPException(status_code=400,
                detail=f"invalid scope permission: {s}")
    if _coll().find_one({"tenant_id": ten, "name": body.name}):
        raise HTTPException(status_code=409,
            detail=f"api key with name '{body.name}' already exists")

    plaintext = _gen_plaintext()
    kid = f"key_{uuid.uuid4().hex[:20]}"
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "id":            kid, "tenant_id": ten, "name": body.name,
        "description":   body.description,
        "prefix":        _preview(plaintext),
        "hash":          _hash(plaintext),
        "scopes":        list(body.scopes or []),
        "enabled":       True, "revoked_at": None,
        "created_at":    now, "updated_at": now,
        "created_by":    pid,
        "expires_at":    body.expires_at,
        "last_used_at":  None, "last_used_ip": None,
        "use_count":     0,
    }
    _coll().insert_one(dict(doc))
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="API_KEY_CREATED", resource_kind="api_key", resource_id=kid,
        after={"name": body.name, "scopes": body.scopes,
                    "prefix": doc["prefix"], "expires_at": body.expires_at},
    )
    return {"ok": True, "data": {
        **_mask(doc),
        "plaintext": plaintext,
        "reveal_notice": ("This is the only time the full key will be "
                                  "displayed.  Store it in a secret manager."),
    }, "audit_ref": audit["id"]}


@router.get("",
                     dependencies=[Depends(require_permission("api_keys.read"))])
def list_keys(request: Request,
                    enabled: bool | None = Query(None),
                    limit: int = Query(200, ge=1, le=1000)):
    if _coll() is None:
        return {"ok": False, "error": {"code": "STORAGE_UNAVAILABLE"}}
    ten, _, _ = _principal(request)
    q: dict[str, Any] = {"tenant_id": ten}
    if enabled is not None:
        q["enabled"] = enabled
    cur = _coll().find(q).sort("created_at", DESCENDING).limit(limit)
    rows = [_mask(d) for d in cur]
    return {"ok": True, "data": {"api_keys": rows, "count": len(rows)}}


@router.get("/{key_id}",
                     dependencies=[Depends(require_permission("api_keys.read"))])
def get_key(key_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, _, _ = _principal(request)
    doc = _coll().find_one({"id": key_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="api key not found")
    return {"ok": True, "data": _mask(doc)}


@router.put("/{key_id}",
                    dependencies=[Depends(require_permission("api_keys.create"))])
def update_key(key_id: str, body: UpdateKeyBody, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": key_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="api key not found")
    patch: dict[str, Any] = {}
    if body.name is not None:        patch["name"]        = body.name
    if body.description is not None: patch["description"] = body.description
    if body.enabled is not None:     patch["enabled"]     = body.enabled
    if body.expires_at is not None:  patch["expires_at"]  = body.expires_at
    if body.scopes is not None:
        for s in body.scopes:
            if not _valid_permission(s):
                raise HTTPException(status_code=400,
                    detail=f"invalid scope permission: {s}")
        patch["scopes"] = list(body.scopes)
    if not patch:
        raise HTTPException(status_code=400, detail="no updatable fields")
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    _coll().update_one({"_id": doc["_id"]}, {"$set": patch})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="API_KEY_UPDATED",
                                resource_kind="api_key", resource_id=key_id,
                                before={k: doc.get(k) for k in patch if k != "updated_at"},
                                after={k: v for k, v in patch.items() if k != "updated_at"})
    return {"ok": True,
                 "data": _mask(_coll().find_one({"id": key_id})),
                 "audit_ref": audit["id"]}


@router.post("/{key_id}/rotate",
                       dependencies=[Depends(require_permission("api_keys.rotate"))])
def rotate_key(key_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": key_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="api key not found")
    plaintext = _gen_plaintext()
    now = datetime.now(timezone.utc).isoformat()
    _coll().update_one({"_id": doc["_id"]}, {"$set": {
        "hash": _hash(plaintext), "prefix": _preview(plaintext),
        "updated_at": now, "rotated_at": now,
        "last_used_at": None, "last_used_ip": None, "use_count": 0,
    }})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="API_KEY_ROTATED",
                                resource_kind="api_key", resource_id=key_id,
                                before={"prefix": doc.get("prefix")},
                                after={"prefix": _preview(plaintext)})
    updated = _coll().find_one({"id": key_id})
    return {"ok": True, "data": {**_mask(updated),
                                                    "plaintext": plaintext,
                                                    "reveal_notice": ("This is the only time the rotated "
                                                                                "key will be displayed.")},
                 "audit_ref": audit["id"]}


@router.post("/{key_id}/revoke",
                       dependencies=[Depends(require_permission("api_keys.revoke"))])
def revoke_key(key_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": key_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="api key not found")
    now = datetime.now(timezone.utc).isoformat()
    _coll().update_one({"_id": doc["_id"]},
                                    {"$set": {"enabled": False, "revoked_at": now,
                                                    "updated_at": now,
                                                    "revoked_by": pid}})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="API_KEY_REVOKED",
                                resource_kind="api_key", resource_id=key_id)
    return {"ok": True, "data": {"id": key_id, "revoked": True},
                 "audit_ref": audit["id"]}


@router.delete("/{key_id}",
                          dependencies=[Depends(require_permission("api_keys.delete"))])
def delete_key(key_id: str, request: Request):
    if _coll() is None:
        raise HTTPException(status_code=503, detail="storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _coll().find_one({"id": key_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="api key not found")
    _coll().delete_one({"_id": doc["_id"]})
    audit = emit_audit(tenant_id=ten, principal_id=pid, principal_kind=pkd,
                                action="API_KEY_DELETED",
                                resource_kind="api_key", resource_id=key_id,
                                before={"name": doc.get("name"),
                                              "prefix": doc.get("prefix")})
    return {"ok": True, "data": {"id": key_id, "deleted": True},
                 "audit_ref": audit["id"]}


# ── Server-internal verify helper ────────────────────────────────
def verify_api_key(plaintext: str, *, source_ip: str | None = None
                              ) -> dict | None:
    """Verify a presented API key and update `last_used_at`.

    Returns the (masked) key document on success, `None` otherwise.
    Callers who receive an object may treat `scopes` as the effective
    permission set for the request.
    """
    if _coll() is None or not plaintext or not plaintext.startswith(_KEY_PREFIX):
        return None
    doc = _coll().find_one({"hash": _hash(plaintext)})
    if not doc:
        return None
    if not doc.get("enabled", True):
        return None
    exp = doc.get("expires_at")
    if exp:
        try:
            expires = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) >= expires:
                return None
        except ValueError:
            return None
    now = datetime.now(timezone.utc).isoformat()
    _coll().update_one({"_id": doc["_id"]}, {"$set": {
        "last_used_at": now, "last_used_ip": source_ip or None,
    }, "$inc": {"use_count": 1}})
    doc.update({"last_used_at": now, "last_used_ip": source_ip,
                        "use_count": int(doc.get("use_count", 0)) + 1})
    return _mask(doc)
