"""
XDR Secrets Store — P0-2 of the Admin Control-Plane Spec.

Server-side encrypted secrets with:
- Envelope encryption:   MASTER  →  per-tenant DEK (HKDF-SHA256)  →  Fernet(value)
- Tenant isolation:      All queries scoped by X-Tenant-Id (fail-close).
- Audit integration:     Every mutation writes to xdr_audit_log (append-only).
- Masked reads:          Reads never return plaintext.  Only `preview` (last-4).
- Explicit reveal:       Requires X-Secret-Reveal: yes AND emits SECRET_REVEALED.
- Rotation:              POST /{id}/rotate — bumps `version`, retains last 3
                          previous ciphertexts for rollback.

Storage: MongoDB collection `xdr_secrets`.

NO fabrication.  NO auto-generation.  Empty result sets return `[]`.
"""
from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from pymongo import DESCENDING, MongoClient

from routers.xdr_audit_log import emit_audit  # sibling router
from routers.xdr_rbac import require_permission

router = APIRouter(prefix="/api/xdr/secrets", tags=["xdr-secrets"])

# ── Mongo binding (sync pymongo — same pattern as audit log). ─────
_MONGO_URL = os.environ.get("MONGO_URL")
_DB_NAME   = os.environ.get("DB_NAME") or "test_database"
_client    = MongoClient(_MONGO_URL) if _MONGO_URL else None


def _get_coll():
    if _client is None:
        return None
    return _client[_DB_NAME]["xdr_secrets"]


# ── Envelope encryption ────────────────────────────────────────────
# Master key material.  In production this arrives from the platform
# KMS.  For self-hosted deployments we accept a base64 URL-safe key
# via env, or derive one deterministically from a passphrase.
from security import secret_policy  # noqa: E402

_KEY_CACHE: dict[str, tuple] = {}
#: Ciphertext written after P0-PROD-1 is self-describing:
#: ``nivxk1.<key_id>.<fernet token>``. A row without this prefix was
#: written under the previous, repository-derivable development key.
_CT_PREFIX = "nivxk1."


def _master_key() -> bytes:
    """P0-PROD-1 · resolved through the secret policy, which has NO
    repository fallback. Production requires XDR_SECRETS_MASTER and fails
    closed without it; preview/CI derive an instance-local key labelled
    DERIVED_INSTANCE_LOCAL and domain-separated to this purpose alone."""
    return _master_material()[0]


def _master_material() -> tuple[bytes, str]:
    if "k" not in _KEY_CACHE:
        key, kid, _basis = secret_policy.resolve_fernet(
            "XDR_SECRETS_MASTER", secret_policy.PURPOSE_CONNECTOR_SECRETS)
        _KEY_CACHE["k"] = (key, kid)
    return _KEY_CACHE["k"]


def active_key_id() -> str:
    return _master_material()[1]


def _tenant_dek(tenant_id: str) -> bytes:
    """Per-tenant Data Encryption Key derived from master via HKDF."""
    master_raw = base64.urlsafe_b64decode(_master_key())
    dek = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"xdr-secrets-tenant",
        info=f"tenant:{tenant_id}".encode(),
    ).derive(master_raw)
    return base64.urlsafe_b64encode(dek)


def _encrypt(tenant_id: str, plaintext: str) -> str:
    tok = Fernet(_tenant_dek(tenant_id)).encrypt(plaintext.encode("utf-8"))
    return f"{_CT_PREFIX}{active_key_id()}.{tok.decode('ascii')}"


def _decrypt(tenant_id: str, ciphertext: str) -> str:
    """P0-PROD-1 · a ciphertext belonging to another key is reported as
    exactly that. It is never a 500, and no plaintext is invented."""
    recorded, token = None, ciphertext
    if ciphertext.startswith(_CT_PREFIX):
        _, recorded, token = ciphertext.split(".", 2)
    if recorded != active_key_id():
        raise HTTPException(status_code=409, detail={
            "code": "SECRET_UNDECRYPTABLE_UNDER_CURRENT_KEY",
            "recorded_key_id": recorded,
            "active_key_id": active_key_id(),
            "classification": secret_policy.LEGACY_CLASSIFICATION,
            "also_possible": ("a stored value whose key identity is absent "
                              "may equally have been MODIFIED in storage; "
                              "this read path cannot tell the two apart and "
                              "does not guess between them"),
            "reason": ("this secret was encrypted under different key "
                       "material. It is not recoverable here and nothing "
                       "will be substituted for it — re-enter or rotate "
                       "the credential at its authoritative provider and "
                       "store it again under the active key")})
    try:
        pt = Fernet(_tenant_dek(tenant_id)).decrypt(token.encode("ascii"))
    except InvalidToken as exc:
        raise HTTPException(
            status_code=422,
            detail="secret ciphertext failed authentication (tampered or wrong tenant)",
        ) from exc
    return pt.decode("utf-8")


# ── Preview / masking helpers ─────────────────────────────────────
def _preview(plaintext: str) -> str:
    """Last-4 characters — safe to display in audit / UI."""
    if not plaintext:
        return ""
    if len(plaintext) <= 4:
        return "*" * len(plaintext)
    return plaintext[-4:]


def _mask(doc: dict) -> dict:
    """Strip ciphertext + previous_versions from a stored secret."""
    return {k: v for k, v in doc.items()
             if k not in ("ciphertext", "previous_versions", "_id")}


# ── Principal / tenant extraction ─────────────────────────────────
# A0.5 · delegated to the SINGLE authority (`routers.xdr_rbac`). The local
# copy carried the T-RISK-1 `"default"` tenant fallback and the T-RISK-2
# `"admin@nivxray.com"` identity fallback; both now fail closed.
def _principal(req: Request) -> tuple[str, str, str]:
    from routers.xdr_rbac import resolve_principal
    return resolve_principal(req)


# ── Pydantic bodies ───────────────────────────────────────────────
_ALLOWED_KINDS = {"api_key", "bearer_token", "oauth_client_secret",
                    "hmac_secret", "password", "generic"}


class CreateSecretBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = "generic"
    value: str = Field(min_length=1)
    description: str | None = None
    metadata: dict = Field(default_factory=dict)


class UpdateSecretBody(BaseModel):
    description: str | None = None
    metadata: dict | None = None
    enabled: bool | None = None


class RotateSecretBody(BaseModel):
    value: str = Field(min_length=1)


# ── Endpoints ─────────────────────────────────────────────────────
@router.post("",
                       dependencies=[Depends(require_permission("secrets.create"))])
def create_secret(body: CreateSecretBody, request: Request):
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="secrets storage unavailable")
    if body.kind not in _ALLOWED_KINDS:
        raise HTTPException(status_code=400,
            detail=f"invalid kind '{body.kind}' · allowed: {sorted(_ALLOWED_KINDS)}")
    ten, pid, pkd = _principal(request)

    existing = _get_coll().find_one({"tenant_id": ten, "name": body.name})
    if existing:
        raise HTTPException(status_code=409,
            detail=f"secret with name '{body.name}' already exists for tenant")

    now = datetime.now(timezone.utc).isoformat()
    sid = f"sec_{uuid.uuid4().hex[:20]}"
    doc = {
        "id": sid, "tenant_id": ten, "name": body.name, "kind": body.kind,
        "description": body.description, "metadata": body.metadata or {},
        "ciphertext": _encrypt(ten, body.value),
        "preview": _preview(body.value),
        "version": 1, "enabled": True,
        "created_at": now, "updated_at": now,
        "rotated_at": None, "created_by": pid,
        "previous_versions": [],
    }
    _get_coll().insert_one(doc)

    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="SECRET_CREATED", resource_kind="secret", resource_id=sid,
        after={"name": body.name, "kind": body.kind,
                    "preview": doc["preview"], "version": 1},
    )
    return {"ok": True, "data": _mask(doc), "audit_ref": audit["id"]}


@router.get("",
                     dependencies=[Depends(require_permission("secrets.read"))])
def list_secrets(request: Request,
                        kind: str | None = Query(None),
                        enabled: bool | None = Query(None),
                        limit: int = Query(200, ge=1, le=1000)):
    if _get_coll() is None:
        return {"ok": False, "error": {
            "code": "STORAGE_UNAVAILABLE",
            "detail": "secrets storage not configured"}}
    ten, _, _ = _principal(request)
    q: dict[str, Any] = {"tenant_id": ten}
    if kind:              q["kind"] = kind
    if enabled is not None: q["enabled"] = enabled
    cur = (_get_coll().find(q).sort("created_at", DESCENDING).limit(limit))
    rows = [_mask(d) for d in cur]
    return {"ok": True, "data": {"secrets": rows, "count": len(rows)}}


@router.get("/{secret_id}",
                     dependencies=[Depends(require_permission("secrets.read"))])
def get_secret(secret_id: str, request: Request):
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="secrets storage unavailable")
    ten, _, _ = _principal(request)
    doc = _get_coll().find_one({"id": secret_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="secret not found")
    return {"ok": True, "data": _mask(doc)}


@router.put("/{secret_id}",
                     dependencies=[Depends(require_permission("secrets.update"))])
def update_secret(secret_id: str, body: UpdateSecretBody, request: Request):
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="secrets storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _get_coll().find_one({"id": secret_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="secret not found")

    patch: dict[str, Any] = {}
    if body.description is not None: patch["description"] = body.description
    if body.metadata is not None:    patch["metadata"]    = body.metadata
    if body.enabled is not None:     patch["enabled"]     = body.enabled
    if not patch:
        raise HTTPException(status_code=400, detail="no updatable fields provided")
    patch["updated_at"] = datetime.now(timezone.utc).isoformat()
    _get_coll().update_one({"_id": doc["_id"]}, {"$set": patch})

    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="SECRET_UPDATED", resource_kind="secret", resource_id=secret_id,
        before={k: doc.get(k) for k in patch if k != "updated_at"},
        after={k: v for k, v in patch.items() if k != "updated_at"},
    )
    updated = _get_coll().find_one({"_id": doc["_id"]})
    return {"ok": True, "data": _mask(updated), "audit_ref": audit["id"]}


@router.post("/{secret_id}/rotate",
                       dependencies=[Depends(require_permission("secrets.rotate"))])
def rotate_secret(secret_id: str, body: RotateSecretBody, request: Request):
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="secrets storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _get_coll().find_one({"id": secret_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="secret not found")

    prev_hist = list(doc.get("previous_versions") or [])
    prev_hist.append({"version": doc.get("version", 1),
                             "ciphertext": doc.get("ciphertext"),
                             "preview": doc.get("preview"),
                             "rotated_at": datetime.now(timezone.utc).isoformat()})
    prev_hist = prev_hist[-3:]  # cap history at 3

    now = datetime.now(timezone.utc).isoformat()
    patch = {
        "ciphertext": _encrypt(ten, body.value),
        "preview":    _preview(body.value),
        "version":    int(doc.get("version", 1)) + 1,
        "rotated_at": now, "updated_at": now,
        "previous_versions": prev_hist,
    }
    _get_coll().update_one({"_id": doc["_id"]}, {"$set": patch})

    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="SECRET_ROTATED", resource_kind="secret", resource_id=secret_id,
        before={"version": doc.get("version", 1),
                    "preview": doc.get("preview")},
        after={"version": patch["version"], "preview": patch["preview"]},
    )
    updated = _get_coll().find_one({"_id": doc["_id"]})
    return {"ok": True, "data": _mask(updated), "audit_ref": audit["id"]}


@router.post("/{secret_id}/reveal",
                       dependencies=[Depends(require_permission("secrets.reveal"))])
def reveal_secret(secret_id: str, request: Request):
    """Explicit plaintext reveal.  MUST include header X-Secret-Reveal: yes.
    Always emits SECRET_REVEALED audit — visible in the tamper-evident chain."""
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="secrets storage unavailable")
    if (request.headers.get("X-Secret-Reveal") or "").lower() != "yes":
        raise HTTPException(status_code=403,
            detail="secret reveal requires 'X-Secret-Reveal: yes' header")
    ten, pid, pkd = _principal(request)
    doc = _get_coll().find_one({"id": secret_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="secret not found")
    if not doc.get("enabled", True):
        raise HTTPException(status_code=409, detail="secret is disabled")

    plaintext = _decrypt(ten, doc["ciphertext"])
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="SECRET_REVEALED", resource_kind="secret", resource_id=secret_id,
        outcome="SUCCESS",
        metadata={"reason": request.headers.get("X-Secret-Reveal-Reason") or "unspecified"},
    )
    return {"ok": True, "data": {
        "id": secret_id, "name": doc["name"], "kind": doc["kind"],
        "version": doc.get("version", 1), "value": plaintext,
        "preview": doc.get("preview"),
    }, "audit_ref": audit["id"]}


@router.delete("/{secret_id}",
                          dependencies=[Depends(require_permission("secrets.delete"))])
def delete_secret(secret_id: str, request: Request):
    if _get_coll() is None:
        raise HTTPException(status_code=503, detail="secrets storage unavailable")
    ten, pid, pkd = _principal(request)
    doc = _get_coll().find_one({"id": secret_id, "tenant_id": ten})
    if not doc:
        raise HTTPException(status_code=404, detail="secret not found")
    _get_coll().delete_one({"_id": doc["_id"]})
    audit = emit_audit(
        tenant_id=ten, principal_id=pid, principal_kind=pkd,
        action="SECRET_DELETED", resource_kind="secret", resource_id=secret_id,
        before={"name": doc.get("name"), "kind": doc.get("kind"),
                    "preview": doc.get("preview"),
                    "version": doc.get("version")},
    )
    return {"ok": True, "data": {"id": secret_id, "deleted": True},
                 "audit_ref": audit["id"]}


# ── Internal accessor for other routers (OSINT, webhooks, etc.) ───
def resolve_secret(tenant_id: str, name: str) -> str | None:
    """Server-internal: fetch plaintext by (tenant_id, name) without
    emitting a reveal audit — reserved for backend services calling
    external APIs.  Callers MUST still emit their own domain audit."""
    if _get_coll() is None:
        return None
    doc = _get_coll().find_one({"tenant_id": tenant_id, "name": name,
                                                "enabled": True})
    if not doc:
        return None
    return _decrypt(tenant_id, doc["ciphertext"])
