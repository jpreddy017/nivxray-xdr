"""
Round 28 · Generalized Vendor Wizard.
=====================================

Vendor-parameterised routes at `/api/xdr/vendor/{vendor_key}/...`.
The wizard has no vendor-specific knowledge — it looks the vendor
up in the registry and reads its `metadata()` for the credential
schema.

Preserved: the legacy `/api/xdr/vendor/cortex/...` routes from
Round 25a/26/26.5/27 stay mounted so existing clients continue to
work.  Both surfaces write to the SAME `xdr_integrations`
collection — no schema drift.
"""
from __future__ import annotations

import datetime as _dt
import logging
import uuid
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

from deps import db
from detection_content.xdr_vendor_registry import (
    get_vendor_class, has_vendor, list_production_vendors,
    list_all_vendors,
)
from detection_content.xdr_credential_vault import get_vault
from routers.xdr_cortex_wizard import _make_httpx_connector  # reuse HTTPX shim

log = logging.getLogger("nivxray.xdr.vendor_wizard")
router = APIRouter(prefix="/api/xdr/vendor", tags=["xdr-vendor-wizard"])
COLLECTION = "xdr_integrations"


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ── Vendor catalogue ───────────────────────────────────────
@router.get("/_catalog")
async def vendor_catalog(include_internal: bool = False):
    """Vendors visible to the customer-facing UI."""
    vendors = list_all_vendors(include_internal=include_internal) \
                    if include_internal else list_production_vendors()
    return {"vendors": vendors, "count": len(vendors)}


@router.get("/{vendor_key}/metadata")
async def vendor_metadata(vendor_key: str):
    if not has_vendor(vendor_key):
        raise HTTPException(404, detail={"error": "unknown_vendor"})
    return get_vendor_class(vendor_key).metadata()


# ── Probe ──────────────────────────────────────────────────
class ProbeBody(BaseModel):
    credentials: dict = Field(default_factory=dict)


@router.post("/{vendor_key}/probe")
async def vendor_probe(vendor_key: str, body: ProbeBody):
    if not has_vendor(vendor_key):
        raise HTTPException(404, detail={"error": "unknown_vendor"})
    cls = get_vendor_class(vendor_key)
    base_url = body.credentials.get("base_url") or ""
    adapter = cls(credentials=body.credentials,
                     connector=_make_httpx_connector(base_url) if base_url else None)
    connect = await adapter.connect()
    caps = []
    if connect.get("ok"):
        try:
            caps = await adapter.capabilities()
        except Exception as e:                                     # noqa: BLE001
            log.warning("vendor probe: capabilities() raised (%s)", e)
    return {"vendor_key": vendor_key,
              "connect": connect,
              "capabilities": caps,
              "probed_at": _iso_now()}


# ── Bind ───────────────────────────────────────────────────
class BindBody(BaseModel):
    label: str = Field(..., min_length=1, max_length=120)
    credentials: dict


@router.post("/{vendor_key}/connections", status_code=201)
async def vendor_bind(vendor_key: str, body: BindBody,
                             x_tenant_id: Optional[str] = Header(default=None)):
    if not has_vendor(vendor_key):
        raise HTTPException(404, detail={"error": "unknown_vendor"})
    cls = get_vendor_class(vendor_key)
    meta = cls.metadata()

    # Guardrail: cannot bind an INTERNAL_TEST_ONLY vendor unless the
    # caller explicitly opts in.  Prevents accidental production use
    # of the stub adapter.
    if meta.get("lifecycle") == "INTERNAL_TEST_ONLY" \
            and not body.credentials.get("_internal_test_ack"):
        raise HTTPException(409, detail={
            "error": "internal_test_only_vendor",
            "reason": "this vendor is framework-test only · "
                          "set credentials._internal_test_ack=true to bind",
        })

    # Real probe first — no fake connections in xdr_integrations.
    base_url = body.credentials.get("base_url") or ""
    adapter = cls(credentials=body.credentials,
                     connector=_make_httpx_connector(base_url) if base_url else None)
    connect = await adapter.connect()
    if not connect.get("ok"):
        raise HTTPException(400, detail={
            "error": "connect_failed",
            "reason": connect.get("reason"),
            "vendor_detail": connect.get("detail"),
        })
    caps = await adapter.capabilities()

    # Vault mint (Round 25b boundary preserved).
    integration_id = f"{vendor_key}-{uuid.uuid4().hex[:12]}"
    tenant_id = x_tenant_id or body.credentials.get("tenant") or "default"
    secret_pt = body.credentials.get("api_key") \
                       or body.credentials.get("secret") \
                       or body.credentials.get("api_token")
    credential_ref = None
    if secret_pt:
        credential_ref = await get_vault(db).mint_secret(
            tenant_id=tenant_id, integration_id=integration_id,
            purpose=f"{vendor_key}_secret", plaintext=secret_pt,
            principal="vendor_wizard")

    doc = {
        "integration_id":  integration_id,
        "vendor_key":      vendor_key,
        "vendor":          _legacy_vendor_alias(vendor_key),
        "label":           body.label,
        "tenant_id":       tenant_id,
        "base_url":        body.credentials.get("base_url"),
        "credentials_public": {
            k: v for k, v in body.credentials.items()
            if k not in ("api_key", "secret", "api_token",
                             "_internal_test_ack")
        },
        "credential_ref":  credential_ref,
        "connected":       True,
        "connect_detail":  connect.get("detail"),
        "capability_matrix": caps,
        "active":     True,
        "probed_at":  _iso_now(),
        "created_at": _iso_now(),
        "updated_at": _iso_now(),
        "lifecycle":  meta.get("lifecycle"),
    }
    await db[COLLECTION].insert_one(doc)
    doc.pop("_id", None)
    return _redact(doc)


def _legacy_vendor_alias(vendor_key: str) -> str:
    """Keep the pre-Round-28 `vendor` field populated so
    xdr_capability_service, xdr_cortex_executor, and legacy
    dashboards continue to resolve records unchanged."""
    return {"cortex": "palo_alto_cortex_xdr"}.get(vendor_key, vendor_key)


def _redact(rec: dict) -> dict:
    out = dict(rec)
    out.pop("credentials_encrypted", None)
    return out


@router.get("/{vendor_key}/connections")
async def vendor_list(vendor_key: str):
    if not has_vendor(vendor_key):
        raise HTTPException(404, detail={"error": "unknown_vendor"})
    q = {"vendor_key": vendor_key} \
            if await db[COLLECTION].count_documents({"vendor_key": vendor_key}) \
            else {"vendor": _legacy_vendor_alias(vendor_key)}
    out = [_redact(r) async for r in db[COLLECTION].find(q, {"_id": 0})]
    return {"connections": out, "count": len(out)}
