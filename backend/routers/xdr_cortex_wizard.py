"""
Round 25a · Cortex XDR Vendor Wizard — backend.
================================================

The typed onboarding surface for **Palo Alto Cortex XDR**.  Every
endpoint below runs against the customer's REAL Cortex tenant via
the `xdr_cortex_adapter` reference implementation — no synthetic
demo path, no fabricated capability.

Owner-locked invariants (Round 25a):
  • The wizard MUST NEVER represent the integration as connected,
    capable, or active unless the adapter's own connect() +
    capability_probe() succeeds with the operator's credentials.
  • The API key is accepted once, encrypted at rest via
    ``XDR_ENCRYPTION_KEY`` (Fernet · rotatable), never rendered
    back, never logged.  Round 25b replaces this with a proper
    envelope-encrypted vault.
  • Probe results write straight into ``xdr_integrations``
    (schema already consumed by ``xdr_capability_service``).  No
    parallel record, no drift.

Endpoints (all under ``/api/xdr/vendor/cortex``):

  POST /probe                → run connect() + capability_probe();
                                return the honest result; no persist.
  POST /connections           → run probe; on success create record.
  GET  /connections           → list, redacted.
  GET  /connections/{id}      → one, redacted.
  DELETE /connections/{id}    → tombstone (active=false); credentials
                                blob is scrubbed.
"""
from __future__ import annotations

import base64
import datetime as _dt
import logging
import os
import uuid
from typing import Any, Optional

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

from detection_content.xdr_cortex_adapter import CortexXdrAdapter
from detection_content.xdr_edr_adapter import (
    AVAILABLE, UNAVAILABLE, FAILED, NOT_SUPPORTED,
)
from detection_content.xdr_capability_service import _ACTION_TO_CAPABILITY
from deps import db

log = logging.getLogger("nivxray.xdr.cortex_wizard")

router = APIRouter(prefix="/api/xdr/vendor/cortex", tags=["xdr-cortex-wizard"])
COLLECTION = "xdr_integrations"


# ── Credential envelope (Round 25a interim · Round 25b vault replaces) ─
def _fernet() -> Fernet:
    key = os.environ.get("XDR_ENCRYPTION_KEY")
    if not key:
        # Boot-generated key mirrored to XDR_STATE_DIR.  Round 25b will
        # replace this with a KMS-agnostic envelope; a plain Fernet is a
        # deliberate short-lived contract, marked TODO in the record.
        state_dir = os.environ.get("XDR_STATE_DIR", "/app/backend/xdr_state")
        os.makedirs(state_dir, exist_ok=True)
        keyfile = os.path.join(state_dir, "wizard.key")
        if os.path.isfile(keyfile):
            with open(keyfile, "rb") as f:
                key = f.read().decode()
        else:
            key = Fernet.generate_key().decode()
            with open(keyfile, "w", encoding="utf-8") as f:
                f.write(key)
            try:
                os.chmod(keyfile, 0o600)
            except OSError:
                pass
        os.environ["XDR_ENCRYPTION_KEY"] = key
    return Fernet(key.encode())


def _encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def _decrypt(ciphertext: str) -> Optional[str]:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return None


# ── Live-tenant HTTP connector used by the adapter ────────────
def _make_httpx_connector(base_url: str, timeout: float = 8.0):
    """Return an async callable matching the adapter's `_connector`
    contract:  connector(method, path, headers, json) -> dict."""
    async def _call(method: str, path: str, headers: dict, json: Any):
        url = base_url.rstrip("/") + path
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as c:
                resp = await c.request(method, url, headers=headers, json=json)
            if resp.status_code in (200, 204):
                return {
                    "ok":               True,
                    "detail":           f"{method} {path} · HTTP {resp.status_code}",
                    "vendor_reference": resp.headers.get("x-request-id"),
                    "http_status":      resp.status_code,
                }
            if resp.status_code in (401, 403):
                return {
                    "ok":     False,
                    "reason": "AUTHENTICATION_FAILED",
                    "detail": f"Cortex rejected credentials · HTTP {resp.status_code}",
                    "http_status": resp.status_code,
                }
            if 500 <= resp.status_code < 600:
                return {
                    "ok":     False,
                    "reason": "VENDOR_ERROR",
                    "detail": f"Cortex returned {resp.status_code}",
                    "http_status": resp.status_code,
                }
            return {
                "ok":     False,
                "reason": "UNEXPECTED_STATUS",
                "detail": f"Cortex returned {resp.status_code}",
                "http_status": resp.status_code,
            }
        except httpx.ConnectError as e:
            return {"ok": False, "reason": "CONNECTION_FAILED",
                        "detail": f"cannot reach {base_url}: {e}"}
        except httpx.TimeoutException:
            return {"ok": False, "reason": "CONNECTION_FAILED",
                        "detail": "vendor request timed out"}
        except Exception as e:                                    # noqa: BLE001
            return {"ok": False, "reason": "CONNECTION_FAILED",
                        "detail": f"transport error: {type(e).__name__}"}
    return _call


# ── Request models ────────────────────────────────────────────
class CortexProbeBody(BaseModel):
    base_url:    str  = Field(..., description="e.g. https://api-corp.xdr.us.paloaltonetworks.com")
    api_key_id:  str
    api_key:     str  = Field(..., description="Cortex Advanced-API key (write-only)")
    tenant:      Optional[str] = None
    advanced_api: bool = True


class CortexCreateBody(CortexProbeBody):
    label: str = Field(..., min_length=1, max_length=120)


# ── Probe (no persist) ────────────────────────────────────────
def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


async def _run_probe(body: CortexProbeBody) -> dict:
    adapter = CortexXdrAdapter({
        "base_url": body.base_url,
        "tenant":   body.tenant,
        "credentials": {
            "api_key_id":  body.api_key_id,
            "api_key":     body.api_key,
            "base_url":    body.base_url,
            "tenant":      body.tenant,
        },
        "_connector": _make_httpx_connector(body.base_url),
    })
    connect = await adapter.connect()
    # Reason inference for the wizard.  The adapter's connect()
    # already returns ok/detail; the connector's own reason (if any)
    # is preserved verbatim so the UI can render the exact honest
    # state (AUTHENTICATION_FAILED vs CONNECTION_FAILED vs ...).
    reason_code = "AVAILABLE" if connect.get("ok") else "CONNECTION_FAILED"
    detail = connect.get("detail") or ""
    if not connect.get("ok"):
        lowered = detail.lower()
        if "reject" in lowered or "401" in lowered or "403" in lowered \
                or "authentication_failed" in lowered:
            reason_code = "AUTHENTICATION_FAILED"
        elif "timed out" in lowered or "cannot reach" in lowered \
                or "transport error" in lowered or "connection_failed" in lowered:
            reason_code = "CONNECTION_FAILED"
        elif "credentials not configured" in lowered \
                or "no http connector" in lowered:
            reason_code = "NO_LIVE_TENANT"

    capabilities: list[dict] = []
    if connect.get("ok"):
        try:
            capabilities = await adapter.capability_probe()
        except Exception as e:                                     # noqa: BLE001
            capabilities = []
            log.warning("cortex wizard: capability_probe raised (%s)", e)

    return {
        "vendor":       "palo_alto_cortex_xdr",
        "connect": {
            "ok":                bool(connect.get("ok")),
            "reason":            reason_code,
            "detail":            detail,
            "vendor_reference":  connect.get("vendor_reference"),
        },
        "capabilities": capabilities,
        "probed_at":    _iso_now(),
    }


@router.post("/probe")
async def cortex_probe(body: CortexProbeBody,
                              x_tenant_id: Optional[str] = Header(default=None)):
    """Run connect + capability_probe.  Never persists.  Never leaks
    the API key back to the caller."""
    return await _run_probe(body)


# ── Persistence ───────────────────────────────────────────────
def _redact_record(rec: dict) -> dict:
    out = dict(rec)
    out.pop("credentials_encrypted", None)
    out["credentials"] = {
        "api_key_id": rec.get("api_key_id"),
        "api_key":    "***",
        "base_url":   rec.get("base_url"),
        "tenant":     rec.get("tenant"),
    }
    return out


@router.post("/connections", status_code=201)
async def cortex_create(body: CortexCreateBody,
                                x_tenant_id: Optional[str] = Header(default=None)):
    """Probe first, persist only on success.  Refuses to create an
    integration record that would falsely claim to be connected."""
    probe = await _run_probe(body)
    if not probe["connect"]["ok"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "connect_failed",
                        "reason": probe["connect"]["reason"],
                        "vendor_detail": probe["connect"]["detail"]},
        )

    integration_id = f"cortex-{uuid.uuid4().hex[:12]}"
    now = _iso_now()
    tenant_id = x_tenant_id or body.tenant or "default"
    doc = {
        "integration_id":  integration_id,
        "vendor":          "palo_alto_cortex_xdr",
        "label":           body.label,
        "tenant_id":       tenant_id,
        "base_url":        body.base_url,
        "api_key_id":      body.api_key_id,
        "tenant":          body.tenant,
        "advanced_api":    body.advanced_api,
        # Round 25a interim envelope · Round 25b vault replaces this
        # field with a KMS-wrapped DEK reference.
        "credentials_encrypted": _encrypt(body.api_key),
        "credentials_scheme":    "fernet-v1",
        "credentials_todo":      "replace-with-round25b-envelope",
        "connected":       True,
        "connect_detail":  probe["connect"]["detail"],
        "capability_matrix": [
            {
                "action_id":     e["action_id"],
                "capability_id": _ACTION_TO_CAPABILITY.get(e["action_id"]),
                "state":         e["state"],
                "detail":        e.get("detail"),
            }
            for e in probe["capabilities"]
        ],
        "active":     True,
        "probed_at":  probe["probed_at"],
        "created_at": now,
        "updated_at": now,
    }
    await db[COLLECTION].insert_one(doc)
    doc.pop("_id", None)
    return _redact_record(doc)


@router.get("/connections")
async def cortex_list(x_tenant_id: Optional[str] = Header(default=None)):
    q: dict = {"vendor": "palo_alto_cortex_xdr"}
    if x_tenant_id:
        q["tenant_id"] = x_tenant_id
    out: list[dict] = []
    async for rec in db[COLLECTION].find(q, {"_id": 0}):
        out.append(_redact_record(rec))
    return {"connections": out, "count": len(out)}


@router.get("/connections/{integration_id}")
async def cortex_get(integration_id: str):
    rec = await db[COLLECTION].find_one(
        {"integration_id": integration_id, "vendor": "palo_alto_cortex_xdr"},
        {"_id": 0},
    )
    if not rec:
        raise HTTPException(404, detail={"error": "integration_not_found"})
    return _redact_record(rec)


@router.delete("/connections/{integration_id}")
async def cortex_delete(integration_id: str):
    result = await db[COLLECTION].update_one(
        {"integration_id": integration_id, "vendor": "palo_alto_cortex_xdr"},
        {"$set": {"active": False, "connected": False,
                     "updated_at": _iso_now()},
          "$unset": {"credentials_encrypted": ""}},
    )
    if result.matched_count == 0:
        raise HTTPException(404, detail={"error": "integration_not_found"})
    return {"ok": True, "integration_id": integration_id,
              "tombstoned": True}
