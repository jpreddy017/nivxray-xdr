"""
Round 25a · Cortex XDR Vendor Wizard — backend.
================================================

The typed onboarding surface for **Palo Alto Cortex XDR**.  Every
endpoint below runs against the customer's REAL Cortex tenant via
the `xdr_cortex_adapter` reference implementation — no synthetic
demo path, no fabricated capability.

Owner-locked invariants (Round 25a + 25b):
  • The wizard MUST NEVER represent the integration as connected,
    capable, or active unless the adapter's own connect() +
    capability_probe() succeeds with the operator's credentials.
  • Credentials NEVER live on the `xdr_integrations` document.  They
    are minted into the `CredentialVault` (Round 25b) and only the
    opaque `credential_ref` is stored on the integration.
  • Adapters access credentials via `vault.access(ref, purpose,
    principal)` — a scoped, audit-logged one-shot decrypt at the
    execution boundary.  Round 25b prohibits any adapter reading
    `xdr_integrations.credentials` directly.

Endpoints (all under ``/api/xdr/vendor/cortex``):

  POST /probe                     → run connect() + capability_probe();
                                    return the honest result; no persist.
  POST /connections               → run probe; on success create record
                                    with credential_ref only (vault-backed).
  GET  /connections               → list, redacted.
  GET  /connections/{id}          → one, redacted.
  DELETE /connections/{id}        → tombstone + revoke vault secret.
  POST /connections/{id}/rotate   → mint new secret, revoke old, re-probe.
  GET  /connections/{id}/audit    → vault audit trail scoped to this integration.
"""
from __future__ import annotations

import datetime as _dt
import logging
import os
import uuid
from typing import Any, Optional

import httpx
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field

from detection_content.xdr_cortex_adapter import CortexXdrAdapter
from detection_content.xdr_edr_adapter import (
    AVAILABLE, UNAVAILABLE, FAILED, NOT_SUPPORTED,
)
from detection_content.xdr_capability_service import _ACTION_TO_CAPABILITY
from detection_content.xdr_credential_vault import (
    CredentialVault, VaultAccessError, get_vault,
)
from deps import db

log = logging.getLogger("nivxray.xdr.cortex_wizard")

router = APIRouter(prefix="/api/xdr/vendor/cortex", tags=["xdr-cortex-wizard"])
COLLECTION = "xdr_integrations"
VENDOR = "palo_alto_cortex_xdr"


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
    # Backwards compat: scrub any legacy inline ciphertext that pre-25b
    # records may still carry.  The vault is the ONLY authoritative
    # store from Round 25b onward.
    out.pop("credentials_encrypted", None)
    out.pop("credentials_scheme", None)
    out.pop("credentials_todo", None)
    out["credentials"] = {
        "api_key_id":    rec.get("api_key_id"),
        "api_key":       "***",
        "base_url":      rec.get("base_url"),
        "tenant":        rec.get("tenant"),
        "credential_ref": rec.get("credential_ref"),
        "vault":         "xdr_credential_vault",
    }
    return out


@router.post("/connections", status_code=201)
async def cortex_create(body: CortexCreateBody,
                                x_tenant_id: Optional[str] = Header(default=None)):
    """Probe first, persist only on success.  Refuses to create an
    integration record that would falsely claim to be connected.

    Round 25b: the API key is minted into the CredentialVault BEFORE
    the integration record is written.  The record itself never
    carries the key — only the opaque `credential_ref`.
    """
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
    vault = get_vault(db)
    credential_ref = await vault.mint_secret(
        tenant_id      = tenant_id,
        integration_id = integration_id,
        purpose        = "cortex_api_key",
        plaintext      = body.api_key,
        principal      = "cortex_wizard",
    )
    doc = {
        "integration_id":  integration_id,
        "vendor":          VENDOR,
        "label":           body.label,
        "tenant_id":       tenant_id,
        "base_url":        body.base_url,
        "api_key_id":      body.api_key_id,
        "tenant":          body.tenant,
        "advanced_api":    body.advanced_api,
        # Round 25b: credentials live in the vault ONLY.
        "credential_ref":  credential_ref,
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
    """Tombstone the integration AND revoke its vault secret so an
    accidental leaked reference cannot be re-used post-deletion."""
    rec = await db[COLLECTION].find_one(
        {"integration_id": integration_id, "vendor": VENDOR},
        {"_id": 0, "credential_ref": 1},
    )
    if rec is None:
        raise HTTPException(404, detail={"error": "integration_not_found"})
    if rec.get("credential_ref"):
        try:
            await get_vault(db).revoke(secret_ref=rec["credential_ref"],
                                             principal="cortex_wizard")
        except VaultAccessError:
            pass
    await db[COLLECTION].update_one(
        {"integration_id": integration_id, "vendor": VENDOR},
        {"$set": {"active": False, "connected": False,
                     "updated_at": _iso_now()},
          "$unset": {"credential_ref": ""}},
    )
    return {"ok": True, "integration_id": integration_id,
              "tombstoned": True, "vault_revoked": bool(rec.get("credential_ref"))}


class CortexRotateBody(BaseModel):
    api_key: str = Field(..., description="New Cortex Advanced-API key.")


@router.post("/connections/{integration_id}/rotate")
async def cortex_rotate(integration_id: str, body: CortexRotateBody):
    """Rotate the API key without breaking the running integration.
    Runs a fresh probe with the new key; on success rotates the vault
    secret (old ref tombstoned, new ref installed) and updates the
    capability_matrix + connect_detail from the fresh probe.

    On probe failure the OLD secret stays active — no partial state.
    """
    rec = await db[COLLECTION].find_one(
        {"integration_id": integration_id, "vendor": VENDOR}, {"_id": 0})
    if rec is None:
        raise HTTPException(404, detail={"error": "integration_not_found"})
    if not rec.get("credential_ref"):
        raise HTTPException(409, detail={
            "error": "vault_ref_missing",
            "reason": "integration predates Round 25b vault · re-onboard first",
        })

    probe = await _run_probe(CortexProbeBody(
        base_url    = rec["base_url"],
        api_key_id  = rec.get("api_key_id") or "",
        api_key     = body.api_key,
        tenant      = rec.get("tenant"),
        advanced_api= bool(rec.get("advanced_api", True)),
    ))
    if not probe["connect"]["ok"]:
        raise HTTPException(400, detail={
            "error": "rotate_probe_failed",
            "reason": probe["connect"]["reason"],
            "vendor_detail": probe["connect"]["detail"],
            "note": "old credential preserved · rotation aborted",
        })

    new_ref = await get_vault(db).rotate_secret(
        secret_ref    = rec["credential_ref"],
        new_plaintext = body.api_key,
        principal     = "cortex_wizard",
    )
    await db[COLLECTION].update_one(
        {"integration_id": integration_id, "vendor": VENDOR},
        {"$set": {
            "credential_ref":   new_ref,
            "connect_detail":   probe["connect"]["detail"],
            "capability_matrix": [
                {
                    "action_id":     e["action_id"],
                    "capability_id": _ACTION_TO_CAPABILITY.get(e["action_id"]),
                    "state":         e["state"],
                    "detail":        e.get("detail"),
                }
                for e in probe["capabilities"]
            ],
            "probed_at":  probe["probed_at"],
            "updated_at": _iso_now(),
        }},
    )
    return {"ok": True, "integration_id": integration_id,
              "credential_ref": new_ref, "rotated_at": _iso_now()}


@router.get("/connections/{integration_id}/audit")
async def cortex_audit(integration_id: str, limit: int = 100):
    """Return the vault audit trail scoped to this integration.  Every
    MINT / ACCESS / ROTATE / REVOKE is captured."""
    rec = await db[COLLECTION].find_one(
        {"integration_id": integration_id, "vendor": VENDOR},
        {"_id": 0, "integration_id": 1},
    )
    if rec is None:
        raise HTTPException(404, detail={"error": "integration_not_found"})
    trail = await get_vault(db).audit_trail(
        integration_id=integration_id, limit=limit)
    return {"integration_id": integration_id,
              "audit": trail, "count": len(trail)}
