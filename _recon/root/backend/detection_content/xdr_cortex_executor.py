"""
Round 25b · Cortex XDR execution boundary.
==========================================

The **single sanctioned path** through which any NivXRay code may
run a Cortex XDR adapter method against a persisted integration.

    xdr_integrations (credential_ref only)
              │
              ▼
     xdr_credential_vault.access(...)     ← audited, one-shot
              │
              ▼
    scoped CortexXdrAdapter instance      ← plaintext held only
              │                              inside this call frame
              ▼
     Cortex REST API                       ← real HTTP call

Consumers (Round 26 ingest, Round 27 response console) MUST NOT
instantiate `CortexXdrAdapter` themselves against a stored
integration.  They call:

    run_cortex_action(db, integration_id, action_id, params, principal)
    ingest_cortex_alerts(db, integration_id, since_cursor, principal)

which handles the vault access, adapter construction, HTTPX
connector wiring, and error surface uniformly.

Invariants (locked):
  * Plaintext lives only in the local variable inside this module,
    never in a class attribute persisted beyond the call.
  * Every access is audit-logged by the vault.
  * If the vault denies the access (revoked / not found /
    decrypt-fail), the caller receives a structured error — never a
    silent fallback to a stored value.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

from .xdr_cortex_adapter import CortexXdrAdapter
from .xdr_credential_vault import (
    CredentialVault, VaultAccessError, get_vault,
)

log = logging.getLogger("nivxray.xdr.cortex_executor")
VENDOR = "palo_alto_cortex_xdr"
INTEGRATIONS = "xdr_integrations"


def _httpx_connector(base_url: str, timeout: float = 8.0):
    async def _call(method: str, path: str, headers: dict, json: Any):
        url = base_url.rstrip("/") + path
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=True) as c:
                resp = await c.request(method, url,
                                             headers=headers, json=json)
            return {
                "ok":               resp.status_code < 300,
                "detail":           f"{method} {path} · HTTP {resp.status_code}",
                "vendor_reference": resp.headers.get("x-request-id"),
                "http_status":      resp.status_code,
            }
        except Exception as e:                                     # noqa: BLE001
            return {"ok": False, "reason": "CONNECTION_FAILED",
                        "detail": f"{type(e).__name__}: {e}"}
    return _call


async def _load_integration(db, integration_id: str) -> dict:
    rec = await db[INTEGRATIONS].find_one(
        {"integration_id": integration_id, "vendor": VENDOR}, {"_id": 0})
    if rec is None:
        raise LookupError(f"integration_not_found: {integration_id}")
    if not rec.get("active"):
        raise LookupError(f"integration_inactive: {integration_id}")
    if not rec.get("credential_ref"):
        raise LookupError(f"credential_ref_missing: {integration_id}")
    return rec


async def _scoped_adapter(db, integration_id: str, *,
                              purpose: str, principal: str,
                              ) -> CortexXdrAdapter:
    rec = await _load_integration(db, integration_id)
    vault: CredentialVault = get_vault(db)
    api_key = await vault.access(secret_ref=rec["credential_ref"],
                                        purpose=purpose,
                                        principal=principal)
    return CortexXdrAdapter({
        "base_url": rec["base_url"],
        "tenant":   rec.get("tenant"),
        "credentials": {
            "api_key_id":  rec.get("api_key_id"),
            "api_key":     api_key,
            "base_url":    rec["base_url"],
            "tenant":      rec.get("tenant"),
        },
        "_connector": _httpx_connector(rec["base_url"]),
    })


async def run_cortex_action(db, *, integration_id: str,
                                action_id: str, params: dict,
                                principal: str) -> dict:
    """Execute one canonical response action.  Round 27 hook."""
    try:
        adapter = await _scoped_adapter(
            db, integration_id,
            purpose="cortex_action:" + action_id,
            principal=principal,
        )
    except (LookupError, VaultAccessError) as e:
        return {"ok": False, "action_id": action_id,
                    "vendor": VENDOR, "error": str(e),
                    "vendor_request_id": None,
                    "vendor_response_id": None}
    connect = await adapter.connect()
    if not connect.get("ok"):
        return {"ok": False, "action_id": action_id, "vendor": VENDOR,
                    "error": connect.get("detail"),
                    "vendor_request_id": None,
                    "vendor_response_id": None}
    return await adapter.execute_action(action_id, params)


async def ingest_cortex_alerts(db, *, integration_id: str,
                                     since_cursor: Optional[str],
                                     principal: str) -> dict:
    """Pull vendor alerts newer than `since_cursor`.  Round 26 hook."""
    try:
        adapter = await _scoped_adapter(
            db, integration_id,
            purpose="cortex_ingest",
            principal=principal,
        )
    except (LookupError, VaultAccessError) as e:
        return {"events": [], "next_cursor": since_cursor,
                    "error": str(e)}
    connect = await adapter.connect()
    if not connect.get("ok"):
        return {"events": [], "next_cursor": since_cursor,
                    "error": connect.get("detail")}
    return await adapter.ingest_alerts(since_cursor=since_cursor)
