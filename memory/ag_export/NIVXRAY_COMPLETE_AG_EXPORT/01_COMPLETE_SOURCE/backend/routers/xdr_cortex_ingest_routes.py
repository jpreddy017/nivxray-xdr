"""
Round 26 · Cortex Ingest Fabric — HTTP surface.
================================================

Endpoints (all under ``/api/xdr/vendor/cortex``):

  POST /webhooks/{integration_id}    → Cortex push notifications.
                                        HMAC-verified · replay-guarded.
  POST /connections/{id}/poll        → Operator-triggered pull.  Uses
                                        `xdr_cortex_executor.ingest_cortex_alerts`.
  GET  /connections/{id}/ingest      → Last ingest run audit + current
                                        checkpoint.

Locked security (owner · Round 26):
  · Webhook rejects: unknown integration · bad signature · replay
    outside 5-minute window.
  · Both push and pull upsert deterministically (Round 26.5 handles
    incident promotion / dedup at a higher layer).
  · Vault credentials are NEVER read here; the executor is the ONLY
    path that touches the vault.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request

from deps import db
from detection_content.xdr_cortex_ingest import (
    ingest_payload, get_checkpoint, set_checkpoint,
    latest_modification_time, INGEST_AUDIT,
)
from detection_content.xdr_credential_vault import get_vault
from detection_content.xdr_cortex_executor import ingest_cortex_alerts
from detection_content.xdr_cortex_parser import parse_batch

log = logging.getLogger("nivxray.xdr.cortex_ingest_routes")

router = APIRouter(prefix="/api/xdr/vendor/cortex",
                     tags=["xdr-cortex-ingest"])
VENDOR = "palo_alto_cortex_xdr"
INTEGRATIONS = "xdr_integrations"

# 5-minute replay window (verbatim from webhook contract §4).
REPLAY_WINDOW_SECONDS = 300


async def _load_integration(integration_id: str) -> dict:
    rec = await db[INTEGRATIONS].find_one(
        {"integration_id": integration_id, "vendor": VENDOR},
        {"_id": 0},
    )
    if rec is None:
        raise HTTPException(404, detail={"error": "integration_not_found"})
    if not rec.get("active"):
        raise HTTPException(409, detail={"error": "integration_inactive"})
    return rec


# ── Webhook — HMAC + replay-guarded ─────────────────────────
@router.post("/webhooks/{integration_id}")
async def cortex_webhook(integration_id: str, request: Request):
    rec = await _load_integration(integration_id)

    if not rec.get("credential_ref"):
        raise HTTPException(409, detail={
            "error": "vault_ref_missing",
            "reason": "integration has no vault-backed secret",
        })

    body = await request.body()
    signature = request.headers.get("x-xdr-signature")
    timestamp = request.headers.get("x-xdr-timestamp")

    if not signature or not timestamp:
        raise HTTPException(401, detail={
            "error": "signature_missing",
            "reason": "webhook must supply X-XDR-Signature and X-XDR-Timestamp",
        })
    try:
        ts_int = int(timestamp)
    except ValueError:
        raise HTTPException(401, detail={"error": "timestamp_invalid"})
    if abs(int(time.time()) - ts_int) > REPLAY_WINDOW_SECONDS:
        raise HTTPException(401, detail={
            "error": "replay_rejected",
            "reason": f"timestamp outside {REPLAY_WINDOW_SECONDS}s window",
        })

    # Vault access — one-shot decrypt at the execution boundary.
    try:
        api_key = await get_vault(db).access(
            secret_ref=rec["credential_ref"],
            purpose="cortex_webhook_hmac",
            principal="cortex_webhook",
        )
    except Exception as e:                                         # noqa: BLE001
        raise HTTPException(401, detail={
            "error": "vault_access_denied",
            "reason": str(e),
        })

    # HMAC-SHA256 over `<timestamp>.<body>` with the Cortex API key
    # as the shared secret.  This mirrors the Cortex Advanced-API
    # signing scheme used for outbound calls, so operators can reuse
    # the same key material for the push channel.
    mac = hmac.new(
        api_key.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + body,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(mac, signature.strip()):
        raise HTTPException(401, detail={
            "error": "signature_mismatch",
            "reason": "HMAC verification failed",
        })

    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except json.JSONDecodeError:
        raise HTTPException(400, detail={"error": "invalid_json"})

    envelope = await ingest_payload(
        db, integration_id=integration_id,
        payload=payload, source="webhook",
        principal="cortex_webhook",
    )
    return {"ok": True, **envelope}


# ── Operator-triggered pull ─────────────────────────────────
@router.post("/connections/{integration_id}/poll")
async def cortex_poll(integration_id: str, limit: int = 100):
    rec = await _load_integration(integration_id)
    since_ms = await get_checkpoint(db, integration_id)
    # since_ms may be None on first run — the executor + vendor
    # endpoint accept that as "from the beginning".
    result = await ingest_cortex_alerts(
        db, integration_id=integration_id,
        since_cursor=str(since_ms) if since_ms else None,
        principal="cortex_poller",
    )
    if result.get("error"):
        raise HTTPException(502, detail={
            "error": "poll_failed",
            "reason": result["error"],
        })
    events = result.get("events") or []
    envelope = await ingest_payload(
        db, integration_id=integration_id,
        payload={"incidents": events},
        source="poller",
        principal="cortex_poller",
    )
    # Advance checkpoint deterministically from the batch itself so
    # we do not re-poll already-ingested rows on the next run.
    rows = parse_batch({"incidents": events},
                            integration_id=integration_id)
    new_ck = latest_modification_time(rows)
    if new_ck is not None and (since_ms is None or new_ck > since_ms):
        await set_checkpoint(db, integration_id, new_ck)
        envelope["checkpoint_advanced_to"] = new_ck
    else:
        envelope["checkpoint_advanced_to"] = since_ms
    return {"ok": True, **envelope}


# ── Read: last runs + checkpoint ────────────────────────────
@router.get("/connections/{integration_id}/ingest")
async def cortex_ingest_status(integration_id: str, limit: int = 20):
    await _load_integration(integration_id)
    cursor = db[INGEST_AUDIT].find(
        {"integration_id": integration_id}, {"_id": 0}
    ).sort("at", -1).limit(limit)
    runs = [row async for row in cursor]
    ck = await get_checkpoint(db, integration_id)
    return {
        "integration_id":            integration_id,
        "runs":                      runs,
        "count":                     len(runs),
        "checkpoint_ms":             ck,
        "checkpoint_iso":            _epoch_iso(ck),
    }


def _epoch_iso(ms: Optional[int]) -> Optional[str]:
    import datetime as _dt
    if ms is None:
        return None
    try:
        return _dt.datetime.fromtimestamp(
            ms / 1000, tz=_dt.timezone.utc).isoformat()
    except Exception:                                              # noqa: BLE001
        return None
