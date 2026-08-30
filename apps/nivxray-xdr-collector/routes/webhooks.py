"""
Webhook receiver route · Phase B.

POST /api/xdr/webhooks/{secret_id}
  - Body: raw bytes (JSON preferred).  Raw body is kept verbatim in
    the envelope for provenance.
  - Signature verification: X-Hub-Signature-256 (or override) using
    the connector's `credentials.hmac_secret`.  Failed signature →
    HTTP 401 with reason.
  - Replay guard: optional X-Timestamp seconds-since-epoch header
    (5-minute window).
"""
from __future__ import annotations

import json
from typing import Any, Dict

from fastapi         import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from framework.webhook import WebhookConnector


router = APIRouter(tags=["webhooks"])


def _find_webhook(request: Request, secret_id: str) -> WebhookConnector | None:
    """Lookup a live WebhookConnector instance by its `secret_id`
    configuration.  We deliberately search the runtime instance table
    (not the store) so a disabled record doesn't accept traffic."""
    for inst in request.app.state.instances.values():
        if isinstance(inst, WebhookConnector) \
             and (inst.config.get("secret_id") == secret_id):
            return inst
    return None


@router.post("/webhooks/{secret_id}")
async def inbound_webhook(secret_id: str, request: Request):
    conn = _find_webhook(request, secret_id)
    if conn is None:
        raise HTTPException(404, detail={"error": "webhook_not_configured",
                                              "secret_id": secret_id})

    body = await request.body()
    headers = {k: v for k, v in request.headers.items()}
    check = conn.verify(body, headers)
    if not check.get("ok"):
        conn.metrics.events_rejected += 1
        conn.metrics.last_error = check.get("reason")
        return JSONResponse(status_code=401,
                                content={"error": "signature_verification_failed",
                                            "detail": check})

    try:
        parsed = json.loads(body.decode("utf-8")) if body else {}
    except Exception:                                           # noqa: BLE001
        parsed = {"raw_body": body.decode("utf-8", errors="replace")}

    envs = conn.envelopes_from(parsed)
    conn.metrics.events_collected += len(envs)
    await request.app.state.runtime.deliver(conn, envs)
    return {"ok": True, "accepted": len(envs),
              "authenticated": check.get("authenticated", False)}
