"""
Ingest preflight route · Phase B.5 production-readiness.

`POST /api/xdr/ingest-preflight` sends ONE synthetic envelope through
the real IngestClient (same code path as production delivery) and
returns the concrete outcome.  It lets operators prove:

  • NIVX_INGEST_URL is set
  • Bearer token is accepted
  • The base ingest endpoint speaks the contract (see INGEST_CONTRACT.md)
  • Network path (DNS, TLS, firewall) is open

The synthetic envelope carries `event_type = "preflight"` and
`canonical.nivxray_preflight = true` so the base backend can
short-circuit the SSOT/Verdict/IKG pipeline if desired.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from typing import Optional

from fastapi   import APIRouter, HTTPException, Request, Header

from framework.base     import Envelope
from framework.delivery import IngestOutcome


router = APIRouter(tags=["preflight"])


def _synth_envelope(tenant_id: str, collector_id: str) -> Envelope:
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    return Envelope(
        tenant_id            = tenant_id,
        source               = "nivxray-xdr-collector · preflight",
        source_event_id      = f"preflight-{uuid.uuid4().hex[:12]}",
        connector_id         = "preflight",
        collector_id         = collector_id,
        collection_method    = "preflight",
        parser_version       = "phaseB5.preflight.1",
        source_timestamp     = now,
        collection_timestamp = now,
        event_type           = "preflight",
        raw                  = {"note": "synthetic preflight envelope",
                                  "docs":  "see INGEST_CONTRACT.md §3"},
        canonical            = {"nivxray_preflight": True,
                                  "issued_at":       now},
    )


@router.post("/ingest-preflight")
async def ingest_preflight(request: Request,
                                x_tenant_id: Optional[str] = Header(default=None)):
    runtime = getattr(request.app.state, "runtime", None)
    if runtime is None:
        raise HTTPException(503, detail={"error": "runtime_not_ready"})

    if not runtime.ingest.configured():
        return {
            "ok":          False,
            "preflight_ok": False,
            "state":       "not_configured",
            "reason":      "NIVX_INGEST_URL is not set on the collector process. "
                              "See DEPLOY.md §2.",
        }

    import os
    collector_id = os.environ.get("XDR_COLLECTOR_ID", "collector-local")
    tenant_id    = x_tenant_id or "preflight"
    env = _synth_envelope(tenant_id, collector_id)
    result = await runtime.ingest.deliver([env])

    outcome = result.get("outcome")
    return {
        "ok":            outcome == IngestOutcome.OK,
        "preflight_ok":  outcome == IngestOutcome.OK,
        "outcome":       outcome,
        "state":         "healthy"   if outcome == IngestOutcome.OK
                            else "degraded" if outcome == IngestOutcome.RETRYABLE
                            else "error",
        "status_code":   result.get("status_code"),
        "reason":        result.get("reason"),
        "envelope":      {"tenant_id":       env.tenant_id,
                            "source_event_id": env.source_event_id,
                            "collector_id":    env.collector_id},
        "docs":          "see INGEST_CONTRACT.md §3",
    }
