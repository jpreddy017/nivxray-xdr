"""
Ingest client · Phase B.5.

Ships canonical envelopes to the authoritative NivXRay ingestion API.
Callers (the delivery worker) act on the returned outcome:

    OK          → HTTP 2xx, mark envelopes DELIVERED
    RETRYABLE   → HTTP 5xx, 408, 429, or transport/timeout error →
                     mark RETRYING with backoff
    FATAL       → HTTP 4xx (except 408, 429) or unparsable response →
                     mark DEAD_LETTER

The client never silently accepts an event as delivered.  If
`NIVX_INGEST_URL` is not configured, `deliver()` returns
`ok=False, retryable=True, reason=ingest_not_configured` — the
worker keeps the envelope in the outbox and reports NOT_CONFIGURED
in health so operators fix it.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List

import httpx

from framework.base import Envelope


class IngestOutcome:
    OK        = "ok"
    RETRYABLE = "retryable"
    FATAL     = "fatal"


class IngestClient:
    def __init__(self) -> None:
        self.url     = os.environ.get("NIVX_INGEST_URL") or None
        self.token   = os.environ.get("NIVX_INGEST_TOKEN") or None
        self.timeout = float(os.environ.get("NIVX_INGEST_TIMEOUT", "10"))
        self.delivered:       int = 0
        self.failed_retryable: int = 0
        self.failed_fatal:    int = 0
        self.last_error: str | None = None
        self.last_delivery_at: str | None = None

    def configured(self) -> bool:
        return bool(self.url)

    def status(self) -> Dict[str, Any]:
        return {
            "configured":         self.configured(),
            "url_set":            bool(self.url),
            "token_set":          bool(self.token),
            "delivered":          self.delivered,
            "failed_retryable":   self.failed_retryable,
            "failed_fatal":       self.failed_fatal,
            "last_error":         self.last_error,
            "last_delivery_at":   self.last_delivery_at,
            "state":              "connected" if self.configured() else "not_configured",
        }

    async def deliver(self, envelopes: Iterable[Envelope]) -> Dict[str, Any]:
        batch: List[Dict[str, Any]] = [e.to_dict() for e in envelopes]
        if not batch:
            return {"outcome": IngestOutcome.OK, "delivered": 0}

        if not self.configured():
            self.failed_retryable += len(batch)
            self.last_error = "ingest_not_configured"
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "reason":    "ingest_not_configured"}

        try:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.url, json={"envelopes": batch},
                                              headers=headers)
        except (httpx.TimeoutException, httpx.TransportError) as e:
            self.failed_retryable += len(batch)
            self.last_error = f"{type(e).__name__}: {e}"
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "reason": self.last_error}
        except Exception as e:                                  # noqa: BLE001
            self.failed_retryable += len(batch)
            self.last_error = f"{type(e).__name__}: {e}"
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "reason": self.last_error}

        code = resp.status_code
        if 200 <= code < 300:
            import datetime as _dt
            self.delivered += len(batch)
            self.last_error = None
            self.last_delivery_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
            return {"outcome": IngestOutcome.OK, "delivered": len(batch),
                     "status_code": code}
        if code in (408, 429) or 500 <= code < 600:
            self.failed_retryable += len(batch)
            self.last_error = f"HTTP {code}"
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "status_code": code,
                     "reason": self.last_error}
        # Any other 4xx is a fatal, don't-retry response.
        self.failed_fatal += len(batch)
        self.last_error = f"HTTP {code}"
        return {"outcome": IngestOutcome.FATAL,
                 "delivered": 0, "status_code": code,
                 "reason": self.last_error}
