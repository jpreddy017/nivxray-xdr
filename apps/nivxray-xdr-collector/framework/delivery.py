"""
Ingest client · Phase B "outbox" stub.

Owns the responsibility of shipping canonical envelopes to the
authoritative NivXRay ingestion endpoint.  Phase B ships events
best-effort; Phase B.5 makes it durable (retry / DLQ / observability).

The boundary is critical: the collector NEVER decides "is this
malicious".  Its outbox emits envelopes; NivXRay's authoritative
ingest owns evidence, verdict, IKG and SSOT.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List

import httpx

from framework.base import Envelope


class IngestClient:
    """Best-effort forwarder.  Absent config → no-op emit (queue only).

    Config env vars:
      NIVX_INGEST_URL   – full URL to the authoritative XDR ingest API
      NIVX_INGEST_TOKEN – bearer token
      NIVX_INGEST_TIMEOUT – seconds, default 10
    """

    def __init__(self) -> None:
        self.url     = os.environ.get("NIVX_INGEST_URL") or None
        self.token   = os.environ.get("NIVX_INGEST_TOKEN") or None
        self.timeout = float(os.environ.get("NIVX_INGEST_TIMEOUT", "10"))
        self.last_error: str | None = None
        self.delivered: int = 0
        self.queued:    int = 0

    def configured(self) -> bool:
        return bool(self.url)

    def status(self) -> Dict[str, Any]:
        return {
            "configured":  self.configured(),
            "url_set":     bool(self.url),
            "token_set":   bool(self.token),
            "delivered":   self.delivered,
            "queued":      self.queued,
            "last_error":  self.last_error,
        }

    async def deliver(self, envelopes: Iterable[Envelope]) -> Dict[str, Any]:
        batch: List[Dict[str, Any]] = [e.to_dict() for e in envelopes]
        if not batch:
            return {"ok": True, "delivered": 0, "queued": 0}
        if not self.configured():
            # Phase B: honest "queued but not delivered" — Phase B.5
            # replaces with a durable outbox.
            self.queued += len(batch)
            return {"ok": False, "delivered": 0, "queued": len(batch),
                     "reason": "ingest_not_configured"}
        try:
            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.url, json={"envelopes": batch},
                                              headers=headers)
                resp.raise_for_status()
            self.delivered += len(batch)
            self.last_error = None
            return {"ok": True, "delivered": len(batch), "queued": 0}
        except Exception as e:                                 # noqa: BLE001
            self.last_error = f"{type(e).__name__}: {e}"
            self.queued += len(batch)
            return {"ok": False, "delivered": 0, "queued": len(batch),
                     "reason": self.last_error}
