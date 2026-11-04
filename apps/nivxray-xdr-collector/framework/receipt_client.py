"""Machine-authenticated receipt client · the endpoint's only receipt source.

The endpoint asks the authoritative plane ONE question, with the SAME
credential it delivers with:

    for these delivery identities, what did you actually do with them?

It is a read on the server side (`POST /api/xdr/ingest/delivery/receipts` is
backed by the read-only reconciliation service), so it can be called after a
2xx, after a timeout, after a crash and after a restart without any risk of
duplicating evidence.

The credential is never logged, never persisted and never echoed; only its
presence is ever asserted.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import httpx

from framework.identity import collector_id

RECEIPTS_PATH = "/api/xdr/ingest/delivery/receipts"
TELEMETRY_SUFFIX = "/api/xdr/ingest/telemetry"

#: The server bounds one request; mirror it so a batch is never silently cut.
MAX_IDENTITIES = 500


class ReceiptUnavailable(Exception):
    """No authoritative answer was obtained. The delivery stays UNKNOWN."""


class ReceiptClient:
    def __init__(self) -> None:
        self.requests = 0
        self.failures = 0
        self.last_error: Optional[str] = None

    # Read env fresh on every call, exactly like IngestClient, so an operator
    # fix is picked up by the next reconciliation without a restart.
    @property
    def url(self) -> Optional[str]:
        explicit = os.environ.get("NIVX_RECEIPT_URL")
        if explicit:
            return explicit
        ingest = os.environ.get("NIVX_INGEST_URL")
        if not ingest:
            return None
        if ingest.endswith(TELEMETRY_SUFFIX):
            return ingest[:-len(TELEMETRY_SUFFIX)] + RECEIPTS_PATH
        return None

    @property
    def token(self) -> Optional[str]:
        return os.environ.get("NIVX_INGEST_TOKEN") or None

    @property
    def auth_mode(self) -> str:
        return (os.environ.get("NIVX_INGEST_AUTH_MODE") or "api_key").lower()

    @property
    def timeout(self) -> float:
        return float(os.environ.get("NIVX_RECEIPT_TIMEOUT",
                                    os.environ.get("NIVX_INGEST_TIMEOUT",
                                                   "10")))

    def configured(self) -> bool:
        return bool(self.url)

    def status(self) -> Dict[str, Any]:
        return {"configured": self.configured(), "url_set": bool(self.url),
                "token_set": bool(self.token), "auth_mode": self.auth_mode,
                "requests": self.requests, "failures": self.failures,
                "last_error": self.last_error}

    async def fetch(self, *, tenant_id: str,
                    identities: List[Dict[str, Any]],
                    collector: Optional[str] = None) -> Dict[str, Any]:
        """The authoritative dispositions for one bounded population."""
        if not identities:
            return {"rows": [], "authority": {"tenant_id": tenant_id,
                                              "collector_id": collector
                                              or collector_id()}}
        if len(identities) > MAX_IDENTITIES:
            raise ReceiptUnavailable(
                f"at most {MAX_IDENTITIES} identities per receipt request; "
                f"{len(identities)} were supplied")
        if not self.configured():
            raise ReceiptUnavailable("receipt surface is not configured")
        cid = collector or collector_id()
        headers = {"Content-Type": "application/json",
                   "X-Tenant-Id": tenant_id,
                   "X-Principal-Id": f"collector:{cid}",
                   "X-Principal-Kind": "system"}
        if self.token:
            if self.auth_mode == "bearer":
                headers["Authorization"] = f"Bearer {self.token}"
            else:
                headers["X-XDR-API-Key"] = self.token
        self.requests += 1
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.url, headers=headers,
                    json={"collector_id": cid, "identities": identities})
        except Exception as ex:                                # noqa: BLE001
            self.failures += 1
            self.last_error = f"{type(ex).__name__}: {ex}"
            raise ReceiptUnavailable(
                f"receipt surface unreachable: {self.last_error}") from ex
        if not (200 <= resp.status_code < 300):
            self.failures += 1
            self.last_error = f"HTTP {resp.status_code}"
            raise ReceiptUnavailable(
                f"receipt surface answered HTTP {resp.status_code}; no "
                "authoritative disposition was obtained")
        try:
            body = resp.json()
        except Exception as ex:                                # noqa: BLE001
            self.failures += 1
            self.last_error = f"malformed receipt body: {type(ex).__name__}"
            raise ReceiptUnavailable(self.last_error) from ex
        if not isinstance(body, dict) or not isinstance(body.get("rows"),
                                                        list):
            self.failures += 1
            self.last_error = "receipt body has no rows"
            raise ReceiptUnavailable(self.last_error)
        self.last_error = None
        return body
