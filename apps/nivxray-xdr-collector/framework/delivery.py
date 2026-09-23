"""
Ingest client · Phase B.5.

Ships canonical envelopes to the authoritative NivXRay ingestion API.
Callers (the delivery worker) act on the returned outcome:

    OK          → HTTP 2xx, mark envelopes DELIVERED
    RETRYABLE   → HTTP 5xx, 408, 429, transport/timeout error, OR a 4xx
                     that cannot be attributed to the authoritative
                     application → mark RETRYING with backoff
    FATAL       → an application-attributable permanent refusal only →
                     mark DEAD_LETTER

G1-R1 · RETRY CLASSIFICATION CORRECTNESS
----------------------------------------
A response is NOT terminal merely because its status is in the 4xx class.
During the G1 proof run, infrastructure in front of the application answered
HTTP 404 for ~5h46m while the backend was not running, and 14,868 acquired
events were destroyed on their FIRST attempt because any non-408/429 4xx was
treated as fatal. Those responses never reached the application, so they were
never refusals at all.

Terminality now requires an *attributable* refusal:

    ACCEPTED              2xx
    RETRYABLE             408 / 429 / 5xx / transport / not-configured
    UNATTRIBUTED_FAILURE  a 4xx with no proof it came from the application,
                          or ANY 404 → bounded retry, and only the existing
                          max_attempts machinery may end it
    AUTHORITATIVE_TERMINAL an application-attributed 4xx refusal → dead letter

Attribution signal: every NivXRay application response carries an
``X-Request-ID`` header (backend/request_hardening.py stamps it on success and
on error paths alike). Infrastructure responses generated when no backend is
listening do not. This is deliberately a conservative, header-only test — it
can only ever *withhold* terminality, never invent it. Richer failure-detail
capture (body excerpt, content-type, resolved URL) is G1-R2 and is NOT done
here.

404 is never terminal, even when attributed: the application's only ingest 404
is "collector not found", which a later enrolment legitimately resolves.

Security semantics are unchanged and still fail-closed: a refusal is never
laundered into success, retries stay bounded by ``max_attempts`` with backoff,
and exhaustion produces an explicit terminal disposition that is truthfully
distinct from an authoritative refusal.

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
from framework.identity import collector_id, tenant_id


class IngestOutcome:
    """Worker-facing action. Deliberately unchanged wire values."""
    OK        = "ok"
    RETRYABLE = "retryable"
    FATAL     = "fatal"


class DeliveryClassification:
    """Why the outcome is what it is (G1-R1). Reported, never guessed."""
    ACCEPTED               = "ACCEPTED"
    RETRYABLE              = "RETRYABLE"
    UNATTRIBUTED_FAILURE   = "UNATTRIBUTED_FAILURE"
    AUTHORITATIVE_TERMINAL = "AUTHORITATIVE_TERMINAL"


# Present on every application response; absent when no backend answered.
APP_ATTRIBUTION_HEADER = "X-Request-ID"


class IngestClient:
    def __init__(self) -> None:
        self.delivered:       int = 0
        self.failed_retryable: int = 0
        self.failed_fatal:    int = 0
        self.failed_unattributed: int = 0
        self.last_error: str | None = None
        self.last_classification: str | None = None
        self.last_delivery_at: str | None = None

    # Read env fresh on every call so operators can hot-fix the token
    # by setting the env and letting the next delivery pick it up.
    @property
    def url(self) -> str | None:
        return os.environ.get("NIVX_INGEST_URL") or None
    @property
    def token(self) -> str | None:
        return os.environ.get("NIVX_INGEST_TOKEN") or None
    @property
    def timeout(self) -> float:
        return float(os.environ.get("NIVX_INGEST_TIMEOUT", "10"))

    @property
    def auth_mode(self) -> str:
        """`api_key` (default) or `bearer` for a user JWT."""
        return (os.environ.get("NIVX_INGEST_AUTH_MODE") or "api_key").lower()

    def configured(self) -> bool:
        return bool(self.url)

    def status(self) -> Dict[str, Any]:
        return {
            "configured":         self.configured(),
            "url_set":            bool(self.url),
            "token_set":          bool(self.token),
            "auth_mode":          self.auth_mode,
            "delivered":          self.delivered,
            "failed_retryable":   self.failed_retryable,
            "failed_fatal":       self.failed_fatal,
            "failed_unattributed": self.failed_unattributed,
            "last_classification": self.last_classification,
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
            self.last_classification = DeliveryClassification.RETRYABLE
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "classification": DeliveryClassification.RETRYABLE,
                     "reason":    "ingest_not_configured"}

        try:
            headers = {"Content-Type": "application/json"}
            # The authoritative boundary authenticates a collector with
            # `X-XDR-API-Key` + `X-Tenant-Id` (xdr_rbac.require_permission).
            # Sending the same value as a bearer token routes it down the
            # JWT path instead, where it can only ever fail — and presenting
            # BOTH is rejected as ambiguous-credentials. So the credential
            # goes in the key header unless an operator explicitly says the
            # configured value is a user JWT.
            if self.token:
                if self.auth_mode == "bearer":
                    headers["Authorization"] = f"Bearer {self.token}"
                else:
                    headers["X-XDR-API-Key"] = self.token
            # The core's tenant-isolation guard compares this header
            # against the enrolled collector's tenant. Derive it from
            # the batch so a mis-set env can never masquerade.
            batch_tenants = {b.get("tenant_id") for b in batch if b.get("tenant_id")}
            headers["X-Tenant-Id"] = (batch_tenants.pop()
                                      if len(batch_tenants) == 1
                                      else tenant_id())
            headers["X-Principal-Id"] = f"collector:{collector_id()}"
            headers["X-Principal-Kind"] = "system"
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.url, json={"envelopes": batch},
                                              headers=headers)
        except (httpx.TimeoutException, httpx.TransportError) as e:
            self.failed_retryable += len(batch)
            self.last_error = f"{type(e).__name__}: {e}"
            self.last_classification = DeliveryClassification.RETRYABLE
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "classification": DeliveryClassification.RETRYABLE,
                     "reason": self.last_error}
        except Exception as e:                                  # noqa: BLE001
            self.failed_retryable += len(batch)
            self.last_error = f"{type(e).__name__}: {e}"
            self.last_classification = DeliveryClassification.RETRYABLE
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "classification": DeliveryClassification.RETRYABLE,
                     "reason": self.last_error}

        code = resp.status_code
        # Did the authoritative application answer, or did something in front
        # of it? Header-only, conservative: it can withhold terminality but
        # never manufacture it.
        app_attributed = APP_ATTRIBUTION_HEADER in resp.headers

        if 200 <= code < 300:
            import datetime as _dt
            self.delivered += len(batch)
            self.last_error = None
            self.last_classification = DeliveryClassification.ACCEPTED
            self.last_delivery_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
            return {"outcome": IngestOutcome.OK, "delivered": len(batch),
                     "classification": DeliveryClassification.ACCEPTED,
                     "app_attributed": app_attributed,
                     "status_code": code}

        if code in (408, 429) or 500 <= code < 600:
            self.failed_retryable += len(batch)
            self.last_error = f"HTTP {code}"
            self.last_classification = DeliveryClassification.RETRYABLE
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "status_code": code,
                     "classification": DeliveryClassification.RETRYABLE,
                     "app_attributed": app_attributed,
                     "reason": self.last_error}

        # ── G1-R1 · a 4xx is terminal ONLY when attributable ──────────
        # 404 is never terminal: unattributed it is an outage (the exact G1
        # failure shape), and attributed it is "collector not found", which a
        # later enrolment legitimately resolves.
        if code == 404 or not app_attributed:
            self.failed_unattributed += len(batch)
            detail = ("no " + APP_ATTRIBUTION_HEADER
                      if not app_attributed else "app-attributed")
            self.last_error = (f"HTTP {code} | UNATTRIBUTED_FAILURE ({detail}) "
                               f"| bounded retry")
            self.last_classification = DeliveryClassification.UNATTRIBUTED_FAILURE
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "status_code": code,
                     "classification": DeliveryClassification.UNATTRIBUTED_FAILURE,
                     "app_attributed": app_attributed,
                     "reason": self.last_error}

        # An application-attributed 4xx refusal (tenant isolation, auth,
        # malformed batch). Fail closed: terminal, never retried into success.
        self.failed_fatal += len(batch)
        self.last_error = f"HTTP {code} | AUTHORITATIVE_TERMINAL (app-attributed refusal)"
        self.last_classification = DeliveryClassification.AUTHORITATIVE_TERMINAL
        return {"outcome": IngestOutcome.FATAL,
                 "delivered": 0, "status_code": code,
                 "classification": DeliveryClassification.AUTHORITATIVE_TERMINAL,
                 "app_attributed": app_attributed,
                 "reason": self.last_error}
