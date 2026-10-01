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
import re
from typing import Any, Dict, Iterable, List

import httpx

from framework.base import Envelope
from framework.identity import collector_id, tenant_id


#: G1-R2 · bounded body excerpt. Enough to identify the refusal contract,
#: never enough to become a payload store.
FAILURE_BODY_EXCERPT_CHARS = 300

#: Defensive redaction. Our own API never echoes the credential, but a
#: failure record must not be able to become the place a secret leaks.
_REDACT = (
    (re.compile(r"nvx_[A-Za-z0-9_\-]+"), "nvx_<redacted>"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+"), "Bearer <redacted>"),
    (re.compile(r"(?i)(api[-_]?key\"?\s*[:=]\s*\"?)[A-Za-z0-9._\-]+"),
     r"\1<redacted>"),
)


def _redact(text: str) -> str:
    for pattern, replacement in _REDACT:
        text = pattern.sub(replacement, text)
    return text


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


class CommitState:
    """What this attempt proves about a possible BACKEND COMMIT.

    The distinction the R5/R6 recovery had to reconstruct by hand: a request
    that never left the endpoint cannot have been committed, while a request
    that was sent and whose answer was lost MAY have been committed and must
    never be blindly re-sent as though it had not.
    """
    #: The request provably never reached the destination application.
    NOT_SENT = "NOT_SENT"
    #: The destination answered 2xx: it CLAIMS acceptance. Not proof of
    #: canonicalisation, and not a receipt.
    CLAIMED = "COMMIT_CLAIMED"
    #: Sent, and the outcome is unknown: timeout, reset, 5xx, or a refusal
    #: that cannot be attributed to the authoritative application.
    UNKNOWN = "UNKNOWN"
    #: The application itself refused this delivery.
    TERMINAL_CLAIMED = "TERMINAL_CLAIMED"


#: Transport failures that provably happened BEFORE the request was sent.
_NOT_SENT_TRANSPORT = ("ConnectError", "ConnectTimeout", "ProxyError",
                       "UnsupportedProtocol", "InvalidURL")


def _transport_commit_state(exc: Exception) -> str:
    return (CommitState.NOT_SENT
            if type(exc).__name__ in _NOT_SENT_TRANSPORT
            else CommitState.UNKNOWN)


# Present on every application response; absent when no backend answered.
APP_ATTRIBUTION_HEADER = "X-Request-ID"


def _failure_detail(*, classification: str, reason: str,
                    status_code: int | None = None,
                    app_attributed: bool | None = None,
                    resp: "httpx.Response | None" = None,
                    url: str | None = None) -> Dict[str, Any]:
    """G1-R2 · the bounded, redacted record of one failed attempt.

    It answers, after the fact and without the original process: what did the
    far side actually say, and was it the authoritative application at all.
    """
    import datetime as _dt
    detail: Dict[str, Any] = {
        "classification":  classification,
        "reason":          reason,
        "attempted_at":    _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "url":             url,
        "status_code":     status_code,
        "app_attributed":  app_attributed,
        "attribution_header": APP_ATTRIBUTION_HEADER,
        "request_id":      None,
        "content_type":    None,
        "server":          None,
        "body_excerpt":    None,
        "body_bytes":      None,
        "body_truncated":  None,
        "capture_note": ("bounded and redacted; body excerpt capped at "
                         f"{FAILURE_BODY_EXCERPT_CHARS} chars and never "
                         "contains the credential"),
    }
    if resp is None:
        return detail
    headers = resp.headers
    detail["request_id"]   = headers.get(APP_ATTRIBUTION_HEADER)
    detail["content_type"] = headers.get("content-type")
    detail["server"]       = headers.get("server")
    try:
        body = resp.text or ""
    except Exception:                                        # noqa: BLE001
        body = ""
    detail["body_bytes"]     = len(body)
    detail["body_truncated"] = len(body) > FAILURE_BODY_EXCERPT_CHARS
    detail["body_excerpt"]   = _redact(body[:FAILURE_BODY_EXCERPT_CHARS])
    return detail


class IngestClient:
    def __init__(self) -> None:
        self.delivered:       int = 0
        self.failed_retryable: int = 0
        self.failed_fatal:    int = 0
        self.failed_unattributed: int = 0
        self.last_error: str | None = None
        self.last_classification: str | None = None
        self.last_failure_detail: Dict[str, Any] | None = None
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
            "last_failure_detail": self.last_failure_detail,
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
            detail = _failure_detail(
                classification=DeliveryClassification.RETRYABLE,
                reason="ingest_not_configured", url=None)
            self.last_failure_detail = detail
            detail["commit_state"] = CommitState.NOT_SENT
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "classification": DeliveryClassification.RETRYABLE,
                     "commit_state": CommitState.NOT_SENT,
                     "failure_detail": detail,
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
            detail = _failure_detail(
                classification=DeliveryClassification.RETRYABLE,
                reason=self.last_error, url=self.url,
                app_attributed=False)
            detail["transport_error"] = type(e).__name__
            detail["commit_state"] = _transport_commit_state(e)
            self.last_failure_detail = detail
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "classification": DeliveryClassification.RETRYABLE,
                     "commit_state": detail["commit_state"],
                     "failure_detail": detail,
                     "reason": self.last_error}
        except Exception as e:                                  # noqa: BLE001
            self.failed_retryable += len(batch)
            self.last_error = f"{type(e).__name__}: {e}"
            self.last_classification = DeliveryClassification.RETRYABLE
            detail = _failure_detail(
                classification=DeliveryClassification.RETRYABLE,
                reason=self.last_error, url=self.url,
                app_attributed=False)
            detail["transport_error"] = type(e).__name__
            detail["commit_state"] = _transport_commit_state(e)
            self.last_failure_detail = detail
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0,
                     "classification": DeliveryClassification.RETRYABLE,
                     "commit_state": detail["commit_state"],
                     "failure_detail": detail,
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
            self.last_failure_detail = None
            self.last_delivery_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
            return {"outcome": IngestOutcome.OK, "delivered": len(batch),
                     "classification": DeliveryClassification.ACCEPTED,
                     "app_attributed": app_attributed,
                     "commit_state": CommitState.CLAIMED,
                     "status_code": code}

        if code in (408, 429) or 500 <= code < 600:
            self.failed_retryable += len(batch)
            self.last_error = f"HTTP {code}"
            self.last_classification = DeliveryClassification.RETRYABLE
            detail = _failure_detail(
                classification=DeliveryClassification.RETRYABLE,
                reason=self.last_error, status_code=code,
                app_attributed=app_attributed, resp=resp, url=self.url)
            # 429 is an explicit refusal to process, so nothing was committed.
            # A 408 or a 5xx was received BY something: the commit state of
            # the delivery behind it is unknown.
            commit = (CommitState.NOT_SENT if code == 429
                      else CommitState.UNKNOWN)
            detail["commit_state"] = commit
            self.last_failure_detail = detail
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "status_code": code,
                     "classification": DeliveryClassification.RETRYABLE,
                     "app_attributed": app_attributed,
                     "commit_state": commit,
                     "failure_detail": detail,
                     "reason": self.last_error}

        # ── G1-R1 · a 4xx is terminal ONLY when attributable ──────────
        # 404 is never terminal: unattributed it is an outage (the exact G1
        # failure shape), and attributed it is "collector not found", which a
        # later enrolment legitimately resolves.
        if code == 404 or not app_attributed:
            self.failed_unattributed += len(batch)
            detail_note = ("no " + APP_ATTRIBUTION_HEADER
                           if not app_attributed else "app-attributed")
            self.last_error = (f"HTTP {code} | UNATTRIBUTED_FAILURE ({detail_note}) "
                               f"| bounded retry")
            self.last_classification = DeliveryClassification.UNATTRIBUTED_FAILURE
            detail = _failure_detail(
                classification=DeliveryClassification.UNATTRIBUTED_FAILURE,
                reason=self.last_error, status_code=code,
                app_attributed=app_attributed, resp=resp, url=self.url)
            detail["commit_state"] = CommitState.UNKNOWN
            self.last_failure_detail = detail
            return {"outcome": IngestOutcome.RETRYABLE,
                     "delivered": 0, "status_code": code,
                     "classification": DeliveryClassification.UNATTRIBUTED_FAILURE,
                     "app_attributed": app_attributed,
                     "commit_state": CommitState.UNKNOWN,
                     "failure_detail": detail,
                     "reason": self.last_error}

        # An application-attributed 4xx refusal (tenant isolation, auth,
        # malformed batch). Fail closed: terminal, never retried into success.
        self.failed_fatal += len(batch)
        self.last_error = f"HTTP {code} | AUTHORITATIVE_TERMINAL (app-attributed refusal)"
        self.last_classification = DeliveryClassification.AUTHORITATIVE_TERMINAL
        detail = _failure_detail(
            classification=DeliveryClassification.AUTHORITATIVE_TERMINAL,
            reason=self.last_error, status_code=code,
            app_attributed=app_attributed, resp=resp, url=self.url)
        detail["commit_state"] = CommitState.TERMINAL_CLAIMED
        self.last_failure_detail = detail
        return {"outcome": IngestOutcome.FATAL,
                 "delivered": 0, "status_code": code,
                 "classification": DeliveryClassification.AUTHORITATIVE_TERMINAL,
                 "app_attributed": app_attributed,
                 "commit_state": CommitState.TERMINAL_CLAIMED,
                 "failure_detail": detail,
                 "reason": self.last_error}
