"""Microsoft 365 Management Activity connector (Phase 1b · acquisition).

Built on the EXISTING collector framework — `Connector`, `Envelope`,
`Checkpoint`, the scheduler, the dedup cache and the durable outbox are
reused unchanged. No second acquisition framework exists.

Microsoft's actual model, followed exactly:

    token (client credentials, app-only)
      → POST  /subscriptions/start?contentType=…      (idempotent)
      → GET   /subscriptions/content?contentType=&startTime=&endTime=
      → follow the `NextPageUri` response header until exhausted
      → GET   each `contentUri` (an aggregated content BLOB)
      → one Envelope per audit RECORD inside the blob
      → checkpoint the window, remember the contentIds
      → deliver to the authoritative ingest with declared_source
        `m365-unified-audit`

Honesty rules carried from D11–D21:

* `contentCreated` is when the BLOB became available. It is delivered as
  acquisition metadata (`_m365_acquisition`) and is NEVER presented as the
  activity instant — the DSM keeps `CreationTime` as the activity basis.
* The API performs no server-side deduplication and does not guarantee
  ordering, so replay protection lives here: a contentId already processed
  is counted as a duplicate and not re-read.
* Throttling, an expired blob, a rejected credential and an unreachable
  endpoint are four different reported states. None of them silently
  advances the checkpoint, so nothing is lost across a restart.
"""
from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from framework.base import Capability, Connector, Envelope, Health
from framework.identity import collector_id
from framework.oauth2 import ClientCredentialsTokenProvider, TokenError
from framework.parsers import utcnow_iso

DEFAULT_CONTENT_TYPES = ["Audit.Exchange", "Audit.AzureActiveDirectory",
                         "Audit.General"]
#: Microsoft's "subscription already enabled" error code.
_ALREADY_SUBSCRIBED = "AF20024"


def _iso_minute(dt: datetime) -> str:
    """Microsoft accepts startTime/endTime to the minute, in UTC."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class M365ManagementActivityConnector(Connector):
    source_type = "m365-management-activity"
    label = "Microsoft 365 Unified Audit (Management Activity API)"
    capabilities = [Capability.USERS, Capability.DETECTIONS]
    credential_requirements = ["client_id", "client_secret"]

    #: The source this connector DECLARES at the authoritative boundary.
    #: One connector, one declaration — content never chooses.
    DECLARED_SOURCE = "m365-unified-audit"

    configuration_schema = {
        "type": "object",
        "required": ["microsoft_tenant_id"],
        "properties": {
            "microsoft_tenant_id": {"type": "string"},
            "publisher_identifier": {"type": "string"},
            "content_types": {"type": "array", "items": {"type": "string"}},
            "base_url": {"type": "string"},
            "authority": {"type": "string"},
            "scope": {"type": "string"},
            "lookback_minutes": {"type": "integer", "minimum": 1},
            "max_window_hours": {"type": "integer", "minimum": 1,
                                 "maximum": 24},
            "max_pages_per_poll": {"type": "integer", "minimum": 1},
            "interval_seconds": {"type": "integer", "minimum": 60},
            "timeout_seconds": {"type": "integer", "minimum": 1},
            "remember_content_ids": {"type": "integer", "minimum": 100},
            "credentials": {"type": "object"},
        },
    }

    def __init__(self, tenant_id: str, config: Dict[str, Any],
                 identity: Optional[str] = None,
                 state: Optional[Any] = None,
                 outbox: Optional[Any] = None):
        super().__init__(tenant_id, config)
        if identity:
            self.identity = identity
        cfg = self.config
        self.base_url = (cfg.get("base_url")
                         or "https://manage.office.com/api/v1.0").rstrip("/")
        self.ms_tenant = str(cfg.get("microsoft_tenant_id") or "")
        self.publisher = str(cfg.get("publisher_identifier")
                             or self.ms_tenant)
        self.content_types = list(cfg.get("content_types")
                                  or DEFAULT_CONTENT_TYPES)
        self.timeout = float(cfg.get("timeout_seconds") or 30)
        self.lookback = int(cfg.get("lookback_minutes") or 60)
        self.max_window = int(cfg.get("max_window_hours") or 24)
        self.max_pages = int(cfg.get("max_pages_per_poll") or 20)
        self._remember = int(cfg.get("remember_content_ids") or 5000)
        self.tokens = ClientCredentialsTokenProvider(
            authority=cfg.get("authority")
            or "https://login.microsoftonline.com",
            tenant_id=self.ms_tenant,
            scope=cfg.get("scope") or "https://manage.office.com/.default",
            credentials=cfg.get("credentials") or {},
            timeout=self.timeout)
        self.subscriptions_started: List[str] = []
        self.blobs_read: int = 0
        self.blobs_expired: int = 0
        self.blobs_duplicate: int = 0
        self.blobs_in_flight_elsewhere: int = 0
        self.checkpoint.vendor_state = {}
        # Durable acquisition state (generic primitive). When absent the
        # connector still works, but its window lives only in memory — which
        # is exactly what a restart would lose, so the runtime always
        # attaches one.
        self.state = state
        self.outbox = outbox

    def attach_state(self, state: Any, outbox: Any = None) -> None:
        self.state = state
        if outbox is not None:
            self.outbox = outbox

    @property
    def durable(self) -> bool:
        return self.state is not None

    # ── restart recovery ─────────────────────────────────────────
    def restore_checkpoint(self, vendor_state: Dict[str, Any]) -> None:
        """Resume exactly where the previous process stopped."""
        self.checkpoint.vendor_state = dict(vendor_state or {})

    def _state(self, content_type: str) -> Dict[str, Any]:
        store = self.checkpoint.vendor_state.setdefault(content_type, {})
        store.setdefault("window_start", None)
        store.setdefault("next_page_uri", None)
        store.setdefault("seen_content_ids", [])
        return store

    def _seen(self, state: Dict[str, Any], content_id: str) -> bool:
        ids = state["seen_content_ids"]
        if content_id in ids:
            return True
        ids.append(content_id)
        if len(ids) > self._remember:
            del ids[:len(ids) - self._remember]
        return False

    # ── HTTP helpers ─────────────────────────────────────────────
    def _feed_url(self, path: str, **params: Any) -> str:
        q = {"PublisherIdentifier": self.publisher, **params}
        query = "&".join(f"{k}={quote(str(v))}" for k, v in q.items()
                         if v is not None)
        return (f"{self.base_url}/{self.ms_tenant}/activity/feed/{path}"
                f"?{query}")

    async def _get(self, client: httpx.AsyncClient, url: str,
                   token: str) -> httpx.Response:
        return await client.get(url, headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json"})

    # ── lifecycle ────────────────────────────────────────────────
    async def test_connection(self) -> Dict[str, Any]:
        """Prove the credential and the subscription surface, nothing more."""
        try:
            token = await self.tokens.token()
        except TokenError as e:
            self.health = (Health.AUTHENTICATION_FAILED if not e.retryable
                           else Health.DISCONNECTED)
            self.metrics.last_error = f"{e.code}: {e.message}"
            return {"ok": False, "code": e.code, "error": e.message,
                    "credential": self.tokens.describe()}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await self._get(
                    client, self._feed_url("subscriptions/list"), token)
        except Exception as e:                                # noqa: BLE001
            self.health = Health.DISCONNECTED
            self.metrics.last_error = f"{type(e).__name__}: {e}"
            return {"ok": False, "code": "ENDPOINT_UNREACHABLE",
                    "error": self.metrics.last_error}
        ok = resp.status_code < 400
        self.health = Health.CONNECTED if ok else (
            Health.AUTHENTICATION_FAILED if resp.status_code in (401, 403)
            else Health.ERROR)
        return {"ok": ok, "status_code": resp.status_code,
                "subscriptions": resp.json() if ok else None,
                "credential": self.tokens.describe()}

    async def start(self) -> None:
        """Ensure a subscription exists for every configured content type."""
        try:
            token = await self.tokens.token()
        except TokenError as e:
            self.health = (Health.AUTHENTICATION_FAILED if not e.retryable
                           else Health.DISCONNECTED)
            self.metrics.last_error = f"{e.code}: {e.message}"
            return
        started: List[str] = []
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for ct in self.content_types:
                url = self._feed_url("subscriptions/start", contentType=ct)
                try:
                    resp = await client.post(url, headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json"})
                except Exception as e:                        # noqa: BLE001
                    self.metrics.last_error = (f"subscription start {ct}: "
                                               f"{type(e).__name__}: {e}")
                    continue
                if resp.status_code < 300:
                    started.append(ct)
                    continue
                body = resp.text or ""
                if _ALREADY_SUBSCRIBED in body:
                    # Already enabled is success, not an error to retry.
                    started.append(ct)
                    continue
                self.metrics.last_error = (f"subscription start {ct}: HTTP "
                                           f"{resp.status_code} "
                                           f"{body[:160]}")
        self.subscriptions_started = started
        if started:
            self.health = Health.CONNECTED

    # ── collection ───────────────────────────────────────────────
    async def collect(self) -> List[Envelope]:
        self.metrics.last_attempt = utcnow_iso()
        if not self.ms_tenant:
            self.health = Health.ERROR
            self.metrics.last_error = ("microsoft_tenant_id is not "
                                       "configured; there is no tenant to "
                                       "collect from")
            return []
        try:
            token = await self.tokens.token()
        except TokenError as e:
            self.health = (Health.AUTHENTICATION_FAILED if not e.retryable
                           else Health.DISCONNECTED)
            self.metrics.last_error = f"{e.code}: {e.message}"
            return []

        envelopes: List[Envelope] = []
        now = datetime.now(timezone.utc)
        # Before acquiring anything, find out what the previous run
        # actually got ACCEPTED — the window may only advance on that.
        if self.state is not None and self.outbox is not None:
            self.state.reconcile(self.outbox, tenant_id=self.tenant_id,
                                 connector_id_=self.identity)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for ct in self.content_types:
                envelopes += await self._collect_content_type(
                    client, token, ct, now)
        self.metrics.events_collected += len(envelopes)
        if self.health not in (Health.RATE_LIMITED,
                               Health.AUTHENTICATION_FAILED):
            self.health = Health.CONNECTED
            self.metrics.last_success = utcnow_iso()
        self.checkpoint.updated_at = utcnow_iso()
        return envelopes

    async def _collect_content_type(self, client: httpx.AsyncClient,
                                    token: str, content_type: str,
                                    now: datetime) -> List[Envelope]:
        state = self._state(content_type)
        if self.state is not None:
            # The durable record is authoritative: it knows what was
            # ACCEPTED, which memory cannot after a restart.
            durable = self.state.window(self.tenant_id, self.identity,
                                        content_type)
            state["window_start"] = durable["committed_until"]
            state["next_page_uri"] = durable["next_page_ref"]
        start_iso = state.get("window_start")
        if start_iso:
            start = datetime.fromisoformat(start_iso)
        else:
            start = now - timedelta(minutes=self.lookback)
        end = min(now, start + timedelta(hours=self.max_window))

        url = state.get("next_page_uri") or self._feed_url(
            "subscriptions/content", contentType=content_type,
            startTime=_iso_minute(start), endTime=_iso_minute(end))

        out: List[Envelope] = []
        pages = 0
        window_end_iso = end.isoformat()
        while url and pages < self.max_pages:
            pages += 1
            try:
                resp = await self._get(client, url, token)
            except Exception as e:                            # noqa: BLE001
                self.health = Health.DISCONNECTED
                self.metrics.last_error = (f"content list {content_type}: "
                                           f"{type(e).__name__}: {e}")
                state["next_page_uri"] = url      # resume from this page
                return out
            if resp.status_code == 429:
                # Throttled: keep the page and the window untouched.
                self.health = Health.RATE_LIMITED
                self.metrics.last_error = (
                    f"429 Too Many Requests (Retry-After="
                    f"{resp.headers.get('Retry-After')}) on {content_type}")
                state["next_page_uri"] = url
                self._persist_window(content_type, state)
                return out
            if resp.status_code in (401, 403):
                self.tokens.invalidate()
                self.health = Health.AUTHENTICATION_FAILED
                self.metrics.last_error = (f"content list {content_type}: "
                                           f"HTTP {resp.status_code}")
                state["next_page_uri"] = url
                self._persist_window(content_type, state)
                return out
            if resp.status_code >= 400:
                self.health = Health.ERROR
                self.metrics.last_error = (f"content list {content_type}: "
                                           f"HTTP {resp.status_code} "
                                           f"{(resp.text or '')[:160]}")
                state["next_page_uri"] = url
                self._persist_window(content_type, state)
                return out

            items = resp.json()
            if not isinstance(items, list):
                items = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                out += await self._read_blob(client, token, content_type,
                                             item, state,
                                             window_end=window_end_iso)
            url = resp.headers.get("NextPageUri")
            state["next_page_uri"] = url or None

        if not state.get("next_page_uri"):
            # The window is fully READ. In durable mode it is only PENDING:
            # it advances when the records are accepted, not now.
            state["window_start"] = window_end_iso
            self.checkpoint.last_timestamp = window_end_iso
            self._persist_window(content_type, state,
                                 pending_until=window_end_iso)
        else:
            self._persist_window(content_type, state)
        return out

    def _persist_window(self, content_type: str, state: Dict[str, Any],
                        pending_until: Optional[str] = None) -> None:
        if self.state is None:
            return
        self.state.set_pending_window(
            self.tenant_id, self.identity, content_type,
            pending_until=pending_until or self.state.window(
                self.tenant_id, self.identity, content_type)["pending_until"],
            next_page_ref=state.get("next_page_uri"),
            declared_source=self.DECLARED_SOURCE)

    async def _read_blob(self, client: httpx.AsyncClient, token: str,
                         content_type: str, item: Dict[str, Any],
                         state: Dict[str, Any],
                         window_end: Optional[str] = None) -> List[Envelope]:
        content_id = str(item.get("contentId") or "")
        content_uri = item.get("contentUri")
        if not content_uri:
            return []
        if self.state is not None and content_id:
            # Durable claim: decides duplication and concurrency, not memory.
            outcome = self.state.claim_batch(
                self.tenant_id, self.identity, content_type, content_id,
                reference=str(content_uri),
                batch_created=item.get("contentCreated"),
                batch_expires=item.get("contentExpiration"),
                declared_source=self.DECLARED_SOURCE,
                window_end=window_end)
            if outcome == "ALREADY_COMMITTED":
                self.blobs_duplicate += 1
                self.metrics.events_duplicated += 1
                return []
            if outcome == "CLAIMED_ELSEWHERE":
                # Another collector process holds a live lease on it.
                self.blobs_in_flight_elsewhere += 1
                return []
        elif content_id and self._seen(state, content_id):
            self.blobs_duplicate += 1
            self.metrics.events_duplicated += 1
            return []
        try:
            resp = await self._get(client, str(content_uri), token)
        except Exception as e:                                # noqa: BLE001
            self.metrics.last_error = (f"content blob {content_id}: "
                                       f"{type(e).__name__}: {e}")
            self.metrics.events_failed += 1
            self._release(content_type, content_id,
                          f"BLOB_FETCH_FAILED:{type(e).__name__}")
            return []
        if resp.status_code in (404, 410):
            # Microsoft expires content after its retention window. Recorded
            # as lost with a reason — never silently skipped.
            self.blobs_expired += 1
            self.metrics.events_failed += 1
            self.metrics.last_error = (
                f"content blob {content_id} for {content_type} is no longer "
                f"available (HTTP {resp.status_code}); contentExpiration="
                f"{item.get('contentExpiration')}")
            # The vendor can never serve it again, so it must not hold the
            # window open — but the loss is reported, not hidden.
            if self.state is not None and content_id:
                self.state.release_batch(
                    self.tenant_id, self.identity, content_type, content_id,
                    reason=f"VENDOR_CONTENT_EXPIRED_HTTP_{resp.status_code}")
                self.state.forget_batch(self.tenant_id, self.identity,
                                        content_type, content_id)
            return []
        if resp.status_code >= 400:
            self.metrics.events_failed += 1
            self.metrics.last_error = (f"content blob {content_id}: HTTP "
                                       f"{resp.status_code}")
            self._release(content_type, content_id,
                          f"BLOB_HTTP_{resp.status_code}")
            return []
        records = resp.json()
        if not isinstance(records, list):
            records = [records]
        self.blobs_read += 1

        acquisition = {
            "contentId": content_id,
            "contentType": item.get("contentType") or content_type,
            "contentUri": str(content_uri),
            "contentCreated": item.get("contentCreated"),
            "contentExpiration": item.get("contentExpiration"),
            "acquiredAt": utcnow_iso(),
            "publisherIdentifier": self.publisher,
            "microsoftTenantId": self.ms_tenant,
        }
        out: List[Envelope] = []
        record_keys: List[str] = []
        for ordinal, rec in enumerate(records):
            if not isinstance(rec, dict):
                continue
            raw = dict(rec)
            microsoft_id = str(rec.get("Id")) if rec.get("Id") else ""
            if microsoft_id:
                key = microsoft_id
                reference_basis = "MICROSOFT_EVENT_ID"
            else:
                # A NivX-owned transport identity, deterministic so a
                # re-acquisition of the same blob produces the same key.
                # It is NOT presented as a Microsoft event id, and the
                # absence of one is preserved as a source fact.
                key = f"m365:{content_id}:{ordinal}"
                reference_basis = ("NIVX_ACQUISITION_REFERENCE — the record "
                                   "carried no Microsoft Id; "
                                   "microsoft_event_id is NOT_OBSERVED")
            record_keys.append(key)
            # NivX acquisition metadata, namespaced so it can never be
            # mistaken for a Microsoft field. The DSM reads it as
            # acquisition provenance only.
            raw["_m365_acquisition"] = {
                **acquisition,
                "recordReference": key,
                "recordReferenceBasis": reference_basis,
                "microsoftEventId": microsoft_id or "NOT_OBSERVED",
            }
            out.append(Envelope(
                tenant_id=self.tenant_id,
                source=self.label,
                source_event_id=key,
                connector_id=self.identity,
                collector_id=collector_id(),
                collection_method="rest-poll",
                parser_version="phase1b.m365-management-activity.1",
                # The activity instant as Microsoft recorded it. The core
                # re-derives the authoritative basis from the record itself.
                source_timestamp=(str(rec.get("CreationTime"))
                                  if rec.get("CreationTime") else None),
                collection_timestamp=utcnow_iso(),
                event_type="cloud_audit",
                raw=raw,
                canonical={},
                declared_source=self.DECLARED_SOURCE,
            ))
        self.checkpoint.last_event_id = (out[-1].source_event_id if out
                                         else self.checkpoint.last_event_id)
        if self.state is not None and content_id:
            # The batch now waits on the ACCEPTANCE of exactly these keys.
            self.state.record_batch_keys(self.tenant_id, self.identity,
                                         content_type, content_id,
                                         record_keys)
        return out

    def _release(self, content_type: str, content_id: str,
                 reason: str) -> None:
        if self.state is not None and content_id:
            self.state.release_batch(self.tenant_id, self.identity,
                                     content_type, content_id, reason=reason)

    # ── introspection ────────────────────────────────────────────
    def describe(self) -> Dict[str, Any]:
        d = super().describe()
        d["declared_source"] = self.DECLARED_SOURCE
        d["microsoft"] = {
            "tenant_id": self.ms_tenant,
            "content_types": self.content_types,
            "publisher_identifier": self.publisher,
            "subscriptions_started": self.subscriptions_started,
            "blobs_read": self.blobs_read,
            "blobs_duplicate_skipped": self.blobs_duplicate,
            "blobs_in_flight_elsewhere": self.blobs_in_flight_elsewhere,
            "blobs_expired": self.blobs_expired,
            "credential": self.tokens.describe(),
            "durable_acquisition_state": self.durable,
        }
        if self.state is not None:
            d["acquisition_state"] = self.state.status(self.tenant_id,
                                                       self.identity)
        d["checkpoint"]["vendor_state"] = {
            ct: {"window_start": s.get("window_start"),
                 "next_page_uri": s.get("next_page_uri"),
                 "content_ids_remembered": len(s.get("seen_content_ids")
                                               or [])}
            for ct, s in (self.checkpoint.vendor_state or {}).items()}
        return d
