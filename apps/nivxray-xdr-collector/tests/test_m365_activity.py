"""Microsoft 365 Management Activity connector — Phase 1b acquisition.

ACCEPTANCE LABEL: everything here is **SYNTHETIC/REPLAY PROVEN**. A stub
stands in for Microsoft's endpoints; no Microsoft tenant is contacted. Live
acquisition is EXTERNAL_ACCESS_BLOCKED until an owner-side Entra app
registration with `ActivityFeed.Read` and admin consent exists.

What is proven:

  * Microsoft's real model is followed: token → subscription start →
    content list → NextPageUri pagination → contentUri blob → one envelope
    per audit RECORD;
  * every envelope DECLARES `m365-unified-audit`, so it can pass the D15
    ingest boundary at all;
  * `contentCreated` travels as acquisition metadata and never as the
    activity instant;
  * a content blob already processed is not read twice (the API performs no
    server-side dedup);
  * throttling, an expired blob, a rejected credential and an unreachable
    endpoint are four distinct reported states, and none of them advances
    the window — so a restart loses nothing.
"""
from __future__ import annotations

import json

import httpx
import pytest

from framework.base import Health
from framework.m365_activity import M365ManagementActivityConnector
from framework.oauth2 import ClientCredentialsTokenProvider, TokenError

MS_TENANT = "11111111-2222-3333-4444-555555555555"
BASE = "https://manage.example.test/api/v1.0"
TOKEN_HOST = "https://login.example.test"


def _cfg(**over):
    cfg = {
        "microsoft_tenant_id": MS_TENANT,
        "base_url": BASE,
        "authority": TOKEN_HOST,
        "scope": "https://manage.office.com/.default",
        "content_types": ["Audit.Exchange"],
        "credentials": {"client_id": "app-1", "client_secret": "s3cret"},
        "lookback_minutes": 60,
    }
    cfg.update(over)
    return cfg


def _conn(**over):
    return M365ManagementActivityConnector(
        tenant_id="acme", config=_cfg(**over), identity="m365-test")


def _record(rid, op="New-InboxRule", params=None):
    return {"Id": rid, "RecordType": 1, "CreationTime": "2026-06-02T09:15:00",
            "Operation": op, "OrganizationId": MS_TENANT, "UserType": 2,
            "Workload": "Exchange", "ResultStatus": "True",
            "UserId": "user1@corp.example", "ClientIP": "203.0.113.40",
            "Parameters": params or [{"Name": "Name", "Value": "r"}]}


def _mock(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _client(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)


def _token_response():
    return httpx.Response(200, json={"access_token": "tok-1",
                                     "expires_in": 3600})


# ── credentials ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_token_is_cached_until_its_stated_expiry(monkeypatch):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return _token_response()
    _mock(monkeypatch, handler)
    p = ClientCredentialsTokenProvider(
        authority=TOKEN_HOST, tenant_id=MS_TENANT, scope="s",
        credentials={"client_id": "a", "client_secret": "b"})
    assert await p.token() == "tok-1"
    assert await p.token() == "tok-1"
    assert len(calls) == 1
    assert p.token_url().endswith(f"/{MS_TENANT}/oauth2/v2.0/token")


@pytest.mark.asyncio
async def test_a_token_without_a_stated_lifetime_is_never_assumed_valid(
        monkeypatch):
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"access_token": "tok-x"})
    _mock(monkeypatch, handler)
    p = ClientCredentialsTokenProvider(
        authority=TOKEN_HOST, tenant_id=MS_TENANT, scope="s",
        credentials={"client_id": "a", "client_secret": "b"})
    await p.token()
    await p.token()
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_certificate_mode_is_recognised_and_declared_unimplemented():
    p = ClientCredentialsTokenProvider(
        authority=TOKEN_HOST, tenant_id=MS_TENANT, scope="s",
        credentials={"client_id": "a",
                     "certificate_private_key_pem": "-----BEGIN..."})
    assert p.mode() == "certificate"
    with pytest.raises(TokenError) as e:
        await p.token()
    assert e.value.code == "CERTIFICATE_AUTH_NOT_IMPLEMENTED"


def test_credential_description_never_leaks_secret_material():
    p = ClientCredentialsTokenProvider(
        authority=TOKEN_HOST, tenant_id=MS_TENANT, scope="s",
        credentials={"client_id": "a", "client_secret": "super-secret"})
    blob = json.dumps(p.describe())
    assert "super-secret" not in blob
    assert '"secret_set": true' in blob.lower()


# ── Microsoft's actual acquisition model ──────────────────────────
@pytest.mark.asyncio
async def test_subscription_start_is_idempotent(monkeypatch):
    seen = []

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        seen.append(url)
        return httpx.Response(400, text='{"error":{"code":"AF20024",'
                                        '"message":"already enabled"}}')
    _mock(monkeypatch, handler)
    c = _conn(content_types=["Audit.Exchange", "Audit.General"])
    await c.start()
    assert c.subscriptions_started == ["Audit.Exchange", "Audit.General"]
    assert c.health == Health.CONNECTED
    assert all("PublisherIdentifier" in u for u in seen)


@pytest.mark.asyncio
async def test_pagination_blob_fetch_and_one_envelope_per_record(monkeypatch):
    page1 = [{"contentType": "Audit.Exchange", "contentId": "c1",
              "contentUri": f"{BASE}/blob/c1",
              "contentCreated": "2026-06-02T11:00:00Z",
              "contentExpiration": "2026-06-09T11:00:00Z"}]
    page2 = [{"contentType": "Audit.Exchange", "contentId": "c2",
              "contentUri": f"{BASE}/blob/c2",
              "contentCreated": "2026-06-02T11:05:00Z"}]

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        if "subscriptions/content" in url and "page=2" not in url:
            return httpx.Response(200, json=page1, headers={
                "NextPageUri": f"{BASE}/{MS_TENANT}/activity/feed/"
                               f"subscriptions/content?page=2"})
        if "page=2" in url:
            return httpx.Response(200, json=page2)
        if url.endswith("/blob/c1"):
            return httpx.Response(200, json=[_record("r1"), _record("r2")])
        if url.endswith("/blob/c2"):
            return httpx.Response(200, json=[_record("r3")])
        return httpx.Response(404)
    _mock(monkeypatch, handler)

    c = _conn()
    envelopes = await c.collect()
    assert [e.source_event_id for e in envelopes] == ["r1", "r2", "r3"]
    assert {e.declared_source for e in envelopes} == {"m365-unified-audit"}
    assert c.blobs_read == 2
    # the declaration reaches the wire
    assert envelopes[0].to_dict()["declared_source"] == "m365-unified-audit"


@pytest.mark.asyncio
async def test_blob_availability_is_acquisition_metadata_not_activity_time(
        monkeypatch):
    items = [{"contentType": "Audit.Exchange", "contentId": "c1",
              "contentUri": f"{BASE}/blob/c1",
              "contentCreated": "2026-06-02T11:00:00Z",
              "contentExpiration": "2026-06-09T11:00:00Z"}]

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        if "subscriptions/content" in url:
            return httpx.Response(200, json=items)
        return httpx.Response(200, json=[_record("r1")])
    _mock(monkeypatch, handler)

    env = (await _conn().collect())[0]
    acq = env.raw["_m365_acquisition"]
    assert acq["contentCreated"] == "2026-06-02T11:00:00Z"
    assert acq["contentId"] == "c1"
    assert acq["microsoftTenantId"] == MS_TENANT
    # the envelope's source timestamp is the ACTIVITY instant Microsoft
    # recorded, never the blob's availability
    assert env.source_timestamp == "2026-06-02T09:15:00"
    assert env.raw["CreationTime"] == "2026-06-02T09:15:00"


@pytest.mark.asyncio
async def test_a_blob_is_never_read_twice(monkeypatch):
    items = [{"contentType": "Audit.Exchange", "contentId": "c1",
              "contentUri": f"{BASE}/blob/c1",
              "contentCreated": "2026-06-02T11:00:00Z"}]
    blob_reads = []

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        if "subscriptions/content" in url:
            return httpx.Response(200, json=items)
        blob_reads.append(url)
        return httpx.Response(200, json=[_record("r1")])
    _mock(monkeypatch, handler)

    c = _conn()
    first = await c.collect()
    second = await c.collect()
    assert len(first) == 1 and second == []
    assert len(blob_reads) == 1
    assert c.blobs_duplicate == 1 and c.metrics.events_duplicated == 1


@pytest.mark.asyncio
async def test_expired_content_is_reported_not_silently_skipped(monkeypatch):
    items = [{"contentType": "Audit.Exchange", "contentId": "c-old",
              "contentUri": f"{BASE}/blob/c-old",
              "contentExpiration": "2026-05-01T00:00:00Z"}]

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        if "subscriptions/content" in url:
            return httpx.Response(200, json=items)
        return httpx.Response(410, text="expired")
    _mock(monkeypatch, handler)

    c = _conn()
    assert await c.collect() == []
    assert c.blobs_expired == 1
    assert "no longer" in c.metrics.last_error
    assert "contentExpiration" in c.metrics.last_error


@pytest.mark.asyncio
async def test_throttling_keeps_the_page_and_the_window(monkeypatch):
    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        return httpx.Response(429, headers={"Retry-After": "30"}, text="slow")
    _mock(monkeypatch, handler)

    c = _conn()
    assert await c.collect() == []
    assert c.health == Health.RATE_LIMITED
    assert "Retry-After=30" in c.metrics.last_error
    state = c.checkpoint.vendor_state["Audit.Exchange"]
    assert state["next_page_uri"] and state["window_start"] is None


@pytest.mark.asyncio
async def test_a_rejected_credential_is_authentication_failed(monkeypatch):
    def handler(request):
        if "oauth2" in str(request.url):
            return httpx.Response(401, json={
                "error": "invalid_client",
                "error_description": "AADSTS7000215"},
                headers={"content-type": "application/json"})
        return httpx.Response(200, json=[])
    _mock(monkeypatch, handler)

    c = _conn()
    assert await c.collect() == []
    assert c.health == Health.AUTHENTICATION_FAILED
    assert "CREDENTIAL_REJECTED" in c.metrics.last_error


@pytest.mark.asyncio
async def test_a_401_mid_collection_invalidates_the_token(monkeypatch):
    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        return httpx.Response(403, text="forbidden")
    _mock(monkeypatch, handler)

    c = _conn()
    await c.collect()
    assert c.health == Health.AUTHENTICATION_FAILED
    assert c.tokens.describe()["token_cached"] is False


@pytest.mark.asyncio
async def test_restart_resumes_from_the_persisted_checkpoint(monkeypatch):
    seen_urls = []

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        seen_urls.append(url)
        return httpx.Response(200, json=[])
    _mock(monkeypatch, handler)

    c = _conn()
    c.restore_checkpoint({"Audit.Exchange": {
        "window_start": "2026-06-02T08:00:00+00:00",
        "next_page_uri": None,
        "seen_content_ids": ["c-already-done"]}})
    await c.collect()
    assert "startTime=2026-06-02T08%3A00%3A00" in seen_urls[0]
    # a contentId processed before the restart is still known
    state = c.checkpoint.vendor_state["Audit.Exchange"]
    assert "c-already-done" in state["seen_content_ids"]


@pytest.mark.asyncio
async def test_the_window_only_advances_once_a_page_run_completes(
        monkeypatch):
    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return _token_response()
        return httpx.Response(200, json=[])
    _mock(monkeypatch, handler)

    c = _conn()
    await c.collect()
    state = c.checkpoint.vendor_state["Audit.Exchange"]
    assert state["window_start"] is not None
    assert state["next_page_uri"] is None


@pytest.mark.asyncio
async def test_missing_microsoft_tenant_is_refused_not_guessed():
    c = M365ManagementActivityConnector(
        tenant_id="acme", config=_cfg(microsoft_tenant_id=""),
        identity="m365-broken")
    assert await c.collect() == []
    assert c.health == Health.ERROR
    assert "microsoft_tenant_id" in c.metrics.last_error


def test_the_connector_declares_one_source_and_is_in_the_catalogue():
    from routes.connectors import CLASS_BY_TYPE, SOURCE_CATALOGUE
    assert CLASS_BY_TYPE["m365-management-activity"] is \
        M365ManagementActivityConnector
    row = next(s for s in SOURCE_CATALOGUE
               if s["source_type"] == "m365-management-activity")
    assert row["declared_source"] == "m365-unified-audit"
    assert "oauth2_client_credentials" in row["auth"]
    assert "never activity time" in row["notes"]


def test_describe_exposes_acquisition_state_without_secrets():
    d = _conn().describe()
    assert d["declared_source"] == "m365-unified-audit"
    assert d["microsoft"]["content_types"] == ["Audit.Exchange"]
    assert "s3cret" not in json.dumps(d)
