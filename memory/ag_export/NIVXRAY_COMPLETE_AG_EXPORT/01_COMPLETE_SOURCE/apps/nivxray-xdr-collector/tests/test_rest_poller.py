"""Test the REST poller against a stub upstream API via FastAPI TestClient
piped through httpx.MockTransport."""
import httpx
import pytest

from framework.rest_poller import RestPollerConnector


def _make(config: dict) -> RestPollerConnector:
    return RestPollerConnector(tenant_id="acme", config=config,
                                    identity="rest-test")


@pytest.mark.asyncio
async def test_rest_poller_collects_and_advances_cursor(monkeypatch):
    payloads = [
        {"results": [{"id": "e1", "ts": "2024-01-01T00:00:00Z"},
                        {"id": "e2", "ts": "2024-01-01T00:00:01Z"}],
          "meta":    {"next": "cursor-2"}},
        {"results": [{"id": "e3", "ts": "2024-01-01T00:00:02Z"}],
          "meta":    {"next": None}},
    ]
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.query.decode())
        return httpx.Response(200, json=payloads[len(calls) - 1])

    transport = httpx.MockTransport(handler)

    orig_client = httpx.AsyncClient
    def _client(*a, **kw):
        kw["transport"] = transport
        return orig_client(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)

    conn = _make({
        "url":            "https://example.com/events",
        "records_path":   "results",
        "cursor_path":    "meta.next",
        "cursor_param":   "after",
        "event_id_path":  "id",
        "timestamp_path": "ts",
    })

    envs1 = await conn.collect()
    assert len(envs1) == 2
    assert envs1[0].source_event_id == "e1"
    assert conn.checkpoint.cursor == "cursor-2"
    assert conn.metrics.events_collected == 2

    envs2 = await conn.collect()
    assert len(envs2) == 1
    assert envs2[0].source_event_id == "e3"
    # second call should have sent `after=cursor-2`
    assert "after=cursor-2" in calls[1]


@pytest.mark.asyncio
async def test_rest_poller_handles_429(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)
    transport = httpx.MockTransport(handler)
    orig_client = httpx.AsyncClient
    def _client(*a, **kw):
        kw["transport"] = transport
        return orig_client(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)

    conn = _make({"url": "https://example.com/events",
                     "records_path": "results", "event_id_path": "id"})
    envs = await conn.collect()
    assert envs == []
    assert conn.health.value == "rate_limited"
    assert "429" in (conn.metrics.last_error or "")


@pytest.mark.asyncio
async def test_rest_poller_auth_bearer_header(monkeypatch):
    seen_headers = {}
    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(dict(request.headers))
        return httpx.Response(200, json={"results": []})
    transport = httpx.MockTransport(handler)
    orig_client = httpx.AsyncClient
    def _client(*a, **kw):
        kw["transport"] = transport
        return orig_client(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)

    conn = _make({
        "url": "https://example.com/x",
        "records_path": "results",
        "auth":        {"type": "bearer"},
        "credentials": {"token": "T0P-SECRET"},
    })
    await conn.collect()
    assert seen_headers.get("authorization") == "Bearer T0P-SECRET"


@pytest.mark.asyncio
async def test_rest_poller_test_connection_reports_status(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "bad token"})
    transport = httpx.MockTransport(handler)
    orig_client = httpx.AsyncClient
    def _client(*a, **kw):
        kw["transport"] = transport
        return orig_client(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)

    conn = _make({"url": "https://example.com/x"})
    out = await conn.test_connection()
    assert out["ok"] is False
    assert out["status_code"] == 401
    assert conn.health.value == "authentication_failed"
