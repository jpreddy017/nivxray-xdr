"""End-to-end route + runtime smoke test using FastAPI ASGI transport.

Collector Auth P0 · the collector control plane FAILS CLOSED when this app is
run standalone, because standalone has no authentication authority, RBAC store
or tenant registry to consult (`framework.authz`). These runtime/transport
tests therefore override the guard explicitly — the contract itself is
asserted, unweakened, by `test_standalone_control_plane_fails_closed` below and
by `/app/backend/tests/test_collector_plane_auth.py` against the real
authenticated mount.
"""
import pytest
import httpx
from contextlib import asynccontextmanager

from framework.authz import collector_guard
from main import app


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t")


@asynccontextmanager
async def _lifespan_client():
    """Runtime/transport client · guard overridden deliberately and
    restored afterwards, so no other test inherits the override."""
    app.dependency_overrides[collector_guard] = lambda: "TEST_PLANE"
    try:
        async with app.router.lifespan_context(app):
            async with _client() as c:
                yield c
    finally:
        app.dependency_overrides.pop(collector_guard, None)


@pytest.mark.asyncio
async def test_standalone_control_plane_fails_closed():
    """No override: every control-plane operation is refused, and the
    refusal is an AUTHENTICATION refusal — not a tenant one."""
    async with app.router.lifespan_context(app):
        async with _client() as c:
            for method, url in (("get", "/api/xdr/connectors"),
                                ("get", "/api/xdr/collectors"),
                                ("get", "/api/xdr/data-sources"),
                                ("get", "/api/xdr/telemetry-health"),
                                ("get", "/api/xdr/outbox"),
                                ("get", "/api/xdr/outbox/health"),
                                ("get", "/api/xdr/source-types")):
                r = await getattr(c, method)(url,
                                             headers={"X-Tenant-Id": "acme"})
                assert r.status_code == 403, f"{url} -> {r.status_code} {r.text}"
                assert r.json()["detail"]["code"] == "COLLECTOR_AUTH_UNAVAILABLE"
            r = await c.post("/api/xdr/connectors",
                             json={"source_type": "webhook", "label": "x",
                                   "config": {}},
                             headers={"X-Tenant-Id": "acme"})
            assert r.status_code == 403, r.text
            # MACHINE passthrough: the HMAC webhook is still reachable, and
            # refuses by its own contract rather than by RBAC.
            r = await c.post("/api/xdr/webhooks/no-such-secret-id", json={})
            assert r.status_code == 404, r.text
            assert "webhook_not_configured" in r.text


@pytest.mark.asyncio
async def test_health_endpoint():
    async with _lifespan_client() as c:
        r = await c.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert j["phase"] == "B.5"
    assert "connectors" in j


@pytest.mark.asyncio
async def test_source_types_catalogue_lists_all_three_transports():
    async with _lifespan_client() as c:
        r = await c.get("/api/xdr/source-types")
    assert r.status_code == 200
    st = {s["source_type"] for s in r.json()["source_types"]}
    # Phase 1b added the Microsoft 365 Management Activity source alongside
    # the three generic transports.
    assert st == {"rest", "webhook", "syslog", "m365-management-activity"}


@pytest.mark.asyncio
async def test_connector_crud_and_webhook_delivery():
    async with _lifespan_client() as c:
        # 1) create webhook connector
        body = {"source_type": "webhook", "label": "Test Webhook",
                  "config":  {"secret_id": "wh-t1",
                              "event_id_path": "id",
                              "records_path":  "events"}}
        r = await c.post("/api/xdr/connectors", json=body,
                              headers={"X-Tenant-Id": "acme"})
        assert r.status_code == 201, r.text
        cid = r.json()["id"]

        # 2) list
        r = await c.get("/api/xdr/connectors", headers={"X-Tenant-Id": "acme"})
        assert any(x["id"] == cid for x in r.json()["connectors"])

        # 3) deliver webhook (no HMAC configured → accepted unauthenticated)
        r = await c.post("/api/xdr/webhooks/wh-t1",
                              json={"events": [{"id": "abc"}, {"id": "def"}]})
        assert r.status_code == 200, r.text
        j = r.json()
        assert j["accepted"] == 2
        assert j["authenticated"] is False

        # 4) telemetry-health reflects the instance
        r = await c.get("/api/xdr/telemetry-health")
        j = r.json()
        wh_rows = [x for x in j["transports"] if x["source_type"] == "webhook"]
        assert any(x.get("identity") == cid for x in wh_rows)
        # ingest is not configured in the test env → must say so honestly
        assert j["ingest"]["state"] == "not_configured"

        # 5) data-sources projection shows accepted events
        r = await c.get("/api/xdr/data-sources")
        row = next(x for x in r.json()["data_sources"] if x["connector_id"] == cid)
        assert row["events_collected"] >= 2

        # 6) delete
        r = await c.delete(f"/api/xdr/connectors/{cid}")
        assert r.status_code == 200
        r = await c.get(f"/api/xdr/connectors/{cid}")
        assert r.status_code == 404
