"""End-to-end route + runtime smoke test using FastAPI ASGI transport."""
import pytest
import httpx
from contextlib import asynccontextmanager

from main import app


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t")


@asynccontextmanager
async def _lifespan_client():
    async with app.router.lifespan_context(app):
        async with _client() as c:
            yield c


@pytest.mark.asyncio
async def test_health_endpoint():
    async with _lifespan_client() as c:
        r = await c.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert j["phase"] == "B"
    assert "connectors" in j


@pytest.mark.asyncio
async def test_source_types_catalogue_lists_all_three_transports():
    async with _lifespan_client() as c:
        r = await c.get("/api/xdr/source-types")
    assert r.status_code == 200
    st = {s["source_type"] for s in r.json()["source_types"]}
    assert st == {"rest", "webhook", "syslog"}


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
        rows = r.json()["rows"]
        wh_rows = [x for x in rows if x["source_type"] == "webhook"]
        assert any(x.get("identity") == cid for x in wh_rows)

        # 5) data-sources projection shows accepted events
        r = await c.get("/api/xdr/data-sources")
        row = next(x for x in r.json()["data_sources"] if x["connector_id"] == cid)
        assert row["events_collected"] >= 2

        # 6) delete
        r = await c.delete(f"/api/xdr/connectors/{cid}")
        assert r.status_code == 200
        r = await c.get(f"/api/xdr/connectors/{cid}")
        assert r.status_code == 404
