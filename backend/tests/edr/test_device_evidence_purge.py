"""Contract for the device-scoped evidence purge.

The dangerous half of a purge route is everything it must REFUSE, so that is
what is pinned here: no token means the route does not exist, a dry run writes
nothing, an ambiguous hostname is never guessed, and the endpoint record
survives a purge of its evidence.
"""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from server import app

TOKEN = "test-maintenance-token"
URL = "/api/edr/maintenance/purge-device-evidence"
HOST = "PURGE-FIXTURE-01"
EP = "ep_purge_fixture_01"


@pytest.fixture(scope="module")
def client():
    # One application startup for the whole module: each TestClient entry
    # rebuilds every router and scheduler, which dominates the runtime.
    prior_enabled = os.environ.get("EDR_PURGE_ENABLED")
    prior = os.environ.get("EDR_MAINTENANCE_TOKEN")
    os.environ["EDR_PURGE_ENABLED"] = "1"
    os.environ["EDR_MAINTENANCE_TOKEN"] = TOKEN
    try:
        ctx = TestClient(app)
        c = ctx.__enter__()
        try:
            yield c
        finally:
            # Deliberately no application shutdown: it blocks on the scheduler
            # and LLM client teardown for longer than the suite timeout, and
            # closes the shared Mongo client other modules may still hold.
            pass
    finally:
        if prior_enabled is None:
            os.environ.pop("EDR_PURGE_ENABLED", None)
        else:
            os.environ["EDR_PURGE_ENABLED"] = prior_enabled
        if prior is None:
            os.environ.pop("EDR_MAINTENANCE_TOKEN", None)
        else:
            os.environ["EDR_MAINTENANCE_TOKEN"] = prior


@pytest.fixture()
def seeded(client):
    # Own the writer, like the other EDR suites: a sync handle borrowed from
    # the app can be closed by another module's teardown mid-session.
    from pymongo import MongoClient
    owned = MongoClient(os.environ["MONGO_URL"])
    sync = owned[os.environ["DB_NAME"]]
    sync["edr_endpoints"].delete_many({"endpoint_id": EP})
    sync["v2_shadow_observations"].delete_many({"event.raw.computer": HOST})
    sync["edr_endpoints"].insert_one({
        "endpoint_id": EP, "hostname": HOST, "tenant_id": "default",
        "enrollment_state": "REVOKED", "platform": "WINDOWS"})
    sync["v2_shadow_observations"].insert_many([
        {"event": {"raw": {"computer": HOST}}, "captured_at": "2026-09-10T00:00:00Z",
         "tenant_id": "default"},
        {"event": {"raw": {"computer": HOST}}, "captured_at": "2026-09-20T00:00:00Z",
         "tenant_id": "default"},
        {"event": {"raw": {"computer": HOST}}, "captured_at": "2026-10-05T00:00:00Z",
         "tenant_id": "default"},
    ])
    yield sync
    sync["edr_endpoints"].delete_many({"endpoint_id": EP})
    sync["v2_shadow_observations"].delete_many({"event.raw.computer": HOST})
    owned.close()



@pytest.mark.parametrize("enabled", [None, "", "0", "false", "true", "2", " 1", "1 "])
@pytest.mark.parametrize("mode", ["dry", "execute"])
def test_purge_requires_explicit_enablement(client, monkeypatch, enabled, mode):
    # A valid token and execute confirmation must not bypass the release switch.
    # Refuse before even looking up the endpoint, so disabled requests cannot
    # read or delete evidence.
    from routers import edr_device_purge

    class NoDatabaseAccess:
        def __getitem__(self, name):
            raise AssertionError("disabled purge accessed the database")

    monkeypatch.setattr(edr_device_purge, "_db", NoDatabaseAccess())
    monkeypatch.setenv("EDR_MAINTENANCE_TOKEN", TOKEN)
    if enabled is None:
        monkeypatch.delenv("EDR_PURGE_ENABLED", raising=False)
    else:
        monkeypatch.setenv("EDR_PURGE_ENABLED", enabled)
    r = client.post(URL, json={
        "endpoint_id": EP, "mode": mode,
        "confirm": "DELETE-DEVICE-EVIDENCE", "backup": "test-only-reference",
    }, headers={"X-Maintenance-Token": TOKEN})
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found"}


def test_without_a_token_the_route_does_not_exist(client, seeded):
    prior = os.environ.pop("EDR_MAINTENANCE_TOKEN", None)
    try:
        r = client.post(URL, json={"endpoint_id": EP},
                        headers={"X-Maintenance-Token": TOKEN})
        assert r.status_code == 404
    finally:
        if prior is not None:
            os.environ["EDR_MAINTENANCE_TOKEN"] = prior


def test_a_wrong_token_is_refused(client, seeded):
    r = client.post(URL, json={"endpoint_id": EP},
                    headers={"X-Maintenance-Token": "not-the-token"})
    assert r.status_code == 403


def test_a_dry_run_counts_and_deletes_nothing(client, seeded):
    r = client.post(URL, json={"endpoint_id": EP},
                    headers={"X-Maintenance-Token": TOKEN})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["executed"] is False
    entry = body["collections"]["v2_shadow_observations"]
    assert entry["matched"] == 3
    assert "deleted" not in entry
    assert seeded["v2_shadow_observations"].count_documents(
        {"event.raw.computer": HOST}) == 3


def test_execute_requires_the_confirmation_and_a_backup(client, seeded):
    r = client.post(URL, json={"endpoint_id": EP, "mode": "execute"},
                    headers={"X-Maintenance-Token": TOKEN})
    assert r.status_code == 400
    r = client.post(URL, json={"endpoint_id": EP, "mode": "execute",
                               "confirm": "DELETE-DEVICE-EVIDENCE"},
                    headers={"X-Maintenance-Token": TOKEN})
    assert r.status_code == 400
    assert seeded["v2_shadow_observations"].count_documents(
        {"event.raw.computer": HOST}) == 3


def test_a_window_purges_only_that_window_and_keeps_the_endpoint(client, seeded):
    r = client.post(URL, json={"endpoint_id": EP, "mode": "execute",
                               "confirm": "DELETE-DEVICE-EVIDENCE",
                               "backup": "owner waiver 2026-10-31",
                               "time_start": "2026-09-01", "time_end": "2026-10-01"},
                    headers={"X-Maintenance-Token": TOKEN})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["collections"]["v2_shadow_observations"]["deleted"] == 2
    left = list(seeded["v2_shadow_observations"].find({"event.raw.computer": HOST}))
    assert [d["captured_at"] for d in left] == ["2026-10-05T00:00:00Z"]
    assert seeded["edr_endpoints"].count_documents({"endpoint_id": EP}) == 1


def test_an_ambiguous_hostname_is_refused_rather_than_guessed(client, seeded):
    seeded["edr_endpoints"].insert_one({
        "endpoint_id": EP + "_twin", "hostname": HOST, "tenant_id": "other"})
    try:
        r = client.post(URL, json={"hostname": HOST},
                        headers={"X-Maintenance-Token": TOKEN})
        assert r.status_code == 409
        assert r.json()["detail"]["code"] == "ENDPOINT_AMBIGUOUS"
    finally:
        seeded["edr_endpoints"].delete_many({"endpoint_id": EP + "_twin"})


def test_an_unknown_endpoint_is_not_found(client, seeded):
    r = client.post(URL, json={"endpoint_id": "ep_does_not_exist"},
                    headers={"X-Maintenance-Token": TOKEN})
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "ENDPOINT_NOT_FOUND"
