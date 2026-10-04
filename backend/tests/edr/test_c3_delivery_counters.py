"""DELIVERY FIDELITY · every received event reaches a counted outcome.

A parser failure used to disappear into an uncounted gap: the bytes were
retained, but nothing said "this event was received and NOT accounted
for". These counters close that, and they refuse to become anything more
than counters — no payload, no path, no identity, no evidence authority.
"""
from __future__ import annotations

import asyncio
import os
import sys
import uuid

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

sys.path.insert(0, "/app/backend")

from edr_plane import delivery_counters as dc                   # noqa: E402

TENANT = "ten_c3_counters"
ENDPOINT = "ep_c3"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"


def with_db(fn):
    """One disposable database per test."""
    def wrapper():
        asyncio.run(_scoped(fn))
    wrapper.__name__ = fn.__name__
    wrapper.__doc__ = fn.__doc__
    return wrapper


async def _scoped(fn):
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    name = f"c3_counters_{uuid.uuid4().hex[:10]}"
    handle = client[name]
    await dc.ensure_indexes(handle)
    try:
        await fn(handle)
    finally:
        await client.drop_database(name)
        client.close()


# ── A · the declared boundaries ────────────────────────────────────

def test_the_delivery_boundaries_are_all_distinct():
    for name in ("received", "parsed", "parse_failed", "refused", "accepted",
                 "deduplicated", "canonicalized"):
        assert name in dc.SERVER_BOUNDARIES
    assert len(set(dc.SERVER_BOUNDARIES)) == len(dc.SERVER_BOUNDARIES)


def test_endpoint_side_boundaries_are_separate_from_server_measurements():
    assert not set(dc.SENSOR_BOUNDARIES) & set(dc.SERVER_BOUNDARIES)


def test_a_boundary_that_was_not_declared_is_refused():
    with pytest.raises(ValueError):
        dc.validate_sensor_counters({"totally_made_up": 1})


# ── B · monotonic, and never reset ─────────────────────────────────

@with_db
async def test_counters_only_ever_increase(db):
    for _ in range(3):
        await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                        channel=CHANNEL, outcomes=[dc.RECEIVED, dc.ACCEPTED])
    out = await dc.read(db, tenant_id=TENANT)
    assert out["server_observed"][dc.RECEIVED] == 3
    assert out["server_observed"][dc.ACCEPTED] == 3
    assert out["monotonic"] is True


def test_the_module_only_increments():
    from pathlib import Path
    source = Path("/app/backend/edr_plane/delivery_counters.py").read_text()
    # No reset, no $set of a counter value, no deletion.
    assert '"$set": {"counters' not in source
    assert "delete_many" not in source
    assert "$unset" not in source


# ── C · a parse failure is an accounted OUTCOME ────────────────────

@with_db
async def test_received_is_always_fully_accounted(db):
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL,
                    outcomes=[dc.RECEIVED, dc.ACCEPTED, dc.CANONICALIZED,
                              dc.PARSED])
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL,
                    outcomes=[dc.RECEIVED, dc.ACCEPTED, dc.PARSE_FAILED],
                    reason_code="PARSER_FAILED")
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL,
                    outcomes=[dc.RECEIVED, dc.DEDUPLICATED,
                              "deduplicated_payload"])
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL,
                    outcomes=[dc.RECEIVED, dc.ACCEPTED, dc.REFUSED],
                    reason_code="ROUTING_REFUSED")
    out = await dc.read(db, tenant_id=TENANT)
    assert out["server_observed"][dc.RECEIVED] == 4
    # Storage layer: accepted + byte-identical re-delivery == received.
    assert out["unaccounted_received"] == 0
    assert out["parse_failure_reasons"] == {"PARSER_FAILED": 1}
    assert out["refusal_reasons"] == {"ROUTING_REFUSED": 1}


@with_db
async def test_deduplication_is_not_loss_and_is_classified(db):
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL,
                    outcomes=[dc.RECEIVED, dc.DEDUPLICATED,
                              "deduplicated_payload"])
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL,
                    outcomes=[dc.RECEIVED, dc.ACCEPTED, dc.PARSED,
                              dc.DEDUPLICATED, "deduplicated_activity"])
    out = await dc.read(db, tenant_id=TENANT)
    assert out["server_observed"]["deduplicated_payload"] == 1
    assert out["server_observed"]["deduplicated_activity"] == 1
    assert out["unaccounted_received"] == 0
    assert out["unaccounted_accepted"] == 0
    assert "NOT loss" in out["note"]


# ── D · sensor-claimed boundaries stay claims ──────────────────────

@with_db
async def test_sensor_counters_are_stored_as_a_claim_not_a_measurement(db):
    await dc.record_sensor_reported(
        db, tenant_id=TENANT, endpoint_id=ENDPOINT, counter_epoch="epoch-1",
        counters={"endpoint_observed": 40, "sensor_sent": 39,
                  "sensor_failed": 1}, sensor_version="0.2.0")
    out = await dc.read(db, tenant_id=TENANT)
    claim = out["sensor_claimed"][0]
    assert claim["counters"]["endpoint_observed"] == 40
    assert out["boundary_measurability"]["endpoint_observed"] == \
        "SENSOR_CLAIMED"
    assert out["boundary_measurability"]["received"] == "SERVER_MEASURED"
    # A sensor claim never contributes to a server measurement.
    assert out["server_observed"][dc.RECEIVED] == 0


@with_db
async def test_a_sensor_restart_is_an_epoch_change_not_a_decrease(db):
    await dc.record_sensor_reported(
        db, tenant_id=TENANT, endpoint_id=ENDPOINT, counter_epoch="epoch-1",
        counters={"sensor_sent": 900})
    result = await dc.record_sensor_reported(
        db, tenant_id=TENANT, endpoint_id=ENDPOINT, counter_epoch="epoch-2",
        counters={"sensor_sent": 3})
    assert result["epoch_changed"] is True
    doc = await db[dc.COLLECTION].find_one(
        {"tenant_id": TENANT, "channel": "__sensor__"})
    history = doc["sensor_epoch_history"]
    assert history[0]["counter_epoch"] == "epoch-1"
    assert history[0]["final_snapshot"]["sensor_sent"] == 900
    assert doc["sensor_counters"]["sensor_sent"] == 3
    assert "instead of being added to or subtracted" in \
        doc["restart_semantics"]


def test_sensor_counters_are_validated_and_bounded():
    for bad in ({"sensor_sent": -1}, {"sensor_sent": "3"},
                {"sensor_sent": True}, {"payload": "secret"},
                {"sensor_sent": 2 ** 60}):
        with pytest.raises(ValueError):
            dc.validate_sensor_counters(bad)


# ── E · counters never carry content ───────────────────────────────

@with_db
async def test_a_counter_document_holds_no_event_content(db):
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=dc.channel_of(
                        '{"activity":"PROCESS","command_line":"curl evil"}'),
                    outcomes=[dc.RECEIVED, dc.ACCEPTED])
    doc = await db[dc.COLLECTION].find_one({"tenant_id": TENANT})
    body = str(doc)
    assert "curl" not in body
    assert "evil" not in body
    assert doc["evidence_authority"] is False
    assert doc["channel"] == "SENSOR_PROCESS"


def test_the_channel_is_coarse_metadata_only():
    assert dc.channel_of(
        '{"kind":"WINDOWS_EVENT_LOG","winlog":{"channel":"Security",'
        '"xml":"<Event>secret</Event>"}}') == "Security"
    assert dc.channel_of("not json") == "UNPARSEABLE_ENVELOPE"
    assert dc.channel_of({}) == "UNKNOWN"


# ── F · tenancy ────────────────────────────────────────────────────

@with_db
async def test_counters_are_tenant_scoped(db):
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL, outcomes=[dc.RECEIVED])
    other = await dc.read(db, tenant_id="ten_c3_other")
    assert other["server_observed"][dc.RECEIVED] == 0
    assert other["channels"] == []


@with_db
async def test_counters_can_be_read_per_endpoint(db):
    await dc.record(db, tenant_id=TENANT, endpoint_id=ENDPOINT,
                    channel=CHANNEL, outcomes=[dc.RECEIVED])
    await dc.record(db, tenant_id=TENANT, endpoint_id="ep_other",
                    channel=CHANNEL, outcomes={dc.RECEIVED: 2})
    one = await dc.read(db, tenant_id=TENANT, endpoint_id=ENDPOINT)
    assert one["server_observed"][dc.RECEIVED] == 1
    both = await dc.read(db, tenant_id=TENANT)
    assert both["server_observed"][dc.RECEIVED] == 3
