"""G-41 · the transitional legacy read must not lose unmigrated evidence.

Historical rows predate `observation_us`. If the comparable query were the only
read, every one of them would VANISH from Device Trajectory and from Behavior's
window the moment this change shipped — a far worse failure than the ordering
defect it fixes. These tests pin the transitional behaviour: unmigrated rows are
still returned, ordered correctly against migrated ones, and COUNTED so the
remaining exposure is visible rather than silent.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import temporal_authority as ta  # noqa: E402
from edr_trajectory import production_adapter as pa  # noqa: E402

TENANT = "ten_g41t"
EP = "ep_g41transition"
CANON = pa.STORE_CANONICAL


def base(event_time, eid):
    return {"tenant_id": TENANT, "event_time": event_time, "event_id": eid,
            "ingest_time": "2026-09-30T00:00:00+00:00",
            "additional_fields": {"endpoint_id": EP, "activity_type": "process",
                                  "activity_identity": eid},
            "host": {"hostname": "h1"},
            "provenance": {"collector_id": EP, "trace_id": "r-" + eid},
            "process": {"pid": 1, "executable_path": "/x"}}


def migrated(event_time, eid):
    return ta.stamp(base(event_time, eid))


def unmigrated(event_time, eid):
    """Exactly what production holds today: evidence with no comparable value."""
    return base(event_time, eid)


@pytest_asyncio.fixture
async def db():
    name = f"g41t_{uuid.uuid4().hex[:10]}"
    database = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    class Scoped:
        def __getitem__(self, key):
            return database[name] if key == CANON else database[key]

    yield Scoped(), database[name]
    await database[name].drop()


async def page(scoped, **kw):
    return await pa.page_device_evidence(scoped, tenant_id=TENANT, refs=[EP],
                                         stores=(CANON,), **kw)


async def drain(scoped, size):
    ids, cursor = [], None
    for _ in range(40):
        p = await page(scoped, page_size=size, cursor=cursor)
        ids += [i["event_id"] for i in p["items"]]
        cursor = p["next_cursor"]
        if not cursor:
            break
    return ids


@pytest.mark.asyncio
async def test_unmigrated_evidence_is_still_returned(db):
    scoped, coll = db
    await coll.insert_many([unmigrated("2026-09-27T10:00:00Z", "old_a"),
                            unmigrated("2026-09-27 11:00:00.000", "old_b")])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["old_b", "old_a"]
    assert p["pending_temporal_migration"] == 2


@pytest.mark.asyncio
async def test_migrated_and_unmigrated_interleave_in_correct_order(db):
    scoped, coll = db
    await coll.insert_many([
        migrated("2026-09-27T04:00:00Z", "new_04"),
        unmigrated("2026-09-27 03:00:00.000", "old_03"),
        migrated("2026-09-27T02:00:00Z", "new_02"),
        unmigrated("2026-09-27 01:00:00.000", "old_01"),
    ])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == \
        ["new_04", "old_03", "new_02", "old_01"]
    assert p["pending_temporal_migration"] == 2


@pytest.mark.asyncio
async def test_nothing_is_lost_across_pages_during_the_transition(db):
    scoped, coll = db
    rows, want = [], []
    for h in range(10):
        t_new = f"2026-09-27T{h:02d}:30:00.000Z"
        t_old = f"2026-09-27 {h:02d}:00:00.000"
        rows += [migrated(t_new, f"new{h}"), unmigrated(t_old, f"old{h}")]
        want += [(ta.to_epoch_us(t_new), f"new{h}"),
                 (ta.to_epoch_us(t_old), f"old{h}")]
    await coll.insert_many(rows)
    expect = [e for _, e in sorted(want, reverse=True)]
    for size in (1, 3, 7, 20):
        ids = await drain(scoped, size)
        assert ids == expect, f"page_size={size}"
        assert len(ids) == len(set(ids)) == 20


@pytest.mark.asyncio
async def test_a_fully_migrated_collection_reports_zero_pending(db):
    scoped, coll = db
    await coll.insert_many([migrated("2026-09-27T10:00:00Z", "a"),
                            migrated("2026-09-27 11:00:00.000", "b")])
    p = await page(scoped, page_size=10)
    assert p["pending_temporal_migration"] == 0
    assert [i["event_id"] for i in p["items"]] == ["b", "a"]


@pytest.mark.asyncio
async def test_the_window_still_applies_to_unmigrated_evidence(db):
    scoped, coll = db
    await coll.insert_many([unmigrated("2026-09-27 12:00:00.000", "inside"),
                            unmigrated("2026-09-25 12:00:00.000", "outside")])
    p = await page(scoped, page_size=10, time_start="2026-09-27T00:00:00Z",
                   time_end="2026-09-28T00:00:00Z")
    assert [i["event_id"] for i in p["items"]] == ["inside"]


@pytest.mark.asyncio
async def test_tenant_isolation_holds_for_unmigrated_evidence(db):
    scoped, coll = db
    other = unmigrated("2026-09-27T10:00:00Z", "theirs")
    other["tenant_id"] = "ten_other"
    await coll.insert_many([unmigrated("2026-09-27T10:00:00Z", "mine"), other])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["mine"]
