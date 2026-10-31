"""G-41 RETIREMENT · the canonical transitional legacy read is GONE.

These tests were written to pin the opposite behaviour: while the historical
population was unstamped, a second `event_time`-ordered read existed so that
unmigrated evidence could not vanish from Device Trajectory. That population is
now fully stamped (production census: 0 of 124,898 canonical rows lack
`observation_us`) and the second read is retired, so the tests are INVERTED
rather than deleted — the file now proves the retirement did not quietly
reintroduce either of the two failures it could cause:

  1. canonical selection, ordering, paging or resume falling back to the raw
     stored string, which is the G-41 defect itself; and
  2. an unstamped row becoming INVISIBLE instead of merely unplaceable — a
     "clean" zero that actually means the read stopped looking.

The shadow store is deliberately untouched by this change and is pinned here so
a later edit cannot silently drag it onto the comparable path.
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
SHADOW = pa.STORE_SHADOW


def base(event_time, eid):
    return {"tenant_id": TENANT, "event_time": event_time, "event_id": eid,
            "ingest_time": "2026-09-30T00:00:00+00:00",
            "additional_fields": {"endpoint_id": EP, "activity_type": "process",
                                  "activity_identity": eid},
            "host": {"hostname": "h1"},
            "provenance": {"collector_id": EP, "trace_id": "r-" + eid},
            "process": {"pid": 1, "executable_path": "/x"}}


def stamped(event_time, eid):
    """Evidence as the writer and the completed migration leave it."""
    return ta.stamp(base(event_time, eid))


def unstamped(event_time, eid):
    """Evidence with NO comparable value.

    After the migration this can only arise from `temporal_authority.stamp()`
    FAILING CLOSED on an absent or unparseable stored time. It must never be
    placed at an invented instant, and it must never be silently forgotten.
    """
    return base(event_time, eid)


def shadow(ts, eid):
    return {"tenant_id": TENANT, "activity_identity": eid,
            "observation_id": "obs-" + eid, "ingest_job_id": "r-" + eid,
            "ingest_time": "2026-09-30T00:00:00+00:00",
            "event": {"ts": ts, "device_iid": EP, "activity": "process",
                      "process": {"pid": 1, "image": "/x"}}}


@pytest_asyncio.fixture
async def db():
    name = f"g41t_{uuid.uuid4().hex[:10]}"
    database = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

    class Scoped:
        def __getitem__(self, key):
            if key == CANON:
                return database[name]
            if key == SHADOW:
                return database[name + "_sh"]
            return database[key]

    yield Scoped(), database[name], database[name + "_sh"]
    await database[name].drop()
    await database[name + "_sh"].drop()


async def page(scoped, stores=(CANON,), **kw):
    return await pa.page_device_evidence(scoped, tenant_id=TENANT, refs=[EP],
                                         stores=stores, **kw)


async def drain(scoped, size, stores=(CANON,)):
    ids, cursor = [], None
    for _ in range(40):
        p = await page(scoped, stores=stores, page_size=size, cursor=cursor)
        ids += [i["event_id"] for i in p["items"]]
        cursor = p["next_cursor"]
        if not cursor:
            break
    return ids


# ── 1 · unstamped canonical evidence cannot enter comparable ordering ──────

@pytest.mark.asyncio
async def test_unstamped_canonical_evidence_is_not_selected(db):
    scoped, coll, _ = db
    await coll.insert_many([unstamped("2026-09-27T10:00:00Z", "old_a"),
                            unstamped("2026-09-27 11:00:00.000", "old_b")])
    p = await page(scoped, page_size=10)
    assert p["items"] == []
    assert p["next_cursor"] is None


@pytest.mark.asyncio
async def test_unstamped_evidence_cannot_displace_stamped_evidence(db):
    scoped, coll, _ = db
    await coll.insert_many([
        stamped("2026-09-27T04:00:00Z", "new_04"),
        unstamped("2026-09-27 03:00:00.000", "old_03"),
        stamped("2026-09-27T02:00:00Z", "new_02"),
        unstamped("2026-09-27 01:00:00.000", "old_01"),
    ])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["new_04", "new_02"]


# ── 2 · the unplaceable condition is never represented as clean ────────────

@pytest.mark.asyncio
async def test_unstamped_evidence_is_reported_not_silently_dropped(db):
    scoped, coll, _ = db
    await coll.insert_many([stamped("2026-09-27T04:00:00Z", "new_04"),
                            unstamped("2026-09-27 03:00:00.000", "old_03")])
    p = await page(scoped, page_size=10)
    th = p["temporal_health"]
    assert th["assessed"] is True
    assert th["unstamped_evidence_present"] is True
    assert th["state"] == pa.TEMPORAL_UNSTAMPED
    # the row is NOT in items and NOT in the unplaceable counter, so this flag
    # is the only honest signal that it exists
    assert [i["event_id"] for i in p["items"]] == ["new_04"]
    assert th["state"] != pa.TEMPORAL_HEALTHY


@pytest.mark.asyncio
async def test_a_clean_verdict_is_a_measured_verdict(db):
    scoped, coll, _ = db
    await coll.insert_many([stamped("2026-09-27T10:00:00Z", "a"),
                            stamped("2026-09-27 11:00:00.000", "b")])
    p = await page(scoped, page_size=10)
    th = p["temporal_health"]
    assert th["assessed"] is True
    assert th["unstamped_evidence_present"] is False
    assert th["state"] == pa.TEMPORAL_HEALTHY
    assert [i["event_id"] for i in p["items"]] == ["b", "a"]


@pytest.mark.asyncio
async def test_an_unaddressable_endpoint_is_not_reported_clean(db):
    scoped, _, _ = db
    p = await pa.page_device_evidence(scoped, tenant_id=TENANT, refs=[],
                                      stores=(CANON,))
    th = p["temporal_health"]
    assert th["assessed"] is False
    assert th["unstamped_evidence_present"] is None
    assert th["state"] == pa.TEMPORAL_NOT_ASSESSED


@pytest.mark.asyncio
async def test_the_verdict_survives_paging_without_reprobing(db):
    scoped, coll, _ = db
    rows = [stamped(f"2026-09-27T{h:02d}:00:00Z", f"s{h}") for h in range(6)]
    rows.append(unstamped("2026-09-26 01:00:00.000", "bad"))
    await coll.insert_many(rows)
    p = await page(scoped, page_size=2)
    assert p["temporal_health"]["unstamped_evidence_present"] is True
    seen = 1
    while p["next_cursor"]:
        p = await page(scoped, page_size=2, cursor=p["next_cursor"])
        seen += 1
        assert p["temporal_health"]["assessed"] is True
        assert p["temporal_health"]["unstamped_evidence_present"] is True
    assert seen >= 3


# ── 3 · canonical paging uses ONLY observation_us + _id ───────────────────

def test_canonical_selection_never_touches_the_raw_stored_string():
    flt = {"tenant_id": TENANT, "provenance.collector_id": {"$in": [EP]}}
    for kwargs in ({}, {"upper_bound": 1}, {"lo": 1, "hi": 2}):
        q, sort = pa.branch_query(flt, pa.TEMPORAL_SELECT_KEY[CANON],
                                  comparable=True,
                                  tiebreak=pa.TEMPORAL_TIEBREAK_KEY, **kwargs)
        assert ta.SOURCE_FIELD not in q, kwargs
        assert ta.OBSERVATION_US in q
        assert sort == [(ta.OBSERVATION_US, -1), ("_id", -1)]


def test_the_canonical_selection_key_is_the_comparable_integer():
    assert pa.TEMPORAL_SELECT_KEY[CANON] == ta.OBSERVATION_US
    assert pa.COMPARABLE_TEMPORAL[CANON] is True
    assert pa.TEMPORAL_TIEBREAK_KEY == "_id"
    # the verbatim evidence value is still DECLARED, just no longer a selector
    assert pa.OBSERVATION_TIME_KEY[CANON] == ta.SOURCE_FIELD


@pytest.mark.asyncio
async def test_the_canonical_cursor_carries_no_raw_string_bound(db):
    scoped, coll, _ = db
    await coll.insert_many([stamped(f"2026-09-27T{h:02d}:00:00Z", f"s{h}")
                            for h in range(5)])
    p = await page(scoped, page_size=2)
    assert p["next_cursor"]
    decoded = pa._decode(p["next_cursor"])
    assert CANON not in decoded["b"]
    assert isinstance(decoded["us"], int)
    assert decoded["id"]


# ── 4 · historical normalized evidence remains visible and correctly ordered

@pytest.mark.asyncio
async def test_migrated_historical_evidence_is_still_visible_in_order(db):
    """The production defect, with the historical rows now stamped.

    `"2026-09-27 23:55:38.144"` sorts BELOW `"2026-09-27T00:06:30.755Z"` byte
    by byte. Both representations exist in production evidence, and both are
    now stamped, so chronology must hold across them.
    """
    scoped, coll, _ = db
    await coll.insert_many([stamped("2026-09-27 23:55:38.144", "late_space"),
                            stamped("2026-09-27T00:06:30.755Z", "early_z")])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["late_space", "early_z"]
    assert p["temporal_health"]["unstamped_evidence_present"] is False


@pytest.mark.asyncio
async def test_nothing_is_lost_across_pages_at_any_page_size(db):
    scoped, coll, _ = db
    rows, want = [], []
    for h in range(10):
        t_z = f"2026-09-27T{h:02d}:30:00.000Z"
        t_space = f"2026-09-27 {h:02d}:00:00.000"
        rows += [stamped(t_z, f"z{h}"), stamped(t_space, f"sp{h}")]
        want += [(ta.to_epoch_us(t_z), f"z{h}"),
                 (ta.to_epoch_us(t_space), f"sp{h}")]
    await coll.insert_many(rows)
    expect = [e for _, e in sorted(want, reverse=True)]
    for size in (1, 3, 7, 20):
        ids = await drain(scoped, size)
        assert ids == expect, f"page_size={size}"
        assert len(ids) == len(set(ids)) == 20


@pytest.mark.asyncio
async def test_the_window_still_applies_to_migrated_evidence(db):
    scoped, coll, _ = db
    await coll.insert_many([stamped("2026-09-27 12:00:00.000", "inside"),
                            stamped("2026-09-25 12:00:00.000", "outside")])
    p = await page(scoped, page_size=10, time_start="2026-09-27T00:00:00Z",
                   time_end="2026-09-28T00:00:00Z")
    assert [i["event_id"] for i in p["items"]] == ["inside"]


@pytest.mark.asyncio
async def test_tenant_isolation_holds(db):
    scoped, coll, _ = db
    other = stamped("2026-09-27T10:00:00Z", "theirs")
    other["tenant_id"] = "ten_other"
    await coll.insert_many([stamped("2026-09-27T10:00:00Z", "mine"), other])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["mine"]


# ── 5 · the shadow store is UNCHANGED by this retirement ──────────────────

def test_shadow_store_still_selects_and_orders_on_its_stored_string():
    assert pa.COMPARABLE_TEMPORAL[SHADOW] is False
    assert pa.TEMPORAL_SELECT_KEY[SHADOW] == pa.OBSERVATION_TIME_KEY[SHADOW] \
        == "event.ts"
    flt = {"tenant_id": TENANT, "event.device_iid": {"$in": [EP]}}
    q, sort = pa.branch_query(flt, pa.TEMPORAL_SELECT_KEY[SHADOW],
                              upper_bound="2026-09-27T10:00:00Z")
    assert q["event.ts"] == {"$lte": "2026-09-27T10:00:00Z"}
    assert sort == [("event.ts", -1)]       # no _id tiebreak for this store


@pytest.mark.asyncio
async def test_shadow_paging_still_carries_its_raw_string_resume_bound(db):
    scoped, _, sh = db
    await sh.insert_many([shadow(f"2026-09-27T{h:02d}:00:00Z", f"sh{h}")
                          for h in range(5)])
    p = await page(scoped, stores=(SHADOW,), page_size=2)
    assert [i["event_id"] for i in p["items"]] == ["sh4", "sh3"]
    assert p["next_cursor"]
    assert SHADOW in pa._decode(p["next_cursor"])["b"]
    # no comparable store was read, so no temporal claim is made about one
    assert p["temporal_health"]["assessed"] is False


@pytest.mark.asyncio
async def test_shadow_evidence_is_not_excluded_by_the_canonical_retirement(db):
    scoped, coll, sh = db
    await coll.insert_many([stamped("2026-09-27T05:00:00Z", "canon_05")])
    await sh.insert_many([shadow("2026-09-27T06:00:00Z", "shadow_06")])
    p = await page(scoped, stores=(SHADOW, CANON), page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["shadow_06", "canon_05"]
    assert p["provenance"]["rows_per_store"] == {SHADOW: 1, CANON: 1}
