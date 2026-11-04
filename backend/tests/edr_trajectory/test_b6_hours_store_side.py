"""B6 · store-side hour grouping, validated against a DEDICATED mongod.

Runs against `E3_TEST_MONGO_URI` (default 127.0.0.1:27019) — a separate
instance on separate storage from the shared /app + /data/db volume, so these
assertions never depend on, and never add to, that volume's pressure.

Covers the five things the review asked for:
  timestamp handling · tenant/endpoint filtering · count parity ·
  malformed-data behaviour · memory limits
plus a demonstration that the replaced guard still catches the ORIGINAL
day-range defect it was written for.
"""
import asyncio
import os
import uuid

import pytest
from fastapi import HTTPException
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import OperationFailure

from routers.edr_trajectory_v3 import _MEM_LIMIT_CODE, _NOT_UTC, _hour_buckets

URI = os.environ.get("E3_TEST_MONGO_URI", "mongodb://127.0.0.1:27019")
COLL = "v2_shadow_observations"
TKEY = "event.ts"
EP, OTHER_EP = "ep_b6_probe", "ep_b6_other"
TEN, OTHER_TEN = "ten-b6", "ten-b6-other"
DAY, LO, HI = "2026-10-18", "2026-10-17", "2026-10-20"


def _doc(ts, *, ep=EP, tenant=TEN):
    return {"tenant_id": tenant, "connector_id": ep,
            "event": {"ts": ts, "raw": {"computer": ep}, "device_iid": "dev_b6"}}


SEED = [
    # ── provably UTC, inside the requested day ───────────────────────────
    _doc("2026-10-18T00:00:00Z"),                      # hour 0
    _doc("2026-10-18T14:37:37.510000+00:00"),          # hour 14
    _doc("2026-10-18T14:59:59.999Z"),                  # hour 14
    _doc("2026-10-18T23:59:59Z"),                      # hour 23
    # ── the deliberately widened edge days: matched, never counted ──────
    _doc("2026-10-17T23:00:00Z"),
    _doc("2026-10-19T01:00:00Z"),
    # ── malformed / not provably UTC → the sentinel bucket ──────────────
    _doc("2026-10-18T14:37:37+05:30"),                 # real offset
    _doc("2026-10-18 14:37:37Z"),                      # no T separator
    _doc("not-a-timestamp-at-all"),
    # ── must be excluded by the partition / alias filters ───────────────
    _doc("2026-10-18T14:00:00Z", tenant=OTHER_TEN),
    _doc("2026-10-18T15:00:00Z", ep=OTHER_EP),
]


def _match(refs=(EP,), tenant=TEN):
    return {"$or": [{"event.raw.computer": {"$in": list(refs)}},
                    {"connector_id": {"$in": list(refs)}}],
            TKEY: {"$gte": LO, "$lt": HI},
            "tenant_id": tenant}


def _run(fn):
    """One client per call — a motor client cannot outlive its event loop."""
    async def go():
        cli = AsyncIOMotorClient(URI, serverSelectionTimeoutMS=2500)
        try:
            return await fn(cli[DBNAME])
        finally:
            cli.close()
    return asyncio.run(go())


DBNAME = f"b6_hours_{uuid.uuid4().hex[:10]}"


@pytest.fixture(scope="module", autouse=True)
def seeded():
    async def setup(db):
        await db.command("ping")
        await db[COLL].insert_many([dict(d) for d in SEED])
    try:
        _run(setup)
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"dedicated test mongod not reachable at {URI}: {e}")
    yield

    async def teardown(db):
        await db.client.drop_database(DBNAME)
    _run(teardown)


def _buckets(match=None):
    async def go(db):
        return await _hour_buckets(db, COLL, match or _match(), TKEY)
    return {r["_id"]: r["n"] for r in _run(go)}


# ─── timestamp handling + count parity ───────────────────────────────────
def test_utc_hours_are_bucketed_exactly():
    c = _buckets()
    assert c.get("2026-10-18T00") == 1
    assert c.get("2026-10-18T14") == 2, "both provably-UTC 14:xx rows, Z and +00:00"
    assert c.get("2026-10-18T23") == 1


def test_widened_edge_days_are_returned_but_distinguishable():
    c = _buckets()
    assert c.get("2026-10-17T23") == 1
    assert c.get("2026-10-19T01") == 1
    in_day = sum(n for k, n in c.items() if k.startswith(DAY))
    assert in_day == 4, "the route counts only buckets whose date equals the day"


# ─── malformed data ──────────────────────────────────────────────────────
def test_malformed_and_non_utc_go_to_the_sentinel_not_an_hour():
    c = _buckets()
    assert c.get(_NOT_UTC) == 2, "the +05:30 offset and the bad separator"
    assert c.get("2026-10-18T14") == 2, \
        "a +05:30 row must never be substring-bucketed into hour 14"


def test_a_time_string_that_cannot_sort_into_the_range_is_invisible():
    """PRE-EXISTING, and deliberately left unchanged.

    `not-a-timestamp-at-all` sorts above `2026-10-20`, so the lexicographic
    range predicate never matches it — it reaches neither an hour nor the
    sentinel. That predicate is byte-identical before and after B6, so this is
    not a regression; it is recorded here so the limit is known rather than
    discovered. Such a row is unplaceable by definition: no hour can be claimed
    for it without inventing one.
    """
    async def go(db):
        return await db[COLL].count_documents(
            {"connector_id": EP, TKEY: "not-a-timestamp-at-all"})
    assert _run(go) == 1, "the row exists in the store"
    assert sum(_buckets().values()) == 8, "but contributes to no bucket"


def test_missing_time_field_does_not_crash_the_grouping():
    async def go(db):
        await db[COLL].insert_one({"tenant_id": TEN, "connector_id": EP,
                                   "event": {"raw": {"computer": EP}}})
        return await _hour_buckets(db, COLL, _match(), TKEY)
    assert isinstance(_run(go), list)


# ─── tenant / endpoint filtering ─────────────────────────────────────────
def test_other_tenant_rows_are_not_counted():
    assert _buckets().get("2026-10-18T14") == 2, "other tenant's 14:00 row excluded"
    assert _buckets(_match(tenant=OTHER_TEN)).get("2026-10-18T14") == 1, \
        "and must still be visible to ITS OWN tenant"


def test_other_endpoint_rows_are_not_counted():
    assert "2026-10-18T15" not in _buckets(), "other endpoint's 15:00 row excluded"
    assert _buckets(_match(refs=(EP, OTHER_EP))).get("2026-10-18T15") == 1, \
        "and must appear when its alias IS addressed"


# ─── the ORIGINAL day-range defect ───────────────────────────────────────
def test_a_large_out_of_day_history_cannot_hide_the_requested_day():
    """The defect the replaced guard was written for.

    Before, the read took an unordered prefix of the endpoint's whole history
    and filtered the day in Python, so a day holding real observations could
    report 0. The range now bounds the QUERY, so volume cannot change the answer.
    """
    async def go(db):
        await db[COLL].insert_many([_doc(f"2026-09-{d:02d}T{h:02d}:00:00Z")
                                    for d in range(1, 29) for h in range(24)])
        return await _hour_buckets(db, COLL, _match(), TKEY)
    c = {r["_id"]: r["n"] for r in _run(go)}
    assert c.get("2026-10-18T14") == 2, "history volume must not change the day's count"
    assert not any(k.startswith("2026-09") for k in c), "out-of-range rows must not match"


def test_the_replacement_guard_still_rejects_the_original_defective_source():
    """Feed the rule the PRE-FIX shape: it must still fail."""
    from tests.edr_trajectory.test_v3_presentation import (hours_day_range_rule,
                                                           hours_source)
    defective = '''
    async def trajectory_hours(endpoint_id, day):
        match = {"$or": [{f: {"$in": list(res.refs)}} for f in fields]}
        async for doc in _db[store].find(match).sort(tkey, -1).limit(CAP):
            us = observation_us(cur)
            if d0 <= ms < d1:
                counts[(ms - d0) // HOUR_MS] += 1
        return {"hours": counts, "truncation_meaning": "..."}
    '''
    with pytest.raises(AssertionError, match="bound the QUERY"):
        hours_day_range_rule(defective)
    hours_day_range_rule(hours_source())          # and must pass on what shipped


# ─── memory limits ───────────────────────────────────────────────────────
def test_bucket_cardinality_is_bounded_by_the_window_not_the_volume():
    """Why the memory limit is unreachable: ~4 days x 24 hours + 1 sentinel."""
    c = _buckets()
    assert len(c) <= 4 * 24 + 1, f"grouping produced {len(c)} keys"


def test_memory_limit_is_a_refusal_never_an_empty_day():
    """allowDiskUse=False can still raise 292. That must NOT render as zeros."""
    class _Boom:
        def aggregate(self, *_a, **_k):
            raise OperationFailure("exceeded memory limit", code=_MEM_LIMIT_CODE)

    with pytest.raises(HTTPException) as ei:
        asyncio.run(_hour_buckets({COLL: _Boom()}, COLL, _match(), TKEY))
    assert ei.value.status_code == 503
    d = ei.value.detail
    assert d["state"] == "HOURS_UNAVAILABLE"
    assert d["reason"] == "STORE_SIDE_HOUR_GROUPING_EXCEEDED_MEMORY_LIMIT"
    assert "REFUSAL" in d["meaning"]


def test_other_operation_failures_are_not_swallowed():
    """Only 292 is translated; anything else must propagate unchanged."""
    class _Other:
        def aggregate(self, *_a, **_k):
            raise OperationFailure("something else entirely", code=9999)

    with pytest.raises(OperationFailure):
        asyncio.run(_hour_buckets({COLL: _Other()}, COLL, _match(), TKEY))


@pytest.mark.parametrize("ts", ["2026-10-18T24:00:00Z", "2026-10-18T99:00:00Z", "2026-10-18T14:60:00Z", "2026-10-18T14:00:60Z", "2026-10-18T14:99:99Z"])
def test_invalid_clock_values_use_authoritative_fallback(ts):
    from edr_trajectory.production_adapter import observation_us
    assert observation_us(ts) is None
    async def go(db):
        coll = "invalid_clock_" + uuid.uuid4().hex
        await db[coll].insert_one(_doc(ts))
        return await _hour_buckets(db, coll, _match(), TKEY)
    assert _run(go) == [{"_id": _NOT_UTC, "n": 1}]

@pytest.mark.parametrize("value", [None, 42, {"bad": "timestamp"}, ["2026-10-18T14:00:00Z"]])
def test_non_string_time_is_safe_in_group_expression(value):
    async def go(db):
        coll = "invalid_type_" + uuid.uuid4().hex
        await db[coll].insert_one(_doc(value))
        return await _hour_buckets(db, coll, {"tenant_id": TEN}, TKEY)
    assert _run(go) == [{"_id": _NOT_UTC, "n": 1}]
