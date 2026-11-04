"""B6 · /trajectory/hours must count by store-side aggregation, with identical answers.

The previous read sorted matched rows by observation time and streamed them to
Python to count. `$or` across the seven endpoint-alias fields cannot be served by
one index together with that sort, so every call paid a blocking in-memory sort;
under concurrency the sort spilled to disk and the route returned 500.

These tests pin the two things that must not drift:
  1. the COUNTS are byte-identical to placement by `observation_us` (the ordering
     authority), including the widened edge days and non-UTC/corrupt offsets;
  2. concurrent calls succeed, because nothing spills any more.
"""
import asyncio
import os
import re

import httpx
import pytest

from routers.edr_trajectory_v3 import _NOT_UTC, _UTC_ISO
from edr_trajectory.production_adapter import OBSERVATION_TIME_KEY, STORES, observation_us

BASE = os.environ.get("E3_PREVIEW_HTTP", "http://localhost:8001")
_RE = re.compile(_UTC_ISO)


# ─── 1. bucketing parity: the regex gate must only claim what it can prove ───
@pytest.mark.parametrize("value,hour", [
    ("2026-10-18T14:37:37.510000+00:00", 14),
    ("2026-10-18T14:37:37Z", 14),
    ("2026-10-18T00:00:00Z", 0),
    ("2026-10-18T23:59:59.999Z", 23),
])
def test_strict_utc_substring_agrees_with_observation_us(value, hour):
    """A value the gate accepts must bucket exactly where observation_us places it."""
    assert _RE.match(value), "gate must accept a provably-UTC value"
    assert int(value[11:13]) == hour
    us = observation_us(value)
    assert us is not None
    assert (us // 1000 // 3_600_000) % 24 == hour


@pytest.mark.parametrize("value", [
    "2026-10-18T14:37:37+05:30",   # real offset — substring would mis-place it
    "2026-10-18 14:37:37Z",        # no T separator
    "2026-10-18T14:37Z",           # no seconds
    "not-a-timestamp",
    "",
])
def test_non_utc_or_corrupt_is_refused_by_the_gate(value):
    """Anything else must fall to observation_us, never be bucketed by substring."""
    assert not _RE.match(value), f"{value!r} must NOT be substring-bucketed"


def test_sentinel_cannot_collide_with_a_real_bucket():
    assert not _RE.match(_NOT_UTC)
    assert len(_NOT_UTC) != 13 or _NOT_UTC[:10].count("-") != 2


# ─── 2. HTTP parity + concurrency, against the running preview backend ───
def _login():
    email = os.environ.get("ADMIN_EMAIL")
    pw = os.environ.get("ADMIN_PASSWORD")
    if not (email and pw):
        pytest.skip("ADMIN_EMAIL/ADMIN_PASSWORD not set")
    try:
        r = httpx.post(f"{BASE}/api/auth/login",
                       json={"email": email, "password": pw}, timeout=30)
    except httpx.HTTPError as e:
        pytest.skip(f"preview backend not reachable: {e}")
    if r.status_code != 200:
        pytest.skip(f"login unavailable: {r.status_code}")
    tok = r.json().get("token") or r.json().get("access_token")
    return {"Authorization": f"Bearer {tok}", "X-Tenant-Id": "default"}


@pytest.fixture(scope="module")
def probe():
    """An endpoint that really carries observations AND really resolves.

    Never a fixture device: candidates come from the evidence itself, and the
    first one the resolver actually accepts under this principal is used. If
    none resolves, the test skips rather than asserting against a device the
    platform is right to refuse.
    """
    from deps import sync_collection
    obs = sync_collection("v2_shadow_observations")
    cands = obs.aggregate([
        {"$group": {"_id": "$event.raw.computer", "n": {"$sum": 1},
                    "ts": {"$max": "$event.ts"}}},
        {"$match": {"_id": {"$type": "string", "$regex": "^ep_"}}},
        {"$sort": {"n": -1}},
        {"$limit": 8},
    ])
    h = _login()
    for row in cands:
        ep, ts = row["_id"], row.get("ts")
        if not ts:
            continue
        day = ts[:10]
        r = httpx.get(f"{BASE}/api/edr/endpoints/{ep}/trajectory/hours",
                      params={"day": day}, headers=h, timeout=120)
        if r.status_code == 200 and r.json().get("state") == "HOURS_READY":
            return ep, day, h
    pytest.skip("no endpoint in this database both carries observations and resolves")


def test_hours_totals_match_independent_placement(probe):
    """The route's per-hour counts must equal placement by the ordering authority."""
    ep, day, h = probe
    r = httpx.get(f"{BASE}/api/edr/endpoints/{ep}/trajectory/hours",
                  params={"day": day}, headers=h, timeout=120)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["state"] == "HOURS_READY"
    assert len(body["hours"]) == 24
    assert body["ingest_time_used_as_observation_time"] is False
    assert body["ordering_authority"] == "STORED_OBSERVATION_TIME"

    # independent recount, in Python, from the same stores
    from deps import sync_collection
    from services.edr.endpoint_query import (ENDPOINT_KEYED_STORES,
                                             TENANT_PARTITIONED_STORES)
    refs = [ep]
    expect = [0] * 24
    for store in STORES:
        tkey = OBSERVATION_TIME_KEY[store]
        fields = ENDPOINT_KEYED_STORES.get(store) or []
        match = {"$or": [{f: {"$in": refs}} for f in fields],
                 tkey: {"$gte": day, "$lt": day + "\uffff"}}
        if TENANT_PARTITIONED_STORES.get(store):
            match[TENANT_PARTITIONED_STORES[store]] = body["tenant_id"]
        for doc in sync_collection(store).find(match, {"_id": 0, tkey.split(".")[0]: 1}):
            cur = doc
            for part in tkey.split("."):
                cur = cur.get(part) if isinstance(cur, dict) else None
            us = observation_us(cur)
            if us is None:
                continue
            if (cur or "")[:10] == day:
                expect[(us // 1000 // 3_600_000) % 24] += 1
    assert body["hours"] == expect, "store-side buckets must equal Python placement"


def test_absence_is_still_reported_as_absence(probe):
    """A day with nothing retained must return zeros, not an error and not a guess."""
    ep, _day, h = probe
    r = httpx.get(f"{BASE}/api/edr/endpoints/{ep}/trajectory/hours",
                  params={"day": "1999-01-01"}, headers=h, timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hours"] == [0] * 24
    assert body["state"] == "HOURS_READY"
    assert "0 means no observation is RETAINED" in body["note"]


def test_unresolved_endpoint_still_fails_closed(probe):
    _ep, day, h = probe
    r = httpx.get(f"{BASE}/api/edr/endpoints/ep_does_not_exist_000000/trajectory/hours",
                  params={"day": day}, headers=h, timeout=60)
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "ENDPOINT_NOT_RESOLVED"


def test_concurrent_reads_do_not_fail(probe):
    """Six at once used to 500 — the sort spilled. Nothing may spill now."""
    ep, day, h = probe

    async def hit():
        async with httpx.AsyncClient(timeout=180) as c:
            return await asyncio.gather(*[
                c.get(f"{BASE}/api/edr/endpoints/{ep}/trajectory/hours",
                      params={"day": day}, headers=h) for _ in range(6)])

    rs = asyncio.run(hit())
    assert [x.status_code for x in rs] == [200] * 6, [x.status_code for x in rs]
    totals = {sum(x.json()["hours"]) for x in rs}
    assert len(totals) == 1, f"concurrent reads disagreed: {totals}"
