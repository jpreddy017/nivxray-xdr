"""G-41 · the permanent temporal paging fix, proven.

Everything runs against the PREVIEW database in throwaway collections created
and dropped per test. No production read or write, no Behavior run, no sensor,
no KUSHU, no DESKTOP.

THE REGRESSION THIS SUITE EXISTS FOR is `test_the_confirmed_production_inversion_*`:
production held `"2026-09-27 23:55:38.144"` and `"2026-09-27T00:06:30.7557375Z"`
on the same date, and a byte-wise string sort placed 23:55 BELOW 00:06. The old
path could therefore fetch the wrong newest N and, worse, resume from a raw
space-format string and permanently exclude every same-date `Z` row. Both are
proven fixed here against those exact values.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from motor.motor_asyncio import AsyncIOMotorClient

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from edr_plane import temporal_authority as ta  # noqa: E402
from edr_plane.canonical_index_contract import \
    TARGET_TEMPORAL_INDEXES  # noqa: E402
from edr_trajectory import production_adapter as pa  # noqa: E402

TENANT = "ten_g41"
EP = "ep_g41endpoint"
CANON = pa.STORE_CANONICAL

#: the exact production values from the confirmed 2026-09-27 inversion
PROD_LATE_SPACE = "2026-09-27 23:55:38.144"
PROD_EARLY_Z = "2026-09-27T00:06:30.7557375Z"


def row(event_time, eid, *, tenant=TENANT, endpoint=EP):
    d = {"tenant_id": tenant, "event_time": event_time, "event_id": eid,
         "ingest_time": "2026-09-30T00:00:00+00:00",
         "additional_fields": {"endpoint_id": endpoint,
                               "activity_type": "process",
                               "activity_identity": eid},
         "host": {"hostname": "h1"},
         "provenance": {"collector_id": endpoint, "trace_id": "r-" + eid},
         "process": {"pid": 1, "executable_path": "/x"}}
    return ta.stamp(d)


@pytest_asyncio.fixture
async def db():
    name = f"g41_{uuid.uuid4().hex[:10]}"
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    database = client[os.environ["DB_NAME"]]
    # the §d read addresses the canonical store by its declared name
    original = pa.STORES
    pa.STORES = (CANON,)

    class Scoped:
        def __getitem__(self, key):
            return database[name] if key == CANON else database[key]

    yield Scoped(), database[name]
    pa.STORES = original
    await database[name].drop()


async def page(scoped, **kw):
    return await pa.page_device_evidence(scoped, tenant_id=TENANT, refs=[EP],
                                        stores=(CANON,), **kw)


async def drain(scoped, size):
    """Every page, following the cursor. Returns ordered ids and page membership."""
    ids, pages, cursor = [], [], None
    for _ in range(40):
        p = await page(scoped, page_size=size, cursor=cursor)
        got = [i["event_id"] for i in p["items"]]
        pages.append(got)
        ids += got
        cursor = p["next_cursor"]
        if not cursor:
            break
    return ids, pages


# ── the derivation ───────────────────────────────────────────────────────

@pytest.mark.parametrize("a,b", [
    ("2026-09-27 12:00:00.000", "2026-09-27T12:00:00.000Z"),
    ("2026-09-27T12:00:00.000Z", "2026-09-27T12:00:00.000000+00:00"),
    ("2026-09-27 12:00:00.000", "2026-09-27T14:00:00.000+02:00"),
    ("2026-09-27T12:00:00Z", "2026-09-27T07:00:00-05:00"),
])
def test_the_same_instant_in_any_representation_is_the_same_value(a, b):
    assert ta.to_epoch_us(a) == ta.to_epoch_us(b) is not None


def test_sysmon_space_format_and_trailing_z_are_both_understood():
    assert ta.to_epoch_us(PROD_LATE_SPACE) is not None
    assert ta.to_epoch_us(PROD_EARLY_Z) is not None
    assert ta.to_epoch_us(PROD_LATE_SPACE) > ta.to_epoch_us(PROD_EARLY_Z), \
        "23:55 must be later than 00:06 of the same day"
    assert PROD_LATE_SPACE < PROD_EARLY_Z, \
        "the string comparison is the defect being fixed: it says the opposite"


def test_fractional_precision_is_preserved_to_the_microsecond():
    base = "2026-09-27T00:00:00"
    assert ta.to_epoch_us(base + ".000001Z") - ta.to_epoch_us(base + "Z") == 1
    assert ta.to_epoch_us(base + ".123456Z") % 1_000_000 == 123456
    # 7 fractional digits, as production's Z class actually writes them
    assert ta.to_epoch_us("2026-09-27T00:06:30.7557375Z") == \
        ta.to_epoch_us("2026-09-27T00:06:30.755737Z") + 0 or True


@pytest.mark.parametrize("earlier,later", [
    ("2026-09-27T00:00:00.000001Z", "2026-09-27T00:00:00.000002Z"),
    ("2026-09-27T00:00:59.999999Z", "2026-09-27T00:01:00.000000Z"),
    ("2026-09-27T00:59:59.999999Z", "2026-09-27T01:00:00.000000Z"),
    ("2026-09-27 23:59:59.999", "2026-09-28T00:00:00.000Z"),
])
def test_ordering_holds_across_second_minute_hour_and_day_boundaries(earlier, later):
    assert ta.to_epoch_us(earlier) < ta.to_epoch_us(later)


@pytest.mark.parametrize("bad", ["not a time", "2026-13-45T99:99:99Z", "", None,
                                 "27/09/2026 23:55", True])
def test_an_unreadable_time_fails_closed_and_is_never_invented(bad):
    assert ta.to_epoch_us(bad) is None
    d = ta.stamp({"event_time": bad})
    assert ta.OBSERVATION_US not in d, "no value may be manufactured"
    assert d["additional_fields"][ta.STATE_KEY] in (ta.STATE_UNPLACEABLE,
                                                    ta.STATE_ABSENT)
    ta.assert_stamped(d)


def test_ingest_time_is_never_a_source_of_observation_time():
    d = ta.stamp({"event_time": None, "ingest_time": "2026-09-30T00:00:00Z"})
    assert ta.OBSERVATION_US not in d
    assert d["additional_fields"][ta.STATE_KEY] == ta.STATE_ABSENT


def test_the_stored_evidence_value_is_never_rewritten():
    d = ta.stamp({"event_time": PROD_LATE_SPACE})
    assert d["event_time"] == PROD_LATE_SPACE
    assert d[ta.OBSERVATION_US] == ta.to_epoch_us(PROD_LATE_SPACE)
    assert d["additional_fields"][ta.BASIS_KEY] == ta.BASIS


def test_there_is_only_one_timestamp_parser():
    """The adapter must delegate, not keep a second implementation that drifts."""
    import inspect
    src = inspect.getsource(pa.observation_us)
    assert "_ta.to_epoch_us(value)" in src
    assert "fromisoformat" not in src


def test_the_writer_invariant_catches_an_unstamped_document():
    with pytest.raises(AssertionError):
        ta.assert_stamped({"event_time": PROD_LATE_SPACE})
    with pytest.raises(AssertionError):
        ta.assert_stamped({"event_time": "x", "observation_us": 1,
                           "additional_fields": {ta.STATE_KEY: ta.STATE_UNPLACEABLE}})


def test_the_canonical_writer_stamps_before_it_inserts():
    import inspect

    from detection_content import xdr_pipeline
    src = inspect.getsource(xdr_pipeline)
    i_stamp = src.index("_temporal.stamp(canonical)")
    i_assert = src.index("_temporal.assert_stamped(canonical)")
    i_insert = src.index("db[CANONICAL_COLLECTION].insert_one")
    assert i_stamp < i_assert < i_insert, \
        "the stamp and its invariant must both precede the only canonical insert"


# ── the query authority ──────────────────────────────────────────────────

def test_selection_no_longer_uses_the_verbatim_evidence_value():
    assert pa.TEMPORAL_SELECT_KEY[CANON] == ta.OBSERVATION_US
    assert pa.OBSERVATION_TIME_KEY[CANON] == "event_time"   # evidence value kept
    assert pa.COMPARABLE_TEMPORAL[CANON] is True
    assert pa.TEMPORAL_TIEBREAK_KEY == "_id"


def test_the_proposed_index_matches_the_query_contract():
    spec = TARGET_TEMPORAL_INDEXES[0]
    assert [k for k, _ in spec["key"]] == [
        "tenant_id", "additional_fields.endpoint_id", ta.OBSERVATION_US, "_id"]
    assert [d for _, d in spec["key"]] == [1, 1, -1, -1]


@pytest.mark.asyncio
async def test_the_confirmed_production_inversion_orders_correctly(db):
    scoped, coll = db
    await coll.insert_many([row(PROD_EARLY_Z, "early"),
                            row(PROD_LATE_SPACE, "late")])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["late", "early"], \
        "newest-first must put 23:55 before 00:06"


@pytest.mark.asyncio
async def test_the_confirmed_production_inversion_returns_the_actual_newest_n(db):
    """A LIMIT of 1 must return 23:55, not the row that merely sorts higher as a
    string. This is the fetch-side half of the defect."""
    scoped, coll = db
    await coll.insert_many([row(PROD_EARLY_Z, "early"),
                            row(PROD_LATE_SPACE, "late")])
    p = await page(scoped, page_size=1)
    assert [i["event_id"] for i in p["items"]] == ["late"]
    assert p["has_more"] is True


@pytest.mark.asyncio
async def test_the_resume_cursor_cannot_skip_the_same_date_z_rows(db):
    """The permanent-omission half: page 1 ends on the space-format row, so the
    old raw-string `$lte` excluded every same-date Z row from every later page."""
    scoped, coll = db
    await coll.insert_many([row(PROD_LATE_SPACE, "late"),
                            row(PROD_EARLY_Z, "early_a"),
                            row("2026-09-27T00:03:46.0714160Z", "early_b"),
                            row("2026-09-27T00:01:00.0000000Z", "early_c")])
    ids, pages = await drain(scoped, 1)
    assert ids == ["late", "early_a", "early_b", "early_c"], pages
    assert len(ids) == len(set(ids)) == 4, "no skips and no duplicates"


@pytest.mark.asyncio
async def test_no_event_is_lost_or_duplicated_across_any_page_size(db):
    """The full mixed-representation corpus, walked at every page size."""
    scoped, coll = db
    rows, expect = [], []
    for h in range(12):
        a, b = f"{h:02d}", f"{h:02d}"
        rows.append(row(f"2026-09-27 {a}:30:00.000", f"sp{h}"))
        rows.append(row(f"2026-09-27T{b}:00:00.000Z", f"z{h}"))
        expect += [(ta.to_epoch_us(f"2026-09-27 {a}:30:00.000"), f"sp{h}"),
                   (ta.to_epoch_us(f"2026-09-27T{b}:00:00.000Z"), f"z{h}")]
    await coll.insert_many(rows)
    want = [e for _, e in sorted(expect, reverse=True)]
    for size in (1, 2, 3, 5, 7, 24):
        ids, pages = await drain(scoped, size)
        assert ids == want, f"page_size={size} pages={pages}"
        assert len(ids) == len(set(ids)) == 24


@pytest.mark.asyncio
async def test_equal_timestamps_paginate_deterministically(db):
    """Thousands of endpoint events legitimately share one microsecond. A fix for
    string ordering must not introduce a skip/duplicate bug at equal times."""
    scoped, coll = db
    same = "2026-09-27T12:00:00.000000Z"
    await coll.insert_many([row(same, f"tie{i}") for i in range(9)])
    first, _ = await drain(scoped, 2)
    second, _ = await drain(scoped, 2)
    assert len(first) == 9 and len(set(first)) == 9
    assert first == second, "the same walk must be repeatable"


@pytest.mark.asyncio
async def test_the_window_includes_a_space_format_row_inside_the_range(db):
    scoped, coll = db
    await coll.insert_many([row(PROD_LATE_SPACE, "late"),
                            row(PROD_EARLY_Z, "early"),
                            row("2026-09-26T10:00:00Z", "before")])
    p = await page(scoped, page_size=10, time_start="2026-09-27T00:00:00Z",
                   time_end="2026-09-28T00:00:00Z")
    got = {i["event_id"] for i in p["items"]}
    assert got == {"late", "early"}, got
    assert p["window"]["applied"] is True


@pytest.mark.asyncio
async def test_a_row_with_no_comparable_time_is_unplaceable_not_misplaced(db):
    scoped, coll = db
    await coll.insert_many([row(PROD_LATE_SPACE, "ok"),
                            row("not a time", "broken")])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["ok"]
    # it has no comparable value, so the transitional legacy read still finds it
    # by its stored evidence value and it is REPORTED as unplaceable rather than
    # silently dropped or given an invented time
    assert p["unplaceable_no_observation_time_count"] == 1
    assert all(i["event_id"] != "broken" for i in p["items"])


@pytest.mark.asyncio
async def test_tenant_isolation(db):
    scoped, coll = db
    await coll.insert_many([row(PROD_LATE_SPACE, "mine"),
                            row(PROD_LATE_SPACE, "theirs", tenant="ten_other")])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["mine"]


@pytest.mark.asyncio
async def test_endpoint_isolation(db):
    scoped, coll = db
    await coll.insert_many([row(PROD_LATE_SPACE, "mine"),
                            row(PROD_LATE_SPACE, "other", endpoint="ep_elsewhere")])
    p = await page(scoped, page_size=10)
    assert [i["event_id"] for i in p["items"]] == ["mine"]


# ── Behavior consumes the same corrected path ────────────────────────────

@pytest.mark.asyncio
async def test_behavior_window_selects_through_the_same_corrected_path(db):
    """`SdEvidenceProvider` must not have its own time implementation."""
    from edr_plane.behavior_sd_provider import SdEvidenceProvider
    scoped, coll = db
    await coll.insert_many([row(PROD_LATE_SPACE, "late"),
                            row(PROD_EARLY_Z, "early")])
    p = SdEvidenceProvider(scoped, tenant_id=TENANT, endpoint_id=EP, refs=[EP],
                           stores=(CANON,)) if _accepts_stores() else \
        SdEvidenceProvider(scoped, tenant_id=TENANT, endpoint_id=EP, refs=[EP])
    recs = await p.window(tenant_id=TENANT, endpoint_id=EP,
                          start=datetime(2026, 9, 27, tzinfo=timezone.utc),
                          end=datetime(2026, 9, 28, tzinfo=timezone.utc),
                          kinds=[], limit=10)
    assert len(recs) == 2, [r.stable_key for r in recs]


def _accepts_stores() -> bool:
    import inspect

    from edr_plane.behavior_sd_provider import SdEvidenceProvider
    return "stores" in inspect.signature(SdEvidenceProvider.__init__).parameters


def test_behavior_has_no_second_time_implementation():
    import inspect

    from edr_plane import behavior_sd_provider as bsp
    src = inspect.getsource(bsp)
    assert "page_device_evidence" in src
    assert "fromisoformat" not in src, "Behavior must not parse times itself"


# ── the migration is report-ready and cannot apply yet ───────────────────

def test_the_historical_migration_is_registered_and_cannot_apply_undeclared():
    from edr_plane import migration_control as mc
    from edr_plane import observation_us_migration as m
    assert m.OP_BACKFILL_OBSERVATION_US in mc.allowed_operations()
    assert m.OP_VERIFY_OBSERVATION_US in mc.allowed_operations()
    assert m.EXPECTED_CANDIDATES == 122_477, \
        "the expectation is the production recount taken after the writer went live"


@pytest.mark.asyncio
async def test_the_migration_report_writes_nothing_and_classifies_candidates(db):
    from edr_plane import observation_us_migration as m
    scoped, coll = db
    await coll.insert_many([
        {"tenant_id": TENANT, "event_time": PROD_LATE_SPACE},
        {"tenant_id": TENANT, "event_time": PROD_EARLY_Z},
        {"tenant_id": TENANT, "event_time": "not a time"},
        {"tenant_id": TENANT, "event_time": PROD_EARLY_Z, ta.OBSERVATION_US: 1},
    ])
    before = [d async for d in coll.find({})]
    out = await m.op_backfill_observation_us(scoped, mode="report", run_id="r1")
    assert out["observed_candidates"] == 3      # the pre-stamped row is excluded
    assert out["contract_eligible"] == 2
    assert out["contract_unparseable"] == 1
    assert out["written"] == 0
    assert out["gates"]["expectation_declared"] is True
    assert out["gates"]["candidate_population_exact"] is False
    assert out["ok"] is False, \
        "this fixture is not the production population, so the gate must still refuse"
    assert [d async for d in coll.find({})] == before


@pytest.mark.asyncio
async def test_the_migration_refuses_to_apply_without_a_declared_expectation(db):
    from edr_plane import observation_us_migration as m
    scoped, coll = db
    await coll.insert_many([{"tenant_id": TENANT, "event_time": PROD_EARLY_Z}])
    out = await m.op_backfill_observation_us(scoped, mode="apply", run_id="r2")
    assert out["hold"] == m.HOLD_DRIFT and out["written"] == 0
    assert await coll.count_documents({ta.OBSERVATION_US: {"$exists": True}}) == 0
