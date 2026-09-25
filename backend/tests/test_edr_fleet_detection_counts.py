"""NivXForge EDR · Computers detection counts + Command Intelligence authority.

Two guarantees are asserted here, because both were explicit owner
requirements:

  1. the Computers grid produces `detections_24h` AND `detections_total`
     for the WHOLE fleet in ONE aggregation (no N+1, no second scan), and
     `null` (not evaluated) is never collapsed into `0`;
  2. Command Intelligence is sourced from OBSERVED endpoint evidence, not
     from the response plane (`edr_response_commands`), which records what
     the platform DISPATCHED.

EVIDENCE LABELLING — TEST/SYNTHETIC: synthetic tenant and synthetic raw
events. No real endpoint is touched.
"""
from __future__ import annotations

import asyncio
import inspect
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

os.environ.setdefault("DB_NAME", "test_database")

from deps import db as _db, init_database, validate_config  # noqa: E402
from routers import edr as edr_router                          # noqa: E402
from routers import edr_onboarding as onboarding               # noqa: E402

RUN = uuid.uuid4().hex[:10]
TENANT = f"ten_detcount_{RUN}"
EP_HOT = f"ep_hot_{RUN}"
EP_QUIET = f"ep_quiet_{RUN}"
EP_UNADDRESSABLE = None


def _iso(hours_ago: float) -> str:
    return (datetime.now(timezone.utc)
            - timedelta(hours=hours_ago)).isoformat()


def _raw(endpoint_ref: str, hours_ago: float, matches: int) -> dict:
    return {
        "raw_id": f"raw_{uuid.uuid4().hex}",
        "tenant_id": TENANT,
        "dedup_key": uuid.uuid4().hex,
        "endpoint_ref": endpoint_ref,
        "ingest_time": _iso(hours_ago),
        "trust_state": "AUTHENTICATED",
        "payload": "{}",
        "derivations": (
            [{"outcome": "DETECTION_MATCHED", "reason": "rules: T-1",
              "event_id": f"cev_{uuid.uuid4().hex}"}] * matches
            or [{"outcome": "DETECTION_EVALUATED_NO_MATCH"}]),
    }


@pytest.fixture(scope="module")
def seeded():
    validate_config()
    init_database()

    async def go():
        await _db[onboarding.RAW_EVENTS].insert_many([
            _raw(EP_HOT, 1, 2),        # inside the 24h window
            _raw(EP_HOT, 5, 1),        # inside the 24h window
            _raw(EP_HOT, 240, 3),      # 10 days old · total only
            _raw(EP_QUIET, 2, 0),      # evaluated, no match
        ])
        yield
        await _db[onboarding.RAW_EVENTS].delete_many({"tenant_id": TENANT})

    loop = asyncio.new_event_loop()
    gen = go()
    loop.run_until_complete(gen.__anext__())
    yield loop
    with pytest.raises(StopAsyncIteration):
        loop.run_until_complete(gen.__anext__())
    loop.close()


def _records():
    return [
        {"tenant_id": TENANT, "endpoint_id": EP_HOT, "hostname": "HOT"},
        {"tenant_id": TENANT, "endpoint_id": EP_QUIET, "hostname": "QUIET"},
        {"tenant_id": TENANT, "endpoint_id": f"ep_never_{RUN}",
         "hostname": "NEVER"},
    ]


def test_both_counts_come_from_one_aggregation(seeded, monkeypatch):
    calls = []
    real_collection = _db[onboarding.RAW_EVENTS]

    class CountingCollection:
        def aggregate(self, pipeline, *a, **kw):
            calls.append(pipeline)
            return real_collection.aggregate(pipeline, *a, **kw)

    class CountingDb:
        def __getitem__(self, name):
            return (CountingCollection() if name == onboarding.RAW_EVENTS
                    else _db[name])

    monkeypatch.setattr(onboarding, "_db", CountingDb())
    counts = seeded.run_until_complete(
        onboarding._detection_counts(TENANT, _records()))     # noqa: SLF001

    assert len(calls) == 1, (
        f"the whole grid must cost ONE aggregation, not {len(calls)}")
    stages = [next(iter(s)) for s in calls[0]]
    assert stages == ["$match", "$project", "$group"], stages
    assert counts[EP_HOT]["detections_total"] == 6
    assert counts[EP_HOT]["detections_window"] == 3
    # evaluated and genuinely zero — an addressable endpoint with no match
    assert counts[EP_QUIET]["detections_total"] == 0
    assert counts[EP_QUIET]["detections_window"] == 0


def test_an_endpoint_with_no_reference_is_not_evaluated_not_zero(seeded):
    record = {"tenant_id": TENANT, "hostname": "NO-ID"}   # no endpoint_id
    row = onboarding._row(record, None, None, None, 24)       # noqa: SLF001
    assert row["detections_24h"] is None
    assert row["detections_total"] is None
    assert "no endpoint reference" in row["detections_basis"]


def test_an_addressable_endpoint_reports_zero_as_zero(seeded):
    counts = seeded.run_until_complete(
        onboarding._detection_counts(TENANT, _records()))     # noqa: SLF001
    row = onboarding._row({"tenant_id": TENANT,               # noqa: SLF001
                           "endpoint_id": EP_QUIET},
                          None, None, counts.get(EP_QUIET), 24)
    assert row["detections_24h"] == 0
    assert row["detections_total"] == 0
    assert "edr_raw_events.derivations" in row["detections_basis"]


def test_the_window_is_declared_on_every_row(seeded):
    row = onboarding._row({"tenant_id": TENANT,               # noqa: SLF001
                           "endpoint_id": EP_HOT},
                          None, None,
                          {"detections_window": 3, "detections_total": 6,
                           "last_detection_at": _iso(1)}, 168)
    assert row["detections_window_hours"] == 168


# ── Command Intelligence authority ────────────────────────────────
def test_command_intelligence_does_not_read_the_response_plane():
    source = inspect.getsource(edr_router.list_endpoint_commands)
    assert "edr_response_commands" not in source
    assert "response/actions" in source, (
        "the surface must state which authority it is NOT")
    assert "edr_raw_events" in source
    assert "v2_decoded_payloads" in source


def test_the_decoder_join_is_content_addressed_and_batched():
    source = inspect.getsource(edr_router.list_endpoint_commands)
    assert 'sha256(\n                command_line.encode()).hexdigest()' \
        in source or "hashlib.sha256" in source
    assert '{"_id": {"$in": digests}}' in source, (
        "one batched read for the page, never a per-row decode lookup")
