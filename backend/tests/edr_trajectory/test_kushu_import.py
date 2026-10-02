import os

import pytest
from fastapi import HTTPException

from edr_trajectory import kushu_import as kx

pytestmark = pytest.mark.skipif(not os.environ.get("MONGO_URL"), reason="needs a local MongoDB (preview DB only)")
DEV = "dev_test_import"
T = 1_790_000_000_000


@pytest.fixture
async def db():
    from motor.motor_asyncio import AsyncIOMotorClient
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c["e3_dt_preview_pytest_import"]
    await c.drop_database("e3_dt_preview_pytest_import")


def _ev(i, **k):
    return {"event_iid": f"obs_{i:012x}#{i:010x}", "observation_id": f"obs_{i:012x}", "timestamp_instant_ms": T + i * 1000,
            "timestamp": kx._iso(T + i * 1000), "event_type": "process_create", "lane_id": f"proc::{i % 3}",
            "lane_label": f"p{i % 3}.exe", "image": f"C:\\p{i % 3}.exe", **k}


def _body(evs, **k):
    return {"format": kx.FORMAT, "device": DEV, "source_origin": "https://prod.example", "events": evs, **k}


async def test_ingest_is_idempotent_and_rejects_bad_rows(db):
    r1 = await kx.ingest(db, _body([_ev(i) for i in range(10)] + [{"x": 1}]))
    r2 = await kx.ingest(db, _body([_ev(i) for i in range(5, 12)]))
    assert (r1["accepted"], r1["rejected"], r2["stored_total"]) == (10, 1, 12)
    with pytest.raises(HTTPException):
        await kx.ingest(db, {"format": "nope", "device": DEV, "events": []})


async def test_newest_first_paging_covers_window_without_dupes(db):
    await kx.ingest(db, _body([_ev(i) for i in range(1200)]))
    m = await kx.meta_for(db, DEV)
    first = await kx.trajectory(db, m, limit=500)
    assert first["events"][-1]["event_iid"] == _ev(1199)["event_iid"]
    seen, before = [e["event_iid"] for e in first["events"]], first["e3_preview"]["older_cursor"]
    while before:
        p = await kx.trajectory(db, m, limit=500, before=before)
        seen = [e["event_iid"] for e in p["events"]] + seen
        before = p["e3_preview"]["older_cursor"]
    assert len(seen) == len(set(seen)) == 1200


async def test_deep_link_focus_and_detection_mapping(db):
    await kx.ingest(db, _body([_ev(i) for i in range(50)] + [_ev(77, is_detection=True, detection={"name": "X", "severity": "high"})]))
    m = await kx.meta_for(db, DEV)
    f = await kx.focus(db, m, event_iid=_ev(3)["event_iid"])
    assert f["state"] == "FOCUS_RESOLVED" and f["focus"]["observation_id"] == "obs_000000000003"
    assert (await kx.focus(db, m, event_iid="obs_nope#0"))["state"] == "OBSERVATION_NOT_RESOLVED"
    page = await kx.trajectory(db, m, limit=10)
    det = next(e for e in page["events"] if e.get("e3_detection"))
    assert det["e3_detection"]["severity"] == "HIGH" and det["e3_detection"]["is_verdict"] is False


async def test_trace_shows_oldest_first_drops_newest(db):
    await kx.ingest(db, _body([_ev(i) for i in range(1200)]))
    m = await kx.meta_for(db, DEV)
    out = await kx.trace(db, m, event_iid=None, now_ms=T + 1200 * 1000, limit=500)
    assert out["e1_disappears_at"] == "4_page_selection_oldest_first" and out["e3_disappears_at"] is None
