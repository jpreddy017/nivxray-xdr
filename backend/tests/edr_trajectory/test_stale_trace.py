import os
import time

import pytest
import pytest_asyncio

from edr_plane.instant import instant_ms
from edr_trajectory import e1_shape_preview as pv
from edr_trajectory import prodshape as ps
from edr_trajectory.stale_trace import trace

pytestmark = pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                                reason="needs a local MongoDB (preview DB only)")


@pytest_asyncio.fixture
async def seeded(monkeypatch):
    monkeypatch.setenv("E3_PREVIEW_DB", "e3_dt_preview_pytest")
    pv._state.clear()
    pv._state.update({"ident": None, "lock": None})
    meta = await pv.ensure_seeded(force=True)
    yield meta
    await pv._db().client.drop_database("e3_dt_preview_pytest")
    pv._state.clear()
    pv._state.update({"ident": None, "lock": None})


@pytest.mark.asyncio
async def test_newest_observation_vanishes_at_e1_page_selection_and_survives_newest_first(seeded):
    out = await trace(pv._db(), pv._state["ident"], pv._refs(pv._state["ident"]), observation_id=None,
                      now_ms=int(time.time() * 1000))
    assert all(s["present"] for s in out["stages"])
    assert out["e1_disappears_at"] == "4_page_selection_oldest_first"
    assert out["e3_disappears_at"] is None
    assert out["e3"]["row_model"]["present"]
    assert out["e1"]["page_selection"]["matched_in_window"] > 500
    assert out["e3"]["page_selection"]["remaining_older"] == out["e1"]["page_selection"]["matched_in_window"] - 500
    assert not out["e1_deep_link_locate"]["present"] and out["e1_deep_link_locate"]["observations_examined"] == 15000


@pytest.mark.asyncio
async def test_paging_into_history_loses_and_duplicates_nothing(seeded):
    t1 = int(time.time() * 1000)
    q = {"time_start": ps._iso(t1 - ps.D), "time_end": ps._iso(t1), "lane_start": 0, "lane_end": 100000,
         "cursor": None, "kinds": None, "q": None, "dispositions": None, "hist_day": None}
    first = await pv.trajectory("e3", **q, limit=500)
    seen = [e["event_iid"] for e in first["events"]]
    before = first["e3_preview"]["older_cursor"]
    while before:
        page = await pv.trajectory("e3", **q, limit=500, before=before)
        seen = [e["event_iid"] for e in page["events"]] + seen
        before = page["e3_preview"]["older_cursor"]
    assert len(seen) == len(set(seen)) == first["e3_preview"]["window_rows"]


def test_timestamp_text_sort_is_not_time_order():
    mixed = ["2026-10-02 07:10:00.000", "2026-10-02T06:00:00.000Z", "2026-10-02 05:00:00.000", "2026-10-02T07:20:00.000Z"]
    text_desc = sorted(mixed, reverse=True)
    true_desc = sorted(mixed, key=instant_ms, reverse=True)
    assert text_desc != true_desc
    assert text_desc[0] == "2026-10-02T07:20:00.000Z" and text_desc[1] == "2026-10-02T06:00:00.000Z"
    assert true_desc[:2] == ["2026-10-02T07:20:00.000Z", "2026-10-02 07:10:00.000"]
