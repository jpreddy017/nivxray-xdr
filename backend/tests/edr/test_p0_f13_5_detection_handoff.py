"""P0-F.13.5 · detection → exact trajectory observation handoff.

The regression this file exists to pin: the resolver read the paging
cursor from a nested ``page`` object that the projection never returns,
so it silently searched only the FIRST page (4 000 observations) and then
reported ``OBSERVATION_NOT_RESOLVED`` with a plausible but WRONG
"missing link" for every detection later in the corpus.
"""
from __future__ import annotations

import pytest

import routers.edr as edr


PAGE = 4000
TARGET_RAW = "raw_beyond_the_first_page"


def _obs(i: int, raw_id: str) -> dict:
    return {"event_iid": f"evt_{i}#d{i}",
            "timestamp": f"2026-09-06T10:{i % 60:02d}:00+00:00",
            "event_type": "process_create", "process_iid": f"proc_{i}",
            "lane_index": i % 500, "lane_id": f"proc::proc_{i}",
            "provenance": {"raw_event_id": raw_id,
                           "canonical_event_id": raw_id.replace("raw_",
                                                                "cev_")}}


@pytest.fixture()
def paged(monkeypatch):
    """Two pages; the target observation is the LAST row of page 2."""
    pages = [
        [_obs(i, f"raw_page1_{i}") for i in range(PAGE)],
        ([_obs(PAGE + i, f"raw_page2_{i}") for i in range(PAGE - 1)]
         + [_obs(2 * PAGE, TARGET_RAW)]),
    ]
    calls = {"n": 0, "cursors": []}

    async def fake_query_window(_db, **kw):
        calls["cursors"].append(kw.get("cursor"))
        idx = calls["n"]
        calls["n"] += 1
        return {"events": pages[idx] if idx < len(pages) else [],
                "next_cursor": "cur_page2" if idx == 0 else None}

    from edr_plane import trajectory_window as tw
    monkeypatch.setattr(tw, "query_window", fake_query_window)
    monkeypatch.setattr(edr.dir_svc, "resolve",
                        lambda ref, scope: {"device_iid": "dev_test",
                                            "hostname": "host-test",
                                            "tenant_id": "default"})
    return calls


@pytest.mark.asyncio
async def test_detection_beyond_the_first_page_is_resolved(paged):
    out = await edr.trajectory_focus("dev_test", raw_event_id=TARGET_RAW,
                                     user={"email": "admin@nivxray.com",
                                           "role": "admin"})
    assert out["state"] == "FOCUS_RESOLVED"
    assert out["focus"]["event_iid"] == f"evt_{2 * PAGE}#d{2 * PAGE}"
    # the cursor was actually followed
    assert paged["cursors"] == [None, "cur_page2"]
    assert out["search"]["pages_searched"] == 2
    assert out["search"]["observations_examined"] == 2 * PAGE
    assert out["search"]["cursor_state"] == "EXHAUSTED_SEARCH_COMPLETED"


@pytest.mark.asyncio
async def test_unresolved_reports_the_real_search_scope(paged):
    out = await edr.trajectory_focus("dev_test",
                                     raw_event_id="raw_never_ingested",
                                     user={"email": "admin@nivxray.com",
                                           "role": "admin"})
    assert out["state"] == "OBSERVATION_NOT_RESOLVED"
    assert out["focus"] is None
    # the count is the number actually examined — never a fabricated total
    assert out["search"]["observations_examined"] == 2 * PAGE
    assert out["search"]["pages_searched"] == 2
    assert out["search"]["cursor_state"] == "EXHAUSTED_SEARCH_COMPLETED"
    assert out["search"]["identities_searched"]["raw_event_ids"] == [
        "raw_never_ingested"]


@pytest.mark.asyncio
async def test_no_identifier_is_never_guessed_from_a_timestamp(paged):
    out = await edr.trajectory_focus("dev_test",
                                     user={"email": "admin@nivxray.com",
                                           "role": "admin"})
    assert out["state"] == "NO_IDENTIFIER_SUPPLIED"
    assert out["focus"] is None
    assert paged["n"] == 0          # nothing was even searched


@pytest.mark.asyncio
async def test_unresolvable_endpoint_fails_closed(monkeypatch):
    monkeypatch.setattr(edr.dir_svc, "resolve", lambda ref, scope: None)
    out = await edr.trajectory_focus("dev_does_not_exist",
                                     raw_event_id=TARGET_RAW,
                                     user={"email": "a@b.c",
                                           "role": "analyst"})
    assert out["state"] == "ENDPOINT_NOT_RESOLVED"
    assert out["focus"] is None


@pytest.mark.asyncio
async def test_pivot_context_is_carried_through(paged):
    out = await edr.trajectory_focus("dev_test", raw_event_id=TARGET_RAW,
                                     user={"email": "admin@nivxray.com",
                                           "role": "admin"})
    ctx = out["context"]
    assert ctx["endpoint_id"] == "dev_test"
    assert ctx["device_iid"] == "dev_test"
    assert ctx["tenant_id"] == "default"
