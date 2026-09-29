"""P0-F.13.5 · detection → exact trajectory observation handoff.

The regression this file exists to pin: the resolver read the paging
cursor from a nested ``page`` object that the projection never returns,
so it silently searched only the FIRST page (4 000 observations) and then
reported ``OBSERVATION_NOT_RESOLVED`` with a plausible but WRONG
"missing link" for every detection later in the corpus.
"""
from __future__ import annotations

import uuid

import pytest

import routers.edr as edr

PAGE = 4000
TARGET_RAW = "raw_beyond_the_first_page"

#: OBSOLETE_CONTRACT CORRECTION (B1 wave, 2026-06).
#:
#: OLD CONTRACT (what these tests encoded): `trajectory_focus()` could be
#: called with no tenant and would resolve one itself.
#: WHY WRONG: the route now takes the authoritative tenant as an EXPLICIT
#: injected parameter (`tenant_id: str = Depends(edr_tenant)`, P2 B5/B7 —
#: "authority narrows, it never widens; there is no default tenant"). A
#: direct in-process call that omits it passes FastAPI's `Depends(...)`
#: SENTINEL OBJECT into the authorisation check, so the test was asserting
#: against a refusal caused by its own call shape.
#: NEW CONTRACT: every caller — test or HTTP — names the tenant, and the
#: principal must actually hold it.
#: EVIDENCE: routers/edr.py:1621 `_tenant_scope(user, tenant_id)` →
#: routers/edr_tenancy.py:381 refused with `requested_tenant =
#: Depends(edr_tenant)`.
#: TEST CHANGED: yes. Production authorisation logic UNCHANGED — granting
#: a default tenant to make this pass would be a security regression.
TENANT = "ten_f135_handoff_test"


def _obs(i: int, raw_id: str) -> dict:
    return {"event_iid": f"evt_{i}#d{i}",
            "timestamp": f"2026-09-06T10:{i % 60:02d}:00+00:00",
            "event_type": "process_create", "process_iid": f"proc_{i}",
            "lane_index": i % 500, "lane_id": f"proc::proc_{i}",
            "provenance": {"raw_event_id": raw_id,
                           "canonical_event_id": raw_id.replace("raw_",
                                                                "cev_")}}


@pytest.fixture()
def principal():
    """The suite's OWN authorized principal.

    Previously every test passed `admin@nivxray.com` and depended on that
    user already existing in whatever database the run happened to point
    at: on a fresh CI Mongo `resolve_tenant_scope` found no user, so the
    router correctly refused with 403 and five tests failed for a reason
    that has nothing to do with what they assert. The principal is now
    created here, under a unique identity, and removed afterwards. The
    authorization rule itself is untouched — see
    `test_an_unseeded_principal_is_still_refused`.
    """
    from deps import sync_collection

    email = f"ci-principal-{uuid.uuid4().hex[:10]}@tests.invalid"
    users = sync_collection("users")
    users.insert_one({"email": email, "role": "admin",
                      # The principal must HOLD the tenant it names.
                      "tenant_ids": [TENANT]})
    try:
        yield {"email": email, "role": "admin"}
    finally:
        users.delete_one({"email": email})


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
                                            "tenant_id": TENANT})
    return calls


@pytest.mark.asyncio
async def test_detection_beyond_the_first_page_is_resolved(paged, principal):
    out = await edr.trajectory_focus("dev_test", raw_event_id=TARGET_RAW,
                                     user=principal, tenant_id=TENANT)
    assert out["state"] == "FOCUS_RESOLVED"
    assert out["focus"]["event_iid"] == f"evt_{2 * PAGE}#d{2 * PAGE}"
    # the cursor was actually followed
    assert paged["cursors"] == [None, "cur_page2"]
    assert out["search"]["pages_searched"] == 2
    assert out["search"]["observations_examined"] == 2 * PAGE
    assert out["search"]["cursor_state"] == "EXHAUSTED_SEARCH_COMPLETED"


@pytest.mark.asyncio
async def test_unresolved_reports_the_real_search_scope(paged, principal):
    out = await edr.trajectory_focus("dev_test",
                                     raw_event_id="raw_never_ingested",
                                     user=principal, tenant_id=TENANT)
    assert out["state"] == "OBSERVATION_NOT_RESOLVED"
    assert out["focus"] is None
    # the count is the number actually examined — never a fabricated total
    assert out["search"]["observations_examined"] == 2 * PAGE
    assert out["search"]["pages_searched"] == 2
    assert out["search"]["cursor_state"] == "EXHAUSTED_SEARCH_COMPLETED"
    assert out["search"]["identities_searched"]["raw_event_ids"] == [
        "raw_never_ingested"]


@pytest.mark.asyncio
async def test_no_identifier_is_never_guessed_from_a_timestamp(paged, principal):
    out = await edr.trajectory_focus("dev_test",
                                     user=principal, tenant_id=TENANT)
    assert out["state"] == "NO_IDENTIFIER_SUPPLIED"
    assert out["focus"] is None
    assert paged["n"] == 0          # nothing was even searched


@pytest.mark.asyncio
async def test_unresolvable_endpoint_fails_closed(monkeypatch, principal):
    monkeypatch.setattr(edr.dir_svc, "resolve", lambda ref, scope: None)
    out = await edr.trajectory_focus("dev_does_not_exist",
                                     raw_event_id=TARGET_RAW,
                                     user=principal,
                                     tenant_id=TENANT)
    assert out["state"] == "ENDPOINT_NOT_RESOLVED"
    assert out["focus"] is None


@pytest.mark.asyncio
async def test_pivot_context_is_carried_through(paged, principal):
    out = await edr.trajectory_focus("dev_test", raw_event_id=TARGET_RAW,
                                     user=principal, tenant_id=TENANT)
    ctx = out["context"]
    assert ctx["endpoint_id"] == "dev_test"
    assert ctx["device_iid"] == "dev_test"
    assert ctx["tenant_id"] == TENANT


# ── negative control · the fixture must not have weakened authority ──
@pytest.mark.asyncio
async def test_an_unseeded_principal_is_still_refused(paged):
    """The five tests above pass because they CREATE an authorized
    principal, never because authorization was relaxed. A principal the
    registry does not know must still be refused outright."""
    from fastapi import HTTPException

    unknown = {"email": f"nobody-{uuid.uuid4().hex[:8]}@tests.invalid",
               "role": "analyst"}
    with pytest.raises(HTTPException) as ex:
        await edr.trajectory_focus("dev_test", raw_event_id=TARGET_RAW,
                                   user=unknown, tenant_id=TENANT)
    assert ex.value.status_code == 403
    assert ex.value.detail["code"] == "TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL"
    assert paged["n"] == 0, "a refused principal must not search anything"


@pytest.mark.asyncio
async def test_an_anonymous_caller_is_refused(paged):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as ex:
        await edr.trajectory_focus("dev_test", raw_event_id=TARGET_RAW,
                                   user={}, tenant_id=TENANT)
    assert ex.value.status_code == 403
    assert ex.value.detail["code"] == "ACCESS_DENIED"
