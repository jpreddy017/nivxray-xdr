"""The V3 deep-link route must carry the resolver's outcome WITHOUT re-interpreting it.

Authenticated, in-process calls through the real route function with the real authorisation
dependencies satisfied. The resolver itself is stubbed per case so each outcome can be driven
deterministically — what is under test here is the ROUTE's translation, which is where an
unfinished search could still arrive at the UI wearing the words "not found", and where an
offered candidate could arrive without an identity the UI can navigate by.
"""
from __future__ import annotations

import uuid

import pytest


import routers.edr as edr
from edr_trajectory import production_adapter as pa
from edr_trajectory import v3_presentation as e3v3
from edr_trajectory.identity import encode_identity

TENANT = "ten_focus_route_test"
ENDPOINT = "dev_focus_route"


@pytest.fixture(autouse=True)
def _bound_db(bound_db):
    """Every test in this module needs `deps.db` bound to its own loop (see tests/edr/conftest)."""
    return bound_db


@pytest.fixture()
def principal():
    """An authorized principal that actually HOLDS the tenant it names."""
    from deps import sync_collection

    email = f"ci-focus-route-{uuid.uuid4().hex[:10]}@tests.invalid"
    users = sync_collection("users")
    users.insert_one({"email": email, "role": "admin", "tenant_ids": [TENANT]})
    try:
        yield {"email": email, "role": "admin"}
    finally:
        users.delete_one({"email": email})


class _Resolved:
    identity = {"tenant_id": TENANT, "device_iid": ENDPOINT, "hostname": "host-focus"}
    refs = [ENDPOINT]

    def predicate(self, _collection):
        return {"tenant_id": TENANT, "endpoint_id": ENDPOINT}

    def descriptor(self):
        return {"endpoint_id": ENDPOINT, "hostname": "host-focus"}


@pytest.fixture()
def route(monkeypatch, principal):
    """Call the route with the endpoint resolved and ONE stubbed resolver outcome."""
    monkeypatch.setattr(edr.eq, "resolve_endpoint", lambda ref, scope: _Resolved())

    def _with(deep=None, raise_with=None, seen=None):
        async def fake_resolve(_db, **kw):
            if seen is not None:
                seen.update(kw)
            if raise_with is not None:
                raise raise_with
            return deep

        monkeypatch.setattr(pa, "resolve_evidence", fake_resolve)
        iid = e3v3.encode_iid(encode_identity((0, "target")))
        return iid, lambda **kw: edr.trajectory_focus(
            ENDPOINT, event_iid=iid, user=principal, tenant_id=TENANT, **kw)

    return _with


# ── the three non-resolved outcomes keep their own words ──────────────────────

@pytest.mark.asyncio
async def test_an_incomplete_search_is_not_reported_as_not_resolved(route):
    _iid, call = route({"state": pa.FOCUS_SEARCH_INCOMPLETE,
                        "reason": "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE",
                        "event": None, "scanned": 4000,
                        "search": {"state": "PAGE_BUDGET_REACHED_8"},
                        "scope": {"applied": False},
                        "partial_matches": [{"event_id": encode_identity((0, "a"))}],
                        "retry": {"retryable": True},
                        "meaning": "neither proof"})
    out = await call()
    assert out["state"] == "OBSERVATION_LOOKUP_INCOMPLETE"
    assert out["lookup_complete"] is False
    assert out["focus"] is None
    assert out["observations_searched"] == 4000
    assert out["retry"]["retryable"] is True
    # a partial match is disclosed, and it too is navigable
    assert out["partial_matches"][0]["event_iid"]


@pytest.mark.asyncio
async def test_an_ambiguous_identifier_is_offered_never_narrowed(route):
    a, b = encode_identity((0, "dup")), encode_identity((1, "dup"))
    _iid, call = route({"state": "FOCUS_AMBIGUOUS",
                        "reason": "LEGACY_IDENTITY_MATCHES_MULTIPLE_ROWS",
                        "event": None,
                        "candidates": [{"event_id": a, "identity_keys": [(0, "dup")]},
                                       {"event_id": b, "identity_keys": [(1, "dup")]}],
                        "search": {"state": "AMBIGUITY_PROVEN_SEARCH_STOPPED"},
                        "retry": {"retryable": False}})
    out = await call()
    assert out["state"] == "OBSERVATION_IDENTIFIER_AMBIGUOUS"
    assert out["lookup_complete"] is False
    assert out["focus"] is None
    assert len(out["candidates"]) == 2
    assert out["retry"]["retryable"] is False


@pytest.mark.asyncio
async def test_every_offered_candidate_carries_a_navigable_presentation_identity(route):
    """THE DEFECT THIS PINS: candidates were returned with the §d evidence identity only.

    `decode_iid` deliberately rejects anything outside the V3 namespace, so a button built from
    `event_id` could never resolve — the UI would offer a choice it could not act on.
    """
    a = encode_identity((0, "dup"))
    _iid, call = route({"state": "FOCUS_AMBIGUOUS", "event": None,
                        "candidates": [{"event_id": a, "identity_keys": [(0, "dup")]}],
                        "retry": {"retryable": False}})
    out = await call()
    cand = out["candidates"][0]
    assert cand["event_id"] == a
    assert cand["event_iid"] == e3v3.encode_iid(a)
    # and it round-trips: the UI's own decoder accepts what the route handed it
    assert e3v3.decode_iid(cand["event_iid"]) == a
    # proof the bare evidence identity would NOT have worked
    assert e3v3.decode_iid(a) is None


@pytest.mark.asyncio
async def test_a_completed_zero_match_search_is_the_only_not_resolved(route):
    _iid, call = route({"state": "FOCUS_NOT_RESOLVED",
                        "reason": "EVIDENCE_IDENTITY_NOT_FOUND_FOR_THIS_ENDPOINT",
                        "event": None, "scanned": 12,
                        "search": {"state": "EXHAUSTED_SEARCH_COMPLETED",
                                   "stores_unavailable": []},
                        "scope": {"applied": False}})
    out = await call()
    assert out["state"] == "OBSERVATION_NOT_RESOLVED"
    assert out["lookup_complete"] is True
    assert out["focus"] is None
    assert "no observation on this endpoint" in out["missing_link"]


@pytest.mark.asyncio
async def test_an_authority_failure_declares_itself_incomplete(route):
    _iid, call = route(raise_with=RuntimeError("store unreachable"))
    out = await call()
    assert out["state"] == "FOCUS_AUTHORITY_UNAVAILABLE"
    assert out["lookup_complete"] is False
    assert out["focus"] is None
    assert "NOT a" in out["meaning"]


# ── scoped lookup reaches the resolver ────────────────────────────────────────

@pytest.mark.asyncio
async def test_the_requested_scope_is_passed_to_the_resolver_and_reported_back(route):
    seen: dict = {}
    _iid, call = route({"state": pa.FOCUS_SEARCH_INCOMPLETE,
                        "reason": "SCOPED_SEARCH_FOUND_NOTHING_IN_THE_REQUESTED_WINDOW",
                        "event": None,
                        "scope": {"applied": True,
                                  "time_start": "2026-06-01T00:00:00+00:00",
                                  "time_end": "2026-06-01T06:00:00+00:00"},
                        "retry": {"retryable": True}}, seen=seen)
    out = await call(time_start="2026-06-01T00:00:00+00:00",
                     time_end="2026-06-01T06:00:00+00:00")
    assert seen["time_start"] == "2026-06-01T00:00:00+00:00"
    assert seen["time_end"] == "2026-06-01T06:00:00+00:00"
    # the tenant and endpoint bounds are NOT widened by a scope
    assert seen["tenant_id"] == TENANT
    assert seen["refs"] == [ENDPOINT]
    assert out["scope"]["applied"] is True


@pytest.mark.asyncio
async def test_an_unscoped_lookup_sends_no_bounds(route):
    seen: dict = {}
    _iid, call = route({"state": "FOCUS_NOT_RESOLVED", "event": None,
                        "search": {"state": "EXHAUSTED_SEARCH_COMPLETED"}}, seen=seen)
    await call()
    assert seen["time_start"] is None and seen["time_end"] is None


# ── a resolved deep link still resolves ───────────────────────────────────────

@pytest.mark.asyncio
async def test_a_resolved_lookup_returns_a_focus_the_ui_can_navigate_to(route):
    eid = encode_identity((0, "target"))
    _iid, call = route({"state": "FOCUS_RESOLVED", "event_id": eid,
                        "observed_at": "2026-06-01T00:30:00+00:00",
                        "event": {"event_id": eid, "kind": "PROCESS_START",
                                  "observed_at": "2026-06-01T00:30:00+00:00",
                                  "observed_ms": 1780273800000,
                                  "provenance": {"ref": "obs_1"}},
                        "position": {"scanned_newer_first": 3},
                        "provenance": {"ordering_authority": "STORED_OBSERVATION_TIME"}})
    out = await call()
    assert out["state"] == "FOCUS_RESOLVED"
    assert out["focus"]["event_id"] == eid
    assert e3v3.decode_iid(out["focus"]["event_iid"]) == eid
    assert out["focus"]["window"]["time_start"] < out["focus"]["window"]["time_end"]
