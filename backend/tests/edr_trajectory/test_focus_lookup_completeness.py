"""Deep-link lookup COMPLETENESS — an unfinished search is not an answer.

The versioned identity encoding made exported ids unambiguous, but a LEGACY bare id stays
non-unique: the same text can name rows in more than one identity namespace. Resolving a single
legacy match therefore depends on whether the relevant search actually finished. These tests pin
the three outcomes apart:

  * FOCUS_RESOLVED          — exact identity, or ONE legacy match after a COMPLETED exhaustive
                              search over every requested store.
  * FOCUS_AMBIGUOUS         — two verified matches; reported as soon as it is proven.
  * FOCUS_SEARCH_INCOMPLETE — budget reached, continuation remaining, or a store that could not
                              be read. `event` is None and NOTHING is claimed either way.

Only a completed zero-match search may say FOCUS_NOT_RESOLVED.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from edr_trajectory import production_adapter as pa
from edr_trajectory import production_service as ps
from edr_trajectory import v3_presentation as v3
from edr_trajectory.identity import encode_identity
from test_sd_production_adapter import DEV, T, FakeDB, shadow_doc

SHADOW = (pa.STORE_SHADOW,)
BOTH = (pa.STORE_SHADOW, pa.STORE_CANONICAL)


def doc(seconds: int, *, activity: str | None = None, canonical: str | None = None,
        tenant: str = T, device: str = DEV) -> dict[str, Any]:
    """One shadow observation with EXPLICIT identity fields.

    `activity` lands at rank 0 and `canonical` at rank 1, so the same TEXT can be placed in two
    different namespaces — which is exactly how a legacy bare id becomes non-unique.
    """
    ts = f"2026-06-01T00:00:{seconds:02d}+00:00"
    d = shadow_doc(ts, seconds, tenant=tenant, device=device)
    d["activity_identity"] = activity if activity is not None else f"act_{seconds}"
    if canonical is not None:
        d["canonical_event_id"] = canonical
    return d


def resolve(db, event_id, *, tenant=T, stores=SHADOW, max_pages=pa.FOCUS_PAGE_BUDGET,
            refs=(DEV,)):
    return asyncio.run(pa.resolve_evidence(db, tenant_id=tenant, refs=list(refs),
                                           event_id=event_id, max_pages=max_pages,
                                           stores=stores))


@pytest.fixture
def tiny_pages(monkeypatch):
    """Two observations per page, so a budget can be reached without 1,000 fixtures."""
    monkeypatch.setattr(pa, "PAGE_MAX", 2)
    return 2


class Unreadable:
    """A collection whose read FAILS. Its rows are never compared, so they prove nothing."""

    def __init__(self, exc=RuntimeError):
        self.exc = exc

    def find(self, flt, projection=None):
        raise self.exc("evidence store unavailable")


# ── A. a single legacy match only counts after a COMPLETED search ─────────────

def test_one_match_inside_budget_with_a_second_beyond_it_is_never_resolved(tiny_pages):
    """The decisive case. One match is visible; a second exists past the searched range.

    Resolving the visible one would be a silent, wrong choice between two rows — and the caller
    could not tell, because the response would look like an ordinary success.
    """
    db = FakeDB(shadow=[doc(6, activity="same"),          # newest, inside the budget
                        doc(5), doc(4), doc(3),
                        doc(2, activity="act_2", canonical="same"),   # beyond the budget
                        doc(1)])
    got = resolve(db, "same", max_pages=2)
    assert got["state"] == pa.FOCUS_SEARCH_INCOMPLETE
    assert got["event"] is None
    assert got["reason"] == "SEARCH_BUDGET_REACHED_BEFORE_EXHAUSTING_RETAINED_EVIDENCE"
    # the match that WAS seen is disclosed as partial, never promoted to the answer
    assert len(got["partial_matches"]) == 1
    assert got["search"]["continuation_available"] is True
    assert got["retry"]["retryable"] is True


def test_the_same_fixture_resolves_once_the_search_is_allowed_to_finish(tiny_pages):
    """Same data, bigger budget: now the second match is SEEN, and ambiguity is reported."""
    db = FakeDB(shadow=[doc(6, activity="same"), doc(5), doc(4), doc(3),
                        doc(2, activity="act_2", canonical="same"), doc(1)])
    got = resolve(db, "same", max_pages=8)
    assert got["state"] == "FOCUS_AMBIGUOUS"
    assert got["event"] is None
    assert len(got["candidates"]) == 2


def test_zero_matches_before_budget_exhaustion_is_incomplete_not_absent(tiny_pages):
    """A capped walk that found nothing has NOT shown that the endpoint never held it."""
    db = FakeDB(shadow=[doc(n) for n in range(6, 0, -1)])
    got = resolve(db, "never_stored", max_pages=2)
    assert got["state"] == pa.FOCUS_SEARCH_INCOMPLETE
    assert got["state"] != "FOCUS_NOT_RESOLVED"
    assert got["event"] is None
    assert got["partial_matches"] == []
    assert got["search"]["state"] == "PAGE_BUDGET_REACHED_2"
    assert got["search"]["continuation_available"] is True


def test_last_allowed_page_exhausts_the_data_and_one_match_resolves(tiny_pages):
    """The budget was reached AND the evidence ran out on the same page: that is exhaustive."""
    db = FakeDB(shadow=[doc(4), doc(3), doc(2), doc(1, activity="only_one")])
    got = resolve(db, "only_one", max_pages=2)
    assert got["state"] == "FOCUS_RESOLVED"
    assert got["resolved_via"] == "LEGACY_IDENTITY_ALIAS"
    assert got["search"]["state"] == "EXHAUSTED_SEARCH_COMPLETED"
    assert got["search"]["continuation_available"] is False
    assert got["uniqueness_basis"]


def test_a_completed_zero_match_search_is_the_only_path_to_not_resolved():
    db = FakeDB(shadow=[doc(2), doc(1)])
    got = resolve(db, "never_stored")
    assert got["state"] == "FOCUS_NOT_RESOLVED"
    assert got["event"] is None
    assert got["search"]["state"] == "EXHAUSTED_SEARCH_COMPLETED"
    assert got["search"]["stores_unavailable"] == []


# ── B. two verified matches are enough ────────────────────────────────────────

def test_two_known_matches_report_ambiguity_immediately():
    """Ambiguity is PROVEN by what was read, so the walk stops instead of running the budget."""
    db = FakeDB(shadow=[doc(9, activity="dup"),
                        doc(8, activity="act_8", canonical="dup")] +
                       [doc(n) for n in range(7, 0, -1)])
    got = resolve(db, "dup")
    assert got["state"] == "FOCUS_AMBIGUOUS"
    assert got["event"] is None
    assert got["search"]["state"] == "AMBIGUITY_PROVEN_SEARCH_STOPPED"
    assert {c["event_id"] for c in got["candidates"]} == {encode_identity((0, "dup")),
                                                          encode_identity((0, "act_8"))}
    # there is nothing to retry: a wider search cannot make a non-unique id unique
    assert got["retry"]["retryable"] is False


def test_duplicate_representations_of_one_activity_resolve_as_one_row():
    """Two documents stating the SAME identity are one activity, not two candidates."""
    a = doc(5, activity="act_dup")
    b = doc(4, activity="act_dup")
    got = resolve(FakeDB(shadow=[a, b]), "act_dup")
    assert got["state"] == "FOCUS_RESOLVED"
    assert got["event"]["event_id"] == encode_identity((0, "act_dup"))
    assert got["resolved_via"] == "LEGACY_IDENTITY_ALIAS"


# ── C. a store that could not be read proves nothing ──────────────────────────

def test_a_failed_store_read_marks_the_page_incomplete():
    db = FakeDB(shadow=[doc(2), doc(1)])
    db._c[pa.STORE_CANONICAL] = Unreadable()
    page = asyncio.run(pa.page_device_evidence(db, tenant_id=T, refs=[DEV], stores=BOTH))
    assert page["state"] == pa.PARTIAL_STORE_READ
    assert page["provenance"]["read_complete"] is False
    assert page["provenance"]["stores_unavailable"] == [pa.STORE_CANONICAL]
    assert page["provenance"]["stores_read"] == [pa.STORE_SHADOW]
    # the rows that WERE read are still real evidence
    assert len(page["items"]) == 2


def test_a_partial_store_read_can_neither_find_nor_deny():
    """A zero-match result over a store set that was not fully readable is not a result."""
    db = FakeDB(shadow=[doc(2), doc(1)])
    db._c[pa.STORE_CANONICAL] = Unreadable()
    got = resolve(db, "never_stored", stores=BOTH)
    assert got["state"] == pa.FOCUS_SEARCH_INCOMPLETE
    assert got["event"] is None
    assert got["reason"] == "EVIDENCE_STORE_READ_INCOMPLETE"
    assert got["search"]["stores_unavailable"] == [pa.STORE_CANONICAL]


def test_a_partial_store_read_does_not_resolve_a_single_legacy_match():
    """Even WITH a match in hand: the unread store could hold the second one."""
    db = FakeDB(shadow=[doc(2, activity="same"), doc(1)])
    db._c[pa.STORE_CANONICAL] = Unreadable()
    got = resolve(db, "same", stores=BOTH)
    assert got["state"] == pa.FOCUS_SEARCH_INCOMPLETE
    assert got["event"] is None
    assert [m["event_id"] for m in got["partial_matches"]] == [encode_identity((0, "same"))]


def test_an_exact_versioned_identity_still_resolves_through_a_partial_read():
    """The encoding names ONE identity group, so a verified exact hit needs no further search."""
    db = FakeDB(shadow=[doc(2, activity="target"), doc(1)])
    db._c[pa.STORE_CANONICAL] = Unreadable()
    got = resolve(db, encode_identity((0, "target")), stores=BOTH)
    assert got["state"] == "FOCUS_RESOLVED"
    assert got["resolved_via"] == "VERSIONED_EVIDENCE_IDENTITY"


# ── D. tenant isolation ───────────────────────────────────────────────────────

def test_a_legacy_identity_never_crosses_a_tenant_boundary():
    """The same bare id in two customers is two different things, and only one is authorized."""
    other = "ten_other"
    db = FakeDB(shadow=[doc(2, activity="shared", tenant=T),
                        doc(1, activity="shared", tenant=other)])
    mine = resolve(db, "shared", tenant=T)
    assert mine["state"] == "FOCUS_RESOLVED"
    assert mine["event"]["tenant_id"] == T

    theirs = resolve(db, "shared", tenant=other)
    assert theirs["state"] == "FOCUS_RESOLVED"
    assert theirs["event"]["tenant_id"] == other
    # the cross-tenant duplicate is NOT a second candidate for either side
    assert "candidates" not in mine and "candidates" not in theirs


def test_an_identity_held_only_by_another_tenant_is_reported_absent_not_ambiguous():
    db = FakeDB(shadow=[doc(1, activity="theirs_only", tenant="ten_other")])
    got = resolve(db, "theirs_only", tenant=T)
    assert got["state"] == "FOCUS_NOT_RESOLVED"
    assert got["event"] is None


# ── E. malformed and encoding-shaped identifiers are never guessed ────────────

def test_a_raw_value_that_looks_encoded_is_not_resolved_by_decoding_its_text():
    """A stored raw identity may LITERALLY read "e3i1:0:...". Matching it as if the text named
    the namespace it spells out would be a guess, so the legacy path is closed for anything that
    parses as the encoding."""
    lookalike = encode_identity((0, "same"))
    db = FakeDB(shadow=[doc(2, activity=lookalike)])
    got = resolve(db, lookalike)
    # the row's OWN identity is encode((0, lookalike)) — not `lookalike` itself
    assert got["state"] == "FOCUS_NOT_RESOLVED"
    assert got["event"] is None


def test_the_genuine_encoded_identity_still_wins_over_a_raw_lookalike():
    """Both present: the exact-identity match decides, and the lookalike is not consulted."""
    lookalike = encode_identity((0, "same"))
    db = FakeDB(shadow=[doc(3, activity=lookalike), doc(2, activity="same")])
    got = resolve(db, lookalike)
    assert got["state"] == "FOCUS_RESOLVED"
    assert got["event"]["identity_keys"] == [(0, "same")]


@pytest.mark.parametrize("bad", ["e3i1:x:YQ", "e3i2:0:YQ", "e3i1:0", "", ":::", "e3i1::YQ"])
def test_malformed_identifiers_match_nothing_and_are_never_repaired(bad):
    db = FakeDB(shadow=[doc(2, activity="act_2"), doc(1)])
    got = resolve(db, bad) if bad else resolve(db, None)
    assert got["event"] is None
    assert got["state"] in (pa.FOCUS_SEARCH_INCOMPLETE, "FOCUS_NOT_RESOLVED")


# ── F. the state survives the service and presentation layers ─────────────────

def trajectory(db, focus_event_id, *, page_size=50, stores=SHADOW):
    return asyncio.run(ps.device_trajectory(db, tenant_id=T, refs=[DEV], endpoint_id=DEV,
                                            page_size=page_size, stores=stores,
                                            focus_event_id=focus_event_id))


def test_production_service_reports_ambiguity_without_choosing_a_row():
    db = FakeDB(shadow=[doc(9, activity="dup"), doc(8, activity="act_8", canonical="dup")])
    focus = trajectory(db, "dup")["focus"]
    assert focus["state"] == "FOCUS_AMBIGUOUS"
    assert focus["details"] is None
    assert len(focus["candidates"]) == 2


def test_production_service_reports_an_incomplete_lookup_as_incomplete(tiny_pages):
    # 20 observations at 2 per page: the default 8-page budget cannot reach the oldest.
    db = FakeDB(shadow=[doc(n) for n in range(20, 0, -1)])
    focus = asyncio.run(ps.device_trajectory(db, tenant_id=T, refs=[DEV], endpoint_id=DEV,
                                             page_size=2, stores=SHADOW,
                                             focus_event_id="never_stored"))["focus"]
    assert focus["state"] == pa.FOCUS_SEARCH_INCOMPLETE
    assert focus["details"] is None
    assert focus["retry"]["retryable"] is True


def test_production_service_never_resolves_a_legacy_hit_from_the_loaded_page_alone():
    """The loaded page holds one match; a second lives further back. In-page convenience must
    not short-circuit the only search that can count the matches."""
    db = FakeDB(shadow=[doc(9, activity="dup"), doc(8), doc(7),
                        doc(6, activity="act_6", canonical="dup")])
    focus = trajectory(db, "dup", page_size=2)["focus"]
    assert focus["state"] == "FOCUS_AMBIGUOUS"
    assert focus["details"] is None


def test_production_service_still_resolves_an_exact_identity_inside_the_page():
    db = FakeDB(shadow=[doc(2, activity="target"), doc(1)])
    focus = trajectory(db, encode_identity((0, "target")))["focus"]
    assert focus["state"] == "FOCUS_RESOLVED"
    assert focus["basis"] == "RESOLVED_WITHIN_LOADED_PAGE"
    assert focus["details"] is not None


def test_an_empty_page_does_not_turn_an_unfinished_lookup_into_an_absence():
    """No rows in the window, but the identity search is a separate, unwindowed question."""
    db = FakeDB(shadow=[doc(2), doc(1)])
    db._c[pa.STORE_CANONICAL] = Unreadable()
    out = asyncio.run(ps.device_trajectory(
        db, tenant_id=T, refs=[DEV], endpoint_id=DEV, stores=BOTH,
        time_start="2030-01-01T00:00:00+00:00", time_end="2030-01-02T00:00:00+00:00",
        focus_event_id="never_stored"))
    assert out["page"]["items"] == []
    assert out["focus"]["state"] == pa.FOCUS_SEARCH_INCOMPLETE
    assert out["focus"]["details"] is None


@pytest.mark.parametrize("state,complete", [("FOCUS_RESOLVED", True),
                                            ("FOCUS_NOT_RESOLVED", True),
                                            ("FOCUS_AMBIGUOUS", False),
                                            (pa.FOCUS_SEARCH_INCOMPLETE, False)])
def test_v3_presentation_carries_every_focus_state_without_flattening_it(state, complete):
    out = v3._focus_v3({"state": state, "event_id": encode_identity((0, "a")),
                        "reason": "R", "candidates": [{"event_id": encode_identity((1, "b"))}],
                        "search": {"state": "S"}, "retry": {"retryable": True}})
    assert out["state"] == state
    assert out["lookup_complete"] is complete
    if state == "FOCUS_RESOLVED":
        assert out["event_id"]
    else:
        assert out["event_id"] is None
        assert out["reason"] == "R"


def test_v3_presentation_offers_candidates_as_v3_identities_and_selects_none():
    out = v3._focus_v3({"state": "FOCUS_AMBIGUOUS", "event_id": "dup",
                        "candidates": [{"event_id": encode_identity((0, "a"))},
                                       {"event_id": encode_identity((1, "a"))}]})
    assert out["event_id"] is None
    assert len(out["candidates"]) == 2
    assert all(c["event_iid"] for c in out["candidates"])
