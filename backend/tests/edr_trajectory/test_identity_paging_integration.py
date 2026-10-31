"""Pagination integration cover for the versioned identity contract.

Runs against the real paged adapter and a populated endpoint, because cursor stability is a
property of the WALK, not of `dedupe` in isolation: a unit test cannot show that a cursor minted
on one page still resolves the same boundary on the next.

Skips cleanly when no populated endpoint is reachable.
"""
import asyncio
import os

import pytest

from edr_trajectory.identity import decode_identity, encode_identity
from edr_trajectory.production_adapter import page_device_evidence, resolve_evidence

TENANT = os.environ.get("E3_IT_TENANT", "default")
ENDPOINT = os.environ.get("E3_IT_ENDPOINT", "ep_2d57cbe6f80152062109")
PAGE = 50


@pytest.fixture(scope="module")
def loop():
    """One event loop for the whole module.

    The motor client binds to the loop that first used it, so every await in this module must
    run on the same loop; a fresh `asyncio.run` per test closes it under the client.
    """
    lp = asyncio.new_event_loop()
    asyncio.set_event_loop(lp)
    yield lp
    lp.close()


@pytest.fixture(scope="module")
def db(loop):
    import deps
    deps.validate_config()
    deps.init_database()
    return deps.db


@pytest.fixture(scope="module")
def refs(db):
    from services.edr import endpoint_query as eq
    res = eq.resolve_endpoint(ENDPOINT, {"all_tenants": True})
    if not res:
        pytest.skip(f"endpoint {ENDPOINT} does not resolve in this environment")
    return res.refs


@pytest.fixture(scope="module")
def walk(db, refs, loop):
    """Three consecutive pages, plus a re-walk resumed from page 1's cursor."""
    async def _go():
        pages, cursor = [], None
        for _ in range(3):
            p = await page_device_evidence(db, tenant_id=TENANT, refs=refs,
                                           page_size=PAGE, cursor=cursor)
            pages.append(p)
            cursor = p.get("next_cursor")
            if not cursor:
                break
        resumed = None
        if len(pages) > 1 and pages[0].get("next_cursor"):
            resumed = await page_device_evidence(db, tenant_id=TENANT, refs=refs,
                                                 page_size=PAGE,
                                                 cursor=pages[0]["next_cursor"])
        return pages, resumed
    pages, resumed = loop.run_until_complete(_go())
    if not pages or not pages[0]["items"]:
        pytest.skip("no evidence returned for this endpoint")
    return pages, resumed


def _ids(page):
    return [i["event_id"] for i in page["items"]]


def test_every_exported_id_is_versioned_and_decodes(walk):
    pages, _ = walk
    for p in pages:
        for item in p["items"]:
            decoded = decode_identity(item["event_id"])
            assert decoded is not None, f"unversioned id exported: {item['event_id']!r}"
            rank, value = decoded
            assert (rank, value) in [tuple(k) for k in item["identity_keys"]], \
                "the exported id must be one of the row's own identities"


def test_ids_are_unique_within_and_across_pages(walk):
    pages, _ = walk
    seen = set()
    for p in pages:
        page_ids = _ids(p)
        assert len(set(page_ids)) == len(page_ids), "duplicate id inside one page"
        assert not (seen & set(page_ids)), "the same row was emitted on two pages"
        seen |= set(page_ids)


def test_exported_id_is_the_highest_ranked_identity_the_row_holds(walk):
    pages, _ = walk
    for p in pages:
        for item in p["items"]:
            keys = sorted(tuple(k) for k in item["identity_keys"])
            assert item["event_id"] == encode_identity(keys[0])


def test_cursor_resumes_on_the_same_boundary(walk):
    """A cursor minted on page 1 must resolve the same page 2, independent of composition."""
    pages, resumed = walk
    if resumed is None or len(pages) < 2:
        pytest.skip("endpoint does not have enough evidence to page")
    assert _ids(resumed) == _ids(pages[1]), \
        "resuming from the page-1 cursor returned a different page 2"


def test_equal_time_rows_do_not_tie_on_identity(walk):
    pages, _ = walk
    for p in pages:
        keys = [(i["observed_us"], i["event_id"]) for i in p["items"]]
        assert len(set(keys)) == len(keys), "sort key tied, so page boundaries are not total"
        assert keys == sorted(keys, reverse=True), "page is not in newest-first order"


def test_legacy_aliases_are_published_for_every_row(walk):
    pages, _ = walk
    for item in pages[0]["items"]:
        assert item.get("legacy_event_ids"), "no legacy alias published"
        assert item.get("identity_aliases"), "no encoded aliases published"
        assert item["event_id"] in item["identity_aliases"]


def test_deep_link_resolves_by_versioned_id(db, refs, walk, loop):
    pages, _ = walk
    target = pages[0]["items"][0]
    got = loop.run_until_complete(resolve_evidence(db, tenant_id=TENANT, refs=refs,
                                       event_id=target["event_id"]))
    assert got["state"] == "FOCUS_RESOLVED"
    assert got["event_id"] == target["event_id"]


def test_deep_link_resolves_by_legacy_id_or_reports_ambiguity(db, refs, walk, loop):
    """An old link must resolve, or be reported ambiguous - never silently mis-resolved."""
    pages, _ = walk
    target = pages[0]["items"][0]
    legacy = target["legacy_event_ids"][0]
    got = loop.run_until_complete(resolve_evidence(db, tenant_id=TENANT, refs=refs, event_id=legacy))
    assert got["state"] in ("FOCUS_RESOLVED", "FOCUS_AMBIGUOUS", "FOCUS_NOT_RESOLVED")
    if got["state"] == "FOCUS_RESOLVED":
        assert legacy in (got["event"].get("legacy_event_ids") or [])
    elif got["state"] == "FOCUS_AMBIGUOUS":
        assert len(got["candidates"]) > 1
        assert got["event"] is None


def test_unknown_identity_is_not_resolved_to_some_other_row(db, refs, loop):
    got = loop.run_until_complete(resolve_evidence(db, tenant_id=TENANT, refs=refs,
                                       event_id=encode_identity((0, "no-such-identity"))))
    assert got["state"] != "FOCUS_RESOLVED"
    assert got["event"] is None
