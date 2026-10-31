"""Exported-identity contract: versioned encoding, stability, and legacy alias resolution.

Two defects are covered here, both reproduced on the predecessor source:

1. COMPOSITION-DEPENDENT IDS - the exported id was qualified only when it collided inside the
   page, so `A` alone exported `same` while `A+B` exported `r0:same`. A cursor or deep link was
   therefore only valid for the page composition that produced it.

2. QUALIFIED OUTPUT COULD COLLIDE WITH A LEGITIMATE RAW ID - a row whose real identity value was
   literally `r0:same` exported the same string as a qualified `(0,"same")`, so `A+B+C` produced
   3 rows holding only 2 unique ids with `suppressed == 0`.

The contract is now: every exported identity is `e3i1:<rank>:<base64url(value)>`, applied
unconditionally, so it is a pure function of (rank, value).
"""
import pytest

from edr_trajectory.identity import (IDENTITY_ENCODING, RANK_ACTIVITY_IDENTITY,
                                     RANK_CANONICAL_EVENT_ID, RANK_CONTENT, AmbiguousIdentity,
                                     decode_identity, dedupe, encode_identity, resolve_identity)


def row(marker, keys, tenant="t", event_id="same"):
    return {"tenant_id": tenant, "event_id": event_id, "identity_keys": list(keys),
            "marker": marker, "sources": []}


A = row("A", [(RANK_ACTIVITY_IDENTITY, "same")])
B = row("B", [(RANK_CANONICAL_EVENT_ID, "same")])
C = row("C", [(RANK_CONTENT, "r0:same")])          # prefix-shaped RAW value


def ids(rows):
    out, _ = dedupe([dict(r) for r in rows])
    return {e["marker"]: e["event_id"] for e in out}


# ── defect 2: three rows, three unique ids ────────────────────────────────────────────────
def test_prefix_shaped_raw_id_cannot_collide_with_an_encoded_one():
    out, suppressed = dedupe([dict(A), dict(B), dict(C)])
    exported = [e["event_id"] for e in out]
    assert len(out) == 3, "three unmatched identities must stay three rows"
    assert len(set(exported)) == 3, "every exported id must be unique"
    assert suppressed == 0


@pytest.mark.parametrize("raw", ["r0:same", "e3i1:0:c2FtZQ", "0:same", "same", "r1:x"])
def test_arbitrary_prefix_shaped_raw_values_round_trip_without_forging(raw):
    enc = encode_identity((RANK_CONTENT, raw))
    assert decode_identity(enc) == (RANK_CONTENT, raw)
    assert enc != encode_identity((RANK_ACTIVITY_IDENTITY, "same"))


# ── defect 1: stability across subset / superset pages ────────────────────────────────────
def test_exported_id_is_identical_across_subset_and_superset_pages():
    alone = ids([A])["A"]
    assert ids([A, B])["A"] == alone
    assert ids([A, B, C])["A"] == alone
    assert ids([C, B, A])["A"] == alone, "and independent of arrival order"


def test_every_rank_namespace_encodes_distinctly():
    enc = {r: encode_identity((r, "same"))
           for r in (RANK_ACTIVITY_IDENTITY, RANK_CANONICAL_EVENT_ID, RANK_CONTENT)}
    assert len(set(enc.values())) == 3
    for r, e in enc.items():
        assert e.startswith(f"{IDENTITY_ENCODING}:{r}:")
        assert decode_identity(e) == (r, "same")


def test_encoding_is_version_tagged_and_unknown_versions_are_rejected():
    assert decode_identity("e3i0:0:c2FtZQ") is None
    assert decode_identity("same") is None
    assert decode_identity("r0:same") is None


# ── a higher-ranked key appearing later ───────────────────────────────────────────────────
def test_added_representation_raises_rank_but_old_identity_survives_as_alias():
    """A later page may bridge in a higher-ranked key, changing which identity leads.

    Qualification alone cannot prevent that, so the previous identity is retained as an alias
    instead of being dropped.
    """
    before, _ = dedupe([row("x", [(RANK_CANONICAL_EVENT_ID, "k2")])])
    old_id = before[0]["event_id"]

    after, suppressed = dedupe([row("x", [(RANK_CANONICAL_EVENT_ID, "k2")]),
                                row("y", [(RANK_ACTIVITY_IDENTITY, "k1"),
                                          (RANK_CANONICAL_EVENT_ID, "k2")])])
    assert len(after) == 1 and suppressed == 1
    assert after[0]["event_id"] == encode_identity((RANK_ACTIVITY_IDENTITY, "k1"))
    assert old_id in after[0]["identity_aliases"], "the earlier identity must still resolve"
    assert resolve_identity(old_id, after, "t") is after[0]


def test_missing_representation_still_resolves_by_its_own_namespace():
    out, _ = dedupe([row("only", [(RANK_CANONICAL_EVENT_ID, "k2")])])
    assert resolve_identity(encode_identity((RANK_CANONICAL_EVENT_ID, "k2")), out, "t") is out[0]
    assert resolve_identity(encode_identity((RANK_ACTIVITY_IDENTITY, "k2")), out, "t") is None


# ── legacy deep links ─────────────────────────────────────────────────────────────────────
def test_unambiguous_legacy_deep_link_resolves():
    out, _ = dedupe([dict(A)])
    assert out[0]["legacy_event_ids"] == ["same"]
    assert resolve_identity("same", out, "t") is out[0]


def test_ambiguous_legacy_deep_link_raises_instead_of_choosing():
    out, _ = dedupe([dict(A), dict(B)])
    with pytest.raises(AmbiguousIdentity):
        resolve_identity("same", out, "t")


def test_legacy_resolution_is_tenant_scoped():
    out, _ = dedupe([row("t1", [(RANK_ACTIVITY_IDENTITY, "k")], tenant="t1"),
                     row("t2", [(RANK_ACTIVITY_IDENTITY, "k")], tenant="t2")])
    assert resolve_identity("k", out, "t1")["tenant_id"] == "t1"
    assert resolve_identity("k", out, "t2")["tenant_id"] == "t2"
    assert resolve_identity("k", out, "t3") is None


def test_encoded_identity_is_never_resolved_across_tenants():
    out, _ = dedupe([row("t1", [(RANK_ACTIVITY_IDENTITY, "k")], tenant="t1")])
    enc = out[0]["event_id"]
    assert resolve_identity(enc, out, "t1") is out[0]
    assert resolve_identity(enc, out, "t2") is None


# ── ordering / resume boundaries ──────────────────────────────────────────────────────────
def test_equal_time_rows_order_deterministically_by_encoded_identity():
    rows = [row("A", [(RANK_ACTIVITY_IDENTITY, "same")]),
            row("B", [(RANK_CANONICAL_EVENT_ID, "same")]),
            row("C", [(RANK_CONTENT, "r0:same")])]
    fwd, _ = dedupe([dict(r) for r in rows])
    rev, _ = dedupe([dict(r) for r in reversed(rows)])
    key = lambda rs: sorted((0, e["event_id"]) for e in rs)
    assert key(fwd) == key(rev), "equal-time ordering must not depend on arrival order"
    assert len({e["event_id"] for e in fwd}) == 3, "a sort key must never tie on identity"


def test_count_conservation_holds_under_the_new_encoding():
    for rows, expected in (([A, B, C], 3), ([A, A], 1), ([A, B], 2)):
        out, suppressed = dedupe([dict(r) for r in rows])
        assert len(out) == expected
        assert len(out) + suppressed == len(rows)
