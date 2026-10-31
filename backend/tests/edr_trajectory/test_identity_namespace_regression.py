"""Regression cover for the identity-namespace defect in `identity.dedupe`.

Defect: the group store keyed on the bare string (`min(keys)[1]`) while matching compared
ranked tuples, so two rows stating the same text in DIFFERENT namespaces fell into one group
without ever matching — the later row silently overwrote the earlier one, `suppressed` stayed
0, and which evidence survived depended on input order.
"""
import pytest

from edr_trajectory.identity import (RANK_ACTIVITY_IDENTITY, RANK_CANONICAL_EVENT_ID,
                                     RANK_CONTENT, dedupe, encode_identity)


def row(marker, keys, tenant="t", event_id="same"):
    return {"tenant_id": tenant, "event_id": event_id, "identity_keys": list(keys),
            "marker": marker, "sources": []}


# ── the reported defect, both input orders ────────────────────────────────────────────────
A = row("activity", [(RANK_ACTIVITY_IDENTITY, "same")])
B = row("delivery", [(RANK_CANONICAL_EVENT_ID, "same")])


@pytest.mark.parametrize("rows", [[A, B], [B, A]], ids=["activity_first", "delivery_first"])
def test_equal_text_in_different_ranks_is_never_collapsed(rows):
    out, suppressed = dedupe([dict(r) for r in rows])
    assert len(out) == 2, "unmatched namespaces must stay two rows"
    assert sorted(e["marker"] for e in out) == ["activity", "delivery"], "no evidence may be lost"
    assert suppressed == 0, "nothing was merged, so nothing may be counted as suppressed"


def test_result_is_identical_for_both_input_orders():
    fwd, s1 = dedupe([dict(A), dict(B)])
    rev, s2 = dedupe([dict(B), dict(A)])
    key = lambda rs: sorted((e["marker"], e["event_id"], tuple(e["identity_keys"])) for e in rs)
    assert key(fwd) == key(rev), "retained evidence must not depend on arrival order"
    assert s1 == s2 == 0


def test_exported_event_ids_are_unique_so_paging_cannot_collide():
    out, _ = dedupe([dict(A), dict(B)])
    ids = [e["event_id"] for e in out]
    assert len(set(ids)) == len(ids), "two groups must never export the same event_id"
    assert set(ids) == {encode_identity((RANK_ACTIVITY_IDENTITY, "same")),
                        encode_identity((RANK_CANONICAL_EVENT_ID, "same"))}


def test_uncontended_identity_is_still_encoded_but_keeps_a_legacy_alias():
    """Encoding is unconditional, so the exported id cannot depend on page composition.

    The bare value an older build would have exported is retained as a legacy alias so existing
    deep links still resolve.
    """
    out, _ = dedupe([row("only", [(RANK_ACTIVITY_IDENTITY, "act_1")])])
    assert out[0]["event_id"] == encode_identity((RANK_ACTIVITY_IDENTITY, "act_1"))
    assert out[0]["legacy_event_ids"] == ["act_1"]


# ── genuine merges must still happen ──────────────────────────────────────────────────────
def test_same_namespace_same_value_merges():
    out, suppressed = dedupe([row("one", [(RANK_ACTIVITY_IDENTITY, "k")]),
                              row("two", [(RANK_ACTIVITY_IDENTITY, "k")])])
    assert len(out) == 1 and suppressed == 1


def test_transitive_bridge_merges_three_rows_into_one():
    rows = [row("a", [(RANK_ACTIVITY_IDENTITY, "k1")]),
            row("bridge", [(RANK_ACTIVITY_IDENTITY, "k1"), (RANK_CANONICAL_EVENT_ID, "k2")]),
            row("c", [(RANK_CANONICAL_EVENT_ID, "k2")])]
    out, suppressed = dedupe([dict(r) for r in rows])
    assert len(out) == 1, "a shared bridging identity must unify the chain"
    assert out[0]["identity_keys"] == [(RANK_ACTIVITY_IDENTITY, "k1"),
                                       (RANK_CANONICAL_EVENT_ID, "k2")]
    assert out[0]["event_id"] == encode_identity((RANK_ACTIVITY_IDENTITY, "k1")), \
        "rendered under the highest-ranked identity"
    assert sorted(out[0]["legacy_event_ids"]) == ["k1", "k2"]
    assert suppressed == 2


@pytest.mark.parametrize("order", [(0, 1, 2), (2, 1, 0), (1, 0, 2), (1, 2, 0)])
def test_transitive_bridge_is_order_independent(order):
    rows = [row("a", [(RANK_ACTIVITY_IDENTITY, "k1")]),
            row("bridge", [(RANK_ACTIVITY_IDENTITY, "k1"), (RANK_CANONICAL_EVENT_ID, "k2")]),
            row("c", [(RANK_CANONICAL_EVENT_ID, "k2")])]
    out, suppressed = dedupe([dict(rows[i]) for i in order])
    assert len(out) == 1 and suppressed == 2
    assert out[0]["event_id"] == encode_identity((RANK_ACTIVITY_IDENTITY, "k1"))


# ── tenant separation ─────────────────────────────────────────────────────────────────────
def test_same_identity_in_two_tenants_never_merges():
    out, suppressed = dedupe([row("t1", [(RANK_ACTIVITY_IDENTITY, "k")], tenant="t1"),
                              row("t2", [(RANK_ACTIVITY_IDENTITY, "k")], tenant="t2")])
    assert len(out) == 2 and suppressed == 0
    assert sorted(e["tenant_id"] for e in out) == ["t1", "t2"]


def test_tenant_separation_holds_across_ranks():
    rows = [row("t1a", [(RANK_ACTIVITY_IDENTITY, "x")], tenant="t1"),
            row("t1b", [(RANK_CANONICAL_EVENT_ID, "x")], tenant="t1"),
            row("t2a", [(RANK_ACTIVITY_IDENTITY, "x")], tenant="t2")]
    out, suppressed = dedupe([dict(r) for r in rows])
    assert len(out) == 3 and suppressed == 0


# ── count conservation ────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("rows,expected_rows", [
    ([A, B], 2),
    ([row("a", [(RANK_ACTIVITY_IDENTITY, "k")]), row("b", [(RANK_ACTIVITY_IDENTITY, "k")])], 1),
    ([row("a", [(RANK_ACTIVITY_IDENTITY, "k1")]), row("b", [(RANK_ACTIVITY_IDENTITY, "k2")])], 2),
])
def test_rows_plus_suppressed_equals_input_count(rows, expected_rows):
    n = len(rows)
    out, suppressed = dedupe([dict(r) for r in rows])
    assert len(out) == expected_rows
    assert len(out) + suppressed == n, "every input row is either emitted or counted suppressed"


def test_content_fallback_used_only_when_no_identity_is_stated():
    out, _ = dedupe([{"tenant_id": "t", "event_id": "ce_abc", "identity_keys": [],
                      "marker": "m", "sources": []}])
    assert out[0]["identity_keys"] == [(RANK_CONTENT, "ce_abc")]
    assert out[0]["event_id"] == encode_identity((RANK_CONTENT, "ce_abc"))
    assert out[0]["legacy_event_ids"] == ["ce_abc"]
