"""TRAJECTORY_TENANT_ISOLATION — the evidence read is partitioned by customer.

Owner invariant:

    authoritative tenant
        -> authoritative endpoint identity
        -> ONLY that endpoint's evidence

A hostname/computer name must never expand or authorise trajectory
evidence.  Two customers can both enrol `DESKTOP-A9HGFJJ`; before this
gate, keying the read on the alias set alone merged a 3,298-row corpus
and a 3,299-row corpus into one 6,597-row read.
"""
from __future__ import annotations

import pytest

from services.edr.endpoint_query import (
    ENDPOINT_KEYED_STORES,
    TENANT_PARTITIONED_STORES,
    EndpointResolution,
    endpoint_predicate,
)

HOST = "DESKTOP-A9HGFJJ"
T_A = "ten_f1a5479243e901cf159e230fa0"
T_B = "ten_3f7f772b353a6bbbb0ac8bc564"


def _flat(pred):
    """Every leaf clause of a predicate, regardless of $and nesting."""
    out = {}
    for part in pred.get("$and", [pred]):
        out.update(part)
    return out


# A · the evidence stores are DECLARED tenant-partitioned
def test_evidence_stores_are_declared_tenant_partitioned():
    assert TENANT_PARTITIONED_STORES["v2_shadow_observations"] == "tenant_id"
    assert TENANT_PARTITIONED_STORES["edr_raw_events"] == "tenant_id"
    assert TENANT_PARTITIONED_STORES["edr_endpoints"] == "tenant_id"
    for store in TENANT_PARTITIONED_STORES:
        assert store in ENDPOINT_KEYED_STORES


# B · the same hostname in two customers yields two DIFFERENT predicates
@pytest.mark.parametrize("store", sorted(TENANT_PARTITIONED_STORES))
def test_same_hostname_in_two_tenants_is_isolated(store):
    a = endpoint_predicate([HOST], store, tenant_id=T_A)
    b = endpoint_predicate([HOST], store, tenant_id=T_B)
    assert a != b
    assert _flat(a)["tenant_id"] == T_A
    assert _flat(b)["tenant_id"] == T_B


# C · a partitioned store CANNOT be read without a tenant (fail closed)
@pytest.mark.parametrize("store", sorted(TENANT_PARTITIONED_STORES))
@pytest.mark.parametrize("absent", [None, "", [], set(), 0, False])
def test_missing_tenant_fails_closed(store, absent):
    pred = endpoint_predicate([HOST], store, tenant_id=absent)
    assert pred == {"_nivx_unresolved_tenant": {"$exists": True}}
    # explicitly NOT a read of the whole store, and NOT an empty match
    # that a surface could report as "no evidence"
    assert "tenant_id" not in pred


# D · the identity clause survives partitioning (no narrowing of aliases)
def test_identity_clause_is_preserved_under_partitioning():
    refs = ["dev_2adbb41a04a4", HOST, "col_d6b0b9e8172246f29be9"]
    pred = endpoint_predicate(refs, "v2_shadow_observations", tenant_id=T_A)
    assert pred["$and"][0] == {"tenant_id": T_A}
    fields = ENDPOINT_KEYED_STORES["v2_shadow_observations"]
    assert pred["$and"][1] == {"$or": [{f: {"$in": refs}} for f in fields]}


# E · an unscoped store is unchanged (no collateral behaviour change)
def test_unpartitioned_store_predicate_unchanged():
    pred = endpoint_predicate(["ep_1"], "edr_response_commands")
    assert pred == {"endpoint_id": {"$in": ["ep_1"]}}


# F · the $and shape cannot be clobbered by a caller's own $or
def test_predicate_survives_caller_spread_with_or():
    pred = endpoint_predicate([HOST], "edr_raw_events", tenant_id=T_A)
    q = {**pred, "$or": [{"raw_id": "x"}]}
    assert q["$and"][0] == {"tenant_id": T_A}
    assert q["$or"] == [{"raw_id": "x"}]


# G · resolution takes the tenant from the AUTHORITATIVE identity only
def test_resolution_predicate_uses_authoritative_tenant():
    res = EndpointResolution(
        supplied=HOST,
        identity={"device_iid": "dev_2adbb41a04a4", "hostname": HOST,
                  "tenant_id": T_A,
                  "tenant_attribution": "ATTRIBUTED_AUTHENTICATED_ENDPOINT"},
        refs=["dev_2adbb41a04a4", HOST])
    assert _flat(res.predicate("v2_shadow_observations"))["tenant_id"] == T_A


# H · an identity whose ownership failed closed reads NOTHING
@pytest.mark.parametrize("state", ["TENANT_CONFLICT_FAILED_CLOSED",
                                   "TENANT_MISMATCH_FAILED_CLOSED",
                                   "UNATTRIBUTED_LEGACY_OBSERVATION"])
def test_unowned_identity_cannot_read_evidence(state):
    res = EndpointResolution(
        supplied=HOST,
        identity={"hostname": HOST, "tenant_id": None,
                  "tenant_attribution": state},
        refs=[HOST])
    assert res.predicate("v2_shadow_observations") == {
        "_nivx_unresolved_tenant": {"$exists": True}}


# I · a multi-tenant principal may address several customers explicitly,
#     but never "all customers implicitly"
def test_explicit_multi_tenant_list_is_an_in_clause():
    pred = endpoint_predicate([HOST], "edr_raw_events",
                              tenant_id=[T_A, T_B])
    assert _flat(pred)["tenant_id"] == {"$in": sorted([T_A, T_B])}


# J · the trajectory projection CACHE is keyed by customer
def test_projection_cache_key_includes_tenant():
    from edr_plane import trajectory_window as tw
    a = tw._identity_key({"device_iid": "dev_x", "hostname": HOST,
                          "tenant_id": T_A})
    b = tw._identity_key({"device_iid": "dev_x", "hostname": HOST,
                          "tenant_id": T_B})
    assert a != b
    assert T_A in a and T_B in b


# K · no trajectory/raw evidence query site may address a partitioned
#     store without a tenant
def test_no_unscoped_evidence_query_sites_remain():
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[2]
    offenders = []
    for path in list(root.glob("routers/*.py")) + \
            list(root.glob("edr_plane/**/*.py")) + \
            list(root.glob("services/**/*.py")):
        src = path.read_text()
        for call in re.findall(r"endpoint_predicate\((?:[^()]|\([^()]*\))*\)",
                               src):
            store = re.search(r'"([a-z0-9_]+)"', call)
            if not store or store.group(1) not in TENANT_PARTITIONED_STORES:
                continue
            if "tenant_id=" not in call:
                offenders.append(f"{path.name}: {call}")
    assert offenders == [], offenders
