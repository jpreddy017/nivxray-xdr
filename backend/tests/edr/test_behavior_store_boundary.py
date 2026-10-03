"""Locked doors BEFORE the engine enters the room.

The E3 Behavior stores are declared to E1's ONE endpoint resolver and to its
tenant partition contract while the engine itself remains unimported, unmounted
and unexecuted. Owner decisions in force: D1 no product claim, D2 shadow without
Fabric Findings, D3 `endpoint_id` as the sole endpoint-keyed field, D4 new
evidence only, D5 the existing shared ATT&CK authority only.

Nothing here creates a collection, an index, a flag, an adapter or an emitter.
"""
import sys

import pytest

from services.edr.endpoint_query import (ENDPOINT_KEYED_STORES,
                                         TENANT_PARTITIONED_STORES,
                                         endpoint_predicate)

DETECTIONS = "e3_behavior_detections"
CHECKPOINTS = "e3_behavior_replay_checkpoints"
STORES = (DETECTIONS, CHECKPOINTS)

TEN_A = "ten_e759b7288598bd882e3dcac49d"
TEN_B = "ten_b000000000000000000000000"
EP = "ep_a67be48d5b4e01d4d9e8"


# ── declaration shape ────────────────────────────────────────────────────

@pytest.mark.parametrize("store", STORES)
def test_store_is_endpoint_keyed_by_endpoint_id_only(store):
    assert ENDPOINT_KEYED_STORES[store] == ["endpoint_id"]


@pytest.mark.parametrize("store", STORES)
def test_store_is_tenant_partitioned_on_tenant_id(store):
    assert TENANT_PARTITIONED_STORES[store] == "tenant_id"


# ── fail closed ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("store", STORES)
def test_unresolved_tenant_fails_closed(store):
    q = endpoint_predicate([EP], store, tenant_id=None)
    assert q == {"_nivx_unresolved_tenant": {"$exists": True}}
    assert "endpoint_id" not in str(q)


@pytest.mark.parametrize("store", STORES)
def test_empty_tenant_string_fails_closed(store):
    assert endpoint_predicate([EP], store, tenant_id="") == {
        "_nivx_unresolved_tenant": {"$exists": True}}


@pytest.mark.parametrize("store", STORES)
def test_unresolved_endpoint_never_degrades_to_unfiltered_read(store):
    assert endpoint_predicate([], store, tenant_id=TEN_A) == {
        "_nivx_unresolved_endpoint": {"$exists": True}}


# ── tenant isolation ─────────────────────────────────────────────────────

@pytest.mark.parametrize("store", STORES)
def test_tenant_a_predicate_cannot_address_tenant_b(store):
    a = endpoint_predicate([EP], store, tenant_id=TEN_A)
    assert {"tenant_id": TEN_A} in a["$and"]
    assert TEN_B not in str(a)


@pytest.mark.parametrize("store", STORES)
def test_same_endpoint_id_in_two_tenants_stays_isolated(store):
    a = endpoint_predicate([EP], store, tenant_id=TEN_A)
    b = endpoint_predicate([EP], store, tenant_id=TEN_B)
    assert a != b
    assert {"tenant_id": TEN_A} in a["$and"]
    assert {"tenant_id": TEN_B} in b["$and"]


# ── endpoint addressability ──────────────────────────────────────────────

@pytest.mark.parametrize("store", STORES)
def test_endpoint_id_is_the_addressing_field(store):
    q = endpoint_predicate([EP], store, tenant_id=TEN_A)
    assert {"endpoint_id": {"$in": [EP]}} in q["$and"]


@pytest.mark.parametrize("store", STORES)
def test_hostname_cannot_address_a_behavior_record(store):
    with pytest.raises(KeyError):
        endpoint_predicate([EP], store, ["hostname"], tenant_id=TEN_A)


@pytest.mark.parametrize("store", STORES)
def test_device_iid_cannot_independently_address_a_behavior_record(store):
    with pytest.raises(KeyError):
        endpoint_predicate([EP], store, ["device_iid"], tenant_id=TEN_A)


@pytest.mark.parametrize("store", STORES)
def test_a_substituted_hostname_ref_is_matched_as_an_endpoint_id_only(store):
    """A KUSHU-class substituted name may appear in the alias set; it is only
    ever compared against `endpoint_id`, never against a name field."""
    q = endpoint_predicate([EP, "KUSHU"], store, tenant_id=TEN_A)
    assert {"endpoint_id": {"$in": [EP, "KUSHU"]}} in q["$and"]
    assert "hostname" not in str(q)
    assert "device_iid" not in str(q)


# ── the engine stays outside the room ────────────────────────────────────

def test_declaring_the_stores_does_not_import_the_behavior_engine():
    assert not [m for m in sys.modules if m.startswith("edr_behavior")]


def test_no_router_imports_the_behavior_engine():
    from pathlib import Path
    routers = Path(__file__).resolve().parents[2] / "routers"
    offenders = [p.name for p in routers.glob("*.py")
                 if "edr_behavior" in p.read_text()]
    assert offenders == []


def test_behavioral_detection_source_is_still_not_an_implemented_claim():
    from edr_plane.fabric.contracts import (DETECTION_SOURCE_DISCLOSURE,
                                            IMPLEMENTED_DETECTION_SOURCES)
    assert "NIVXFORGE_ENDPOINT_BEHAVIORAL" not in IMPLEMENTED_DETECTION_SOURCES
    assert DETECTION_SOURCE_DISCLOSURE[
        "NIVXFORGE_ENDPOINT_BEHAVIORAL"]["implemented"] is False


# ── no regression in the existing contract ───────────────────────────────

def test_existing_endpoint_keyed_stores_unchanged():
    assert ENDPOINT_KEYED_STORES["edr_raw_events"] == ["endpoint_ref"]
    assert ENDPOINT_KEYED_STORES["edr_endpoints"] == ["endpoint_id",
                                                      "device_iid",
                                                      "hostname"]
    assert ENDPOINT_KEYED_STORES["xdr_canonical_evidence"] == [
        "provenance.collector_id", "host.host_id", "host.hostname"]
    assert "event.device_iid" in ENDPOINT_KEYED_STORES[
        "v2_shadow_observations"]


def test_existing_tenant_partitions_unchanged():
    for store in ("v2_shadow_observations", "edr_raw_events",
                  "xdr_canonical_evidence", "edr_endpoints"):
        assert TENANT_PARTITIONED_STORES[store] == "tenant_id"


def test_an_undeclared_store_is_still_refused():
    with pytest.raises(KeyError):
        endpoint_predicate([EP], "e3_behavior_not_a_store", tenant_id=TEN_A)
