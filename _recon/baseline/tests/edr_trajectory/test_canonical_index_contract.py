"""The canonical §d index contract cannot silently drift from the query shape.

Pure and hermetic: no database, no index creation, no production. The live
`explain` proof is a separate measurement artifact
(`backend/tools/measure_34d_canonical_index.py`), which runs against a scratch
database only.
"""
from __future__ import annotations

from edr_plane.canonical_index_contract import (CANONICAL_COLLECTION,
                                                PRODUCTION_INDEXES_MEASURED,
                                                REQUIRED_CANONICAL_INDEXES,
                                                missing_against)
from edr_trajectory.production_adapter import OBSERVATION_TIME_KEY, branches
from services.edr.endpoint_query import (ENDPOINT_KEYED_STORES,
                                         TENANT_PARTITIONED_STORES)

TENANT = "ten_e759b7288598bd882e3dcac49d"
REFS = ["ep_a67be48d5b4e01d4d9e8", "KUSHU"]


def test_one_spec_per_declared_canonical_identity_field():
    declared = list(ENDPOINT_KEYED_STORES[CANONICAL_COLLECTION])
    assert [s["identity_field"] for s in REQUIRED_CANONICAL_INDEXES] == declared
    assert len(REQUIRED_CANONICAL_INDEXES) == len(set(
        s["name"] for s in REQUIRED_CANONICAL_INDEXES))


def test_tenant_partition_is_the_leading_equality_prefix():
    partition = TENANT_PARTITIONED_STORES[CANONICAL_COLLECTION]
    for spec in REQUIRED_CANONICAL_INDEXES:
        assert spec["key"][0] == (partition, 1), spec["name"]


def test_identity_is_second_and_event_time_is_last_and_descending():
    time_key = OBSERVATION_TIME_KEY[CANONICAL_COLLECTION]
    for spec in REQUIRED_CANONICAL_INDEXES:
        assert len(spec["key"]) == 3
        assert spec["key"][1] == (spec["identity_field"], 1)
        assert spec["key"][2] == (time_key, -1), spec["name"]


def test_every_branch_query_the_adapter_builds_has_a_matching_spec():
    """The guard that matters: the specs are checked against the filters the §d
    production adapter actually constructs, not against a hand-written list."""
    time_key = OBSERVATION_TIME_KEY[CANONICAL_COLLECTION]
    built = branches(CANONICAL_COLLECTION, REFS, TENANT)
    assert built, "the canonical store must still produce branch filters"
    by_field = {s["identity_field"]: s for s in REQUIRED_CANONICAL_INDEXES}
    for flt in built:
        identity = [k for k in flt if k != "tenant_id"]
        assert len(identity) == 1
        spec = by_field[identity[0]]
        # equality prefix, then the $in identity, then the sort key
        assert [k for k, _ in spec["key"]] == ["tenant_id", identity[0],
                                               time_key]
        # the branch is tenant-scoped, so the equality prefix is satisfiable
        assert flt["tenant_id"] == TENANT


def test_no_spec_addresses_an_undeclared_field():
    declared = set(ENDPOINT_KEYED_STORES[CANONICAL_COLLECTION])
    for spec in REQUIRED_CANONICAL_INDEXES:
        assert spec["identity_field"] in declared
        assert spec["collection"] == CANONICAL_COLLECTION
        assert spec["unique"] is False and spec["partial"] is None


def test_the_measured_production_index_set_satisfies_none_of_the_specs():
    """The production weakness, asserted rather than remembered: neither
    existing index can serve a canonical §d branch."""
    existing = [key for _, key in PRODUCTION_INDEXES_MEASURED]
    assert len(missing_against(existing)) == len(REQUIRED_CANONICAL_INDEXES)
    names = {n for n, _ in PRODUCTION_INDEXES_MEASURED}
    assert names == {"_id_", "tenant_id_1_ingest_time_-1"}


def test_an_index_set_that_contains_the_specs_is_reported_complete():
    existing = [s["key"] for s in REQUIRED_CANONICAL_INDEXES]
    assert missing_against(existing) == []
