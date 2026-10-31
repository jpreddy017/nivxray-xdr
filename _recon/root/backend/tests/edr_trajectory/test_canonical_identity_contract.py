"""G-26 target identity contract: pure, hermetic guards.

No database, no index, no migration, no production. These lock the RULES the
Step-34E design rests on, so the contract cannot drift silently before it is
implemented.
"""
from __future__ import annotations

from edr_plane import canonical_identity_contract as idc
from edr_plane.canonical_index_contract import (CANONICAL_COLLECTION,
                                                REQUIRED_CANONICAL_INDEXES,
                                                TARGET_CANONICAL_INDEXES,
                                                missing_against)
from edr_trajectory.production_adapter import OBSERVATION_TIME_KEY
from services.edr.endpoint_query import TENANT_PARTITIONED_STORES

EP = "ep_a67be48d5b4e01d4d9e8"


def row(**kw):
    base = {"tenant_id": "ten_x", "event_time": "2026-06-01T00:00:00Z"}
    base.update(kw)
    return base


# ── what counts as a platform identity ───────────────────────────────────

def test_only_a_platform_minted_value_is_an_identity():
    assert idc.is_platform_minted(EP) is True
    for bad in ("KUSHU", "DESKTOP-A9HGFJJ", "collector-snort-ref", "ep_",
                "", None, "dev_d21e1278f914", "EP_UPPER"):
        assert idc.is_platform_minted(bad) is False, bad


def test_the_authoritative_field_is_the_first_trust_source():
    got, why = idc.classify(row(additional_fields={"endpoint_id": EP},
                                provenance={"collector_id": "ep_other0000000"},
                                host={"host_id": "KUSHU", "hostname": "KUSHU"}))
    assert (got, why) == (EP, idc.RESOLVED_AUTHORITATIVE)


def test_the_authenticated_boundary_is_the_only_fallback():
    got, why = idc.classify(row(provenance={"collector_id": EP},
                                host={"host_id": "KUSHU", "hostname": "KUSHU"}))
    assert (got, why) == (EP, idc.RESOLVED_AUTHENTICATED_BOUNDARY)


# ── what must NEVER become an identity ───────────────────────────────────

def test_a_hostname_is_never_promoted_to_an_endpoint_identity():
    got, why = idc.classify(row(provenance={"collector_id": "collector-snort"},
                                host={"host_id": "KUSHU", "hostname": "KUSHU"}))
    assert got is None and why == idc.UNRESOLVED_NAME_ONLY


def test_a_vendor_host_id_or_device_iid_is_never_promoted():
    for host in ({"host_id": "dev_d21e1278f914"},
                 {"host_id": "snort-sensor-01"},
                 {"host_id": "10.1.2.3"}):
        got, why = idc.classify(row(host=host,
                                    provenance={"collector_id": "collector-x"}))
        assert got is None, host
        assert why in (idc.UNRESOLVED_NO_IDENTITY, idc.UNRESOLVED_NAME_ONLY)


def test_a_non_platform_value_in_the_authoritative_field_is_unresolved():
    got, why = idc.classify(row(additional_fields={"endpoint_id": "collector-x"},
                                provenance={"collector_id": EP}))
    assert got is None and why == idc.UNRESOLVED_NO_IDENTITY


def test_collector_sourced_evidence_is_not_endpoint_scoped():
    got, why = idc.classify(row(provenance={"collector_id": "collector-snort"}))
    assert got is None and why == idc.UNRESOLVED_NOT_ENDPOINT_SCOPED


def test_never_identity_list_covers_the_derived_representations():
    for field in ("host.host_id", "host.hostname", "device_iid"):
        assert field in idc.NEVER_IDENTITY


# ── the only permitted backfill ──────────────────────────────────────────

def test_backfill_only_copies_an_authenticated_platform_id():
    plan = idc.backfill_candidate(row(provenance={"collector_id": EP},
                                      host={"hostname": "KUSHU"}))
    assert plan["set"] == {idc.AUTHORITATIVE_FIELD: EP}
    assert plan["source"] == idc.AUTHENTICATED_BOUNDARY_FIELD


def test_backfill_refuses_names_vendor_ids_and_already_stamped_rows():
    assert idc.backfill_candidate(
        row(provenance={"collector_id": "collector-snort"},
            host={"hostname": "KUSHU"})) is None
    assert idc.backfill_candidate(row(host={"host_id": "KUSHU",
                                            "hostname": "KUSHU"})) is None
    assert idc.backfill_candidate(
        row(additional_fields={"endpoint_id": EP},
            provenance={"collector_id": "ep_other0000000"})) is None


# ── the target index set ─────────────────────────────────────────────────

def test_target_is_one_authoritative_key_plus_one_legacy_name_branch():
    assert len(TARGET_CANONICAL_INDEXES) == 2
    roles = [s["role"] for s in TARGET_CANONICAL_INDEXES]
    assert roles == ["AUTHORITATIVE_ENDPOINT_IDENTITY",
                     "LEGACY_NAME_COMPATIBILITY_ONLY"]
    fields = [s["identity_field"] for s in TARGET_CANONICAL_INDEXES]
    assert fields == [idc.AUTHORITATIVE_FIELD, idc.LEGACY_NAME_FIELD]


def test_target_keeps_the_tenant_equality_prefix_and_time_sort():
    partition = TENANT_PARTITIONED_STORES[CANONICAL_COLLECTION]
    time_key = OBSERVATION_TIME_KEY[CANONICAL_COLLECTION]
    for spec in TARGET_CANONICAL_INDEXES:
        assert spec["key"][0] == (partition, 1)
        assert spec["key"][1] == (spec["identity_field"], 1)
        assert spec["key"][2] == (time_key, -1)
        assert spec["collection"] == CANONICAL_COLLECTION


def test_target_drops_the_two_copy_identity_branches():
    target_fields = {s["identity_field"] for s in TARGET_CANONICAL_INDEXES}
    assert "host.host_id" not in target_fields
    assert "provenance.collector_id" not in target_fields
    # and it is strictly smaller than the 34D fallback set
    assert len(TARGET_CANONICAL_INDEXES) < len(REQUIRED_CANONICAL_INDEXES)


def test_missing_against_can_be_asked_about_the_target_set():
    assert missing_against([s["key"] for s in TARGET_CANONICAL_INDEXES],
                           TARGET_CANONICAL_INDEXES) == []
    assert len(missing_against([], TARGET_CANONICAL_INDEXES)) == 2
