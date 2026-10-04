"""SYSMON SEMANTIC AUDIT · source telemetry is not a detection.

The same invariant already established for Windows Security, applied to
the Sysmon proxies the owner named: 255 and 2 / 4 / 9 / 14 / 24 / 25.

A Sysmon Event ID states what Sysmon OBSERVED. A NivXForge alert or
detection comes from an authoritative detection mechanism, never from a
sensor's own error report, and no Event ID may be given a stronger
meaning than its source evidence supports.
"""
from __future__ import annotations

import pytest

from v2.cem.v1 import schema as cem_schema
from v2.ingestion.canonical import (
    SECURITY_CLAIM_KINDS,
    SYSMON_KIND,
    CanonicalEventRecord,
    resolve_kind,
)

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

#: The owner-scoped rulings, as data. `was` is what the table said before.
RULINGS = {
    2:   ("file_creation_time_changed", "file_write"),
    4:   ("sensor_service_state_changed", "process_exit"),
    9:   ("raw_disk_access_read", "file_write"),
    14:  ("registry_rename", "registry_delete"),
    24:  ("clipboard_change", "file_write"),
    25:  ("process_image_tampering", "process_access"),
    255: ("sensor_error", "alert"),
}


@pytest.mark.parametrize("eid,expected",
                         [(e, v[0]) for e, v in sorted(RULINGS.items())])
def test_the_audited_event_ids_match_the_ruling(eid, expected):
    assert SYSMON_KIND[eid] == expected


@pytest.mark.parametrize("eid,was",
                         [(e, v[1]) for e, v in sorted(RULINGS.items())])
def test_none_of_them_still_carries_its_old_overstated_meaning(eid, was):
    assert SYSMON_KIND[eid] != was


def test_sysmon_255_is_a_sensor_error_not_an_alert():
    """Sysmon reporting its OWN failure is sensor lifecycle telemetry.
    `alert` made the sensor's self-report a NivXForge security claim."""
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=255))
    assert kind == "sensor_error"
    assert kind not in SECURITY_CLAIM_KINDS
    assert basis == "SOURCE_EVENT_ID:sysmon:255"


def test_no_sysmon_event_id_intrinsically_makes_a_security_claim():
    offenders = {eid: kind for eid, kind in SYSMON_KIND.items()
                 if kind in SECURITY_CLAIM_KINDS}
    assert offenders == {}, (
        "a Sysmon Event ID cannot BE a detection or an alert; an "
        f"authoritative detection mechanism concludes one. {offenders}")


def test_the_whole_table_still_only_produces_observations():
    produced = {resolve_kind(CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=eid))[0] for eid in SYSMON_KIND}
    assert produced & SECURITY_CLAIM_KINDS == set()


# ── the proxies did not merely change name, they changed subsystem ──
def test_event_4_no_longer_invents_a_process_death():
    assert SYSMON_KIND[4] == "sensor_service_state_changed"
    assert "process" not in SYSMON_KIND[4]


@pytest.mark.parametrize("eid", [2, 9, 24])
def test_events_that_are_not_file_writes_are_no_longer_file_writes(eid):
    assert SYSMON_KIND[eid] != "file_write"


def test_event_14_no_longer_claims_a_deletion():
    """A renamed registry key still exists; the source never reported a
    deletion."""
    assert SYSMON_KIND[14] == "registry_rename"


def test_event_25_is_neither_understated_nor_turned_into_a_verdict():
    assert SYSMON_KIND[25] == "process_image_tampering"
    assert SYSMON_KIND[25] not in SECURITY_CLAIM_KINDS
    assert SYSMON_KIND[25] != SYSMON_KIND[10]  # not the same as a handle open


# ── vocabulary + lane governance ────────────────────────────────────
@pytest.mark.parametrize("kind", sorted({v[0] for v in RULINGS.values()}))
def test_every_new_kind_is_in_the_locked_cem_vocabulary(kind):
    assert kind in cem_schema.EVENT_KINDS


@pytest.mark.parametrize("kind,lane", [
    ("file_creation_time_changed", "file"),
    ("raw_disk_access_read", "file"),
    ("registry_rename", "registry"),
    ("process_image_tampering", "process"),
    ("clipboard_change", "system"),
    ("sensor_error", "system"),
    ("sensor_service_state_changed", "system"),
])
def test_each_new_kind_lands_in_the_lane_its_evidence_belongs_to(kind, lane):
    from v2.trajectory.schema import lane_for
    assert lane_for(kind) == lane


def test_unchanged_sysmon_mappings_were_left_alone():
    """No broad Sysmon redesign: only the audited ids moved."""
    for eid, expected in ((1, "process_create"), (3, "network_connect"),
                          (5, "process_exit"), (6, "driver_load"),
                          (7, "image_load"), (8, "remote_thread_create"),
                          (10, "process_access"), (11, "file_create"),
                          (12, "registry_create"),
                          (13, "registry_value_set"),
                          (15, "file_create"), (17, "named_pipe_create"),
                          (18, "named_pipe_create"), (19, "wmi_subscribe"),
                          (20, "wmi_subscribe"), (21, "wmi_subscribe"),
                          (22, "dns_query"), (23, "file_delete"),
                          (26, "file_delete")):
        assert SYSMON_KIND[eid] == expected
