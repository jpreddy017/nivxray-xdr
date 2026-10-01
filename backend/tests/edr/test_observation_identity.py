"""OBSERVATION IDENTITY · which record, not which content.

`event.iid` is a CONTENT hash and keeps that meaning. It is NOT an
observation identity: on the real Windows corpus 2,250 of 3,299 genuinely
distinct records hash identically, because a registry value set twice in
the same millisecond by the same image on the same key IS identical
content.

`observation_id` answers "WHICH recorded observation is this". A
compromise's `contributing_event_refs[]` must point at ONE specific
record, so identity is derived from authoritative source identity and
never from content alone — and when the source carried no unique identity
that is reported rather than manufactured.
"""
from __future__ import annotations

import pytest

from v2.ingestion.canonical import (
    OBS_ID_BY_RAW_EVIDENCE,
    OBS_ID_BY_SOURCE_RECORD,
    OBS_ID_NOT_PROVEN,
    ces_to_cem_dict,
    observation_identity,
)
from v2.ingestion.telemetry_bridge import canonical_to_ces, observation_doc

TENANT = "ten_acceptance"
OTHER_TENANT = "ten_other"
ENVELOPE = {"source": "sysmon", "connector_id": "c1", "collector_id": "col1",
            "collection_method": "WINDOWS_EVENTLOG_QUERY",
            "parser_version": "1.0", "source_event_id": "e1",
            "collection_timestamp": "2026-09-22T16:20:09Z"}


def _sysmon_record(*, record_id, ts="2026-09-22T16:20:09.743000+00:00",
                   key="HKLM\\Software\\Nivx\\Run"):
    """Two of these with the SAME ts/key/image are byte-identical content
    and differ only by the record identity Windows assigned them."""
    return {
        "event_id": "sysmon-13-fresh-uuid-each-pass",
        "source_vendor": "Microsoft", "source_product": "Sysmon",
        "source_event_id": "13", "event_type": "registry_event",
        "event_time": ts,
        "host": {"hostname": "DESKTOP-A9HGFJJ", "host_id": "DESKTOP-A9HGFJJ"},
        "identity": {"username": "SYSTEM"},
        "process": {"name": "svchost.exe", "pid": 2404,
                    "executable_path": "C:\\Windows\\system32\\svchost.exe"},
        "network": {}, "file": {}, "authentication": {},
        "registry": {"key_path": key, "value_name": "Updater",
                     "value_data": "C:\\tmp\\x.exe", "action": "set_value"},
        "raw_ref": {"sysmon_event_id": 13,
                    "provider": "Microsoft-Windows-Sysmon",
                    "channel": "Microsoft-Windows-Sysmon/Operational",
                    "record_id": record_id},
        "provenance": {"trace_id": "t1", "normalizer_id": "sysmon-normalizer"},
        "additional_fields": {},
    }


def _sensor_record(raw_id, *, record_id=None):
    """The EDR sensor dialect, whose raw row id is a stable reference."""
    return {
        "event_id": "cev_1_0",
        "source_vendor": "NivXForge", "source_product": "WindowsSensor",
        "event_time": "2026-09-22T15:43:31.770000Z",
        "host": {"hostname": "WS-W1", "host_id": "ep_1"},
        "identity": {}, "process": {}, "network": {}, "file": {},
        "registry": {"key": "HKLM\\Software\\Nivx\\Run"},
        "dns": {}, "authentication": {},
        "raw_ref": {"raw_id": raw_id, "collection": "edr_raw_events"},
        "provenance": {"trace_id": "raw_1"},
        "additional_fields": {
            "payload_format": "nivxforge-windows-eventlog",
            "winlog": {"provider": "Microsoft-Windows-Sysmon",
                       "channel": "Microsoft-Windows-Sysmon/Operational",
                       "event_id": 13, "record_id": record_id,
                       "computer": "WS-W1"}},
    }


def _identity(canonical, *, tenant=TENANT, sequence=0):
    ces = canonical_to_ces(canonical, envelope=ENVELOPE)
    ev = ces_to_cem_dict(ces, case_id=None, sequence=sequence)
    return ev, observation_identity(ev, tenant_id=tenant)


# ── A · content identity keeps its meaning, unchanged ───────────────
def test_two_distinct_records_with_identical_content_share_the_content_iid():
    a, _ = _identity(_sysmon_record(record_id=3312734))
    b, _ = _identity(_sysmon_record(record_id=3312735))
    assert a["iid"] == b["iid"], (
        "event.iid is a CONTENT hash; identical content must still hash "
        "identically or its meaning has been changed silently")


# ── B · DISTINCT_IDENTICAL_CONTENT_TEST ─────────────────────────────
def test_two_distinct_records_with_identical_content_get_different_ids():
    _, (id_a, state_a, _) = _identity(_sysmon_record(record_id=3312734))
    _, (id_b, state_b, _) = _identity(_sysmon_record(record_id=3312735))
    assert id_a != id_b
    assert state_a == state_b == OBS_ID_BY_SOURCE_RECORD


def test_the_discriminator_is_the_source_record_not_the_sequence():
    """Uniqueness must not come from an invented counter: the same record
    at two different ingest positions is still the same observation."""
    _, (id_a, _, _) = _identity(_sysmon_record(record_id=3312734),
                                sequence=0)
    _, (id_b, _, _) = _identity(_sysmon_record(record_id=3312734),
                                sequence=917)
    assert id_a == id_b


# ── C · REPLAY_IDEMPOTENCY ──────────────────────────────────────────
def test_the_same_raw_observation_replayed_twice_yields_the_same_id():
    _, (id_a, _, key_a) = _identity(_sysmon_record(record_id=3312734))
    _, (id_b, _, key_b) = _identity(_sysmon_record(record_id=3312734))
    assert (id_a, key_a) == (id_b, key_b)


def test_identity_ignores_the_non_deterministic_canonical_event_id():
    """Normalizers mint `canonical_event_id` with a fresh uuid4 per pass,
    so it can never take part in an identity that must survive replay."""
    first = _sysmon_record(record_id=3312734)
    second = dict(first, event_id="sysmon-13-a-completely-different-uuid")
    _, (id_a, _, _) = _identity(first)
    _, (id_b, _, _) = _identity(second)
    assert id_a == id_b


# ── D · scoping ─────────────────────────────────────────────────────
def test_identity_is_tenant_scoped():
    _, (id_a, _, _) = _identity(_sysmon_record(record_id=3312734),
                                tenant=TENANT)
    _, (id_b, _, _) = _identity(_sysmon_record(record_id=3312734),
                                tenant=OTHER_TENANT)
    assert id_a != id_b


def test_identity_is_device_scoped():
    here = _sysmon_record(record_id=3312734)
    there = _sysmon_record(record_id=3312734)
    there["host"] = {"hostname": "OTHER-HOST", "host_id": "OTHER-HOST"}
    _, (id_a, _, _) = _identity(here)
    _, (id_b, _, _) = _identity(there)
    assert id_a != id_b


def test_the_same_record_id_on_a_different_channel_is_a_different_record():
    a = _sysmon_record(record_id=3312734)
    b = _sysmon_record(record_id=3312734)
    b["raw_ref"] = dict(b["raw_ref"], channel="Security",
                        provider="Microsoft-Windows-Security-Auditing")
    _, (id_a, _, _) = _identity(a)
    _, (id_b, _, _) = _identity(b)
    assert id_a != id_b


# ── E · the raw-evidence fallback ───────────────────────────────────
def test_a_stable_raw_row_id_is_an_acceptable_identity():
    _, (_, state, _) = _identity(_sensor_record("raw_abc",
                                                record_id=918273))
    assert state == OBS_ID_BY_SOURCE_RECORD  # winlog.record_id wins
    _, (id_b, state_b, _) = _identity(_sensor_record("raw_abc",
                                                     record_id=None))
    assert state_b == OBS_ID_BY_RAW_EVIDENCE
    assert id_b


def test_two_raw_rows_are_two_observations():
    _, (id_a, _, _) = _identity(_sensor_record("raw_abc"))
    _, (id_b, _, _) = _identity(_sensor_record("raw_def"))
    assert id_a != id_b


# ── F · uniqueness is never manufactured ────────────────────────────
def test_a_source_with_no_unique_identity_says_so():
    doc = _sysmon_record(record_id=None)
    doc["raw_ref"] = {"sysmon_event_id": 13,
                      "channel": "Microsoft-Windows-Sysmon/Operational"}
    _, (obs_id, state, _) = _identity(doc)
    assert state == OBS_ID_NOT_PROVEN
    assert obs_id.startswith("obs_")


def test_an_unproven_identity_is_never_silently_upgraded():
    """Two records the source did not distinguish must NOT be handed a
    fabricated distinction — the honest answer is that uniqueness is not
    proven, which a contributor reference can then refuse."""
    doc = _sysmon_record(record_id=None)
    doc["raw_ref"] = {"sysmon_event_id": 13}
    _, (id_a, state_a, _) = _identity(doc, sequence=0)
    assert state_a == OBS_ID_NOT_PROVEN


# ── G · the persisted document carries it ───────────────────────────
def test_the_observation_document_carries_the_identity_and_its_state():
    doc = observation_doc(_sysmon_record(record_id=3312734),
                          envelope=ENVELOPE, tenant_id=TENANT)
    assert doc["observation_id"].startswith("obs_")
    assert doc["observation_identity_state"] == OBS_ID_BY_SOURCE_RECORD
    assert TENANT in doc["observation_identity_key"]
    assert "3312734" in doc["observation_identity_key"]
    # and the content identity is still there, still meaning what it meant
    assert doc["event"]["iid"].startswith("evt_")
    assert doc["observation_id"] != doc["event"]["iid"]


@pytest.mark.parametrize("record_id", [3312734, "3312734"])
def test_a_record_id_is_accepted_in_the_forms_the_sources_use(record_id):
    doc = observation_doc(_sysmon_record(record_id=record_id),
                          envelope=ENVELOPE, tenant_id=TENANT)
    assert doc["observation_identity_state"] == OBS_ID_BY_SOURCE_RECORD
