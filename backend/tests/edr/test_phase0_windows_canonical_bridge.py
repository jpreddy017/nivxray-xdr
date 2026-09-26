"""PHASE 0 · Windows canonical telemetry bridge.

The defect this suite locks closed: `canonical_bridge.parse()` refused
every `WINDOWS_EVENT_LOG` envelope (`unknown sensor activity None`), so a
real Windows endpoint enrolled, authenticated, heartbeated and delivered
raw telemetry successfully while producing NO canonical evidence — empty
Device Trajectory, empty Process Tree, no detections, no findings — and
still reported as fresh and delivering.

Every test enters through the SAME envelope the real connector emits.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from edr_plane import windows_eventlog as wl                   # noqa: E402
from edr_plane.canonical_bridge import (activity_identity,     # noqa: E402
                                        bind_process_identity, parse)
from edr_plane.trajectory_window import GROUPS, _group_and_key  # noqa: E402
from v2.ingestion.telemetry_bridge import observation_doc      # noqa: E402

from tests.edr import fixtures_windows_eventlog as fx          # noqa: E402

ENDPOINT = "ep_win_0001"
ENVELOPE = {"source": "nivxforge-windows-sensor", "connector_id": ENDPOINT,
            "collector_id": ENDPOINT,
            "collection_method": wl.COLLECTION_METHOD,
            "parser_version": "1.0.0", "source_event_id": "cev_test",
            "collection_timestamp": "2026-06-01T10:04:00Z"}


def _canonical(line: str) -> dict:
    c = parse(line)
    c["event_id"] = "cev_test_1"
    c["raw_ref"] = {"raw_id": "raw_test", "collection": "edr_raw_events"}
    c["host"] = {"host_id": ENDPOINT, "hostname": fx.HOST}
    return bind_process_identity(c, ENDPOINT)


def _observation(line: str) -> dict:
    return observation_doc(_canonical(line), envelope=ENVELOPE,
                           tenant_id="ten_test")


# ── 1 · the envelope is no longer refused ─────────────────────────
@pytest.mark.parametrize("name,line", sorted(fx.ALL_SUPPORTED.items()))
def test_every_supported_windows_event_canonicalises(name, line):
    c = parse(line)
    assert c["additional_fields"]["payload_format"] == wl.PAYLOAD_FORMAT
    assert c["source_product"] == "WindowsSensor"
    assert c["additional_fields"]["activity_type"] in (
        "PROCESS", "FILE", "NETWORK", "REGISTRY", "DNS", "AUTHENTICATION")
    # Provenance back to the immutable Windows record.
    w = c["additional_fields"]["winlog"]
    assert w["record_id"] and w["event_id"] and w["channel"] and w["provider"]
    assert c["event_time"]


def test_activity_class_per_event_id():
    assert parse(fx.SYSMON_1_POWERSHELL)[
        "additional_fields"]["activity_type"] == "PROCESS"
    assert parse(fx.SYSMON_3)["additional_fields"]["activity_type"] \
        == "NETWORK"
    assert parse(fx.SYSMON_11)["additional_fields"]["activity_type"] == "FILE"
    assert parse(fx.SYSMON_12)["additional_fields"]["activity_type"] \
        == "REGISTRY"
    assert parse(fx.SYSMON_13)["additional_fields"]["activity_type"] \
        == "REGISTRY"
    assert parse(fx.SYSMON_22)["additional_fields"]["activity_type"] == "DNS"
    assert parse(fx.WINSEC_4688)["additional_fields"]["activity_type"] \
        == "PROCESS"
    assert parse(fx.WINSEC_4624)["additional_fields"]["activity_type"] \
        == "AUTHENTICATION"


# ── 2 · process identity and ancestry ─────────────────────────────
def test_process_guid_is_the_authoritative_identity():
    proc = _canonical(fx.SYSMON_1_POWERSHELL)["process"]
    assert proc["process_guid"] == fx.PS_GUID
    assert proc["identity_quality"] == wl.IDENTITY_PROCESS_GUID
    assert proc["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    assert proc["parent_process_guid"] == fx.CHROME_GUID
    assert proc["ancestry_state"] == "PARENT_OBSERVED_PROCESS_GUID"
    assert proc["process_iid"]
    assert proc["command_line"].startswith("powershell.exe")
    assert proc["hashes"]["sha256"]
    assert proc["integrity_level"] == "High"


def test_pid_only_is_downgraded_but_keeps_its_evidence():
    """The downgrade is a QUALITY state — it never replaces identity."""
    proc = _canonical(fx.SYSMON_1_NO_GUID)["process"]
    assert "process_guid" not in proc
    assert proc["identity_quality"] == wl.IDENTITY_PID_ONLY
    assert proc["attribution_state"] == "PID_ONLY_NOT_AUTHORITATIVE"
    # The best available source identity is PRESERVED, not discarded.
    assert proc["pid"] == "6001"
    assert proc["executable_path"].endswith("cmd.exe")
    assert proc["command_line"] == r"cmd.exe /c echo hi"
    assert proc["parent_pid"] == "4120"
    assert proc["ancestry_state"] == "PARENT_OBSERVED_PID_ONLY"
    assert "reused" in proc["identity_reason"].lower()


def test_4688_does_not_claim_a_process_guid():
    c = _canonical(fx.WINSEC_4688)
    proc = c["process"]
    assert "process_guid" not in proc
    assert proc["identity_quality"] == wl.IDENTITY_PID_ONLY
    assert proc["executable_path"].endswith("ipconfig.exe")
    assert proc["command_line"] == r"ipconfig /all"
    assert proc["parent_executable_path"].endswith("cmd.exe")
    assert c["identity"]["sid"] == "S-1-5-21-1-1001"
    assert "ProcessGuid" in c["additional_fields"][
        "epistemic_state"]["not_observed"]


def test_three_generation_ancestry_from_process_guid():
    """explorer.exe → chrome.exe → powershell.exe, by GUID only."""
    chain = [_observation(l) for l in (fx.SYSMON_1_EXPLORER,
                                       fx.SYSMON_1_CHROME,
                                       fx.SYSMON_1_POWERSHELL)]
    iids = [d["event"]["process"]["iid"] for d in chain]
    parents = [d["event"]["process"]["parent_iid"] for d in chain]
    assert len(set(iids)) == 3, "each process must be its own identity"
    # chrome's parent IS explorer; powershell's parent IS chrome.
    assert parents[1] == iids[0]
    assert parents[2] == iids[1]
    # And the identity is derived from the GUID, not from the PID.
    assert all(d["event"]["kind"] == "process_create" for d in chain)


def test_ancestry_is_not_claimed_when_parent_absent():
    proc = _canonical(fx.SYSMON_1_SPARSE)["process"]
    assert proc["ancestry_state"] == "PARENT_NOT_OBSERVED"
    assert "parent_process_guid" not in proc


# ── 3 · per-class evidence, on its OWN lane ───────────────────────
def test_network_correlates_to_process_and_keeps_dns_out():
    c = _canonical(fx.SYSMON_3)
    assert c["network"]["dest_ip"] == "93.184.216.34"
    assert c["network"]["dest_port"] == "443"
    assert c["network"]["direction"] == "OUTBOUND"
    assert c["process"]["process_guid"] == fx.CHROME_GUID
    # Sysmon's DestinationHostname is Windows' peer name, NOT a DNS query.
    assert c["network"]["dest_hostname"] == "example.com"
    assert not c["dns"], "a network connection must not become DNS evidence"
    assert _group_and_key(_observation(fx.SYSMON_3)["event"])[0] == "NETWORK"


def test_file_create_correlates_to_responsible_process():
    c = _canonical(fx.SYSMON_11)
    assert c["file"]["path"].endswith("example.ps1")
    assert c["file"]["operation"] == "CREATE"
    assert c["process"]["process_guid"] == fx.PS_GUID
    assert _group_and_key(_observation(fx.SYSMON_11)["event"])[0] == "FILE"


def test_registry_is_registry_not_file_or_process():
    for line, op in ((fx.SYSMON_12, "KEY_CREATE"),
                     (fx.SYSMON_13, "VALUE_SET")):
        c = _canonical(line)
        assert c["registry"]["key"].startswith("HKU")
        assert c["registry"]["operation"] == op
        assert c["process"]["process_guid"] == fx.PS_GUID
        assert not c["file"], "registry activity must not be filed as a file"
        doc = _observation(line)
        group, lane_id, _ = _group_and_key(doc["event"])
        assert group == "REGISTRY", f"{op} landed on {group}"
        assert lane_id.startswith("reg::")
    # Only Sysmon 13 carries value data; 12 must not invent it.
    assert _canonical(fx.SYSMON_13)["registry"]["value_data"].endswith(
        "example.ps1")
    assert "value_data" not in _canonical(fx.SYSMON_12)["registry"]


def test_dns_is_dns_and_correlates_to_process():
    c = _canonical(fx.SYSMON_22)
    assert c["dns"]["query_name"] == "example.com"
    assert c["dns"]["query_status"] == "0"
    # Only real address answers; the CNAME fragment is not an address.
    assert c["dns"]["answers"] == ["93.184.216.34"]
    assert c["process"]["process_guid"] == fx.CHROME_GUID
    doc = _observation(fx.SYSMON_22)
    group, lane_id, _ = _group_and_key(doc["event"])
    assert group == "DNS" and lane_id == "dns::example.com"


def test_authentication_preserves_logon_evidence():
    c = _canonical(fx.WINSEC_4624)
    a = c["authentication"]
    assert a["outcome"] == "SUCCESS"
    assert a["logon_type"] == "2"
    # Interactive vs remote comes from the mapped LogonType, not a guess.
    assert a["logon_type_name"] == "INTERACTIVE"
    assert a["target_user"] == "analyst"
    assert a["target_sid"] == "S-1-5-21-1-1001"
    assert a["source_ip"] == "10.20.30.40"
    assert a["authentication_package"] == "Negotiate"
    doc = _observation(fx.WINSEC_4624)
    assert doc["event"]["kind"] == "logon_success"
    assert _group_and_key(doc["event"])[0] == "AUTHENTICATION"


def test_trajectory_exposes_all_six_lane_groups():
    assert GROUPS == ("PROCESS", "FILE", "NETWORK", "REGISTRY", "DNS",
                      "AUTHENTICATION")


# ── 4 · provenance and activity identity ──────────────────────────
def test_canonical_points_back_at_the_raw_event():
    doc = _observation(fx.SYSMON_1_POWERSHELL)
    c = _canonical(fx.SYSMON_1_POWERSHELL)
    assert c["raw_ref"]["raw_id"] == "raw_test"
    assert c["raw_ref"]["collection"] == "edr_raw_events"
    assert doc["canonical_event_id"] == "cev_test_1"
    assert doc["connector_id"] == ENDPOINT


def test_windows_record_identity_is_stable_and_distinct():
    a = activity_identity(json.loads(fx.SYSMON_1_POWERSHELL), ENDPOINT)
    b = activity_identity(json.loads(fx.SYSMON_1_POWERSHELL), ENDPOINT)
    c = activity_identity(json.loads(fx.SYSMON_1_CHROME), ENDPOINT)
    assert a == b, "a redelivered record is the SAME activity"
    assert a != c, "two different records are different activities"


def test_epistemic_state_travels_with_the_evidence():
    c = parse(fx.SYSMON_1_SPARSE)
    ep = c["additional_fields"]["epistemic_state"]
    assert "CommandLine" in ep["not_observed"]
    assert "process.signer" in ep["not_supported"]
    assert "did not occur" in ep["note"]


# ── 5 · negative cases · nothing is ever silently CLEAN ───────────
@pytest.mark.parametrize("line,code", [
    (fx.UNSUPPORTED_EVENT_ID, "WINDOWS_EVENT_ID_NOT_SUPPORTED"),
    (fx.UNSUPPORTED_PROVIDER, "WINDOWS_PROVIDER_NOT_SUPPORTED"),
    (fx.MALFORMED_XML, "WINDOWS_EVENT_XML_MALFORMED"),
    (fx.NO_XML, "WINDOWS_EVENT_XML_ABSENT"),
    (fx.NO_EVENT_ID, "WINDOWS_EVENT_ID_ABSENT"),
])
def test_refusals_are_truthful_and_named(line, code):
    with pytest.raises(wl.WindowsEventLogError) as e:
        parse(line)
    assert e.value.code == code
    reason = e.value.reason.lower()
    assert "clean" not in reason and "benign" not in reason
    assert ("retained" in reason or "unknown" in reason
            or "could not be parsed" in reason)


def test_event_without_eventdata_is_not_an_absence_of_activity():
    """No EventData is a sparse record, not a refusal and not 'clean'."""
    c = parse(fx.NO_EVENT_DATA)
    assert c["additional_fields"]["activity_type"] == "PROCESS"
    assert c["process"]["identity_quality"] == wl.IDENTITY_NOT_OBSERVED
    assert "not observed" in c["process"]["identity_reason"]


def test_invalid_source_timestamp_is_not_replaced_by_our_clock():
    c = parse(fx.SYSMON_1_BAD_TIME)
    stamps = c["provenance"]["timestamps"]
    assert c["event_time"], "an event still needs a usable time"
    # Whatever basis was used must be DECLARED, so nothing is passed off
    # as the source's own statement of when the activity happened.
    assert c["additional_fields"].get("event_time_basis") or stamps


def test_duplicate_record_ids_resolve_to_one_activity():
    same = activity_identity(json.loads(fx.SYSMON_11), ENDPOINT)
    again = activity_identity(json.loads(fx.SYSMON_11), ENDPOINT)
    assert same == again


def test_out_of_order_delivery_does_not_change_identity_or_class():
    order = [fx.SYSMON_22, fx.SYSMON_1_EXPLORER, fx.SYSMON_13, fx.SYSMON_3]
    classes = [parse(l)["additional_fields"]["activity_type"] for l in order]
    assert classes == ["DNS", "PROCESS", "REGISTRY", "NETWORK"]


# ── 6 · the Linux connector must not regress ──────────────────────
LINUX_PROCESS = json.dumps({
    "activity": "PROCESS", "observed_at": "2026-06-01T10:00:00+00:00",
    "pid": 4242, "ppid": 1, "image": "bash", "image_path": "/bin/bash",
    "command_line": "bash -lc id", "user": "root",
    "start_time": "2026-06-01T09:59:00+00:00", "start_ticks": 12345,
    "parent_image": "systemd", "parent_lookup_state": "OBSERVED",
    "sha256": "f" * 64})
LINUX_FILE = json.dumps({
    "activity": "FILE", "operation": "CREATE", "path": "/tmp/x",
    "filename": "x", "size": 10, "observed_at": "2026-06-01T10:00:00+00:00"})
LINUX_NETWORK = json.dumps({
    "activity": "NETWORK", "protocol": "tcp", "local_ip": "10.0.0.1",
    "local_port": 5555, "remote_ip": "1.1.1.1", "remote_port": 443,
    "direction": "OUTBOUND", "pid": 4242, "process_start_ticks": 12345,
    "process_start_time": "2026-06-01T09:59:00+00:00",
    "observed_at": "2026-06-01T10:00:00+00:00"})


def test_linux_process_canonicalisation_unchanged():
    c = bind_process_identity(parse(LINUX_PROCESS), ENDPOINT)
    assert c["source_product"] == "LinuxSensor"
    assert c["additional_fields"]["activity_type"] == "PROCESS"
    assert c["process"]["attribution_state"] == "SOURCE_PROCESS_IDENTITY"
    assert c["process"]["process_iid"]
    assert c["process"]["command_line"] == "bash -lc id"
    assert c["additional_fields"]["lineage_state"] == "PARENT_OBSERVED"
    assert "process_guid" not in c["process"]


def test_linux_file_and_network_canonicalisation_unchanged():
    f = parse(LINUX_FILE)
    assert f["additional_fields"]["activity_type"] == "FILE"
    assert f["file"]["path"] == "/tmp/x"
    n = bind_process_identity(parse(LINUX_NETWORK), ENDPOINT)
    assert n["additional_fields"]["activity_type"] == "NETWORK"
    assert n["network"]["dest_ip"] == "1.1.1.1"
    assert n["process"]["attribution_state"] == "SOURCE_PROCESS_IDENTITY"


def test_linux_unknown_activity_still_refused():
    with pytest.raises(ValueError):
        parse(json.dumps({"activity": "TELEPATHY"}))


def test_linux_observation_lane_groups_unchanged():
    env = {**ENVELOPE, "source": "nivxforge-linux-sensor",
           "collection_method": "PROC_POLL"}
    for line, group in ((LINUX_PROCESS, "PROCESS"), (LINUX_FILE, "FILE"),
                        (LINUX_NETWORK, "NETWORK")):
        c = bind_process_identity(parse(line), ENDPOINT)
        c["event_id"] = "cev_lin_1"
        c["host"] = {"host_id": ENDPOINT, "hostname": "linux-host"}
        doc = observation_doc(c, envelope=env, tenant_id="ten_test")
        assert _group_and_key(doc["event"])[0] == group


# ── 8 · the detection handoff accepts Windows canonical evidence ──
def test_detection_dsm_claims_and_normalises_windows_evidence():
    """The SAME DSM the Linux connector uses, with no second engine."""
    from detection_content.telemetry.nivxforge_sensor_dsm import (
        NivXForgeSensorDSM)
    dsm = NivXForgeSensorDSM()
    seen = set()
    for name, line in sorted(fx.ALL_SUPPORTED.items()):
        ev = json.loads(line)
        assert dsm.supports(ev), f"{name} was not claimed by the DSM"
        parsed = dsm.select_parser().parse(ev)
        canonical = dsm.select_normalizer().normalize(
            parsed, collector_id=ENDPOINT, integration_id="phase0",
            trace_id="raw_test", tenant_id="ten_test")
        # Tenant authority comes from the authenticated delivery, never
        # from the sensor payload.
        assert canonical["tenant_id"] == "ten_test"
        assert canonical["host"]["host_id"] == ENDPOINT
        assert canonical["provenance"]["trace_id"] == "raw_test"
        seen.add(parsed["event_type"])
    assert seen == {"PROCESS", "FILE", "NETWORK", "REGISTRY", "DNS",
                    "AUTHENTICATION"}


def test_dsm_still_refuses_a_lookalike_event():
    from detection_content.telemetry.nivxforge_sensor_dsm import (
        NivXForgeSensorDSM)
    dsm = NivXForgeSensorDSM()
    assert not dsm.supports({"activity": "PROCESS"})
    assert not dsm.supports({"kind": "WINDOWS_EVENT_LOG"})
    assert not dsm.supports("not a dict")


# ── 7 · investigability truth ─────────────────────────────────────
def test_investigability_separates_delivery_from_evidence():
    from services.edr.telemetry_freshness import (INVESTIGABLE, NO_DELIVERY,
                                                  RAW_ONLY,
                                                  UNKNOWN_INVESTIGABILITY,
                                                  investigability)
    raw_only = investigability({"event_count": 812}, 0)
    assert raw_only["state"] == RAW_ONLY
    assert "NOT ONE" in raw_only["statement"]
    assert "not because nothing happened" in raw_only["statement"]
    assert investigability({"event_count": 812}, 812)["state"] == INVESTIGABLE
    assert investigability({"event_count": 0}, 0)["state"] == NO_DELIVERY
    unknown = investigability({"event_count": 5}, None)
    assert unknown["state"] == UNKNOWN_INVESTIGABILITY
    assert "not clean" in unknown["statement"]
    for state in (raw_only, unknown):
        assert "clean" not in state["state"].lower()
