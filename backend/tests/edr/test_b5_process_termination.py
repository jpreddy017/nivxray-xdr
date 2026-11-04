"""B5-1 · Sysmon EventID 5 (ProcessTerminate) server-side readiness.

Admitting EID 5 does not GENERATE it — the endpoint configuration still
has to emit it. What this file pins is that when a termination IS
collected, the server understands it without inventing anything:

* it canonicalises as `process_exit` — the platform's existing CEM kind
  for this fact, not a second name for it;
* the exit instant comes from the EID 5 evidence and is recorded as
  `exit_time`, NEVER as `start_time` (the same `UtcTime` field means the
  opposite thing on EID 1);
* it binds to the B2 process identity through `ProcessGuid`, so the exit
  resolves to the SAME `process_key` as the creation;
* a termination with no authoritative identity is NOT joined by PID;
* lifetime moves from `PROCESS_LIFETIME_UNKNOWN` to
  `PROCESS_TERMINATION_OBSERVED` only on collected evidence;
* malformed, replayed, and cross-tenant records behave.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, "/app/backend")

from edr_plane import canonical_bridge                          # noqa: E402
from edr_plane import process_identity as pi                    # noqa: E402
from edr_plane import windows_eventlog as winlog                # noqa: E402
from tests.edr import fixtures_windows_eventlog as fx           # noqa: E402
from v2.ingestion.telemetry_bridge import observation_doc       # noqa: E402

TENANT = "ten_b5_termination"
OTHER_TENANT = "ten_b5_other"
ENDPOINT = "ep_b5"
GUID = "{fbfbfbfb-0000-0000-0000-00000000000f}"
GUID_B = "{fcfcfcfc-0000-0000-0000-00000000000c}"
IMAGE = r"C:\Windows\System32\cmd.exe"
START = "2026-06-01 10:04:00.123"
EXIT = "2026-06-01 10:09:30.456"

CREATE = {"UtcTime": START, "ProcessGuid": GUID, "ProcessId": "7364",
          "Image": IMAGE, "OriginalFileName": "Cmd.Exe",
          "CommandLine": "cmd /c whoami", "User": "NIVX\\svc-admin",
          "Hashes": "SHA256=" + "a" * 64,
          "ParentProcessGuid": "{aaaaaaaa-0000-0000-0000-00000000000a}",
          "ParentProcessId": "4120",
          "ParentImage": r"C:\Windows\explorer.exe"}

TERMINATE = {"UtcTime": EXIT, "ProcessGuid": GUID, "ProcessId": "7364",
             "Image": IMAGE, "User": "NIVX\\svc-admin"}

ENVELOPE = {"source": "nivxforge-windows-sensor", "connector_id": ENDPOINT,
            "collector_id": ENDPOINT,
            "collection_method": "WINDOWS_EVENT_LOG",
            "parser_version": "1.0.0", "source_event_id": "cev_b5",
            "collection_timestamp": "2026-06-01T10:09:31+00:00"}


def _canonical(event_id: int, record_id: int, data: dict) -> dict:
    c = canonical_bridge.parse(fx.sysmon(event_id, record_id, data))
    canonical_bridge.bind_process_identity(c, ENDPOINT)
    c["event_id"] = f"cev_b5_{record_id}"
    c["additional_fields"]["endpoint_id"] = ENDPOINT
    return c


def _view(event_id: int, record_id: int, data: dict,
          tenant: str = TENANT) -> pi.ProcessView:
    return pi.from_canonical(_canonical(event_id, record_id, data),
                             tenant_id=tenant, endpoint_id=ENDPOINT)


# ── A · server readiness ─────────────────────────────────────────────
def test_sysmon_event_id_5_is_in_the_supported_contract():
    assert ("sysmon", 5) in winlog.SUPPORTED
    assert winlog.SUPPORTED[("sysmon", 5)] == \
        winlog.ACTIVITY_PROCESS_TERMINATION


def test_a_collected_termination_is_no_longer_refused():
    """POSITIVE CONTROL: before B5-1 this raised
    `WINDOWS_EVENT_ID_NOT_SUPPORTED` and produced no evidence."""
    c = _canonical(5, 5001, TERMINATE)
    assert c["event_type"] == "process_exit"
    assert c["additional_fields"]["activity_type"] == \
        winlog.ACTIVITY_PROCESS_TERMINATION


def test_the_dsm_plane_canonicalises_it_identically():
    from detection_content.telemetry.sysmon_dsm import SysmonDSM

    dsm = SysmonDSM()
    ev = {"event_id": 5, "provider": fx.SYSMON_PROVIDER,
          "channel": fx.SYSMON_CHANNEL, "record_id": 5002,
          "computer": fx.HOST, **TERMINATE}
    parsed = dsm.select_parser().parse(ev)
    out = dsm.select_normalizer().normalize(
        parsed, dsm_id=dsm.id, collector_id=ENDPOINT,
        integration_id="b5", trace_id="t", tenant_id=TENANT)
    assert out["event_type"] == "process_exit", (
        "the two canonical dialects must state this fact under ONE name")


def test_the_read_model_kind_is_process_exit():
    doc = observation_doc(_canonical(5, 5003, TERMINATE),
                          envelope=ENVELOPE, tenant_id=TENANT)
    assert doc["event"]["kind"] == "process_exit"
    assert doc["process_guid"] == GUID


# ── B · the exit instant is the exit instant ─────────────────────────
def test_the_exit_time_comes_from_the_event_and_is_not_a_start_time():
    c = _canonical(5, 5004, TERMINATE)
    proc = c["process"]
    assert proc["exit_time"].startswith("2026-06-01T10:09:30")
    assert not proc.get("start_time"), (
        "EID 5's UtcTime is the EXIT instant; recording it as a start "
        "time would fabricate when the process began")
    assert proc["field_provenance"]["exit_time"].endswith(
        "UtcTime (EventID 5)")


def test_a_termination_does_not_carry_over_creation_fields():
    c = _canonical(5, 5005, TERMINATE)
    proc = c["process"]
    for field in ("command_line", "original_file_name",
                  "parent_process_guid", "parent_command_line"):
        assert not proc.get(field), (
            f"{field} was not stated by this record and must not be "
            f"copied from the creation event")
    assert not (proc.get("hashes") or {})
    assert "CommandLine" in c["additional_fields"]["epistemic_state"][
        "not_observed"]
    assert "process.start_time" in c["additional_fields"][
        "epistemic_state"]["not_observed"]


def test_what_this_event_class_can_never_supply_is_declared():
    c = _canonical(5, 5006, TERMINATE)
    assert "process.exit_code" in c["additional_fields"][
        "epistemic_state"]["not_supported"]


# ── C · identity binding ─────────────────────────────────────────────
def test_the_termination_resolves_to_the_same_process_as_the_creation():
    create = pi.resolve_identity(_view(1, 5007, CREATE))
    exit_ = pi.resolve_identity(_view(5, 5008, TERMINATE))
    assert exit_.authority == pi.AUTHORITY_SOURCE_GUID
    assert exit_.process_key == create.process_key, (
        "the exit must bind to the SAME process, through ProcessGuid")


def test_a_termination_with_no_guid_is_not_joined_by_pid():
    view = _view(5, 5009, {k: v for k, v in TERMINATE.items()
                           if k != "ProcessGuid"})
    got = pi.resolve_identity(view)
    assert got.authority == pi.AUTHORITY_PID_ONLY
    assert got.process_key is None, (
        "joining an exit to a process on PID alone is how a lifetime gets "
        "fabricated")
    out = pi.build([_view(1, 5010, CREATE), view])
    assert out["counts"]["processes"] == 1
    assert out["counts"]["unattributed_observations"] == 1
    assert out["processes"][0]["lifecycle"]["lifetime_state"] == \
        pi.PROCESS_LIFETIME_UNKNOWN, (
        "an unattributable exit must NOT terminate a process")


# ── D · lifetime ─────────────────────────────────────────────────────
def test_lifetime_moves_from_unknown_to_termination_observed():
    before = pi.build([_view(1, 5011, CREATE)])["processes"][0]
    assert before["lifecycle"]["lifetime_state"] == \
        pi.PROCESS_LIFETIME_UNKNOWN

    after = pi.build([_view(1, 5012, CREATE),
                      _view(5, 5013, TERMINATE)])
    assert after["counts"]["processes"] == 1
    life = after["processes"][0]["lifecycle"]
    assert life["lifetime_state"] == pi.PROCESS_TERMINATION_OBSERVED
    assert life["start"]["state"] == pi.PROCESS_START_OBSERVED
    assert life["termination"]["observed_at"].startswith(
        "2026-06-01T10:09:30")
    assert life["termination"]["evidence_ref"] == "cev_b5_5013"


def test_a_later_observation_still_never_becomes_a_termination():
    """NEGATIVE CONTROL: activity after the creation is not an exit."""
    out = pi.build([_view(1, 5014, CREATE),
                    _view(22, 5015, {"UtcTime": EXIT, "ProcessGuid": GUID,
                                     "ProcessId": "7364", "Image": IMAGE,
                                     "QueryName": "example.com"})])
    life = out["processes"][0]["lifecycle"]
    assert life["lifetime_state"] == pi.PROCESS_LIFETIME_UNKNOWN
    assert life["observed_evidence_span"]["last_observed_at"]
    assert "not an exit" in life["lifetime_reason"]


# ── E · malformed ────────────────────────────────────────────────────
def test_a_termination_with_no_utctime_does_not_invent_one():
    c = _canonical(5, 5016, {"ProcessGuid": GUID, "ProcessId": "7364",
                             "Image": IMAGE})
    # TimeCreated from the record's System block is the fallback the
    # fixture supplies; what must never happen is a fabricated instant.
    assert c["process"].get("exit_time") in (None, "", c["event_time"])
    assert c["event_type"] == "process_exit"


def test_a_termination_with_no_process_at_all_is_not_observed():
    view = _view(5, 5017, {"UtcTime": EXIT})
    got = pi.resolve_identity(view)
    assert got.authority == pi.AUTHORITY_NOT_OBSERVED
    assert got.process_key is None


def test_a_malformed_event_id_is_still_refused():
    with pytest.raises(winlog.WindowsEventLogError) as ex:
        canonical_bridge.parse(fx.sysmon(999, 5018, TERMINATE))
    assert ex.value.code == "WINDOWS_EVENT_ID_NOT_SUPPORTED"


# ── F · replay / idempotency ─────────────────────────────────────────
def test_a_replayed_termination_is_one_activity_not_two():
    payload = fx.sysmon(5, 5019, TERMINATE)
    first = canonical_bridge.activity_identity(
        __import__("json").loads(payload), ENDPOINT)
    second = canonical_bridge.activity_identity(
        __import__("json").loads(payload), ENDPOINT)
    assert first == second, (
        "a redelivered Windows record is the same activity observed "
        "twice, never a second process exit")
    out = pi.build([_view(1, 5020, CREATE), _view(5, 5021, TERMINATE),
                    _view(5, 5021, TERMINATE)])
    assert out["counts"]["processes"] == 1
    life = out["processes"][0]["lifecycle"]
    assert life["lifetime_state"] == pi.PROCESS_TERMINATION_OBSERVED
    assert life["termination"]["observed_at"].startswith(
        "2026-06-01T10:09:30")


def test_the_observation_identity_is_stable_across_replay():
    a = observation_doc(_canonical(5, 5022, TERMINATE), envelope=ENVELOPE,
                        tenant_id=TENANT)
    b = observation_doc(_canonical(5, 5022, TERMINATE), envelope=ENVELOPE,
                        tenant_id=TENANT)
    assert a["observation_id"] == b["observation_id"]


# ── G · tenant + PID reuse ───────────────────────────────────────────
def test_a_termination_never_terminates_another_tenants_process():
    mine = _view(1, 5023, CREATE, tenant=TENANT)
    theirs = _view(5, 5024, TERMINATE, tenant=OTHER_TENANT)
    assert pi.resolve_identity(mine).process_key != \
        pi.resolve_identity(theirs).process_key
    out = pi.build([mine, theirs])
    assert out["counts"]["processes"] == 2
    by_tenant = {p["tenant_id"]: p["lifecycle"]["lifetime_state"]
                 for p in out["processes"]}
    assert by_tenant[TENANT] == pi.PROCESS_LIFETIME_UNKNOWN, (
        "another tenant's exit event terminated this tenant's process")
    assert by_tenant[OTHER_TENANT] == pi.PROCESS_TERMINATION_OBSERVED


def test_pid_reuse_does_not_terminate_the_wrong_process():
    """Same PID, two processes: the exit belongs to exactly one."""
    first = _view(1, 5025, CREATE)
    second = _view(1, 5026, {**CREATE, "ProcessGuid": GUID_B,
                             "UtcTime": "2026-06-01 10:20:00.000"})
    exit_second = _view(5, 5027, {**TERMINATE, "ProcessGuid": GUID_B,
                                  "UtcTime": "2026-06-01 10:25:00.000"})
    out = pi.build([first, second, exit_second])
    assert out["counts"]["processes"] == 2
    states = {p["process_guid"]: p["lifecycle"]["lifetime_state"]
              for p in out["processes"]}
    assert states[GUID] == pi.PROCESS_LIFETIME_UNKNOWN
    assert states[GUID_B] == pi.PROCESS_TERMINATION_OBSERVED
    assert out["pid_reuse"][0]["count"] == 2
