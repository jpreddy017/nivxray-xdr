"""D12 · cross-DSM activity time — the platform-wide temporal invariant.

The one rule this suite exists to protect, for every DSM that exists today
and every DSM added later:

    activity_occurred_at is AVAILABLE only when the source format PROVED
    it. Not when the value looks close enough. Not when the normalizer
    happens to own a clock.

The mandatory regression is `test_no_dsm_invents_activity_time_when_the_
source_timestamp_is_removed` and its corrupted-value twin: strip or break
each DSM's own timestamp field and prove the canonical event does not
silently acquire a measured activity time.

EVIDENCE LABELLING
  TEST/SYNTHETIC — every sample below is constructed here, in the shape the
  real source emits. No live telemetry, nothing sent to production.
"""
from __future__ import annotations

import json

import pytest

from detection_content.xdr_pipeline import DSM_REGISTRY as REGISTRY
from services import event_time_basis as etb
from services import provenance_timestamps as pts

ACT = "activity_occurred_at"
OBS = "sensor_observed_at"

AUD = "1757452888.555:9002"

# ── one realistic sample per registered DSM, plus which key carries the
# ── source time and whether that format establishes activity occurrence.
SAMPLES: dict[str, dict] = {
    "snort-eve": {
        "event": {"event_type": "alert", "timestamp": "2026-06-01T10:00:00+00:00",
                  "src_ip": "10.0.0.5", "dest_ip": "198.51.100.9",
                  "alert": {"signature_id": 2027865, "signature": "x"}},
        "time_keys": ["timestamp"],
        "proves_activity": True,
        "expect_activity_source": "snort-eve:timestamp",
    },
    "windows-security-evd": {
        "event": {"EventID": 4624, "provider": "Microsoft-Windows-Security-Auditing",
                  "channel": "Security", "Computer": "WIN-DC-01",
                  "TimeCreated": "2026-06-01T10:00:00+00:00",
                  "EventData": {"TargetUserName": "svc_backup",
                                "LogonType": "3",
                                "IpAddress": "10.0.0.9"}},
        "time_keys": ["TimeCreated"],
        "proves_activity": False,
        "expect_observation_source": "windows:System.TimeCreated.SystemTime",
    },
    "linux-auditd": {
        "event": {"tenant_id": "t-d12",
                  "message": (f'type=SYSCALL msg=audit({AUD}): arch=c000003e '
                              f'syscall=59 uid=0 euid=0 comm="bash" '
                              f'exe="/usr/bin/bash" key="exec"'),
                  "collector_id": "col-d12"},
        "time_keys": ["message"],
        "proves_activity": True,
        "expect_activity_source": "auditd:msg=audit(epoch:serial)",
    },
    "aws-cloudtrail": {
        "event": {"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
                  "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
                  "eventID": "ct-1", "sourceIPAddress": "203.0.113.7",
                  "userIdentity": {"type": "IAMUser", "userName": "dev1",
                                   "accountId": "111122223333"}},
        "time_keys": ["eventTime"],
        "proves_activity": True,
        "expect_activity_source": "cloudtrail:eventTime",
    },
    "microsoft-sysmon": {
        "event": {"EventID": 1, "provider": "Microsoft-Windows-Sysmon",
                  "Computer": "WIN-WS-07", "User": "CORP\\dev1",
                  "UtcTime": "2026-06-01T10:00:00+00:00",
                  "TimeCreated": "2026-06-01T10:00:02+00:00",
                  "Image": "C:\\Windows\\System32\\cmd.exe",
                  "CommandLine": "cmd /c whoami", "ProcessId": "4321",
                  "ParentImage": "C:\\Windows\\explorer.exe"},
        "time_keys": ["UtcTime"],
        "proves_activity": True,
        "expect_activity_source": "sysmon:EventData.UtcTime",
        "expect_observation_source": "sysmon:System.TimeCreated",
    },
    "cef-leef": {
        "event": {"line": ("CEF:0|NivX|Firewall|1.0|100|Blocked|5|"
                           "src=10.0.0.4 dst=198.51.100.2 spt=443 "
                           "devTime=1780308000000 rt=1780308060000")},
        "time_keys": ["line"],
        "proves_activity": True,
        "expect_activity_source": "cef-leef:devTime",
        "expect_observation_source": "cef:rt — receipt time by spec",
    },
    "nivxforge-linux-sensor": {
        "event": {"activity": "PROCESS", "operation": "OBSERVED",
                  "collection_method": "proc_scan", "endpoint_id": "dev_d12",
                  "hostname": "linux-d12", "pid": 4242,
                  "start_time": "2026-06-01T10:00:00+00:00",
                  "observed_at": "2026-06-01T10:00:05+00:00",
                  "image_path": "/usr/bin/bash"},
        "time_keys": ["start_time"],
        "proves_activity": True,
        "expect_activity_source": "sensor:/proc start_time",
        "expect_observation_source": "sensor:observed_at",
    },
    # N1 · Zeek is a passive wire sensor: the packet it timestamps IS the
    # activity, exactly as the Suricata/Snort EVE instant is. `_write_ts`
    # is when Zeek wrote the record and stays an observation.
    "zeek-json": {
        "event": {"_path": "dns", "_system_name": "zeek-d12",
                  "ts": 1780308000.0, "_write_ts": 1780308001.5,
                  "uid": "Cd12zeek", "id.orig_h": "10.0.0.7",
                  "id.orig_p": 51000, "id.resp_h": "10.0.0.1",
                  "id.resp_p": 53, "proto": "udp", "query": "example.test",
                  "qtype_name": "A", "rcode_name": "NOERROR",
                  "answers": ["198.51.100.20"], "TTLs": [60.0]},
        "time_keys": ["ts"],
        "proves_activity": True,
        "expect_activity_source": "zeek:dns.log ts",
        "expect_observation_source": "zeek:dns.log _write_ts",
    },
    # W2-1 · the PowerShell ETW channels carry no activity-occurrence
    # field at all. `TimeCreated` is when the provider wrote the record, so
    # this DSM may only ever declare an OBSERVATION.
    "windows-powershell-evd": {
        "event": {"EventID": 4104,
                  "provider": "Microsoft-Windows-PowerShell",
                  "channel": "Microsoft-Windows-PowerShell/Operational",
                  "Computer": "WIN-WS-07",
                  "TimeCreated": "2026-06-01T10:00:00+00:00",
                  "EventData": {"MessageNumber": "1", "MessageTotal": "1",
                                "ScriptBlockText": "Get-Process",
                                "ScriptBlockId": "{d12-d12}",
                                "Path": "C:\\d12\\demo.ps1"}},
        "time_keys": ["TimeCreated"],
        "proves_activity": False,
        "expect_observation_source":
            "windows_powershell:System.TimeCreated.SystemTime",
    },
    # W2-1 lane housekeeping · the M365 Management Activity DSM had no D12
    # sample, which is precisely the gap the guard below exists to catch.
    # `CreationTime` is Microsoft's record of WHEN THE ACTIVITY HAPPENED;
    # the API is a service audit log, so there is no sensor observation to
    # record and that boundary stays NOT_OBSERVED by declaration.
    "m365-unified-audit": {
        "event": {"RecordType": 15, "Operation": "UserLoggedIn",
                  "Workload": "AzureActiveDirectory",
                  "OrganizationId": "d12-org", "Id": "m365-d12",
                  "CreationTime": "2026-06-01T10:00:00",
                  "UserId": "dev1@fixture.test",
                  "ResultStatus": "Success"},
        "time_keys": ["CreationTime"],
        "proves_activity": True,
        "expect_activity_source": "m365:CreationTime",
    },
    # W2-1 · Defender states its OWN `Detection Time`, which IS the activity
    # instant the vendor measured. `TimeCreated` remains the record write.
    "windows-defender-evd": {
        "event": {"EventID": 1116,
                  "provider": "Microsoft-Windows-Windows Defender",
                  "channel": "Microsoft-Windows-Windows Defender/Operational",
                  "Computer": "WIN-WS-07",
                  "TimeCreated": "2026-06-01T10:00:02+00:00",
                  "EventData": {"Threat Name": "Trojan:Win32/Fixture",
                                "Severity Name": "Severe",
                                "Category Name": "Trojan",
                                "Action Name": "Quarantine",
                                "Detection Time": "2026-06-01T10:00:00+00:00",
                                "Path": "file:_C:\\d12\\x.exe",
                                "Detection User": "FIXTURE\\dev1"}},
        "time_keys": ["Detection Time"],
        "proves_activity": True,
        "expect_activity_source": "defender:EventData.Detection Time",
        "expect_observation_source":
            "defender:System.TimeCreated.SystemTime",
    },
}


def _dsms():
    return {d.id: d for d in REGISTRY._dsms}


def normalize(dsm_id: str, event: dict) -> dict:
    dsm = _dsms()[dsm_id]
    parsed = dsm.select_parser().parse(dict(event))
    normalizer = dsm.select_normalizer()
    import inspect
    if "tenant_id" in inspect.signature(normalizer.normalize).parameters:
        return normalizer.normalize(parsed, dsm.id, "col-d12", "int-d12",
                                    "trace-d12", tenant_id="t-d12")
    return normalizer.normalize(parsed, dsm.id, "col-d12", "int-d12",
                                "trace-d12")


def event_time_of(canonical: dict) -> str:
    """`event_time` is the canonical name; the Snort projection predates it
    and calls the same compatibility field `timestamp`."""
    return canonical.get("event_time") or canonical.get("timestamp")


def stamps(canonical: dict) -> dict:
    return (canonical.get("provenance") or {}).get("timestamps") or {}


def declarations(canonical: dict) -> dict:
    return canonical.get("additional_fields") or {}


def _strip_time(dsm_id: str, mode: str) -> dict:
    """Remove or corrupt every timestamp the source format carries."""
    spec = SAMPLES[dsm_id]
    ev = json.loads(json.dumps(spec["event"]))
    for key in spec["time_keys"]:
        if key in ("message", "line"):
            # the timestamp lives inside the verbatim line
            if mode == "remove":
                ev[key] = str(ev[key]).replace(f"msg=audit({AUD}):", "") \
                    .replace("devTime=1780308000000", "") \
                    .replace("rt=1780308060000", "")
            else:
                ev[key] = str(ev[key]).replace(AUD, "BROKEN:NOTANUMBER") \
                    .replace("devTime=1780308000000", "devTime=never") \
                    .replace("rt=1780308060000", "rt=never")
        elif mode == "remove":
            ev.pop(key, None)
            if isinstance(ev.get("EventData"), dict):
                ev["EventData"].pop(key, None)
        else:
            ev[key] = "yesterday afternoon"
            if isinstance(ev.get("EventData"), dict) and \
                    key in ev["EventData"]:
                ev["EventData"][key] = "yesterday afternoon"
    if mode == "corrupt":
        for extra in ("TimeCreated", "observed_at", "timestamp"):
            if extra in ev:
                ev[extra] = "yesterday afternoon"
    elif mode == "remove":
        for extra in ("TimeCreated", "observed_at", "timestamp"):
            ev.pop(extra, None)
    return ev


# ── the mandatory cross-DSM invariants ───────────────────────────────
@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_every_dsm_declares_a_basis_and_all_eight_boundaries(dsm_id):
    c = normalize(dsm_id, SAMPLES[dsm_id]["event"])
    ts = stamps(c)
    assert set(ts) == set(pts.STAMP_NAMES), dsm_id
    d = declarations(c)
    assert d["event_time_basis"] in etb.BASES, (dsm_id, d)
    assert d["event_time_source"]
    assert isinstance(d["event_time_substituted"], bool)
    for name, s in ts.items():
        assert s["status"] in (pts.AVAILABLE, pts.NOT_APPLICABLE,
                               pts.NOT_OBSERVED, pts.MISSING), (dsm_id, name)
        if s["status"] == pts.AVAILABLE:
            assert s["value"] and s["source"], (dsm_id, name)
        else:
            assert s["value"] is None, (dsm_id, name)
            assert s.get("reason"), (dsm_id, name)


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_activity_time_is_available_only_under_activity_time_basis(dsm_id):
    c = normalize(dsm_id, SAMPLES[dsm_id]["event"])
    basis = declarations(c)["event_time_basis"]
    act = stamps(c)[ACT]
    if act["status"] == pts.AVAILABLE:
        assert basis == etb.ACTIVITY_TIME, (dsm_id, basis)
        assert event_time_of(c) == act["value"], dsm_id
        assert declarations(c)["event_time_substituted"] is False, dsm_id
    else:
        assert basis != etb.ACTIVITY_TIME, (dsm_id, basis)


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
@pytest.mark.parametrize("mode", ["remove", "corrupt"])
def test_no_dsm_invents_activity_time_when_the_source_timestamp_is_gone(
        dsm_id, mode):
    """THE regression that protects this architecture at DSM number fifty."""
    try:
        c = normalize(dsm_id, _strip_time(dsm_id, mode))
    except Exception:
        # A parser that REFUSES the event is the strongest possible answer:
        # no canonical event, so no fabricated activity time.
        return
    act = stamps(c)[ACT]
    assert act["status"] != pts.AVAILABLE, (dsm_id, mode, act)
    assert act["value"] is None, (dsm_id, mode, act)
    assert declarations(c)["event_time_basis"] != etb.ACTIVITY_TIME
    assert declarations(c)["event_time_substituted"] is True
    # and the boundary that was NOT the activity must not have been
    # promoted into it either
    obs = stamps(c)[OBS]
    if obs["status"] == pts.AVAILABLE:
        assert obs["value"] != act.get("value")


@pytest.mark.parametrize("dsm_id", sorted(SAMPLES))
def test_the_normalizer_clock_never_becomes_a_source_side_boundary(dsm_id):
    try:
        c = normalize(dsm_id, _strip_time(dsm_id, "remove"))
    except Exception:
        return          # a refusing parser produces no event to fabricate on
    for name in (ACT, OBS):
        s = stamps(c)[name]
        if s["status"] == pts.AVAILABLE:
            assert "clock" not in (s["source"] or ""), (dsm_id, name)
    assert event_time_of(c), dsm_id    # compatibility still satisfied


def test_every_registered_dsm_is_covered_by_this_suite():
    """A DSM added without a temporal declaration must fail HERE, loudly,
    not silently ship a fabricated activity time."""
    assert set(_dsms()) == set(SAMPLES), (
        "a registered DSM has no D12 temporal sample: "
        f"{sorted(set(_dsms()) ^ set(SAMPLES))}")


# ── per-DSM semantic mapping, as ratified ────────────────────────────
def test_sysmon_separates_utctime_from_the_etw_write():
    c = normalize("microsoft-sysmon", SAMPLES["microsoft-sysmon"]["event"])
    ts = stamps(c)
    assert ts[ACT]["source"] == "sysmon:EventData.UtcTime"
    assert ts[ACT]["value"] == "2026-06-01T10:00:00+00:00"
    assert ts[OBS]["source"] == "sysmon:System.TimeCreated"
    assert ts[OBS]["value"] == "2026-06-01T10:00:02+00:00"
    assert ts[ACT]["value"] != ts[OBS]["value"]
    assert declarations(c)["event_time_basis"] == etb.ACTIVITY_TIME


def test_sysmon_without_utctime_does_not_promote_timecreated():
    ev = dict(SAMPLES["microsoft-sysmon"]["event"])
    ev.pop("UtcTime")
    c = normalize("microsoft-sysmon", ev)
    assert stamps(c)[ACT]["status"] == pts.NOT_OBSERVED
    assert stamps(c)[OBS]["status"] == pts.AVAILABLE
    assert declarations(c)["event_time_basis"] == etb.OBSERVATION_TIME
    assert c["event_time"] == "2026-06-01T10:00:02+00:00"


def test_windows_never_promotes_timecreated_to_activity():
    c = normalize("windows-security-evd",
                  SAMPLES["windows-security-evd"]["event"])
    ts = stamps(c)
    assert ts[ACT]["status"] == pts.NOT_OBSERVED
    assert "record-generation instant" in ts[ACT]["reason"]
    assert ts[OBS]["status"] == pts.AVAILABLE
    assert ts[OBS]["source"] == "windows:System.TimeCreated.SystemTime"
    assert declarations(c)["event_time_basis"] == etb.OBSERVATION_TIME
    assert declarations(c)["event_time_substituted"] is True


def test_powershell_never_promotes_timecreated_to_activity():
    c = normalize("windows-powershell-evd",
                  SAMPLES["windows-powershell-evd"]["event"])
    ts = stamps(c)
    assert ts[ACT]["status"] == pts.NOT_OBSERVED
    assert "when the script ran" in ts[ACT]["reason"]
    assert ts[OBS]["status"] == pts.AVAILABLE
    assert ts[OBS]["source"] == \
        "windows_powershell:System.TimeCreated.SystemTime"
    assert declarations(c)["event_time_basis"] == etb.OBSERVATION_TIME
    assert declarations(c)["event_time_substituted"] is True


def test_cloudtrail_eventtime_is_the_activity_instant():
    c = normalize("aws-cloudtrail", SAMPLES["aws-cloudtrail"]["event"])
    ts = stamps(c)
    assert ts[ACT]["status"] == pts.AVAILABLE
    assert ts[ACT]["source"] == "cloudtrail:eventTime"
    assert ts[OBS]["status"] == pts.NOT_OBSERVED
    assert declarations(c)["event_time_basis"] == etb.ACTIVITY_TIME


def test_snort_eve_timestamp_is_the_packet_instant():
    c = normalize("snort-eve", SAMPLES["snort-eve"]["event"])
    ts = stamps(c)
    assert ts[ACT]["status"] == pts.AVAILABLE
    assert ts[ACT]["source"].startswith("snort-eve:timestamp")
    assert ts[OBS]["status"] == pts.NOT_OBSERVED
    assert "no separate instant" in ts[OBS]["reason"]


def test_cef_devtime_is_activity_and_rt_is_only_an_observation():
    c = normalize("cef-leef", SAMPLES["cef-leef"]["event"])
    ts = stamps(c)
    assert ts[ACT]["source"] == "cef-leef:devTime"
    assert ts[OBS]["source"].startswith("cef:rt")
    assert ts[ACT]["value"] != ts[OBS]["value"]
    assert declarations(c)["event_time_basis"] == etb.ACTIVITY_TIME


def test_cef_with_only_rt_refuses_to_call_it_activity():
    ev = {"line": ("CEF:0|NivX|Firewall|1.0|100|Blocked|5|src=10.0.0.4 "
                   "dst=198.51.100.2 rt=1780308060000")}
    c = normalize("cef-leef", ev)
    ts = stamps(c)
    assert ts[ACT]["status"] == pts.NOT_OBSERVED
    assert "receipt time by spec" in ts[ACT]["reason"]
    assert ts[OBS]["status"] == pts.AVAILABLE
    assert declarations(c)["event_time_basis"] == etb.OBSERVATION_TIME


def test_cef_epistemic_ledger_agrees_with_the_canonical_basis():
    """CEF's epistemic state is a projection of canonical provenance, not a
    second authority. UNKNOWN must mean exactly INGEST_TIME_SUBSTITUTED."""
    for ev in (SAMPLES["cef-leef"]["event"],
               {"line": ("CEF:0|NivX|Firewall|1.0|100|Blocked|5|"
                         "src=10.0.0.4 dst=198.51.100.2")}):
        c = normalize("cef-leef", ev)
        d = declarations(c)
        epi = (d.get("epistemic_state") or {}).get("event_time")
        substituted_from_our_clock = (
            d["event_time_basis"] == etb.INGEST_TIME_SUBSTITUTED)
        assert (epi == "UNKNOWN") is substituted_from_our_clock, (epi, d)
        if epi == "UNKNOWN":
            assert stamps(c)[ACT]["status"] != pts.AVAILABLE
            assert stamps(c)[OBS]["status"] != pts.AVAILABLE


def test_sensor_path_no_longer_fabricates_the_observation_boundary():
    ev = dict(SAMPLES["nivxforge-linux-sensor"]["event"])
    ev.pop("observed_at")
    c = normalize("nivxforge-linux-sensor", ev)
    ts = stamps(c)
    assert ts[OBS]["status"] == pts.NOT_OBSERVED
    assert "carried no observed_at" in ts[OBS]["reason"]
    # the activity time it DID observe is untouched
    assert ts[ACT]["status"] == pts.AVAILABLE
    assert declarations(c)["event_time_basis"] == etb.ACTIVITY_TIME
    # and the collector boundary is still structurally absent here
    assert ts["collector_received_at"]["status"] == pts.NOT_APPLICABLE


# ── the resolver itself ──────────────────────────────────────────────
def _resolve(**kw):
    kw.setdefault("clock", "2026-06-01T12:00:00+00:00")
    kw.setdefault("clock_source", "test clock")
    kw.setdefault("activity_absent_reason", "none declared")
    kw.setdefault("observation_absent_reason", "none declared")
    return etb.resolve(**kw)


def test_the_four_bases_are_reachable_and_distinct():
    a = _resolve(activity=[("2026-06-01T10:00:00+00:00", "src:a")])
    assert a.basis == etb.ACTIVITY_TIME and a.substituted is False
    assert a.activity["status"] == pts.AVAILABLE

    o = _resolve(observation=[("2026-06-01T10:00:00+00:00", "src:o")])
    assert o.basis == etb.OBSERVATION_TIME and o.substituted is True
    assert o.activity["status"] == pts.NOT_OBSERVED
    assert o.observation["status"] == pts.AVAILABLE

    s = _resolve(supplied=[("2026-06-01T10:00:00+00:00", "src:s")])
    assert s.basis == etb.SUPPLIED_TIMESTAMP_UNVERIFIED
    assert s.substituted is True
    assert s.activity["status"] == pts.NOT_OBSERVED

    n = _resolve()
    assert n.basis == etb.INGEST_TIME_SUBSTITUTED
    assert n.event_time == "2026-06-01T12:00:00+00:00"
    assert n.activity["status"] == pts.NOT_OBSERVED
    assert n.observation["status"] == pts.NOT_OBSERVED


def test_activity_outranks_observation_outranks_supplied():
    r = _resolve(activity=[("2026-06-01T10:00:00+00:00", "src:a")],
                 observation=[("2026-06-01T10:00:01+00:00", "src:o")],
                 supplied=[("2026-06-01T10:00:02+00:00", "src:s")])
    assert r.basis == etb.ACTIVITY_TIME
    assert r.event_time == "2026-06-01T10:00:00+00:00"
    assert r.observation["value"] == "2026-06-01T10:00:01+00:00"

    r = _resolve(observation=[("2026-06-01T10:00:01+00:00", "src:o")],
                 supplied=[("2026-06-01T10:00:02+00:00", "src:s")])
    assert r.basis == etb.OBSERVATION_TIME


def test_an_unreadable_activity_value_is_demoted_not_promoted():
    r = _resolve(activity=[("yesterday afternoon", "src:a")])
    assert r.basis == etb.SUPPLIED_TIMESTAMP_UNVERIFIED
    assert r.event_time == "yesterday afternoon"      # kept for compatibility
    assert r.format_state == etb.UNPARSEABLE_FORMAT
    assert r.activity["status"] == pts.MISSING
    assert r.activity["value"] is None
    assert r.activity["source"] == "src:a"


def test_an_absent_boundary_must_state_why():
    r = _resolve(activity=[("2026-06-01T10:00:00+00:00", "src:a")],
                 observation_absent_reason="this format has no sensor stage")
    assert r.observation["reason"] == "this format has no sensor stage"
    with pytest.raises(TypeError):
        etb.resolve(clock="x", clock_source="y",
                    activity_absent_reason="only one given")


def test_a_missing_offset_is_flagged_and_never_rewritten():
    r = _resolve(activity=[("2026-06-01T10:00:00", "src:a")])
    assert r.activity["value"] == "2026-06-01T10:00:00"
    assert "offset is UNKNOWN" in r.activity["reason"]


def test_the_invariant_cannot_be_bypassed_by_a_caller():
    """The resolver refuses to return the forbidden combination even if a
    future caller contrives it."""
    r = _resolve(activity=[("2026-06-01T10:00:00+00:00", "src:a")])
    assert r.basis == etb.ACTIVITY_TIME
    with pytest.raises(AssertionError):
        etb.Resolution(
            event_time="2026-06-01T12:00:00+00:00",
            basis=etb.INGEST_TIME_SUBSTITUTED, source="clock",
            substituted=True, format_state=etb.ISO_8601,
            activity=r.activity, observation=r.observation).verify()
