"""W2-1 · Windows Event Log acquisition — invariant tests.

These prove the ACQUISITION CONTRACT on any platform by substituting the
native boundary (`EvtReader`) with a fake that returns real Windows event
XML shapes. Nothing here simulates telemetry for a product surface: the
fixtures exist so the durability rules are provable without a Windows host.

Proven:
  1. first collection has no bookmark and says so;
  2. an event's identity is channel-qualified, not record-id-only;
  3. a record with no EventRecordID is reported unidentifiable, not given a
     surrogate id;
  4. the bookmark does NOT advance until the records are durable;
  5. after Make Durable, the bookmark advances and the next read resumes
     from it;
  6. a lower record id than already seen is reported as LOG CLEARED with
     the evidence loss stated;
  7. a stale bookmark is classified, not silently replaced with "now";
  8. an unread channel is UNSUPPORTED_PLATFORM / not-collected — never an
     empty success;
  9. the three clocks stay separate (activity vs sensor observation);
 10. a SID is carried verbatim — no endpoint-side principal rendering;
 11. WEF/ForwardedEvents and unknown channels are refused by the profile.
"""
from __future__ import annotations

import asyncio
import os
import tempfile

import pytest

from framework.windows_bookmarks import (
    RESUME_BOOKMARK, RESUME_FRESH, RESUME_STALE, WindowsBookmarkStore,
)
from framework.windows_eventlog import (
    BASELINE_PROFILE, CollectionProfile, UnsupportedPlatformReader,
    WindowsEventLogConnector, extract_facts,
)

SYSMON = "Microsoft-Windows-Sysmon/Operational"
PS = "Microsoft-Windows-PowerShell/Operational"


def sysmon_xml(record_id, *, pid=4242, utc="2026-06-01 12:33:44.123",
               computer="WIN-DC-01", sid="S-1-5-21-77-1001"):
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        '<Provider Name="Microsoft-Windows-Sysmon" '
        'Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/>'
        '<EventID>1</EventID><Version>5</Version><Level>4</Level>'
        f'<TimeCreated SystemTime="2026-06-01T12:33:45.9876543Z"/>'
        f'<EventRecordID>{record_id}</EventRecordID>'
        f'<Channel>{SYSMON}</Channel><Computer>{computer}</Computer>'
        f'<Security UserID="{sid}"/>'
        '</System><EventData>'
        f'<Data Name="UtcTime">{utc}</Data>'
        f'<Data Name="ProcessId">{pid}</Data>'
        '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
        '</EventData></Event>')


def no_record_id_xml():
    return ('<Event><System><EventID>1</EventID>'
            f'<Channel>{SYSMON}</Channel><Computer>WIN-DC-01</Computer>'
            '</System><EventData/></Event>')


class FakeReader:
    """Scripted native boundary. Each `read` pops one programmed response."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def read(self, channel, *, bookmark_xml, xpath, limit):
        self.calls.append({"channel": channel, "bookmark_xml": bookmark_xml,
                           "xpath": xpath, "limit": limit})
        for i, (ch, resp) in enumerate(self.script):
            if ch == channel:
                self.script.pop(i)
                return resp
        return {"records": [], "bookmark_xml": bookmark_xml,
                "state": "READ_OK", "reason": None}


@pytest.fixture()
def store(tmp_path):
    return WindowsBookmarkStore(path=str(tmp_path / "outbox.db"))


def make(reader, store, channels=(SYSMON,), **cfg):
    return WindowsEventLogConnector(
        "tenant-a", {"channels": list(channels), **cfg},
        reader=reader, bookmarks=store, collector_id="col-1")


def collect(c):
    # A fresh loop per call: the rest of this suite installs and closes its
    # own loops, and borrowing theirs made these tests order-dependent.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(c.collect())
    finally:
        loop.close()


# ── 1 · first collection declares it has no bookmark ──────────────
def test_first_collection_has_no_bookmark(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(10)],
                              "bookmark_xml": "<BookmarkList>10</BookmarkList>",
                              "state": "READ_OK", "reason": None})])
    c = make(r, store)
    collect(c)
    assert r.calls[0]["bookmark_xml"] is None
    assert c.channel_reports[SYSMON]["resume"] == RESUME_FRESH


# ── 2 · identity is channel-qualified ─────────────────────────────
def test_identity_is_channel_qualified(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(11)],
                              "bookmark_xml": "bm", "state": "READ_OK"})])
    envs = collect(make(r, store))
    assert envs[0].source_event_id == f"tenant-a|WIN-DC-01|{SYSMON}|11"


def test_same_record_id_on_two_channels_is_two_identities(store):
    r = FakeReader([
        (SYSMON, {"records": [sysmon_xml(7)], "bookmark_xml": "a",
                  "state": "READ_OK"}),
        (PS, {"records": [sysmon_xml(7).replace(SYSMON, PS)],
              "bookmark_xml": "b", "state": "READ_OK"})])
    envs = collect(make(r, store, channels=(SYSMON, PS)))
    ids = {e.source_event_id for e in envs}
    assert len(ids) == 2, ids


# ── 3 · no record id → unidentifiable, never a surrogate ──────────
def test_missing_record_id_is_unidentified(store):
    r = FakeReader([(SYSMON, {"records": [no_record_id_xml()],
                              "bookmark_xml": "bm", "state": "READ_OK"})])
    c = make(r, store)
    envs = collect(c)
    assert envs[0].source_event_id is None
    assert c.channel_reports[SYSMON]["unidentified"] == 1


# ── 4+5 · bookmark advances ONLY after Make Durable ───────────────
def test_bookmark_does_not_advance_before_durability(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(20)],
                              "bookmark_xml": "<BM>20</BM>",
                              "state": "READ_OK"})])
    c = make(r, store)
    collect(c)
    assert store.resume_for("tenant-a", "col-1", SYSMON)["classification"] \
        == RESUME_FRESH
    assert c.channel_reports[SYSMON]["bookmark_pending"] is True


def test_bookmark_advances_after_durability_and_next_read_resumes(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(20)],
                              "bookmark_xml": "<BM>20</BM>",
                              "state": "READ_OK"})])
    c = make(r, store)
    collect(c)
    c.advance(durable_channels=[SYSMON])
    resume = store.resume_for("tenant-a", "col-1", SYSMON)
    assert resume["classification"] == RESUME_BOOKMARK
    assert resume["bookmark_xml"] == "<BM>20</BM>"

    r.script = [(SYSMON, {"records": [sysmon_xml(21)],
                          "bookmark_xml": "<BM>21</BM>", "state": "READ_OK"})]
    collect(c)
    assert r.calls[-1]["bookmark_xml"] == "<BM>20</BM>"


def test_channel_not_durable_keeps_its_position(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(30)],
                              "bookmark_xml": "<BM>30</BM>",
                              "state": "READ_OK"})])
    c = make(r, store)
    collect(c)
    out = c.advance(durable_channels=[])
    assert out[SYSMON]["advanced"] is False
    assert store.resume_for("tenant-a", "col-1", SYSMON)["classification"] \
        == RESUME_FRESH


# ── 6 · log-cleared detection states the evidence loss ────────────
def test_log_cleared_is_detected_and_explained(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(5000)],
                              "bookmark_xml": "<BM>5000</BM>",
                              "state": "READ_OK"})])
    c = make(r, store)
    collect(c)
    c.advance(durable_channels=[SYSMON])

    r.script = [(SYSMON, {"records": [sysmon_xml(3)],
                          "bookmark_xml": "<BM>3</BM>", "state": "READ_OK"})]
    collect(c)
    rep = c.channel_reports[SYSMON]
    assert rep["log_cleared"] is True
    assert "cleared or wrapped" in rep["log_cleared_reason"]
    st = store.state_for("tenant-a", "col-1", SYSMON)
    assert st["log_cleared_count"] == 1


# ── 7 · stale bookmark is classified, never silently reset ────────
def test_stale_bookmark_is_classified(tmp_path):
    st = WindowsBookmarkStore(path=str(tmp_path / "outbox.db"),
                              stale_after_seconds=0)
    st.record_read(tenant_id="tenant-a", collector_id="col-1", channel=SYSMON,
                   bookmark_xml="<BM>1</BM>", record_ids=[1])
    resume = st.resume_for("tenant-a", "col-1", SYSMON)
    assert resume["classification"] == RESUME_STALE
    # The bookmark is still THERE — staleness is a report, not a reset.
    assert resume["bookmark_xml"] == "<BM>1</BM>"
    assert "retention" in resume["reason"]


# ── 8 · an unread channel is never an empty success ───────────────
def test_unsupported_platform_reader_reports_not_read(store):
    c = make(UnsupportedPlatformReader(), store)
    envs = collect(c)
    assert envs == []
    rep = c.channel_reports[SYSMON]
    assert rep["state"] == "UNSUPPORTED_PLATFORM"
    assert "not running on Windows" in rep["reason"]
    assert rep["events_read"] == 0


def test_read_failure_records_the_error_not_a_bookmark(store):
    r = FakeReader([(SYSMON, {"records": [], "bookmark_xml": None,
                              "state": "READER_UNAVAILABLE",
                              "reason": "win32evtlog could not be bound"})])
    c = make(r, store)
    collect(c)
    assert c.channel_reports[SYSMON]["state"] == "READER_UNAVAILABLE"
    st = store.state_for("tenant-a", "col-1", SYSMON)
    assert st["bookmark_xml"] is None
    assert "win32evtlog" in st["last_error"]


# ── 9 · the clocks stay separate ──────────────────────────────────
def test_activity_and_sensor_clocks_are_separate(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(40)],
                              "bookmark_xml": "bm", "state": "READ_OK"})])
    env = collect(make(r, store))[0]
    can = env.canonical
    assert can["activity_occurred_at"] == "2026-06-01 12:33:44.123"
    assert can["activity_time_source"] == "EventData.UtcTime"
    assert can["sensor_observed_at"] != can["activity_occurred_at"]
    # The collector never claims to be the ingest authority.
    assert "ingest_time" not in can


def test_timecreated_is_used_only_when_utctime_is_absent(store):
    xml = sysmon_xml(41).replace(
        '<Data Name="UtcTime">2026-06-01 12:33:44.123</Data>', "")
    r = FakeReader([(SYSMON, {"records": [xml], "bookmark_xml": "bm",
                              "state": "READ_OK"})])
    env = collect(make(r, store))[0]
    assert env.canonical["activity_time_source"] == "System.TimeCreated"


# ── 10 · SID verbatim, no endpoint-side rendering ─────────────────
def test_sid_is_carried_verbatim(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(50)],
                              "bookmark_xml": "bm", "state": "READ_OK"})])
    env = collect(make(r, store))[0]
    assert env.canonical["user_sid"] == "S-1-5-21-77-1001"
    assert "user_name" not in env.canonical


def test_raw_xml_is_preserved_verbatim(store):
    xml = sysmon_xml(51)
    r = FakeReader([(SYSMON, {"records": [xml], "bookmark_xml": "bm",
                              "state": "READ_OK"})])
    env = collect(make(r, store))[0]
    assert env.raw["xml"] == xml


# ── 11 · profile refuses what it cannot prove ─────────────────────
def test_forwarded_events_is_declared_unsupported():
    p = CollectionProfile("p", "1", ["ForwardedEvents"])
    problems = p.validate()
    assert problems[0]["code"] == "UNSUPPORTED_CHANNEL"
    assert "origin computer" in problems[0]["reason"]


def test_unknown_channel_is_refused():
    p = CollectionProfile("p", "1", ["Totally/MadeUp"])
    assert p.validate()[0]["code"] == "UNKNOWN_CHANNEL"


def test_unsupported_channel_is_not_collected(store):
    c = make(FakeReader([]), store, channels=("ForwardedEvents",))
    assert collect(c) == []
    assert c.channel_reports["ForwardedEvents"]["state"] == "NOT_COLLECTED"


# ── declared source + origin/collector identity separation ────────
def test_declared_source_is_per_channel(store):
    r = FakeReader([
        (SYSMON, {"records": [sysmon_xml(60)], "bookmark_xml": "a",
                  "state": "READ_OK"}),
        (PS, {"records": [sysmon_xml(61).replace(SYSMON, PS)],
              "bookmark_xml": "b", "state": "READ_OK"})])
    envs = collect(make(r, store, channels=(SYSMON, PS)))
    assert {e.declared_source for e in envs} == {"sysmon", "windows_powershell"}


def test_origin_computer_is_separate_from_collector_host(store):
    r = FakeReader([(SYSMON, {"records": [sysmon_xml(70, computer="WIN-WS-9")],
                              "bookmark_xml": "bm", "state": "READ_OK"})])
    env = collect(make(r, store))[0]
    assert env.canonical["origin_computer"] == "WIN-WS-9"
    assert "collector_host" in env.canonical
    assert env.canonical["collector_host"] != "WIN-WS-9"


def test_acquisition_report_states_platform_and_reader(store):
    c = make(UnsupportedPlatformReader(), store)
    collect(c)
    rep = c.acquisition_report()
    assert rep["reader"] == "UnsupportedPlatformReader"
    assert rep["invariant"].startswith("Read → Make Durable")
    assert rep["profile"]["profile_id"] == BASELINE_PROFILE.profile_id


def test_extract_facts_does_not_default_absent_fields():
    facts = extract_facts("<Event><System></System></Event>")
    assert facts == {}


# ── W2-1A · profiles + the two-state model ───────────────────────
def test_named_profiles_resolve_their_channels(store):
    from framework.windows_eventlog import (
        DOMAIN_CONTROLLER_PROFILE, FORENSIC_PROFILE, PROFILES,
        RECOMMENDED_SECURITY_PROFILE, VALIDATION_PROFILE,
    )
    c = WindowsEventLogConnector(
        "tenant-a", {"profile_id": "windows-recommended-security"},
        reader=UnsupportedPlatformReader(), bookmarks=store,
        collector_id="col-1")
    assert c.profile.channels == RECOMMENDED_SECURITY_PROFILE.channels
    # The first validation profile is deliberately NARROW.
    assert VALIDATION_PROFILE.channels == [
        SYSMON, "Security", PS]
    # Every shipped profile must validate cleanly.
    for p in PROFILES.values():
        assert p.validate() == [], (p.profile_id, p.validate())
    assert "Directory Service" in DOMAIN_CONTROLLER_PROFILE.channels
    assert len(FORENSIC_PROFILE.channels) > len(
        RECOMMENDED_SECURITY_PROFILE.channels)


def test_collection_support_does_not_imply_analysis_support(store):
    # W2-1 · Security and PowerShell are now normalized by core DSMs, so
    # the invariant is asserted on a channel that is genuinely acquired and
    # genuinely not analysable yet. The invariant itself is unchanged.
    TASKS = "Microsoft-Windows-TaskScheduler/Operational"
    r = FakeReader([(TASKS, {"records": [sysmon_xml(90).replace(
        SYSMON, TASKS)], "bookmark_xml": "bm", "state": "READ_OK"})])
    c = make(r, store, channels=(TASKS,))
    collect(c)
    rep = c.channel_reports[TASKS]
    # Acquired successfully...
    assert rep["state"] == "READ_OK"
    assert rep["collection_support"] == "SUPPORTED"
    # ...and explicitly NOT analysable yet.
    assert rep["analysis_support"]["normalization"] == "NOT YET SUPPORTED"
    assert rep["analysis_support"]["detection_coverage"] == "NOT AVAILABLE"
    assert rep["analysis_support"]["roadmap_position"] == 2


def test_windows_channel_analysis_support_is_stated_per_channel(store):
    from framework.windows_eventlog import analysis_support
    assert analysis_support(SYSMON)["normalization"] == "SUPPORTED"
    assert analysis_support(SYSMON)["dsm"] == "sysmon_dsm"
    # W2-1 · normalization is SUPPORTED for these two; detection coverage
    # is stated SEPARATELY and is not claimed where it does not exist.
    assert analysis_support("Security")["normalization"] == "SUPPORTED"
    assert analysis_support("Security")["dsm"] == "windows-security-evd"
    assert analysis_support("Security")["detection_coverage"] == "PARTIAL"
    assert analysis_support(PS)["dsm"] == "windows-powershell-evd"
    assert analysis_support(PS)["detection_coverage"] == "NOT AVAILABLE"
    assert analysis_support("Application")["dsm"] is None


def test_unavailable_channel_does_not_fail_the_whole_collector(store):
    """One bad channel must not stop the others."""
    r = FakeReader([
        ("Security", {"records": [], "bookmark_xml": None,
                      "state": "CHANNEL_NOT_FOUND",
                      "reason": "the channel is not present on this host"}),
        (SYSMON, {"records": [sysmon_xml(91)], "bookmark_xml": "bm",
                  "state": "READ_OK"})])
    c = make(r, store, channels=("Security", SYSMON))
    envs = collect(c)
    assert len(envs) == 1
    assert c.channel_reports["Security"]["state"] == "CHANNEL_NOT_FOUND"
    assert c.channel_reports[SYSMON]["state"] == "READ_OK"


def test_report_carries_the_two_state_note(store):
    c = make(UnsupportedPlatformReader(), store)
    collect(c)
    rep = c.acquisition_report()
    assert "separate facts" in rep["state_model_note"]
    assert rep["analysis_support_by_channel"][SYSMON]["normalization"] \
        == "SUPPORTED"
