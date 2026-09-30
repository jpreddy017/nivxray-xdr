"""B5 · provider-qualified Sysmon event-id measurement (owner-mandated).

WHY THIS EXISTS
---------------
A bare `EventID = 5` count for DESKTOP-A9HGFJJ returned 249 records and
looked like abundant termination evidence. Only **17** were genuine
`Microsoft-Windows-Sysmon` ProcessTerminate events; the rest were
`Microsoft-Windows-IsolatedUserMode` EventID 5 (Secure Trustlet start),
which is not a termination at all. A measurement that can inflate a
termination count by 14x is a measurement that lies, so every Sysmon
event-id count must be provider-qualified.

These tests pin that contract: the provider (by name, provider GUID, or
its privileged channel) AND the event id, in both payload shapes, with
the canonicaliser's own refusal of the impostor provider re-proved.

EVIDENCE LABELLING — TEST/SYNTHETIC payload text. No live telemetry, no
production query, no endpoint contact.
"""
from __future__ import annotations

import json

from edr_plane import windows_eventlog as w
from tests.edr import fixtures_windows_eventlog as fx

GUID = "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
TRUSTLET_GUID = "{73A33AB2-1966-4999-8ADD-868C41415269}"

SYSMON_JSON = ('{"winlog": {"channel": "Microsoft-Windows-Sysmon/Operational",'
               ' "provider": "Microsoft-Windows-Sysmon", "event_id": 5,'
               ' "event_data": {"ProcessGuid":'
               ' "{9949e5f2-d54c-6abb-0000-000000002100}",'
               ' "UtcTime": "2026-09-29 15:17:21.123"}}}')

SYSMON_XML = ("<Event><System><Provider Name='Microsoft-Windows-Sysmon' "
              f"Guid='{GUID}'/><EventID>5</EventID>"
              "<Channel>Microsoft-Windows-Sysmon/Operational</Channel>"
              "</System></Event>")

SYSMON_XML_GUID_ONLY = (f"<Event><System><Provider Guid='{GUID}'/>"
                        "<EventID>5</EventID></System></Event>")

SYSMON_JSON_GUID_ONLY = ('{"winlog": {"provider_guid":'
                         ' "5770385F-C22A-43E0-BF4C-06F5698FFBD9",'
                         ' "event_id": "5"}}')

#: The impostor. Same numeric event id, entirely different meaning.
TRUSTLET_XML = ("<Event><System><Provider "
                "Name='Microsoft-Windows-IsolatedUserMode' "
                f"Guid='{TRUSTLET_GUID}'/><EventID>5</EventID>"
                "<Channel>Microsoft-Windows-IsolatedUserMode/Operational"
                "</Channel></System></Event>")

TRUSTLET_JSON = ('{"winlog": {"channel":'
                 ' "Microsoft-Windows-IsolatedUserMode/Operational",'
                 ' "provider": "Microsoft-Windows-IsolatedUserMode",'
                 ' "event_id": 5}}')

NAKED_XML = "<Event><System><EventID>5</EventID></System></Event>"

#: Mentions Sysmon in a command line. Text, not provenance.
MENTIONS_SYSMON = ('{"winlog": {"channel": "Security", "provider":'
                   ' "Microsoft-Windows-Security-Auditing", "event_id": 4688,'
                   ' "event_data": {"CommandLine": "sc query Sysmon",'
                   ' "NewProcessId": "0x1a4"}}}')


# ------------------------------------------------- the genuine article counts
def test_sysmon_json_envelope_counts():
    assert w.is_sysmon_event(SYSMON_JSON, 5) is True


def test_sysmon_event_xml_counts():
    assert w.is_sysmon_event(SYSMON_XML, 5) is True


def test_provider_guid_alone_is_sufficient_in_xml():
    assert w.is_sysmon_event(SYSMON_XML_GUID_ONLY, 5) is True


def test_provider_guid_alone_is_sufficient_in_json():
    assert w.is_sysmon_event(SYSMON_JSON_GUID_ONLY, 5) is True


# ------------------------------------------------------- the impostor does not
def test_isolated_user_mode_xml_is_not_a_sysmon_event():
    assert w.is_sysmon_event(TRUSTLET_XML, 5) is False


def test_isolated_user_mode_json_is_not_a_sysmon_event():
    assert w.is_sysmon_event(TRUSTLET_JSON, 5) is False


def test_an_event_id_without_any_provider_is_not_counted():
    assert w.is_sysmon_event(NAKED_XML, 5) is False


def test_merely_mentioning_sysmon_in_a_command_line_is_not_provenance():
    assert w.is_sysmon_event(MENTIONS_SYSMON, 5) is False
    assert w.is_sysmon_event(MENTIONS_SYSMON, 4688) is False


def test_the_wrong_event_id_on_the_right_provider_is_not_counted():
    assert w.is_sysmon_event(SYSMON_JSON, 1) is False
    assert w.is_sysmon_event(SYSMON_XML, 12) is False


def test_event_id_5_is_not_matched_by_a_longer_number():
    long_id = SYSMON_JSON.replace('"event_id": 5', '"event_id": 5379')
    assert w.is_sysmon_event(long_id, 5) is False
    assert w.is_sysmon_event(long_id, 5379) is True


# ------------------------------------- the defect that started this, pinned
def test_a_mixed_corpus_counts_only_genuine_sysmon_terminations():
    """The 249-vs-17 defect, in miniature."""
    corpus = ([SYSMON_JSON, SYSMON_XML, SYSMON_XML_GUID_ONLY]
              + [TRUSTLET_XML, TRUSTLET_JSON] * 8
              + [NAKED_XML, MENTIONS_SYSMON])
    naive = sum(1 for p in corpus if "5" in p and "EventID" in p or
                '"event_id": 5' in p)
    qualified = sum(1 for p in corpus if w.is_sysmon_event(p, 5))
    assert qualified == 3
    assert naive > qualified, "a provider-blind count must overstate"


# --------------------------------------------------- the query contract itself
def test_the_sanctioned_clause_requires_provider_and_event_id():
    clause = w.sysmon_event_clause(5)
    terms = clause["$and"]
    assert len(terms) == 2
    assert terms[0]["payload"]["$regex"] == w.FAMILY_PAYLOAD_REGEX["sysmon"]
    assert "5770385F-C22A-43E0-BF4C-06F5698FFBD9" in terms[0]["payload"]["$regex"]
    assert "EventID" in terms[1]["payload"]["$regex"]


def test_the_clause_can_target_another_payload_field():
    clause = w.sysmon_event_clause(5, payload_field="raw.xml")
    assert all("raw.xml" in term for term in clause["$and"])


def test_the_provider_blind_helper_is_documented_as_unsafe_alone():
    assert "PROVIDER-BLIND" in (w.payload_event_id_regex.__doc__ or "")
    assert w.SYSMON_PROVIDER_GUID == "5770385F-C22A-43E0-BF4C-06F5698FFBD9"


def test_the_family_regex_is_keyed_not_a_bare_substring():
    """`Sysmon` appearing as free text must not qualify a record."""
    assert w.is_sysmon_event('{"winlog": {"event_id": 5,'
                             ' "msg": "Sysmon"}}', 5) is False


# ------------------------------- the canonicaliser refuses the impostor too
def test_the_canonicaliser_maps_sysmon_eid5_to_termination():
    ev = json.loads(fx.sysmon(5, 5901, {"UtcTime": "2026-09-29 15:17:21.123",
                             "ProcessGuid": "{9949e5f2-d54c-6abb-0000-0000d}",
                             "ProcessId": "4242",
                             "Image": r"C:\Windows\System32\cmd.exe"}))
    activity, reason = w.envelope_activity(ev)
    assert activity == w.ACTIVITY_PROCESS_TERMINATION
    assert "sysmon, EventID 5" in reason


def test_the_canonicaliser_refuses_isolated_user_mode_eid5():
    ev = json.loads(fx.sysmon(5, 5902, {"UtcTime": "2026-09-29 15:17:21.123"}))
    ev["winlog"]["provider"] = "Microsoft-Windows-IsolatedUserMode"
    ev["winlog"]["channel"] = "Microsoft-Windows-IsolatedUserMode/Operational"
    activity, reason = w.envelope_activity(ev)
    assert activity is None
    assert "not a supported Windows evidence source" in reason
    assert "not evidence of absence" in reason


def test_eid5_still_maps_utctime_to_exit_time_only():
    """The B5 invariant, re-proved alongside the counter fix."""
    ev = json.loads(fx.sysmon(5, 5903, {"UtcTime": "2026-09-29 15:17:21.123",
                             "ProcessGuid": "{9949e5f2-d54c-6abb-0000-0000d}",
                             "ProcessId": "4242",
                             "Image": r"C:\Windows\System32\cmd.exe"}))
    canonical = w.to_canonical(ev)
    proc = canonical["process"]
    assert proc["exit_time"] == "2026-09-29T15:17:21.123Z"
    assert proc.get("start_time") is None
    prov = proc["field_provenance"]
    assert prov["exit_time"].endswith("UtcTime (EventID 5)")
    assert "start_time" not in prov
