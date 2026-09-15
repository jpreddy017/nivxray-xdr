"""D18 · registry evidence — observed, cited, and never manufactured.

    raw registry observation
      -> canonical registry entity
      -> declared evaluated field
      -> predicate
      -> matched observed value
      -> evidence_ref
      -> detection

Two sources genuinely observe the registry — Sysmon 12/13/14 and Windows
Security 4657 — and both are mapped here with per-field provenance.

The line this gate holds: **a command line that mentions the registry is not
registry telemetry.** `reg add …\\Run` is an observed PROCESS with an
inferred intent (DET-PS-005), while DET-PS-001 now carries only observed
registry evidence. Ordinary registry activity does not become persistence
merely by touching the registry.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. Nothing live, nothing
production.
"""
from __future__ import annotations

import pytest

from detection_content.library import REGISTRY
from detection_content.library import declaration_contract as dc
from detection_content.library.registry import RUNTIME_DETECTION_RULES
from detection_content.telemetry import registry_evidence as re_ev
from detection_content.telemetry.sysmon_dsm import (SysmonDSM, SysmonNormalizer,
                                                    SysmonParser)
from detection_content.telemetry.windows_security_dsm import (
    WindowsSecurityDSM, WindowsSecurityNormalizer, WindowsSecurityParser)

TEN = "t-d18"
COL = "col-d18"
RUN_KEY = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
RULES = {r.rule_id: r for r in RUNTIME_DETECTION_RULES}


def sysmon(**over):
    doc = {"EventID": 13, "provider": "Microsoft-Windows-Sysmon",
           "Computer": "WIN-SRV-18", "User": "CORP\\admin",
           "UtcTime": "2026-06-01T10:00:00+00:00",
           "Image": "C:\\Windows\\System32\\reg.exe", "ProcessId": "5150",
           "EventType": "SetValue",
           "TargetObject": f"{RUN_KEY}\\Updater",
           "Details": "C:\\temp\\evil.exe"}
    doc.update(over)
    parsed = SysmonParser().parse(doc)
    return SysmonNormalizer().normalize(parsed, "microsoft-sysmon", COL,
                                        "int-d18", "trace-d18",
                                        tenant_id=TEN)


def windows(**data):
    ed = {"ObjectName": RUN_KEY, "ObjectValueName": "Updater",
          "OperationType": "%%1905", "NewValue": "C:\\temp\\evil.exe",
          "NewValueType": "REG_SZ", "OldValue": "",
          "ProcessName": "C:\\Windows\\System32\\reg.exe",
          "ProcessId": "0x141e", "SubjectUserName": "admin",
          "SubjectDomainName": "CORP", "HandleId": "0x2d8"}
    ed.update(data)
    doc = {"EventID": 4657,
           "provider": "Microsoft-Windows-Security-Auditing",
           "channel": "Security", "Computer": "WIN-DC-18",
           "TimeCreated": "2026-06-01T10:00:00+00:00", "EventData": ed}
    parsed = WindowsSecurityParser().parse(doc)
    return WindowsSecurityNormalizer().normalize(
        parsed, "windows-security-evd", COL, "int-d18", "trace-d18",
        tenant_id=TEN)


def mapping(out):
    return out["additional_fields"]["registry_mapping"]


# ══ 1 · the canonical registry entity exists and is populated ═════
def test_the_evidence_model_carries_a_registry_entity():
    for path in ("registry.hive", "registry.key_path", "registry.value_name",
                 "registry.value_data", "registry.value_type",
                 "registry.action", "registry.target_object",
                 "registry.new_key_path"):
        assert path in dc.CANONICAL_FIELDS, path


def test_sysmon_set_value_becomes_canonical_registry_evidence():
    out = sysmon()
    reg = out["registry"]
    assert reg["key_path"] == RUN_KEY
    assert reg["value_name"] == "Updater"
    assert reg["value_data"] == "C:\\temp\\evil.exe"
    assert reg["action"] == "set_value"
    assert reg["hive"] == "HKLM"
    assert reg["target_object"] == f"{RUN_KEY}\\Updater"


def test_windows_4657_becomes_canonical_registry_evidence():
    out = windows()
    reg = out["registry"]
    assert reg["key_path"] == RUN_KEY
    assert reg["value_name"] == "Updater"
    assert reg["value_data"] == "C:\\temp\\evil.exe"
    assert reg["value_type"] == "REG_SZ"
    assert reg["action"] == "set_value"
    assert out["event_type"] == "registry_value_modified"


def test_the_4657_event_id_is_now_supported_by_the_dsm():
    assert WindowsSecurityDSM().supports(
        {"EventID": 4657, "provider": "Microsoft-Windows-Security-Auditing"})


def test_sysmon_registry_event_ids_are_supported():
    for eid in (12, 13, 14):
        assert SysmonDSM().supports({"EventID": eid,
                                     "provider": "Microsoft-Windows-Sysmon"})


# ══ 2 · per-field provenance ══════════════════════════════════════
def test_every_registry_field_says_where_it_came_from():
    fields = mapping(sysmon())["fields"]
    for name in ("hive", "key_path", "value_name", "value_data",
                 "value_type", "action", "target_object"):
        row = fields[name]
        assert row["state"] in ("OBSERVED", "DERIVED", "NOT_OBSERVED"), name
        assert row["source"], name
        if row["state"] == "DERIVED":
            assert row["basis"], name
        if row["state"] == "NOT_OBSERVED":
            assert row["reason"], name


def test_the_key_value_split_is_declared_as_derived_not_observed():
    fields = mapping(sysmon())["fields"]
    assert fields["key_path"]["state"] == "DERIVED"
    assert "trailing value name" in fields["key_path"]["basis"]
    assert fields["value_name"]["state"] == "DERIVED"
    # the source's verbatim string is preserved beside the split
    assert fields["target_object"]["value"] == f"{RUN_KEY}\\Updater"


def test_sysmon_carries_no_value_type_and_says_so():
    row = mapping(sysmon())["fields"]["value_type"]
    assert row["state"] == "NOT_OBSERVED"
    assert "no separate registry value TYPE" in row["reason"]


def test_a_key_level_operation_names_no_value():
    out = sysmon(EventID=12, EventType="CreateKey", TargetObject=RUN_KEY,
                 Details="")
    reg = out["registry"]
    assert reg["action"] == "create_key"
    assert reg["key_path"] == RUN_KEY
    assert reg["value_name"] == ""
    row = mapping(out)["fields"]["value_name"]
    assert row["state"] == "NOT_OBSERVED"
    assert "key-level operation" in row["reason"]


def test_an_ambiguous_sysmon_12_without_event_type_is_not_guessed():
    out = sysmon(EventID=12, EventType="", TargetObject=RUN_KEY, Details="")
    assert out["registry"]["action"] == ""
    row = mapping(out)["fields"]["action"]
    assert row["state"] == "NOT_OBSERVED"
    assert "BOTH CreateKey and DeleteKey" in row["reason"]
    # and it therefore does not fire the persistence rule
    assert "DET-PS-001" not in {m["rule_id"] for m in
                                REGISTRY.evaluate_event(
                                    {**out, "event_id": "d18-amb"})}


def test_an_unrecognised_hive_is_not_assumed():
    out = sysmon(TargetObject="\\Device\\Something\\Odd\\Value")
    assert out["registry"]["hive"] == ""
    assert mapping(out)["fields"]["hive"]["state"] == "NOT_OBSERVED"


def test_an_undocumented_4657_operation_is_recorded_not_guessed():
    out = windows(OperationType="%%9999")
    assert out["registry"]["action"] == ""
    row = mapping(out)["fields"]["action"]
    assert row["state"] == "NOT_OBSERVED"
    assert "not a documented 4657 operation" in row["reason"]
    assert mapping(out)["fields"]["operation_type_raw"]["value"] == "%%9999"


@pytest.mark.parametrize("code,action", [("%%1904", "create_value"),
                                         ("%%1905", "set_value"),
                                         ("%%1906", "delete_value")])
def test_the_documented_4657_operations_map_exactly(code, action):
    assert windows(OperationType=code)["registry"]["action"] == action


def test_a_rename_carries_its_target_and_nothing_else_does():
    out = sysmon(EventID=14, EventType="RenameKey", TargetObject=RUN_KEY,
                 NewName=f"{RUN_KEY}Old", Details="")
    assert out["registry"]["action"] == "rename_key"
    assert out["registry"]["new_key_path"] == f"{RUN_KEY}Old"
    assert mapping(sysmon())["fields"]["new_key_path"]["state"] \
        == "NOT_OBSERVED"


# ══ 3 · associations are claimed only when evidenced ══════════════
def test_the_acting_process_device_and_user_are_associated_when_present():
    assoc = mapping(sysmon())["associations"]
    assert assoc["device"]["value"] == "WIN-SRV-18"
    assert assoc["process"]["value"] == "C:\\Windows\\System32\\reg.exe"
    assert assoc["identity"]["value"] == "CORP\\admin"
    for row in assoc.values():
        assert row["source"]


def test_an_absent_actor_is_absent_not_system():
    out = sysmon(Image="", User="", ProcessId="")
    assoc = mapping(out)["associations"]
    assert assoc["process"]["state"] == "NOT_OBSERVED"
    assert assoc["identity"]["state"] == "NOT_OBSERVED"
    assert "not SYSTEM" in assoc["identity"]["reason"]
    assert out["registry"]["key_path"] == RUN_KEY   # evidence still stands


def test_the_raw_reference_points_back_at_the_source_record():
    ref = mapping(sysmon())["raw_reference"]
    assert ref["sysmon_event_id"] == 13
    assert ref["target_object"] == f"{RUN_KEY}\\Updater"
    ref4657 = mapping(windows())["raw_reference"]
    assert ref4657["windows_event_id"] == 4657
    assert ref4657["object_name"] == RUN_KEY


def test_the_evidence_class_is_always_declared():
    for out in (sysmon(), windows()):
        assert mapping(out)["evidence_class"] == re_ev.EVIDENCE_CLASS
        assert mapping(out)["observed_by"]


# ══ 4 · registry evidence is never manufactured ═══════════════════
def test_a_command_line_that_mentions_the_registry_creates_no_registry_evidence():
    cmd = f"reg add {RUN_KEY} /v Updater /d C:\\temp\\evil.exe /f"
    out = sysmon(EventID=1, EventType="", TargetObject="", Details="",
                 CommandLine=cmd)
    assert out["registry"]["key_path"] == ""
    assert out["registry"]["action"] == ""
    assert "registry_mapping" not in out["additional_fields"]
    assert out["process"]["command_line"] == cmd


def test_a_non_registry_sysmon_event_carries_an_empty_registry_entity():
    out = sysmon(EventID=1, EventType="", TargetObject="", Details="",
                 CommandLine="cmd /c whoami")
    assert out["registry"] == {"hive": "", "key_path": "", "value_name": "",
                               "value_data": "", "value_type": "",
                               "action": "", "target_object": "",
                               "new_key_path": ""}


def test_other_windows_event_ids_carry_no_registry_evidence():
    doc = {"EventID": 4688,
           "provider": "Microsoft-Windows-Security-Auditing",
           "Computer": "WIN-DC-18",
           "TimeCreated": "2026-06-01T10:00:00+00:00",
           "EventData": {"NewProcessName": "C:\\Windows\\System32\\reg.exe",
                         "CommandLine": f"reg add {RUN_KEY} /v x /d y /f",
                         "SubjectUserName": "admin"}}
    parsed = WindowsSecurityParser().parse(doc)
    out = WindowsSecurityNormalizer().normalize(
        parsed, "windows-security-evd", COL, "int-d18", "trace-d18",
        tenant_id=TEN)
    assert out["registry"]["key_path"] == ""
    assert "registry_mapping" not in out["additional_fields"]


# ══ 5 · observed detection vs inferred detection ══════════════════
def _fire(out, event_id):
    return {m["rule_id"]: m for m in
            REGISTRY.evaluate_event({**out, "event_id": event_id})}


def test_observed_run_key_persistence_fires_the_observed_rule_and_cites_it():
    matches = _fire(sysmon(), "d18-observed")
    assert "DET-PS-001" in matches, sorted(matches)
    assert "DET-PS-005" not in matches
    citation = matches["DET-PS-001"]["citation"]
    assert citation["declaration_state"] == "DECLARED"
    assert citation["citation_completeness"] == "CITED"
    fields = {c["canonical_field"] for c in citation["matched_conditions"]}
    assert fields <= {"registry.key_path", "registry.target_object",
                      "registry.action"}
    assert any(RUN_KEY.lower() in str(c["observed_value"]).lower()
               for c in citation["matched_conditions"])
    assert all(c["evidence_ref"] == "xdr_canonical_evidence/d18-observed"
               for c in citation["matched_conditions"])


def test_windows_4657_run_key_modification_also_fires_the_observed_rule():
    matches = _fire(windows(), "d18-4657")
    assert "DET-PS-001" in matches, sorted(matches)
    assert matches["DET-PS-001"]["citation"]["citation_completeness"] \
        == "CITED"


def test_a_command_line_request_fires_the_INFERENCE_rule_only():
    cmd = f"reg add {RUN_KEY} /v Updater /d C:\\temp\\evil.exe /f"
    event = {"event_id": "d18-inferred", "event_type": "process_execution",
             "process": {"command_line": cmd,
                         "executable_path": "C:\\Windows\\System32\\reg.exe"},
             "command_line": cmd}
    matches = {m["rule_id"]: m for m in REGISTRY.evaluate_event(event)}
    assert "DET-PS-005" in matches, sorted(matches)
    assert "DET-PS-001" not in matches
    citation = matches["DET-PS-005"]["citation"]
    assert {c["canonical_field"] for c in citation["matched_conditions"]} \
        == {"process.command_line"}


def test_the_inference_rule_says_it_is_an_inference():
    assert "INFERENCE" in RULES["DET-PS-005"].description
    assert "not evidence that" in RULES["DET-PS-005"].description


def test_the_two_rules_share_the_technique_but_not_the_evidence():
    assert RULES["DET-PS-001"].technique_id == \
        RULES["DET-PS-005"].technique_id == "T1547.001"
    observed = {c.canonical_field for c in RULES["DET-PS-001"].conditions}
    inferred = {c.canonical_field for c in RULES["DET-PS-005"].conditions}
    assert observed and inferred and not (observed & inferred)


# ══ 6 · benign registry activity stays benign ═════════════════════
BENIGN = [
    ("theme change", {"EventType": "SetValue",
                      "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\"
                                      "CurrentVersion\\Themes\\CurrentTheme",
                      "Details": "dark"}),
    ("explorer advanced setting",
     {"EventType": "SetValue",
      "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\"
                      "Explorer\\Advanced\\Hidden", "Details": "1"}),
    ("uninstall entry", {"EventType": "SetValue",
                         "TargetObject": "HKLM\\Software\\Microsoft\\Windows"
                                         "\\CurrentVersion\\Uninstall\\App"
                                         "\\DisplayName",
                         "Details": "Contoso App"}),
    ("service config", {"EventType": "SetValue",
                        "TargetObject": "HKLM\\System\\CurrentControlSet\\"
                                        "Services\\EventLog\\Start",
                        "Details": "2"}),
    ("run key READ is not a write", {"EventType": "",
                                     "EventID": 12,
                                     "TargetObject": RUN_KEY,
                                     "Details": ""}),
]


@pytest.mark.parametrize("label,over", BENIGN)
def test_ordinary_registry_activity_is_not_persistence(label, over):
    out = sysmon(**over)
    # the evidence is still recorded — it just is not a detection
    assert out["registry"]["key_path"] or out["registry"]["target_object"]
    assert "DET-PS-001" not in _fire(out, f"d18-benign-{label[:6]}"), label


def test_a_benign_4657_modification_is_not_persistence():
    out = windows(ObjectName="HKLM\\Software\\Contoso\\Settings",
                  ObjectValueName="Theme", NewValue="dark")
    assert out["registry"]["key_path"] == "HKLM\\Software\\Contoso\\Settings"
    assert "DET-PS-001" not in _fire(out, "d18-benign-4657")


# ══ 7 · the rest of the evidence contract still holds ═════════════
def test_the_authenticated_tenant_still_owns_registry_evidence():
    out = sysmon(tenant_id="t-attacker-claim")
    assert out["tenant_id"] == TEN
    claim = out["additional_fields"]["tenant_claim"]
    assert claim["claimed_tenant_id"] == "t-attacker-claim"
    assert claim["used"] is False


def test_d12_time_semantics_are_unchanged_for_registry_events():
    out = sysmon()
    extra = out["additional_fields"]
    # Sysmon states when the activity happened
    assert extra["event_time_basis"] == "ACTIVITY_TIME"
    assert extra["event_time_source"] == "sysmon:EventData.UtcTime"
    assert out["event_time"] == "2026-06-01T10:00:00+00:00"
    # Windows 4657 has no activity field, and still refuses to invent one
    w_extra = windows()["additional_fields"]
    assert w_extra["event_time_basis"] == "OBSERVATION_TIME"
    assert w_extra["event_time_source"] == \
        "windows:System.TimeCreated.SystemTime"


def test_the_declaration_contract_is_still_clean():
    report = dc.report(RUNTIME_DETECTION_RULES)
    assert report["contract_problems"] == []
    assert report["declared_but_unexplained"] == []
    assert "DET-PS-001" in report["declared"]
    assert "DET-PS-005" in report["declared"]
