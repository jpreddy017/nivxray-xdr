"""W2-1 · Security + PowerShell canonical evidence — deterministic gate.

Every fixture below is a rendered Windows Event Log record in the EXACT
shape `EvtRender(EvtRenderEventXml)` produces, delivered the way the W2-1
adapter delivers it (`raw = {"xml": ..., "channel": ...}`). No telemetry is
fabricated as "real endpoint evidence": these are format fixtures whose
only purpose is to prove the decode → parse → normalize → provenance chain
behaves, and they are labelled as fixtures.
"""
from __future__ import annotations

import pytest

from detection_content.telemetry import evtx_xml
from detection_content.telemetry.registry import TELEMETRY_DSM_REGISTRY
from detection_content.telemetry.windows_powershell_dsm import (
    WindowsPowerShellDSM, parse_context_block,
)
from detection_content.telemetry.windows_security_dsm import (
    WindowsSecurityDSM, WindowsSecurityParserError,
)
from services import source_routing

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event(*, provider: str, event_id: int, channel: str, computer: str,
           time_created: str, data_xml: str, level: int = 4,
           record_id: int = 1000, pid: int = 4242,
           user_sid: str = "S-1-5-18") -> str:
    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="{provider}"/>'
        f"<EventID>{event_id}</EventID><Version>0</Version>"
        f"<Level>{level}</Level><Task>0</Task><Opcode>0</Opcode>"
        f'<TimeCreated SystemTime="{time_created}"/>'
        f"<EventRecordID>{record_id}</EventRecordID>"
        f'<Correlation ActivityID="{{11111111-2222-3333-4444-555555555555}}"/>'
        f'<Execution ProcessID="{pid}" ThreadID="9"/>'
        f"<Channel>{channel}</Channel><Computer>{computer}</Computer>"
        f'<Security UserID="{user_sid}"/>'
        f"</System>{data_xml}</Event>"
    )


def _delivery(xml: str, channel: str) -> dict:
    """What the W2-1 adapter puts in `Envelope.raw`."""
    return {"xml": xml, "channel": channel}


# ── fixtures · Security channel ────────────────────────────────────
SEC_4688 = _event(
    provider="Microsoft-Windows-Security-Auditing", event_id=4688,
    channel="Security", computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T10:15:30.1234567Z",
    data_xml=(
        "<EventData>"
        '<Data Name="SubjectUserSid">S-1-5-21-99-1001</Data>'
        '<Data Name="SubjectUserName">jdoe</Data>'
        '<Data Name="SubjectDomainName">FIXTURE</Data>'
        '<Data Name="SubjectLogonId">0x3e7a1</Data>'
        '<Data Name="NewProcessId">0x1a4</Data>'
        '<Data Name="NewProcessName">C:\\Windows\\System32\\whoami.exe</Data>'
        '<Data Name="TokenElevationType">%%1937</Data>'
        '<Data Name="CommandLine">whoami /priv</Data>'
        '<Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>'
        "</EventData>"))

SEC_4624 = _event(
    provider="Microsoft-Windows-Security-Auditing", event_id=4624,
    channel="Security", computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T10:16:00.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="TargetUserSid">S-1-5-21-99-1001</Data>'
        '<Data Name="TargetUserName">jdoe</Data>'
        '<Data Name="TargetDomainName">FIXTURE</Data>'
        '<Data Name="TargetLogonId">0x51f2a</Data>'
        '<Data Name="LogonType">10</Data>'
        '<Data Name="WorkstationName">WIN-LAB-02</Data>'
        '<Data Name="LogonProcessName">User32</Data>'
        '<Data Name="AuthenticationPackageName">Negotiate</Data>'
        '<Data Name="IpAddress">10.10.0.42</Data>'
        '<Data Name="IpPort">51823</Data>'
        "</EventData>"))

SEC_4672 = _event(
    provider="Microsoft-Windows-Security-Auditing", event_id=4672,
    channel="Security", computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T10:16:01.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="SubjectUserSid">S-1-5-21-99-500</Data>'
        '<Data Name="SubjectUserName">Administrator</Data>'
        '<Data Name="SubjectDomainName">FIXTURE</Data>'
        '<Data Name="SubjectLogonId">0x51f2a</Data>'
        '<Data Name="PrivilegeList">SeDebugPrivilege'
        "\t\t\tSeTcbPrivilege</Data>"
        "</EventData>"))

SEC_4732 = _event(
    provider="Microsoft-Windows-Security-Auditing", event_id=4732,
    channel="Security", computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T10:17:00.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="MemberName">-</Data>'
        '<Data Name="MemberSid">S-1-5-21-99-1001</Data>'
        '<Data Name="TargetUserName">Administrators</Data>'
        '<Data Name="TargetDomainName">Builtin</Data>'
        '<Data Name="TargetSid">S-1-5-32-544</Data>'
        '<Data Name="SubjectUserSid">S-1-5-21-99-500</Data>'
        '<Data Name="SubjectUserName">Administrator</Data>'
        '<Data Name="SubjectDomainName">FIXTURE</Data>'
        '<Data Name="SubjectLogonId">0x51f2a</Data>'
        "</EventData>"))

SEC_4776 = _event(
    provider="Microsoft-Windows-Security-Auditing", event_id=4776,
    channel="Security", computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T10:18:00.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="PackageName">MICROSOFT_AUTHENTICATION_PACKAGE_V1_0</Data>'
        '<Data Name="TargetUserName">jdoe</Data>'
        '<Data Name="Workstation">WIN-LAB-02</Data>'
        '<Data Name="Status">0xc000006a</Data>'
        "</EventData>"))

SEC_4698 = _event(
    provider="Microsoft-Windows-Security-Auditing", event_id=4698,
    channel="Security", computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T10:19:00.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="SubjectUserSid">S-1-5-21-99-500</Data>'
        '<Data Name="SubjectUserName">Administrator</Data>'
        '<Data Name="SubjectDomainName">FIXTURE</Data>'
        '<Data Name="SubjectLogonId">0x51f2a</Data>'
        '<Data Name="TaskName">\\FixtureTask</Data>'
        '<Data Name="TaskContent">&lt;Task&gt;&lt;Actions&gt;'
        "&lt;Exec&gt;&lt;Command&gt;powershell.exe&lt;/Command&gt;"
        "&lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data>"
        "</EventData>"))

# 1102 keeps its subject in UserData, NOT EventData.
SEC_1102 = (
    f'<Event xmlns="{NS}"><System>'
    '<Provider Name="Microsoft-Windows-Eventlog"/>'
    "<EventID>1102</EventID><Level>4</Level>"
    '<TimeCreated SystemTime="2026-06-01T10:20:00.0000000Z"/>'
    "<EventRecordID>1050</EventRecordID>"
    "<Channel>Security</Channel>"
    "<Computer>WIN-LAB-01.fixture.local</Computer>"
    '<Security UserID="S-1-5-21-99-500"/>'
    "</System>"
    '<UserData><LogFileCleared '
    'xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
    "<SubjectUserName>Administrator</SubjectUserName>"
    "<SubjectDomainName>FIXTURE</SubjectDomainName>"
    "<SubjectUserSid>S-1-5-21-99-500</SubjectUserSid>"
    "<SubjectLogonId>0x51f2a</SubjectLogonId>"
    "</LogFileCleared></UserData></Event>")

# ── fixtures · PowerShell channels ─────────────────────────────────
PS_4104 = _event(
    provider="Microsoft-Windows-PowerShell", event_id=4104,
    channel="Microsoft-Windows-PowerShell/Operational",
    computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T11:00:00.0000000Z", level=5,
    data_xml=(
        "<EventData>"
        '<Data Name="MessageNumber">1</Data>'
        '<Data Name="MessageTotal">1</Data>'
        '<Data Name="ScriptBlockText">Get-Process | '
        "Select-Object -First 3</Data>"
        '<Data Name="ScriptBlockId">'
        "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}</Data>"
        '<Data Name="Path">C:\\fixtures\\demo.ps1</Data>'
        "</EventData>"))

PS_4103 = _event(
    provider="Microsoft-Windows-PowerShell", event_id=4103,
    channel="Microsoft-Windows-PowerShell/Operational",
    computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T11:00:05.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="ContextInfo">Severity = Informational\r\n'
        "Host Name = ConsoleHost\r\n"
        "Host Version = 5.1.19041.4648\r\n"
        "Host ID = 12345678-1111-2222-3333-444444444444\r\n"
        "Host Application = powershell.exe -NoProfile -File demo.ps1\r\n"
        "Engine Version = 5.1.19041.4648\r\n"
        "Runspace ID = 99999999-1111-2222-3333-444444444444\r\n"
        "Pipeline ID = 7\r\n"
        "Command Name = Get-Process\r\n"
        "Command Type = Cmdlet\r\n"
        "User = FIXTURE\\jdoe\r\n"
        "Command Line = Get-Process\r\n</Data>"
        '<Data Name="UserData"></Data>'
        '<Data Name="Payload">CommandInvocation(Get-Process)</Data>'
        "</EventData>"))

# Classic channel · unnamed positional Data, context block in the last one.
PS_400_CLASSIC = _event(
    provider="PowerShell", event_id=400, channel="Windows PowerShell",
    computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T11:01:00.0000000Z",
    data_xml=(
        "<EventData>"
        "<Data>Available</Data>"
        "<Data>None</Data>"
        "<Data>\tNewEngineState=Available\r\n"
        "\tPreviousEngineState=None\r\n"
        "\tSequenceNumber=13\r\n"
        "\tHostName=ConsoleHost\r\n"
        "\tHostVersion=5.1.19041.4648\r\n"
        "\tHostId=12345678-1111-2222-3333-444444444444\r\n"
        "\tHostApplication=powershell.exe -NoProfile\r\n"
        "\tEngineVersion=5.1.19041.4648\r\n"
        "\tRunspaceId=99999999-1111-2222-3333-444444444444\r\n"
        "\tPipelineId=\r\n"
        "\tCommandName=\r\n</Data>"
        "</EventData>"))

# Sysmon · proves the SAME decode unblocks the channel that was already
# claimed as analysis-supported but only ever received flat JSON before.
SYSMON_1 = _event(
    provider="Microsoft-Windows-Sysmon", event_id=1,
    channel="Microsoft-Windows-Sysmon/Operational",
    computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T12:00:00.0000000Z",
    data_xml=(
        "<EventData>"
        '<Data Name="RuleName">-</Data>'
        '<Data Name="UtcTime">2026-06-01 11:59:59.123</Data>'
        '<Data Name="ProcessGuid">{ffffffff-1111-2222-3333-444444444444}</Data>'
        '<Data Name="ProcessId">1444</Data>'
        '<Data Name="Image">C:\\Windows\\System32\\whoami.exe</Data>'
        '<Data Name="OriginalFileName">whoami.exe</Data>'
        '<Data Name="CommandLine">whoami /priv</Data>'
        '<Data Name="User">FIXTURE\\jdoe</Data>'
        '<Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>'
        '<Data Name="ParentCommandLine">cmd.exe /c whoami /priv</Data>'
        "</EventData>"))


def _normalize(dsm, delivery):
    parsed = dsm.select_parser().parse(delivery)
    return dsm.select_normalizer().normalize(
        parsed, dsm_id=dsm.id, collector_id="collector-fixture",
        integration_id="windows-eventlog", trace_id="trace-fixture",
        tenant_id="tenant-fixture")


# ══ the decoder ════════════════════════════════════════════════════
class TestEvtxXmlDecoder:
    def test_system_block_is_decoded_verbatim(self):
        d = evtx_xml.decode(SEC_4688)
        assert d["System"]["EventID"] == 4688
        assert d["System"]["Provider"] == \
            "Microsoft-Windows-Security-Auditing"
        assert d["System"]["Channel"] == "Security"
        assert d["System"]["Computer"] == "WIN-LAB-01.fixture.local"
        assert d["System"]["TimeCreated"] == "2026-06-01T10:15:30.1234567Z"
        assert d["System"]["EventRecordID"] == 1000
        assert d["System"]["UserID"] == "S-1-5-18"
        assert d["System"]["ProcessID"] == 4242

    def test_named_event_data_becomes_a_mapping(self):
        d = evtx_xml.decode(SEC_4688)
        assert d["EventData"]["CommandLine"] == "whoami /priv"
        assert d["EventData"]["NewProcessName"].endswith("whoami.exe")

    def test_event_data_names_are_promoted_for_flat_dsm_contracts(self):
        d = evtx_xml.decode(SYSMON_1)
        assert d["event_id"] == 1
        assert d["provider"] == "Microsoft-Windows-Sysmon"
        assert d["Image"] == "C:\\Windows\\System32\\whoami.exe"
        assert d["UtcTime"] == "2026-06-01 11:59:59.123"

    def test_unnamed_data_is_preserved_positionally(self):
        d = evtx_xml.decode(PS_400_CLASSIC)
        assert d["EventData"]["Data"][0] == "Available"
        assert "NewEngineState=Available" in d["EventData"]["Data"][2]

    def test_user_data_is_decoded_when_present(self):
        d = evtx_xml.decode(SEC_1102)
        assert d["UserData"]["SubjectUserName"] == "Administrator"
        assert "EventData" not in d

    def test_verbatim_xml_is_never_discarded(self):
        d = evtx_xml.decode(SEC_4624)
        assert d["evtx_xml"] == SEC_4624
        assert d["evtx_decoder_id"] == evtx_xml.DECODER_ID

    def test_delivery_keys_win_over_decoded_keys(self):
        merged = evtx_xml.decode_document(
            _delivery(SEC_4688, "Security"))
        assert merged["channel"] == "Security"
        # The delivery already carries the XML; it is not duplicated.
        assert "evtx_xml" not in merged
        assert merged["xml"] == SEC_4688

    def test_a_non_windows_document_is_left_alone(self):
        assert evtx_xml.decode_document({"line": "hello"}) is None
        assert evtx_xml.envelope_xml({"line": "<b>not an event</b>"}) is None

    def test_malformed_xml_is_refused_loudly(self):
        with pytest.raises(evtx_xml.EvtxXmlDecodeError) as exc:
            evtx_xml.decode("<Event><System><EventID>1</EventID>")
        assert exc.value.code == "EVTX_MALFORMED_XML"

    def test_a_record_without_an_event_id_cannot_be_routed(self):
        with pytest.raises(evtx_xml.EvtxXmlDecodeError) as exc:
            evtx_xml.decode(
                f'<Event xmlns="{NS}"><System><Channel>Security</Channel>'
                "</System></Event>")
        assert exc.value.code == "EVTX_MISSING_EVENT_ID"


# ══ Security canonical evidence ════════════════════════════════════
class TestWindowsSecurityFromRenderedXml:
    dsm = WindowsSecurityDSM()

    def test_dsm_claims_the_rendered_delivery(self):
        assert self.dsm.supports(_delivery(SEC_4688, "Security"))
        assert self.dsm.supports(_delivery(SEC_1102, "Security"))
        assert not self.dsm.supports(_delivery(PS_4104, "PowerShell"))
        assert not self.dsm.supports({"line": "not windows"})

    def test_4688_process_creation_is_canonical(self):
        out = _normalize(self.dsm, _delivery(SEC_4688, "Security"))
        assert out["event_type"] == "process_creation"
        assert out["tenant_id"] == "tenant-fixture"
        assert out["process"]["name"] == "whoami.exe"
        assert out["process"]["executable_path"].endswith("whoami.exe")
        assert out["process"]["command_line"] == "whoami /priv"
        assert out["process"]["parent_name"] == "cmd.exe"
        assert out["identity"]["username"] == "jdoe"
        assert out["identity"]["principal_id"] == "FIXTURE\\jdoe"
        assert out["identity"]["is_privileged"] is True
        assert out["host"]["hostname"] == "WIN-LAB-01.fixture.local"

    def test_4624_logon_evidence(self):
        out = _normalize(self.dsm, _delivery(SEC_4624, "Security"))
        assert out["event_type"] == "logon_success"
        assert out["authentication"]["status"] == "SUCCESS"
        assert out["additional_fields"]["logon_type"] == 10
        assert out["additional_fields"]["logon_type_label"] == \
            "remote_interactive"
        assert out["network"]["src_ip"] == "10.10.0.42"
        assert out["network"]["src_port"] == 51823

    def test_4672_records_the_privileges_the_event_stated(self):
        out = _normalize(self.dsm, _delivery(SEC_4672, "Security"))
        assert out["event_type"] == "special_privileges_assigned"
        assert out["identity"]["is_privileged"] is True
        assert out["additional_fields"]["privilege_list"] == \
            ["SeDebugPrivilege", "SeTcbPrivilege"]

    def test_4732_keeps_actor_and_target_apart(self):
        out = _normalize(self.dsm, _delivery(SEC_4732, "Security"))
        assert out["event_type"] == "security_group_member_added"
        assert out["identity"]["username"] == "Administrator"
        assert out["additional_fields"]["group_name"] == "Administrators"
        assert out["additional_fields"]["group_sid"] == "S-1-5-32-544"
        assert out["additional_fields"]["member_sid"] == "S-1-5-21-99-1001"

    def test_4776_failure_is_not_read_as_success(self):
        out = _normalize(self.dsm, _delivery(SEC_4776, "Security"))
        assert out["event_type"] == "credential_validation"
        assert out["authentication"]["auth_type"] == "ntlm"
        assert out["authentication"]["status"] == "FAILURE"
        assert out["authentication"]["failure_reason"] == "0xc000006a"

    def test_4698_carries_the_task_definition_verbatim(self):
        out = _normalize(self.dsm, _delivery(SEC_4698, "Security"))
        assert out["event_type"] == "scheduled_task_created"
        assert out["additional_fields"]["task_name"] == "\\FixtureTask"
        assert "powershell.exe" in out["additional_fields"]["task_content"]

    def test_1102_is_normalized_from_user_data(self):
        out = _normalize(self.dsm, _delivery(SEC_1102, "Security"))
        assert out["event_type"] == "audit_log_cleared"
        assert out["identity"]["username"] == "Administrator"
        assert out["identity"]["user_sid"] == "S-1-5-21-99-500"
        assert "integrity_note" in out["additional_fields"]

    def test_time_basis_is_observation_never_activity(self):
        out = _normalize(self.dsm, _delivery(SEC_4688, "Security"))
        assert out["additional_fields"]["event_time_basis"] == \
            "OBSERVATION_TIME"
        stamps = out["provenance"]["timestamps"]
        assert stamps["activity_occurred_at"]["status"] == "NOT_OBSERVED"
        assert stamps["sensor_observed_at"]["value"] == \
            "2026-06-01T10:15:30.1234567Z"

    def test_provenance_names_the_decode_chain(self):
        out = _normalize(self.dsm, _delivery(SEC_4624, "Security"))
        prov = out["provenance"]
        assert prov["dsm_id"] == "windows-security-evd"
        assert prov["parser_id"] == "windows-security-parser"
        assert prov["normalizer_id"] == "windows-security-normalizer"
        assert prov["collector_id"] == "collector-fixture"

    def test_an_unsupported_security_event_is_refused_not_emptied(self):
        xml = _event(provider="Microsoft-Windows-Security-Auditing",
                     event_id=5379, channel="Security", computer="WIN-LAB-01",
                     time_created="2026-06-01T10:00:00.0000000Z",
                     data_xml="<EventData/>")
        with pytest.raises(WindowsSecurityParserError) as exc:
            self.dsm.select_parser().parse(_delivery(xml, "Security"))
        assert exc.value.code == "UNSUPPORTED_EID"


# ══ PowerShell canonical evidence ══════════════════════════════════
class TestWindowsPowerShellDSM:
    dsm = WindowsPowerShellDSM()

    def test_context_block_parsing(self):
        ctx = parse_context_block(
            "Host Application = powershell.exe -File a.ps1\r\n"
            "User = FIXTURE\\jdoe\r\n"
            "Unknown Key = kept\r\n")
        assert ctx["host_application"] == "powershell.exe -File a.ps1"
        assert ctx["user"] == "FIXTURE\\jdoe"
        assert ctx["unknown_key"] == "kept"

    def test_supports_requires_the_powershell_provider(self):
        assert self.dsm.supports(
            _delivery(PS_4104, "Microsoft-Windows-PowerShell/Operational"))
        assert self.dsm.supports(_delivery(PS_400_CLASSIC,
                                           "Windows PowerShell"))
        # A Security record with a small event id must never be claimed.
        assert not self.dsm.supports(_delivery(SEC_4688, "Security"))
        assert not self.dsm.supports(_delivery(SYSMON_1, "Sysmon"))

    def test_4104_carries_the_script_text_verbatim(self):
        out = _normalize(self.dsm, _delivery(
            PS_4104, "Microsoft-Windows-PowerShell/Operational"))
        add = out["additional_fields"]
        assert out["event_type"] == "powershell_script_block_logged"
        assert add["script_block_text"] == \
            "Get-Process | Select-Object -First 3"
        assert add["script_block_length"] == 36
        assert add["script_block_id"] == \
            "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"
        assert add["script_path"] == "C:\\fixtures\\demo.ps1"
        assert add["script_block_complete"] is True
        assert out["source_product"] == "Microsoft-Windows-PowerShell"

    def test_4103_resolves_host_process_and_principal(self):
        out = _normalize(self.dsm, _delivery(
            PS_4103, "Microsoft-Windows-PowerShell/Operational"))
        assert out["event_type"] == "powershell_pipeline_execution_detail"
        assert out["process"]["name"] == "powershell.exe"
        assert out["process"]["command_line"] == \
            "powershell.exe -NoProfile -File demo.ps1"
        assert out["process"]["pid"] == 4242
        # A PID with no lifetime evidence is context, never attribution.
        assert out["process"]["attribution_state"] == \
            "PID_ONLY_NOT_AUTHORITATIVE"
        assert out["identity"]["username"] == "jdoe"
        assert out["identity"]["domain"] == "FIXTURE"
        assert out["additional_fields"]["command_name"] == "Get-Process"

    def test_classic_channel_engine_state(self):
        out = _normalize(self.dsm,
                         _delivery(PS_400_CLASSIC, "Windows PowerShell"))
        add = out["additional_fields"]
        assert out["event_type"] == "powershell_engine_state_change"
        assert out["source_product"] == "Windows PowerShell"
        assert add["new_engine_state"] == "Available"
        assert add["previous_engine_state"] == "None"
        assert add["engine_version"] == "5.1.19041.4648"
        assert out["process"]["name"] == "powershell.exe"
        assert add["context_info"]["sequence_number"] == "13"

    def test_powershell_time_basis_is_observation(self):
        out = _normalize(self.dsm, _delivery(
            PS_4104, "Microsoft-Windows-PowerShell/Operational"))
        assert out["additional_fields"]["event_time_basis"] == \
            "OBSERVATION_TIME"
        assert out["provenance"]["timestamps"][
            "activity_occurred_at"]["status"] == "NOT_OBSERVED"

    def test_command_intelligence_is_not_invoked(self):
        out = _normalize(self.dsm, _delivery(
            PS_4104, "Microsoft-Windows-PowerShell/Operational"))
        # Evidence only. No decoded/deobfuscated field is produced here.
        assert "decoded_script" not in out["additional_fields"]
        assert "command_intelligence" not in out["additional_fields"]
        assert "downstream consumer" in \
            out["additional_fields"]["analysis_note"]


# ══ registry + declared-source routing ═════════════════════════════
class TestWindowsChannelRouting:
    def test_both_windows_dsms_are_loaded(self):
        ids = [d["id"] for d in TELEMETRY_DSM_REGISTRY.list()]
        assert "windows-security-evd" in ids
        assert "windows-powershell-evd" in ids
        assert TELEMETRY_DSM_REGISTRY.load_failures() == []

    def test_collector_declared_sources_resolve(self):
        assert source_routing.canonical_source("windows_security") == \
            "windows-security-evd"
        assert source_routing.canonical_source("windows_powershell") == \
            "windows-powershell-evd"
        assert source_routing.canonical_source("sysmon") == \
            "microsoft-sysmon"

    def test_declared_routing_accepts_an_authorized_windows_delivery(self):
        decision, dsm = source_routing.route(
            declared="windows_powershell",
            authorized=["windows-powershell-evd"],
            raw_event=evtx_xml.decode_document(
                _delivery(PS_4104,
                          "Microsoft-Windows-PowerShell/Operational")),
            registry=TELEMETRY_DSM_REGISTRY)
        assert decision["routing_result"] == source_routing.ACCEPTED
        assert decision["selected_dsm_id"] == "windows-powershell-evd"
        assert dsm is not None

    def test_an_unauthorized_windows_source_is_refused(self):
        decision, dsm = source_routing.route(
            declared="windows_powershell",
            authorized=["microsoft-sysmon"],
            raw_event=evtx_xml.decode_document(
                _delivery(PS_4104,
                          "Microsoft-Windows-PowerShell/Operational")),
            registry=TELEMETRY_DSM_REGISTRY)
        assert decision["routing_result"] == source_routing.BLOCKED
        assert decision["mismatch_reason"] == \
            source_routing.SOURCE_NOT_AUTHORIZED
        assert dsm is None

    def test_a_security_payload_declared_as_powershell_is_refused(self):
        decision, dsm = source_routing.route(
            declared="windows_powershell",
            authorized=["windows-powershell-evd", "windows-security-evd"],
            raw_event=evtx_xml.decode_document(
                _delivery(SEC_4688, "Security")),
            registry=TELEMETRY_DSM_REGISTRY)
        assert decision["routing_result"] == source_routing.BLOCKED
        assert decision["mismatch_reason"] == \
            source_routing.SOURCE_FORMAT_MISMATCH
        assert dsm is None


# ══ Microsoft Defender · vendor verdict is SOURCE evidence ═════════
DEF_1116 = _event(
    provider="Microsoft-Windows-Windows Defender", event_id=1116,
    channel="Microsoft-Windows-Windows Defender/Operational",
    computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T13:00:05.0000000Z", level=3,
    data_xml=(
        "<EventData>"
        '<Data Name="Threat Name">Trojan:Win32/Fixture.A</Data>'
        '<Data Name="Threat ID">2147683313</Data>'
        '<Data Name="Severity Name">Severe</Data>'
        '<Data Name="Category Name">Trojan</Data>'
        '<Data Name="Action Name">Quarantine</Data>'
        '<Data Name="Detection Time">2026-06-01T13:00:00.000Z</Data>'
        '<Data Name="Detection Source">Real-Time Protection</Data>'
        '<Data Name="Detection User">FIXTURE\\jdoe</Data>'
        '<Data Name="Path">C:\\fixtures\\sample.exe</Data>'
        '<Data Name="Process Name">C:\\Windows\\explorer.exe</Data>'
        "</EventData>"))

DEF_5001 = _event(
    provider="Microsoft-Windows-Windows Defender", event_id=5001,
    channel="Microsoft-Windows-Windows Defender/Operational",
    computer="WIN-LAB-01.fixture.local",
    time_created="2026-06-01T13:05:00.0000000Z", level=3,
    data_xml="<EventData><Data Name=\"Feature Name\">Real-Time "
             "Protection</Data></EventData>")


class TestWindowsDefenderDSM:
    from detection_content.telemetry.windows_defender_dsm import (
        WindowsDefenderDSM as _D,
    )
    dsm = _D()

    def test_supports_requires_the_defender_provider(self):
        assert self.dsm.supports(_delivery(
            DEF_1116, "Microsoft-Windows-Windows Defender/Operational"))
        assert not self.dsm.supports(_delivery(SEC_4688, "Security"))
        assert not self.dsm.supports(_delivery(PS_4104, "PowerShell"))

    def test_vendor_verdict_is_evidence_not_a_nivx_verdict(self):
        out = _normalize(self.dsm, _delivery(
            DEF_1116, "Microsoft-Windows-Windows Defender/Operational"))
        v = out["additional_fields"]["vendor_verdict"]
        assert v["vendor"] == "Microsoft"
        assert v["threat_name"] == "Trojan:Win32/Fixture.A"
        assert v["severity"] == "Severe"
        assert v["action"] == "Quarantine"
        assert "never promoted" in v["authority_note"]
        # NivXRay's own verdict is NOT written by the DSM.
        assert "verdict" not in out
        assert "nivx_verdict" not in out["additional_fields"]
        assert out["additional_fields"]["evidence_class"] == \
            "ENDPOINT_PROTECTION_DETECTION"

    def test_detection_time_is_the_activity_instant(self):
        out = _normalize(self.dsm, _delivery(
            DEF_1116, "Microsoft-Windows-Windows Defender/Operational"))
        stamps = out["provenance"]["timestamps"]
        assert out["additional_fields"]["event_time_basis"] == "ACTIVITY_TIME"
        assert stamps["activity_occurred_at"]["source"] == \
            "defender:EventData.Detection Time"
        assert stamps["sensor_observed_at"]["source"] == \
            "defender:System.TimeCreated.SystemTime"

    def test_file_and_identity_evidence(self):
        out = _normalize(self.dsm, _delivery(
            DEF_1116, "Microsoft-Windows-Windows Defender/Operational"))
        assert out["file"]["path"] == "C:\\fixtures\\sample.exe"
        assert out["file"]["name"] == "sample.exe"
        assert out["identity"]["username"] == "jdoe"
        assert out["process"]["name"] == "explorer.exe"

    def test_protection_disabled_is_a_posture_fact(self):
        out = _normalize(self.dsm, _delivery(
            DEF_5001, "Microsoft-Windows-Windows Defender/Operational"))
        add = out["additional_fields"]
        assert out["event_type"] == "endpoint_protection_disabled"
        assert add["protection_state"] == "DISABLED"
        assert "not evidence of absence" in add["posture_note"]

    def test_command_intelligence_is_not_invoked(self):
        out = _normalize(self.dsm, _delivery(
            DEF_1116, "Microsoft-Windows-Windows Defender/Operational"))
        assert "downstream consumer" in \
            out["additional_fields"]["analysis_note"]

    def test_defender_routing_alias(self):
        assert source_routing.canonical_source("microsoft_defender") == \
            "windows-defender-evd"
        decision, dsm = source_routing.route(
            declared="microsoft_defender",
            authorized=["windows-defender-evd"],
            raw_event=evtx_xml.decode_document(_delivery(
                DEF_1116,
                "Microsoft-Windows-Windows Defender/Operational")),
            registry=TELEMETRY_DSM_REGISTRY)
        assert decision["routing_result"] == source_routing.ACCEPTED
        assert decision["selected_dsm_id"] == "windows-defender-evd"
        assert dsm is not None


# ══ Lane G · the five independent dimensions ═══════════════════════
class TestWindowsChannelTruthModel:
    def test_five_dimensions_never_collapse(self):
        from services import windows_channel_truth as t
        sec = t.detection_capability("Security")
        assert sec["state"] in t.CAPABILITY_STATES
        # Capability must not depend on anything having fired.
        assert "does NOT depend on anything having fired" in \
            sec["independence_note"]
        assert sec["eligible_rule_count"] > 0

    def test_a_channel_without_a_dsm_has_no_capability(self):
        from services import windows_channel_truth as t
        for channel in ("System", "Application",
                        "Microsoft-Windows-TaskScheduler/Operational"):
            cap = t.detection_capability(channel)
            assert cap["state"] == t.NOT_AVAILABLE
            assert "no DSM" in cap["basis"]

    def test_partial_normalization_caps_capability(self):
        from services import windows_channel_truth as t
        cap = t.detection_capability("Windows PowerShell")
        assert cap["state"] == t.PARTIAL

    def test_unsupported_channel_is_declared_not_missing(self):
        from services import windows_channel_truth as t
        cap = t.detection_capability("ForwardedEvents")
        assert cap["state"] == t.NOT_AVAILABLE
        assert "WEF/WEC" in cap["basis"]

    def test_collection_states_distinguish_absence_from_zero(self):
        from services import windows_channel_truth as t
        # No collector authorized, nothing delivered.
        d = t._collection_dimension("Security", None, [], False)
        assert d["state"] == t.NOT_CONFIGURED
        # Authorized, nothing has ever arrived from any channel.
        d = t._collection_dimension("Security", None, ["c1"], False)
        assert d["state"] == t.CONFIGURED
        # Authorized and the collector is delivering other channels.
        d = t._collection_dimension("Security", None, ["c1"], True)
        assert d["state"] == t.NOT_OBSERVED
        # Delivered but stale.
        d = t._collection_dimension(
            "Security", {"events_delivered": 5,
                         "last_received_at": "2020-01-01T00:00:00+00:00"},
            ["c1"], True)
        assert d["state"] == t.GAP_DETECTED
        assert d["gap"]["state"] == "ARRIVAL_STOPPED"
        # Arriving but nothing normalized.
        d = t._collection_dimension(
            "Security", {"events_delivered": 5, "norm_failed": 5,
                         "last_received_at": t._now().isoformat()},
            ["c1"], True)
        assert d["state"] == t.ERROR

    def test_support_dimension_keeps_declaration_and_measurement_apart(self):
        from services import windows_channel_truth as t
        d = t._support_dimension(t.SUPPORTED, None, None, None, None)
        assert d["state"] == t.SUPPORTED
        assert d["measured_state"] == t.NOT_EVALUATED
        assert d["measured"]["ok"] is None          # not zero
        d = t._support_dimension(t.SUPPORTED, 0, 4, 0, None)
        assert d["state"] == t.SUPPORTED
        assert d["measured_state"] == t.ERROR
        assert d["disagreement"] is True

    def test_activity_zero_is_not_the_same_as_unmeasured(self):
        from services import windows_channel_truth as t
        unmeasured = t._activity_dimension(None, False)
        assert unmeasured["detections_fired"] is None
        assert "not zero" in unmeasured["reason"]
        measured = t._activity_dimension(None, True)
        assert measured["detections_fired"] == 0

    def test_the_summary_bar_cannot_manufacture_a_stage(self):
        from services import windows_channel_truth as t
        collection = t._collection_dimension("Security", None, [], False)
        parsing = t._support_dimension(t.SUPPORTED, None, None, None, None)
        norm = t._support_dimension(t.SUPPORTED, None, None, None, None)
        cap = t.detection_capability("Security")
        cov = t.coverage_impact("Security", collection=collection,
                                parsing=parsing, normalization=norm,
                                measured_fields=set())
        stages = t._human_stages(collection, parsing, norm, cap, cov)
        assert [s["stage"] for s in stages] == \
            ["Acquired", "Understood", "Detectable"]
        assert stages[0]["reached"] is False     # nothing acquired
        assert stages[1]["reached"] is False     # so nothing understood
        # Owner correction: applicable content does NOT light this up.
        # Potential coverage exists; effective coverage is not proven.
        assert stages[2]["reached"] is False
        assert stages[2]["state"] == t.COVERAGE_BLOCKED
        assert cov["potential"]["rule_count"] > 0
        assert cap["state"] == t.AVAILABLE   # potential, independently true


# ══ Coverage Impact · POTENTIAL is not EFFECTIVE ═══════════════════
class TestCoverageImpactModel:
    """Owner correction (2026-06): telemetry arriving does not by itself
    prove the parser, the normalization, the required fields, an enabled
    rule, its schema compatibility or the detection execution path."""

    @staticmethod
    def _dims(t, *, collection_state, authorized, norm_measured):
        collection = {"state": collection_state, "reason": "fixture",
                      "authorized_collectors": (["c1"] if authorized else [])}
        parsing = t._support_dimension(t.SUPPORTED, 5, 0, 0, None)
        norm = t._support_dimension(t.SUPPORTED,
                                    5 if norm_measured else None,
                                    0 if norm_measured else None,
                                    0 if norm_measured else None, None)
        return collection, parsing, norm

    def test_applicable_content_with_no_telemetry_is_potential_not_effective(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.NOT_CONFIGURED, authorized=False,
            norm_measured=False)
        cov = t.coverage_impact("Security", collection=collection,
                                parsing=parsing, normalization=norm,
                                measured_fields=set())
        assert cov["potential"]["rule_count"] > 0
        assert cov["effective"]["rule_count"] == 0
        assert cov["effective"]["state"] == t.COVERAGE_BLOCKED
        assert "SOURCE NOT CONFIGURED" in cov["evidence_gaps"]
        assert cov["required_fields"]["state"] == t.PREREQ_NOT_PROVEN

    def test_effective_requires_measured_fields_not_a_declaration(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.RECEIVING, authorized=True,
            norm_measured=True)
        # Prerequisites all pass, but NO field has been measured.
        cov = t.coverage_impact("Security", collection=collection,
                                parsing=parsing, normalization=norm,
                                measured_fields=set())
        assert cov["prerequisites_satisfied"] is True
        assert cov["effective"]["state"] == t.COVERAGE_NOT_PROVEN
        assert cov["effective"]["rule_count"] == 0
        assert "no required field has been measured" in cov["effective"]["basis"]

    def test_effective_is_established_when_fields_are_measured(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.RECEIVING, authorized=True,
            norm_measured=True)
        cov = t.coverage_impact(
            "Security", collection=collection, parsing=parsing,
            normalization=norm,
            measured_fields=set(t.CHANNEL_CANONICAL_FIELDS["Security"]))
        assert cov["effective"]["state"] == t.COVERAGE_EFFECTIVE
        assert cov["effective"]["rule_count"] > 0
        # And still WITHOUT any detection having fired.
        assert all(r["detections_fired"] is None
                   for r in cov["effective"]["rules"])
        assert "does NOT require a detection to have fired" in \
            cov["effective"]["basis_note"]

    def test_the_detectable_stage_reports_effective_never_potential(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.NOT_CONFIGURED, authorized=False,
            norm_measured=False)
        cov = t.coverage_impact("Security", collection=collection,
                                parsing=parsing, normalization=norm,
                                measured_fields=set())
        stages = t._human_stages(collection, parsing, norm,
                                 t.detection_capability("Security"), cov)
        detectable = stages[2]
        # 21-ish applicable rules must NOT light this stage up.
        assert detectable["reached"] is False
        assert detectable["state"] == t.COVERAGE_BLOCKED
        assert "potential coverage:" in detectable["detail"]

    def test_prerequisite_and_content_gaps_are_kept_apart(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.RECEIVING, authorized=True,
            norm_measured=True)
        cov = t.coverage_impact(
            "Security", collection=collection, parsing=parsing,
            normalization=norm,
            measured_fields=set(t.CHANNEL_CANONICAL_FIELDS["Security"]))
        # An onboarding blocker and a rule citing an unsupported field are
        # different problems and are never mixed.
        assert cov["evidence_gaps"] == []
        assert "REQUIRED FIELD NOT SUPPORTED" in cov["content_gaps"]

    def test_unsupported_channel_is_blocked_with_the_reason(self):
        from services import windows_channel_truth as t
        cov = t.coverage_impact(
            "ForwardedEvents",
            collection={"state": t.UNSUPPORTED, "reason": "x",
                        "authorized_collectors": []},
            parsing=t._support_dimension(t.UNSUPPORTED, None, None, None, None),
            normalization=t._support_dimension(t.UNSUPPORTED, None, None,
                                               None, None),
            measured_fields=set())
        assert cov["effective"]["state"] == t.NOT_AVAILABLE
        assert cov["potential"]["rule_count"] == 0
        assert any("not implemented" in (p["blocker"] or "")
                   for p in cov["prerequisites"])

    def test_attack_rows_only_exist_where_content_maps_a_technique(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.RECEIVING, authorized=True,
            norm_measured=True)
        cov = t.coverage_impact(
            "Security", collection=collection, parsing=parsing,
            normalization=norm,
            measured_fields=set(t.CHANNEL_CANONICAL_FIELDS["Security"]))
        assert cov["attack"], "expected at least one mapped technique"
        for row in cov["attack"]:
            assert row["technique_id"]
            assert row["detection_content"]
            assert row["coverage_state"] in (
                t.COVERAGE_EFFECTIVE, t.COVERAGE_POTENTIAL, t.COVERAGE_BLOCKED)
        # A channel with no DSM manufactures no ATT&CK coverage.
        empty = t.coverage_impact(
            "System",
            collection={"state": t.NOT_CONFIGURED, "reason": "x",
                        "authorized_collectors": []},
            parsing=t._support_dimension(t.UNSUPPORTED, None, None, None, None),
            normalization=t._support_dimension(t.UNSUPPORTED, None, None,
                                               None, None),
            measured_fields=set())
        assert empty["attack"] == []

    def test_citation_chain_is_published_with_every_claim(self):
        from services import windows_channel_truth as t
        collection, parsing, norm = self._dims(
            t, collection_state=t.RECEIVING, authorized=True,
            norm_measured=True)
        cov = t.coverage_impact("Security", collection=collection,
                                parsing=parsing, normalization=norm,
                                measured_fields=set())
        assert cov["citation"]["chain"][0] == "channel"
        assert cov["citation"]["chain"][-1] == "supporting evidence"
