"""Phase 0 · captured-shape Windows Event Log fixtures.

Realistic `wevtutil … /f:RenderedXml` output, sanitised. Every fixture
enters the pipeline through the SAME envelope the real Windows connector
emits, so a test can never pass against a shape production never sees.
"""
from __future__ import annotations

import json
from typing import Any, Dict

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_CHANNEL = "Security"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

HOST = "NIVX-WIN-01"
EXPLORER_GUID = "{a1b2c3d4-0000-0001-0000-000000000001}"
CHROME_GUID = "{a1b2c3d4-0000-0002-0000-000000000002}"
PS_GUID = "{a1b2c3d4-0000-0003-0000-000000000003}"


def _event(provider: str, channel: str, event_id: int, record_id: int,
           time_created: str, data: Dict[str, Any]) -> str:
    rows = "".join(
        f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (
        f'<Event xmlns="{NS}"><System>'
        f'<Provider Name="{provider}" Guid="{{00000000-0000-0000-0000-000000000000}}"/>'
        f'<EventID>{event_id}</EventID><Version>5</Version><Level>4</Level>'
        f'<Task>1</Task><Opcode>0</Opcode>'
        f'<TimeCreated SystemTime="{time_created}"/>'
        f'<EventRecordID>{record_id}</EventRecordID>'
        f'<Execution ProcessID="2048" ThreadID="3072"/>'
        f'<Channel>{channel}</Channel><Computer>{HOST}</Computer>'
        f'<Security UserID="S-1-5-18"/>'
        f'</System><EventData>{rows}</EventData></Event>')


def envelope(xml: str, *, channel: str, provider: str, event_id: int,
             record_id: int, observed_at: str = "2026-06-01T10:05:00+00:00"
             ) -> str:
    """The EXACT line the Windows connector writes to its journal."""
    return json.dumps({
        "observed_at": observed_at,
        "kind": "WINDOWS_EVENT_LOG",
        "winlog": {
            "channel": channel, "record_id": record_id,
            "event_id": str(event_id), "time_created": "2026-06-01T10:04:00Z",
            "computer": HOST, "provider": provider, "xml": xml,
        },
    }, separators=(",", ":"))


def sysmon(event_id: int, record_id: int, data: Dict[str, Any],
           time_created: str = "2026-06-01T10:04:00.1234567Z") -> str:
    return envelope(
        _event(SYSMON_PROVIDER, SYSMON_CHANNEL, event_id, record_id,
               time_created, data),
        channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER,
        event_id=event_id, record_id=record_id)


def winsec(event_id: int, record_id: int, data: Dict[str, Any],
           time_created: str = "2026-06-01T10:04:00.1234567Z") -> str:
    return envelope(
        _event(SECURITY_PROVIDER, SECURITY_CHANNEL, event_id, record_id,
               time_created, data),
        channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
        event_id=event_id, record_id=record_id)


# ── Sysmon 1 · process create · a real three-generation chain ──────
SYSMON_1_EXPLORER = sysmon(1, 1001, {
    "RuleName": "-", "UtcTime": "2026-06-01 10:01:08.123",
    "ProcessGuid": EXPLORER_GUID, "ProcessId": "4120",
    "Image": r"C:\Windows\explorer.exe",
    "FileVersion": "10.0.22621.1", "Description": "Windows Explorer",
    "Product": "Microsoft Windows Operating System",
    "Company": "Microsoft Corporation", "OriginalFileName": "EXPLORER.EXE",
    "CommandLine": r"C:\Windows\Explorer.EXE",
    "CurrentDirectory": r"C:\Windows\system32\\",
    "User": r"NIVX\analyst", "LogonGuid": "{a1b2c3d4-0000-0000-0000-00000000aaaa}",
    "LogonId": "0x3e7f1", "TerminalSessionId": "1",
    "IntegrityLevel": "Medium",
    "Hashes": ("SHA256=9f2c1b0f6f4e8d3a2b1c0d9e8f7a6b5c4d3e2f10"
               "11223344556677889900aabb,MD5=0123456789abcdef"
               "0123456789abcdef"),
    "ParentProcessGuid": "{a1b2c3d4-0000-0000-0000-000000000001}",
    "ParentProcessId": "1080",
    "ParentImage": r"C:\Windows\System32\userinit.exe",
    "ParentCommandLine": r"userinit.exe", "ParentUser": r"NIVX\analyst",
})

SYSMON_1_CHROME = sysmon(1, 1002, {
    "RuleName": "-", "UtcTime": "2026-06-01 10:02:14.001",
    "ProcessGuid": CHROME_GUID, "ProcessId": "7310",
    "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "CommandLine": r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
    "CurrentDirectory": r"C:\Users\analyst\\",
    "User": r"NIVX\analyst", "LogonId": "0x3e7f1",
    "TerminalSessionId": "1", "IntegrityLevel": "Medium",
    "ParentProcessGuid": EXPLORER_GUID, "ParentProcessId": "4120",
    "ParentImage": r"C:\Windows\explorer.exe",
    "ParentCommandLine": r"C:\Windows\Explorer.EXE",
})

SYSMON_1_POWERSHELL = sysmon(1, 1003, {
    "RuleName": "-", "UtcTime": "2026-06-01 10:04:33.777",
    "ProcessGuid": PS_GUID, "ProcessId": "9120",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "OriginalFileName": "PowerShell.EXE",
    "CommandLine": r"powershell.exe -NoProfile -Command Get-Process",
    "CurrentDirectory": r"C:\Users\analyst\\",
    "User": r"NIVX\analyst", "LogonId": "0x3e7f1",
    "TerminalSessionId": "1", "IntegrityLevel": "High",
    "Hashes": "SHA256=aabbccddeeff00112233445566778899aabbccddeeff0011",
    "ParentProcessGuid": CHROME_GUID, "ParentProcessId": "7310",
    "ParentImage": (r"C:\Program Files\Google\Chrome\Application"
                    r"\chrome.exe"),
    "ParentCommandLine": r'"chrome.exe"',
})

#: Optional fields absent — the honest-gap case.
SYSMON_1_SPARSE = sysmon(1, 1004, {
    "UtcTime": "2026-06-01 10:06:00.000",
    "ProcessGuid": "{a1b2c3d4-0000-0009-0000-000000000009}",
    "ProcessId": "5150", "Image": r"C:\Windows\System32\whoami.exe",
})

# ── Sysmon 3 · network connection ─────────────────────────────────
SYSMON_3 = sysmon(3, 3001, {
    "RuleName": "-", "UtcTime": "2026-06-01 10:02:15.500",
    "ProcessGuid": CHROME_GUID, "ProcessId": "7310",
    "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "User": r"NIVX\analyst", "Protocol": "tcp", "Initiated": "true",
    "SourceIsIpv6": "false", "SourceIp": "10.20.30.40",
    "SourceHostname": HOST, "SourcePort": "52144",
    "DestinationIsIpv6": "false", "DestinationIp": "93.184.216.34",
    "DestinationHostname": "example.com", "DestinationPort": "443",
    "DestinationPortName": "https",
})

# ── Sysmon 11 · file create ───────────────────────────────────────
SYSMON_11 = sysmon(11, 11001, {
    "RuleName": "-", "UtcTime": "2026-06-01 10:04:34.100",
    "ProcessGuid": PS_GUID, "ProcessId": "9120",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "TargetFilename": r"C:\Users\analyst\AppData\Local\Temp\example.ps1",
    "CreationUtcTime": "2026-06-01 10:04:34.090",
    "User": r"NIVX\analyst",
})

# ── Sysmon 12 · registry key create ───────────────────────────────
SYSMON_12 = sysmon(12, 12001, {
    "RuleName": "-", "EventType": "CreateKey",
    "UtcTime": "2026-06-01 10:04:35.010",
    "ProcessGuid": PS_GUID, "ProcessId": "9120",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "TargetObject": (r"HKU\S-1-5-21-1\Software\Microsoft\Windows"
                     r"\CurrentVersion\Run"),
    "User": r"NIVX\analyst",
})

# ── Sysmon 13 · registry value set ────────────────────────────────
SYSMON_13 = sysmon(13, 13001, {
    "RuleName": "-", "EventType": "SetValue",
    "UtcTime": "2026-06-01 10:04:35.220",
    "ProcessGuid": PS_GUID, "ProcessId": "9120",
    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "TargetObject": (r"HKU\S-1-5-21-1\Software\Microsoft\Windows"
                     r"\CurrentVersion\Run\Updater"),
    "Details": r"C:\Users\analyst\AppData\Local\Temp\example.ps1",
    "User": r"NIVX\analyst",
})

# ── Sysmon 22 · DNS query ─────────────────────────────────────────
SYSMON_22 = sysmon(22, 22001, {
    "RuleName": "-", "UtcTime": "2026-06-01 10:02:15.400",
    "ProcessGuid": CHROME_GUID, "ProcessId": "7310",
    "QueryName": "example.com", "QueryStatus": "0",
    "QueryResults": "type:  5 www.example.com;::ffff:93.184.216.34;",
    "Image": r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "User": r"NIVX\analyst",
})

# ── Security 4688 · process create, no ProcessGuid ────────────────
WINSEC_4688 = winsec(4688, 46881, {
    "SubjectUserSid": "S-1-5-21-1-1001", "SubjectUserName": "analyst",
    "SubjectDomainName": "NIVX", "SubjectLogonId": "0x3e7f1",
    "NewProcessId": "0x23a0",
    "NewProcessName": r"C:\Windows\System32\ipconfig.exe",
    "TokenElevationType": "%%1938", "ProcessId": "0x1018",
    "CommandLine": r"ipconfig /all",
    "ProcessCommandLine": r"ipconfig /all",
    "TargetUserSid": "S-1-0-0", "MandatoryLabel": "S-1-16-8192",
    "CreatorProcessId": "0x1018",
    "CreatorProcessName": r"C:\Windows\System32\cmd.exe",
})

# ── Security 4624 · successful interactive logon ──────────────────
WINSEC_4624 = winsec(4624, 46241, {
    "SubjectUserSid": "S-1-0-0", "SubjectUserName": "-",
    "SubjectDomainName": "-", "SubjectLogonId": "0x0",
    "TargetUserSid": "S-1-5-21-1-1001", "TargetUserName": "analyst",
    "TargetDomainName": "NIVX", "TargetLogonId": "0x3e7f1",
    "LogonType": "2", "LogonProcessName": "User32",
    "AuthenticationPackageName": "Negotiate", "WorkstationName": HOST,
    "LogonGuid": "{a1b2c3d4-0000-0000-0000-00000000aaaa}",
    "ProcessId": "0x2f4", "ProcessName": r"C:\Windows\System32\winlogon.exe",
    "IpAddress": "10.20.30.40", "IpPort": "0",
    "ElevatedToken": "%%1843",
})

# ── negative fixtures ─────────────────────────────────────────────
UNSUPPORTED_EVENT_ID = sysmon(10, 10001, {
    "UtcTime": "2026-06-01 10:07:00.000",
    "SourceProcessGUID": PS_GUID, "TargetImage": r"C:\Windows\lsass.exe",
})

UNSUPPORTED_PROVIDER = envelope(
    _event("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell"
           "/Operational", 4104, 41041, "2026-06-01T10:08:00Z",
           {"ScriptBlockText": "Get-Process"}),
    channel="Microsoft-Windows-PowerShell/Operational",
    provider="Microsoft-Windows-PowerShell", event_id=4104, record_id=41041)

MALFORMED_XML = json.dumps({
    "observed_at": "2026-06-01T10:09:00+00:00",
    "kind": "WINDOWS_EVENT_LOG",
    "winlog": {"channel": SYSMON_CHANNEL, "record_id": 99001,
               "event_id": "1", "provider": SYSMON_PROVIDER,
               "computer": HOST,
               "xml": "<Event><System><EventID>1</EventID></Sy"},
}, separators=(",", ":"))

NO_XML = json.dumps({
    "observed_at": "2026-06-01T10:10:00+00:00",
    "kind": "WINDOWS_EVENT_LOG",
    "winlog": {"channel": SYSMON_CHANNEL, "record_id": 99002,
               "event_id": "1", "provider": SYSMON_PROVIDER},
}, separators=(",", ":"))

NO_EVENT_DATA = envelope(
    f'<Event xmlns="{NS}"><System>'
    f'<Provider Name="{SYSMON_PROVIDER}"/><EventID>1</EventID>'
    f'<TimeCreated SystemTime="2026-06-01T10:11:00Z"/>'
    f'<EventRecordID>99003</EventRecordID><Channel>{SYSMON_CHANNEL}</Channel>'
    f'<Computer>{HOST}</Computer></System></Event>',
    channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER, event_id=1,
    record_id=99003)

NO_EVENT_ID = json.dumps({
    "observed_at": "2026-06-01T10:12:00+00:00",
    "kind": "WINDOWS_EVENT_LOG",
    "winlog": {
        "channel": SYSMON_CHANNEL, "record_id": 99004, "event_id": None,
        "provider": SYSMON_PROVIDER, "computer": HOST,
        "xml": (f'<Event xmlns="{NS}"><System>'
                f'<Provider Name="{SYSMON_PROVIDER}"/>'
                f'<TimeCreated SystemTime="2026-06-01T10:12:00Z"/>'
                f'<EventRecordID>99004</EventRecordID>'
                f'<Channel>{SYSMON_CHANNEL}</Channel>'
                f'<Computer>{HOST}</Computer></System>'
                f'<EventData><Data Name="ProcessId">1</Data>'
                f'</EventData></Event>'),
    },
}, separators=(",", ":"))

#: Sysmon 1 with the ProcessGuid removed — the degraded-identity case.
SYSMON_1_NO_GUID = sysmon(1, 1005, {
    "UtcTime": "2026-06-01 10:13:00.000", "ProcessId": "6001",
    "Image": r"C:\Windows\System32\cmd.exe",
    "CommandLine": r"cmd.exe /c echo hi",
    "ParentProcessId": "4120", "ParentImage": r"C:\Windows\explorer.exe",
    "User": r"NIVX\analyst",
})

#: Invalid timestamp in the source. Must not be silently replaced.
SYSMON_1_BAD_TIME = sysmon(1, 1006, {
    "UtcTime": "not-a-timestamp", "ProcessGuid":
        "{a1b2c3d4-0000-000a-0000-00000000000a}",
    "ProcessId": "6002", "Image": r"C:\Windows\System32\tasklist.exe",
}, time_created="also-not-a-timestamp")

ALL_SUPPORTED = {
    "sysmon_1": SYSMON_1_POWERSHELL,
    "sysmon_3": SYSMON_3,
    "sysmon_11": SYSMON_11,
    "sysmon_12": SYSMON_12,
    "sysmon_13": SYSMON_13,
    "sysmon_22": SYSMON_22,
    "winsec_4688": WINSEC_4688,
    "winsec_4624": WINSEC_4624,
}
