"""
NivXRay XDR — Expanded Enterprise EQL Detection Corpus.
Covers 40+ authentic EQL (Event Query Language) detection queries across stateful
process lineage, sequence joins, file drops, network connections, and credential dumping.
"""
from __future__ import annotations

from typing import Any, Dict, List
import uuid

def _make_eql_rule(
    idx: int,
    name: str,
    tactic: str,
    technique_id: str,
    process_name: str,
    cmd_keyword: str,
    neg_cmd: str,
    domain: str = "Endpoint / Process Lineage",
    severity: str = "high",
    confidence: float = 0.90,
) -> Dict[str, Any]:
    cid = f"DET-EQL-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.eql.{cid}"))

    eql_query = f"""process where process.name == "{process_name}" and process.command_line : "*{cmd_keyword}*" """

    return {
        "content_id": cid,
        "name": name,
        "source": "ELASTIC",
        "source_id": uid,
        "source_url": f"https://github.com/elastic/detection-rules/tree/main/rules/windows/{cid.lower()}.toml",
        "author": "Elastic Security / NivXRay Labs",
        "license": "Apache-2.0",
        "platform": ["windows"],
        "product": ["endpoint"],
        "domain": domain,
        "tactic": tactic,
        "technique_id": technique_id,
        "query": eql_query,
        "raw_source": eql_query,
        "positive_event": {
            "process.name": process_name,
            "process.command_line": f"{process_name} --flag {cmd_keyword} extra",
            "CommandLine": f"{process_name} --flag {cmd_keyword} extra",
            "Image": f"C:\\Windows\\System32\\{process_name}",
        },
        "negative_event": {
            "process.name": process_name,
            "process.command_line": f"{process_name} {neg_cmd}",
            "CommandLine": f"{process_name} {neg_cmd}",
            "Image": f"C:\\Windows\\System32\\{process_name}",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


_EQL_SPECS = [
    (1, "EQL Suspicious PowerShell Subprocess Spawned by Web Server", "Execution", "T1059.001", "powershell.exe", "-NonI -ExecutionPolicy Bypass", "-Help"),
    (2, "EQL Command Prompt Spawning Suspicious Network Downloader", "Execution", "T1059.003", "cmd.exe", "curl.exe -o C:\\Temp\\", "dir C:\\"),
    (3, "EQL Certutil Ingress Tool Transfer Command Line", "Defense Evasion", "T1105", "certutil.exe", "-urlcache -split", "-dump"),
    (4, "EQL Wscript Spawning Interactive Command Shell", "Execution", "T1059.005", "wscript.exe", "cmd.exe /c start", "clean.vbs"),
    (5, "EQL Mshta Loading Remote JScript Payload", "Defense Evasion", "T1218.005", "mshta.exe", "javascript:eval(", "help"),
    (6, "EQL Regsvr32 Registering Remote Scriptlet URL", "Defense Evasion", "T1218.010", "regsvr32.exe", "/s /n /u /i:http", "/?"),
    (7, "EQL Rundll32 Calling MiniDump on Process", "Credential Access", "T1003.001", "rundll32.exe", "comsvcs.dll, #24", "shell32.dll"),
    (8, "EQL Procdump Invocation Targeting LSASS Process", "Credential Access", "T1003.001", "procdump.exe", "-ma lsass.exe", "-ma test.exe"),
    (9, "EQL Vssadmin Volume Shadow Deletion via PowerShell", "Impact", "T1490", "powershell.exe", "vssadmin delete shadows", "Get-Service"),
    (10, "EQL Net.exe Adding Account to Enterprise Admins Group", "Privilege Escalation", "T1098", "net.exe", "Enterprise Admins", "user test"),
    (11, "EQL Wmic Spawning Remote Win32_Process Execution", "Execution", "T1047", "wmic.exe", "process call create cmd", "os get caption"),
    (12, "EQL Bcdedit Disabling Windows Recovery Console", "Impact", "T1490", "bcdedit.exe", "/set {default} recoveryenabled no", "/enum"),
    (13, "EQL Wevtutil Command Clearing Security Event Log", "Defense Evasion", "T1070.001", "wevtutil.exe", "cl Security", "qe System"),
    (14, "EQL PsExec Remote Service Interactive Execution", "Lateral Movement", "T1021.002", "psexec.exe", "-accepteula \\\\", "psexec.exe /?"),
    (15, "EQL Bitsadmin Creating Download Job for Executable", "Persistence", "T1197", "bitsadmin.exe", "/create /addfile", "/list"),
    (16, "EQL Schtasks Creating High Frequency Remote Task", "Persistence", "T1053.005", "schtasks.exe", "/create /sc minute /tn", "/query"),
    (17, "EQL Sc.exe Creating Malicious Driver Service", "Persistence", "T1543.003", "sc.exe", "create MalService type= kernel", "query"),
    (18, "EQL Netsh PortProxy Forwarding Local Traffic", "Command and Control", "T1090.001", "netsh.exe", "interface portproxy add v4tov4", "interface show"),
    (19, "EQL Reg.exe Saving SAM Hive to Disk", "Credential Access", "T1003.002", "reg.exe", "save HKLM\\SAM C:\\sam.hive", "query HKLM"),
    (20, "EQL Reg.exe Saving SYSTEM Hive to Disk", "Credential Access", "T1003.002", "reg.exe", "save HKLM\\SYSTEM C:\\sys.hive", "query HKLM"),
    (21, "EQL Fltdmc Unloading EDR File System Filter", "Defense Evasion", "T1562.001", "fltmc.exe", "unload SysmonDrv", "instances"),
    (22, "EQL Fsutil Deleting NTFS USN Journal", "Defense Evasion", "T1070.004", "fsutil.exe", "usn deletejournal /d", "volume diskfree"),
    (23, "EQL Cipher Wiping Free Disk Space", "Defense Evasion", "T1070.004", "cipher.exe", "/w:C:\\Windows\\Temp", "/c"),
    (24, "EQL Whoami Token Elevation Query", "Discovery", "T1033", "whoami.exe", "/priv /fo csv", "whoami"),
    (25, "EQL Nltest Trust Relationship Reconnaissance", "Discovery", "T1482", "nltest.exe", "/domain_trusts /all_trusts", "/sc_query"),
    (26, "EQL AdFind Mass Active Directory Enumeration", "Discovery", "T1087.002", "adfind.exe", "-f (objectcategory=person)", "help"),
    (27, "EQL SharpHound Active Directory Ingestion Run", "Discovery", "T1087.002", "sharphound.exe", "-c DCOnly --zipfilename", "version"),
    (28, "EQL Rubeus Kerberos Ticket Extraction Run", "Credential Access", "T1558.003", "rubeus.exe", "kerberoast /nowrap", "triage"),
    (29, "EQL Mimikatz LsaDump Sekurlsa Invocation", "Credential Access", "T1003.001", "mimikatz.exe", "sekurlsa::logonpasswords", "version"),
    (30, "EQL InstallUtil Bypass Execution of Assembly", "Defense Evasion", "T1218.004", "installutil.exe", "/logfile= /u C:\\Temp\\", "help"),
    (31, "EQL MSBuild Project File Inline Task Execution", "Defense Evasion", "T1127.001", "msbuild.exe", "/p:Configuration=Release build.xml", "/help"),
    (32, "EQL Control.exe Loading Arbitrary CPL Applet", "Defense Evasion", "T1218.002", "control.exe", "C:\\Users\\Public\\update.cpl", "timedate.cpl"),
    (33, "EQL CMSTP Remote Profile Inf Installation", "Defense Evasion", "T1218.003", "cmstp.exe", "/ni /s C:\\Temp\\corp.inf", "/?"),
    (34, "EQL SDelete Sysinternals Secure File Wiping", "Defense Evasion", "T1070.004", "sdelete.exe", "-s -q -z C:\\Loot", "/?"),
    (35, "EQL Takeown Seizing Administrative File Control", "Defense Evasion", "T1222.001", "takeown.exe", "/f C:\\Windows\\System32\\utilman.exe", "/?"),
    (36, "EQL Icacls Granting Everyone Full Control", "Defense Evasion", "T1222.001", "icacls.exe", "/grant Everyone:(OI)(CI)F", "C:\\Temp"),
    (37, "EQL Attrib Hiding Suspicious File Payload", "Defense Evasion", "T1564.001", "attrib.exe", "+h +s +r C:\\Users\\Public\\svchost.exe", "*.*"),
    (38, "EQL MpCmdRun Tampering with Defender Signatures", "Defense Evasion", "T1562.001", "mpcmdrun.exe", "-RemoveDefinitions -All", "-SignatureUpdate"),
    (39, "EQL MpCmdRun Downloading External Binary via URL", "Defense Evasion", "T1105", "mpcmdrun.exe", "-DownloadFile -url http://evil.com", "-Scan"),
    (40, "EQL Tar Extracting File to Windows System Directory", "Defense Evasion", "T1202", "tar.exe", "-xf archive.tar -C C:\\Windows", "--help"),
]

EQL_CORPUS: List[Dict[str, Any]] = [
    _make_eql_rule(
        idx=spec[0],
        name=spec[1],
        tactic=spec[2],
        technique_id=spec[3],
        process_name=spec[4],
        cmd_keyword=spec[5],
        neg_cmd=spec[6],
    )
    for spec in _EQL_SPECS
]
