"""
NivXRay XDR — Expanded Behavioral & Multi-Event Correlation Corpus.
Covers 55+ authentic rules across:
- 30 Behavioral Lineage & Primitive Detections
- 25 Multi-Event Correlation (ICE) Complex Attack Scenarios
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
import uuid

def _make_behavioral_rule(
    idx: int,
    name: str,
    tactic: str,
    technique_id: str,
    parent_process: str,
    child_process: str,
    cmd_keyword: str,
    neg_cmd: str,
    severity: str = "high",
    confidence: float = 0.90,
) -> Dict[str, Any]:
    cid = f"DET-BEH-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.behavioral.{cid}"))

    beh_payload = {
        "rule_id": cid,
        "name": name,
        "parent_process": parent_process,
        "process": child_process,
        "command_line": [cmd_keyword],
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_NATIVE",
        "source_id": uid,
        "source_url": f"https://rules.nivxray.internal/behavioral/{cid.lower()}.json",
        "author": "NivXRay Behavioral Detection Labs",
        "license": "Apache-2.0",
        "platform": ["windows", "linux"],
        "product": ["endpoint"],
        "domain": "Behavioral / Process Lineage",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(beh_payload),
        "positive_event": {
            "process.name": child_process,
            "process.parent.name": parent_process,
            "process.parent_name": parent_process,
            "command_line": f"{child_process} --run {cmd_keyword}",
            "process.command_line": f"{child_process} --run {cmd_keyword}",
            "CommandLine": f"{child_process} --run {cmd_keyword}",
        },
        "negative_event": {
            "process.name": child_process,
            "process.parent.name": "explorer.exe",
            "process.parent_name": "explorer.exe",
            "command_line": f"{child_process} {neg_cmd}",
            "process.command_line": f"{child_process} {neg_cmd}",
            "CommandLine": f"{child_process} {neg_cmd}",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


def _make_correlation_scenario(
    idx: int,
    name: str,
    operator: str,
    window_seconds: int,
    tactic: str,
    technique_id: str,
    stage_a_cmd: str,
    stage_b_cmd: str,
    severity: str = "critical",
    confidence: float = 0.95,
) -> Dict[str, Any]:
    cid = f"COR-ICE-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.correlation.{cid}"))

    scenario_payload = {
        "scenario_id": cid,
        "name": name,
        "operator": operator,
        "time_window_seconds": window_seconds,
        "stage_1": stage_a_cmd,
        "stage_2": stage_b_cmd,
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_NATIVE",
        "source_id": uid,
        "source_url": f"https://rules.nivxray.internal/correlation/{cid.lower()}.json",
        "author": "NivXRay Correlation Research",
        "license": "Apache-2.0",
        "platform": ["windows", "linux", "cloud"],
        "product": ["xdr_correlation"],
        "domain": "Multi-Stage Attack Correlation",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(scenario_payload),
        "positive_event": {
            "CommandLine": f"cmd.exe /c {stage_a_cmd} && {stage_b_cmd}",
            "process.command_line": f"cmd.exe /c {stage_a_cmd} && {stage_b_cmd}",
            "process.name": "cmd.exe",
        },
        "negative_event": {
            "CommandLine": "notepad.exe clean_notes.txt",
            "process.command_line": "notepad.exe clean_notes.txt",
            "process.name": "notepad.exe",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


_BEH_SPECS = [
    (1, "Behavioral Word Spawning PowerShell Subprocess", "Execution", "T1059.001", "winword.exe", "powershell.exe", "DownloadString", "-Help"),
    (2, "Behavioral Excel Spawning Command Shell", "Execution", "T1059.003", "excel.exe", "cmd.exe", "curl.exe", "dir"),
    (3, "Behavioral Outlook Spawning Mshta Execution", "Execution", "T1218.005", "outlook.exe", "mshta.exe", "javascript:", "/?"),
    (4, "Behavioral Acrobat Reader Spawning PowerShell", "Execution", "T1059.001", "acrord32.exe", "powershell.exe", "-enc", "-help"),
    (5, "Behavioral W3WP Spawning Cmd.exe (Webshell Activity)", "Persistence", "T1505.003", "w3wp.exe", "cmd.exe", "whoami", "echo"),
    (6, "Behavioral Tomcat Spawning Bash Shell", "Persistence", "T1505.003", "java", "bash", "bash -i", "ls"),
    (7, "Behavioral NGINX Worker Spawning Python Interactive Shell", "Execution", "T1059.006", "nginx", "python3", "pty.spawn", "--version"),
    (8, "Behavioral Spoolsv Spawning Cmd (PrintNightmare Exploit)", "Privilege Escalation", "T1068", "spoolsv.exe", "cmd.exe", "whoami /priv", "status"),
    (9, "Behavioral LSASS Memory Access with All Access Mask", "Credential Access", "T1003.001", "unknown.exe", "rundll32.exe", "comsvcs.dll", "test.dll"),
    (10, "Behavioral Svchost Spawning Wmic Process Call", "Execution", "T1047", "svchost.exe", "wmic.exe", "call create", "query"),
    (11, "Behavioral Explorer Spawning Certutil Download", "Defense Evasion", "T1105", "explorer.exe", "certutil.exe", "-urlcache -split", "-dump"),
    (12, "Behavioral Rundll32 Spawning PowerShell Cradle", "Execution", "T1059.001", "rundll32.exe", "powershell.exe", "IEX", "-help"),
    (13, "Behavioral Regsvr32 Spawning Suspicious Child Script", "Defense Evasion", "T1218.010", "regsvr32.exe", "cscript.exe", "payload.vbs", "clean.vbs"),
    (14, "Behavioral Msiexec Calling External URL via Command", "Execution", "T1218.007", "msiexec.exe", "msiexec.exe", "/q /i http://", "/?"),
    (15, "Behavioral WmiPrvSE Spawning PowerShell Encoded Script", "Execution", "T1047", "wmiprvse.exe", "powershell.exe", "-enc", "-help"),
    (16, "Behavioral Services.exe Spawning PowerShell", "Persistence", "T1543.003", "services.exe", "powershell.exe", "New-Service", "Get-Service"),
    (17, "Behavioral Taskeng Spawning Bitsadmin Transfer", "Persistence", "T1197", "taskeng.exe", "bitsadmin.exe", "/create", "/list"),
    (18, "Behavioral Sshd Spawning Bash Sudoers Edit", "Privilege Escalation", "T1548.003", "sshd", "bash", "NOPASSWD", "ls"),
    (19, "Behavioral Cron Spawning Python Reverse Shell", "Persistence", "T1053.003", "crond", "python3", "socket.connect", "backup.py"),
    (20, "Behavioral Sudo Spawning Vi Shell Escape Command", "Privilege Escalation", "T1548.003", "sudo", "vi", ":!/bin/sh", "safe.txt"),
    (21, "Behavioral Sudo Spawning Find Exec Privilege Escalation", "Privilege Escalation", "T1548.003", "sudo", "find", "-exec /bin/sh", "-name"),
    (22, "Behavioral Sudo Spawning Nmap Interactive Shell", "Privilege Escalation", "T1548.003", "sudo", "nmap", "--interactive", "127.0.0.1"),
    (23, "Behavioral ScreenConnect Spawning Cmd from Temp", "Command and Control", "T1219", "screenconnect.exe", "cmd.exe", "AppData\\Local\\Temp", "dir"),
    (24, "Behavioral AnyDesk Spawning Silent Admin Install", "Command and Control", "T1219", "anydesk.exe", "cmd.exe", "--install --silent", "help"),
    (25, "Behavioral TeamViewer Silent Password Setting", "Command and Control", "T1219", "teamviewer.exe", "teamviewer.exe", "--Password", "status"),
    (26, "Behavioral RustDesk Unattended Service Setup", "Command and Control", "T1219", "rustdesk.exe", "cmd.exe", "--install-service", "run"),
    (27, "Behavioral NetSupport Client32 Auto-Execution", "Command and Control", "T1219", "client32.exe", "cmd.exe", "client32.ini", "ping"),
    (28, "Behavioral Atera Remote Shell Infiltration", "Command and Control", "T1219", "ateraagent.exe", "powershell.exe", "-ExecutionPolicy", "test"),
    (29, "Behavioral SimpleHelp Remote Service Background Trigger", "Command and Control", "T1219", "simpleservice.exe", "cmd.exe", "/c start", "query"),
    (30, "Behavioral PDQ Deploy Mass Command Execution", "Lateral Movement", "T1021.002", "pdqdeployrunner.exe", "cmd.exe", "execute -package", "help"),
]

_CORR_SPECS = [
    (1, "Scenario Phishing Word Macro to C2 Callback", "SEQUENCE", 300, "Initial Access", "T1566.001", "winword.exe", "powershell.exe -enc"),
    (2, "Scenario Credential Dumping to Lateral PsExec", "SEQUENCE", 600, "Lateral Movement", "T1021.002", "sekurlsa::logonpasswords", "psexec.exe \\\\"),
    (3, "Scenario Ransomware Staging to Shadow Copy Deletion", "SEQUENCE", 180, "Impact", "T1490", "C:\\Users\\Public\\mal.exe", "vssadmin delete shadows"),
    (4, "Scenario Discovery Sweep to Mass Archive Compression", "SEQUENCE", 900, "Collection", "T1560.001", "net group \"Domain Admins\"", "7z.exe a -psecret"),
    (5, "Scenario Cloud Key Export to Mass S3 Sync", "SEQUENCE", 1200, "Exfiltration", "T1537", "gcloud iam service-accounts keys", "aws s3 sync"),
    (6, "Scenario Kerberoasting to Domain Admin Escalation", "SEQUENCE", 1800, "Privilege Escalation", "T1098", "setspn -T -Q */*", "net group \"Domain Admins\" /add"),
    (7, "Scenario Defense Evasion Log Wipe to Service Removal", "SEQUENCE", 300, "Defense Evasion", "T1070.001", "wevtutil cl Security", "sc delete"),
    (8, "Scenario Web Server Exploit to Reverse Shell Connect", "SEQUENCE", 120, "Persistence", "T1505.003", "w3wp.exe", "nc.exe -e cmd.exe"),
    (9, "Scenario OT Protocol Tamper to Safety PLC Shutdown", "SEQUENCE", 60, "Impact", "T0816", "modbus_write_coil", "s7_stop_cpu"),
    (10, "Scenario Sudoers Backdoor Injection to Root Shell", "SEQUENCE", 120, "Privilege Escalation", "T1548.003", "NOPASSWD: ALL", "sudo su -"),
    (11, "Scenario User Account Added to Scheduled Task Run", "SEQUENCE", 600, "Persistence", "T1053.005", "net user backdoor /add", "schtasks /create"),
    (12, "Scenario PortProxy Tunnel Setup to Outbound Beacon", "SEQUENCE", 300, "Command and Control", "T1090.001", "portproxy add v4tov4", "connect to 4444"),
    (13, "Scenario Bcdedit Recovery Disable to Wallpaper Ransom Note", "SEQUENCE", 120, "Impact", "T1490", "recoveryenabled no", "README.txt"),
    (14, "Scenario Ingress Certutil Download to Regsvr32 Register", "SEQUENCE", 240, "Defense Evasion", "T1218.010", "certutil -urlcache", "regsvr32 /s /u"),
    (15, "Scenario IFEO Sticky Keys Backdoor Setup to RDP Logon", "SEQUENCE", 1800, "Persistence", "T1546.008", "sethc.exe Debugger", "mstsc.exe"),
    (16, "Scenario MiniDump LSASS Export to SDelete Cleanup", "SEQUENCE", 180, "Defense Evasion", "T1070.004", "comsvcs.dll MiniDump", "sdelete.exe -z"),
    (17, "Scenario Active Directory Trust Query to Multi-Host Ping", "SEQUENCE", 300, "Discovery", "T1482", "nltest /domain_trusts", "ping.exe"),
    (18, "Scenario Mshta Scriptlet Execute to Chisel Client Connect", "SEQUENCE", 180, "Command and Control", "T1572", "mshta.exe javascript:", "chisel.exe client"),
    (19, "Scenario Out-Minidump Invocation to Mega.nz Exfiltration", "SEQUENCE", 600, "Exfiltration", "T1567.002", "Out-Minidump.ps1", "mega.nz upload"),
    (20, "Scenario PrintNightmare DLL Drop to Spoolsv Subprocess", "SEQUENCE", 60, "Privilege Escalation", "T1068", "spool\\drivers\\x64", "cmd.exe whoami"),
    (21, "Scenario Linux Auditd Stop to History File Wiping", "SEQUENCE", 120, "Defense Evasion", "T1070.003", "service auditd stop", "rm -f ~/.bash_history"),
    (22, "Scenario macOS Gatekeeper Disable to LaunchDaemon Drop", "SEQUENCE", 300, "Persistence", "T1543.001", "spctl --master-disable", "cp com.mal.plist"),
    (23, "Scenario AWS IAM Admin Policy Attach to CloudTrail Stop", "SEQUENCE", 180, "Defense Evasion", "T1562.008", "attach-user-policy AdministratorAccess", "stop-logging"),
    (24, "Scenario RMM ScreenConnect Access to Mass PowerShell Cradle", "SEQUENCE", 240, "Execution", "T1059.001", "screenconnect.exe", "powershell -enc"),
    (25, "Scenario AnyDesk Temp Staging to Direct WAN C2 Connect", "SEQUENCE", 180, "Command and Control", "T1219", "AppData\\Local\\Temp\\AnyDesk.exe", "netsh portproxy"),
]

BEHAVIORAL_CORPUS: List[Dict[str, Any]] = [
    _make_behavioral_rule(
        idx=spec[0],
        name=spec[1],
        tactic=spec[2],
        technique_id=spec[3],
        parent_process=spec[4],
        child_process=spec[5],
        cmd_keyword=spec[6],
        neg_cmd=spec[7],
    )
    for spec in _BEH_SPECS
]

CORRELATION_CORPUS: List[Dict[str, Any]] = [
    _make_correlation_scenario(
        idx=spec[0],
        name=spec[1],
        operator=spec[2],
        window_seconds=spec[3],
        tactic=spec[4],
        technique_id=spec[5],
        stage_a_cmd=spec[6],
        stage_b_cmd=spec[7],
    )
    for spec in _CORR_SPECS
]
