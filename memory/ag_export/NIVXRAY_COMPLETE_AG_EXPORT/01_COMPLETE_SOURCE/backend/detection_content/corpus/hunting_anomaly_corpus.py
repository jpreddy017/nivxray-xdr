"""
NivXRay XDR — Expanded Threat Hunting & Baseline Anomaly Corpus.
Covers 55+ authentic rules across:
- 30 Proactive Threat Hunting Hypotheses & Queries
- 25 Deterministic Baseline Anomaly & Statistical Threshold Definitions
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
import uuid

def _make_hunting_query(
    idx: int,
    name: str,
    hypothesis: str,
    tactic: str,
    technique_id: str,
    pivot_field: str,
    target_value: str,
    neg_value: str,
    severity: str = "medium",
    confidence: float = 0.85,
) -> Dict[str, Any]:
    cid = f"HNT-QUR-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.hunting.{cid}"))

    payload = {
        "hunt_id": cid,
        "name": name,
        "hypothesis": hypothesis,
        "pivot_field": pivot_field,
        "search_pattern": target_value,
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_HUNTING",
        "source_id": uid,
        "source_url": f"https://hunting.nivxray.internal/hunts/{cid.lower()}.json",
        "author": "NivXRay Threat Hunting Team",
        "license": "Apache-2.0",
        "platform": ["windows", "linux", "cloud"],
        "product": ["hunt_analytics"],
        "domain": "Proactive Threat Hunting",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(payload),
        "positive_event": {
            pivot_field: f"C:\\Windows\\System32\\{target_value}",
            "CommandLine": f"{target_value} --audit",
            "process.command_line": f"{target_value} --audit",
            "process.name": target_value if ".exe" in target_value else "cmd.exe",
        },
        "negative_event": {
            pivot_field: f"C:\\Windows\\System32\\{neg_value}",
            "CommandLine": f"{neg_value} --clean",
            "process.command_line": f"{neg_value} --clean",
            "process.name": neg_value if ".exe" in neg_value else "cmd.exe",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


def _make_anomaly_rule(
    idx: int,
    name: str,
    aggregation_type: str,
    threshold: int,
    window_seconds: int,
    tactic: str,
    technique_id: str,
    entity_key: str,
    severity: str = "high",
    confidence: float = 0.88,
) -> Dict[str, Any]:
    cid = f"ANM-DEF-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.anomaly.{cid}"))

    payload = {
        "anomaly_id": cid,
        "name": name,
        "aggregation_type": aggregation_type,
        "threshold": threshold,
        "window_seconds": window_seconds,
        "group_by": entity_key,
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_UEBA",
        "source_id": uid,
        "source_url": f"https://ueba.nivxray.internal/baselines/{cid.lower()}.json",
        "author": "NivXRay Analytics Research",
        "license": "Apache-2.0",
        "platform": ["windows", "network", "identity"],
        "product": ["ueba_engine"],
        "domain": "Baseline / Behavioral Anomaly",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(payload),
        "positive_event": {
            entity_key: "CORP\\compromised_admin",
            "event_count": threshold + 10,
            "CommandLine": f"trigger {name.lower()}",
            "process.command_line": f"trigger {name.lower()}",
            "process.name": "anomaly_trigger.exe",
        },
        "negative_event": {
            entity_key: "CORP\\normal_user",
            "event_count": 1,
            "CommandLine": "notepad.exe",
            "process.command_line": "notepad.exe",
            "process.name": "notepad.exe",
        },
        "confidence": confidence,
        "severity": severity.upper(),
    }


_HUNT_SPECS = [
    (1, "Hunt Rare Executable Launching from Windows Temp Folder", "Adversaries stage loaders in Temp directories", "Execution", "T1059", "CommandLine", "AppData\\Local\\Temp\\update.exe", "calc.exe"),
    (2, "Hunt Unsigned Binary Running with High Privileges", "Exploit payloads run as LocalSystem without code signature", "Privilege Escalation", "T1068", "CommandLine", "C:\\ProgramData\\svc.exe", "svchost.exe"),
    (3, "Hunt PowerShell Interactive Console without Terminal Window", "Automated malware executes powershell with hidden window style", "Execution", "T1059.001", "CommandLine", "powershell.exe -WindowStyle Hidden", "powershell.exe"),
    (4, "Hunt Unusual Child Process of Spoolsv Printing Service", "Print spooler service should not spawn shells or downloaders", "Execution", "T1068", "CommandLine", "spoolsv.exe cmd.exe", "spoolsv.exe"),
    (5, "Hunt Rundll32 Running without Target Function Export", "Rundll32 invoked without export parameters executes malicious DllMain", "Defense Evasion", "T1218.011", "CommandLine", "rundll32.exe C:\\Temp\\payload.dll", "rundll32.exe shell32.dll,Control_RunDLL"),
    (6, "Hunt Regsvr32 Invoked with Suspicious Non-DLL Extension", "Regsvr32 registering .txt or .png files containing scriptlets", "Defense Evasion", "T1218.010", "CommandLine", "regsvr32.exe /s payload.txt", "regsvr32.exe clean.dll"),
    (7, "Hunt Cmd.exe Parent is Winword or Excel", "Macro-based execution spawning direct command interpreter", "Initial Access", "T1566.001", "CommandLine", "winword.exe cmd.exe", "explorer.exe"),
    (8, "Hunt Certutil Ingress Command in Command Line", "Certutil utilized as utility downloader across endpoints", "Command and Control", "T1105", "CommandLine", "certutil -urlcache", "certutil -dump"),
    (9, "Hunt Bitsadmin Download Jobs with HTTP Target", "Bitsadmin persistent download jobs downloading executables", "Persistence", "T1197", "CommandLine", "bitsadmin /addfile http://", "bitsadmin /list"),
    (10, "Hunt Scheduled Tasks Running Script from User Profile", "Adversaries persist via schtasks pointing to AppData scripts", "Persistence", "T1053.005", "CommandLine", "schtasks /create C:\\Users\\", "schtasks /query"),
    (11, "Hunt Active Directory Users with AdminCount Equals 1", "Discovering high-value accounts targeted for delegation abuse", "Discovery", "T1087.002", "CommandLine", "adminCount=1", "normalAccount"),
    (12, "Hunt SPNs Associated with High Privilege Service Accounts", "Kerberoastable accounts with domain administrative group membership", "Credential Access", "T1558.003", "CommandLine", "setspn -q MSSQLSvc", "setspn -L"),
    (13, "Hunt Newly Added Kerberos Pre-Authentication Disabled Accounts", "AS-REP roastable accounts configured without Kerberos pre-auth", "Credential Access", "T1558.004", "CommandLine", "DONT_REQ_PREAUTH", "NORMAL_AUTH"),
    (14, "Hunt Remote Desktop Enabled via Registry Command", "Enabling RDP remotely for interactive lateral movement", "Persistence", "T1021.001", "CommandLine", "fDenyTSConnections 0", "query"),
    (15, "Hunt PsExec Service Artifacts in System32", "PSEXESVC service binary remaining on lateral victim host", "Lateral Movement", "T1021.002", "CommandLine", "PSEXESVC.exe", "svchost.exe"),
    (16, "Hunt WMI Permanent Event Consumer Subscriptions", "WMI event filters and consumers used for persistent execution", "Persistence", "T1546.003", "CommandLine", "root\\subscription CommandLineEventConsumer", "wmic"),
    (17, "Hunt Linux SUID Binaries in /tmp or /var/tmp", "Privilege escalation binaries staged in world-writable paths", "Privilege Escalation", "T1548.001", "CommandLine", "/tmp/suid_bash", "/bin/su"),
    (18, "Hunt Linux Crontab Entries Executing Python or Bash Scripts", "Hidden persistent cron jobs establishing periodic beacons", "Persistence", "T1053.003", "CommandLine", "/etc/cron.d/reverse_beacon", "anacron"),
    (19, "Hunt Linux SSH Authorized Keys Modified in Last 24 Hours", "New public keys added for backdoored interactive access", "Persistence", "T1098.004", "CommandLine", "authorized_keys", "known_hosts"),
    (20, "Hunt macOS LaunchDaemons Created by Unprivileged User", "LaunchDaemons pointing to non-standard application bundles", "Persistence", "T1543.001", "CommandLine", "/Library/LaunchDaemons/mal.plist", "clean.plist"),
    (21, "Hunt AWS CloudTrail Console Login without Multi-Factor Authentication", "Cloud console access vulnerable to credential stuffing", "Initial Access", "T1078.004", "CommandLine", "MFAUsed: false", "MFAUsed: true"),
    (22, "Hunt AWS STS AssumeRole from Foreign IP Addresses", "Compromised IAM credentials assuming roles from residential IP", "Lateral Movement", "T1078.004", "CommandLine", "AssumeRole sts.amazonaws.com", "DescribeInstances"),
    (23, "Hunt Azure AD Service Principal Credentials Added", "Persistence via client secrets added to Enterprise Applications", "Persistence", "T1098.001", "CommandLine", "Add service principal credentials", "Get user"),
    (24, "Hunt M365 Mailbox Delegation Changes to External Domains", "Email forwarding rules forwarding executive correspondence", "Collection", "T1114.003", "CommandLine", "Add-MailboxPermission -AccessRights FullAccess", "Get-Mailbox"),
    (25, "Hunt S3 Bucket Policy Public Open Access Permissions", "Data exposure via permissive S3 bucket policies", "Exfiltration", "T1537", "CommandLine", "s3:GetObject Principal: *", "private"),
    (26, "Hunt DNP3 Industrial Master Sending Force Restart", "Malicious DNP3 commands aimed at disrupting power grid RTUs", "Impact", "T0816", "CommandLine", "DNP3 Function 0x0D Cold Restart", "DNP3 Read"),
    (27, "Hunt Modbus TCP Function Code 0x10 Multiple Registers Override", "Writing false setpoints into water treatment chemical PLC", "Impair Process Control", "T0836", "CommandLine", "Modbus FC16 Write Multiple Registers", "Modbus FC03 Read"),
    (28, "Hunt Siemens S7 CPU Stop Programmatic Commands", "Causing immediate industrial plant shutdown via S7comm", "Impact", "T0816", "CommandLine", "S7comm Stop PLC CPU", "S7comm Read DB"),
    (29, "Hunt DNS Tunneling Long Base32 Encoded Queries", "Slow data exfiltration bypassing perimeter firewall inspection", "Exfiltration", "T1048.003", "CommandLine", ".tunnel.c2.domain.org", "google.com"),
    (30, "Hunt AnyDesk or TeamViewer Launched from User Temp", "Adversary deployment of unmanaged portable RMM tools", "Command and Control", "T1219", "CommandLine", "AppData\\Local\\Temp\\AnyDesk.exe", "AnyDesk.exe"),
]

_ANM_SPECS = [
    (1, "Anomaly Rapid Failed Authentication Surge per User", "COUNT", 15, 60, "Credential Access", "T1110.001", "identity.username"),
    (2, "Anomaly Outbound Data Transfer Volume Spike", "THRESHOLD", 100000000, 300, "Exfiltration", "T1048", "network.src_ip"),
    (3, "Anomaly Unusual Process Creation Count on Endpoint", "COUNT", 50, 60, "Execution", "T1059", "endpoint.hostname"),
    (4, "Anomaly Rapid Remote Service Creation Spurt", "COUNT", 5, 120, "Persistence", "T1543.003", "endpoint.hostname"),
    (5, "Anomaly Off-Hours Administrative Login from Rare Subnet", "THRESHOLD", 1, 3600, "Initial Access", "T1078", "identity.username"),
    (6, "Anomaly Kerberos TGS Request Frequency Spike", "COUNT", 30, 60, "Credential Access", "T1558.003", "identity.username"),
    (7, "Anomaly Rapid File Rename or Encryption Volume (Ransomware)", "COUNT", 100, 30, "Impact", "T1486", "endpoint.hostname"),
    (8, "Anomaly Multiple Account Lockouts within Minutes", "COUNT", 10, 180, "Credential Access", "T1110.001", "endpoint.hostname"),
    (9, "Anomaly DNS Subdomain Query Count for Single Domain", "COUNT", 200, 60, "Command and Control", "T1071.004", "network.src_ip"),
    (10, "Anomaly Unusual Parent-Child Process Relationship Rate", "COUNT", 10, 300, "Execution", "T1059", "endpoint.hostname"),
    (11, "Anomaly Sudo Failure Rate Spike on Production Server", "COUNT", 8, 120, "Privilege Escalation", "T1548.003", "identity.username"),
    (12, "Anomaly Scheduled Task Registration Volume Surge", "COUNT", 5, 180, "Persistence", "T1053.005", "endpoint.hostname"),
    (13, "Anomaly Mass Security Event Log Clearing Operations", "COUNT", 3, 60, "Defense Evasion", "T1070.001", "endpoint.hostname"),
    (14, "Anomaly Rapid Shadow Copy Deletion Requests", "COUNT", 3, 60, "Impact", "T1490", "endpoint.hostname"),
    (15, "Anomaly High Number of Unique Destination Ports from Single IP", "COUNT", 50, 60, "Discovery", "T1046", "network.src_ip"),
    (16, "Anomaly AWS IAM Policy Attach Operations by Single User", "COUNT", 5, 300, "Persistence", "T1098", "identity.principal_id"),
    (17, "Anomaly Azure AD Conditional Access Policy Failure Surge", "COUNT", 10, 120, "Initial Access", "T1078.004", "identity.username"),
    (18, "Anomaly M365 Email Forwarding Rules Created in Fleet", "COUNT", 4, 3600, "Collection", "T1114.003", "cloud.tenant_id"),
    (19, "Anomaly Industrial Modbus Write Request Rate Exceeded", "COUNT", 50, 10, "Impact", "T0855", "network.src_ip"),
    (20, "Anomaly S7comm Session Connect Frequency to PLC", "COUNT", 15, 60, "Impact", "T0816", "network.src_ip"),
    (21, "Anomaly Unenrolled RMM Tool Executions in Single Tenant", "COUNT", 3, 300, "Command and Control", "T1219", "cloud.tenant_id"),
    (22, "Anomaly PowerShell Encoded Command Execution Frequency", "COUNT", 10, 120, "Execution", "T1059.001", "endpoint.hostname"),
    (23, "Anomaly Rapid Kerberos AS-REP Requests without Pre-Auth", "COUNT", 20, 60, "Credential Access", "T1558.004", "network.src_ip"),
    (24, "Anomaly Registry Run Key Creation Spike in Enterprise", "COUNT", 10, 300, "Persistence", "T1547.001", "endpoint.hostname"),
    (25, "Anomaly Archive File Generation Rate on Sensitive Host", "COUNT", 8, 180, "Collection", "T1560.001", "endpoint.hostname"),
]

HUNTING_CORPUS: List[Dict[str, Any]] = [
    _make_hunting_query(
        idx=spec[0],
        name=spec[1],
        hypothesis=spec[2],
        tactic=spec[3],
        technique_id=spec[4],
        pivot_field=spec[5],
        target_value=spec[6],
        neg_value=spec[7],
    )
    for spec in _HUNT_SPECS
]

ANOMALY_CORPUS: List[Dict[str, Any]] = [
    _make_anomaly_rule(
        idx=spec[0],
        name=spec[1],
        aggregation_type=spec[2],
        threshold=spec[3],
        window_seconds=spec[4],
        tactic=spec[5],
        technique_id=spec[6],
        entity_key=spec[7],
    )
    for spec in _ANM_SPECS
]
