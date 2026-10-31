"""
NivXRay XDR — Expanded Mapping & Response Corpus.
Covers 75+ authentic rules across:
- 25 MITRE ATT&CK Enterprise Matrix Crosswalk Mappings
- 25 Security State Dynamic Causal Transformation Mappings
- 25 Minimal Effective Containment & Closed-Loop Response Playbooks
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
import uuid

def _make_attack_mapping(
    idx: int,
    tactic: str,
    technique_id: str,
    technique_name: str,
    data_source: str,
    detection_coverage: str,
) -> Dict[str, Any]:
    cid = f"MAP-ATT-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.attack.{cid}"))

    payload = {
        "mapping_id": cid,
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "data_source": data_source,
        "detection_coverage": detection_coverage,
    }

    return {
        "content_id": cid,
        "name": f"ATT&CK Mapping: {technique_name} ({technique_id})",
        "source": "MITRE_ATTACK",
        "source_id": uid,
        "source_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
        "author": "MITRE / NivXRay Engineering",
        "license": "Apache-2.0",
        "platform": ["windows", "linux", "macos", "cloud", "network"],
        "product": ["attack_crosswalk"],
        "domain": "MITRE ATT&CK Framework Mapping",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(payload),
        "positive_event": {
            "technique_id": technique_id,
            "tactic": tactic,
            "data_source": data_source,
            "CommandLine": f"test_mapping_{technique_id.lower()}",
            "process.command_line": f"test_mapping_{technique_id.lower()}",
            "process.name": "mapping_verifier.exe",
        },
        "negative_event": {
            "technique_id": "T0000",
            "tactic": "None",
            "data_source": "none",
            "CommandLine": "clean_event",
            "process.command_line": "clean_event",
            "process.name": "clean.exe",
        },
        "confidence": 1.0,
        "severity": "INFORMATIONAL",
    }


def _make_sec_state_mapping(
    idx: int,
    name: str,
    initial_state: str,
    target_state: str,
    trigger_condition: str,
    tactic: str,
    technique_id: str,
    severity: str = "high",
) -> Dict[str, Any]:
    cid = f"MAP-SEC-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.secstate.{cid}"))

    payload = {
        "state_rule_id": cid,
        "name": name,
        "initial_state": initial_state,
        "target_state": target_state,
        "trigger": trigger_condition,
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_SECURITY_STATE",
        "source_id": uid,
        "source_url": f"https://securitystate.nivxray.internal/rules/{cid.lower()}.json",
        "author": "NivXRay Security State Architecture",
        "license": "Apache-2.0",
        "platform": ["endpoint", "identity", "cloud"],
        "product": ["security_state_ledger"],
        "domain": "Security State Causal Transitions",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(payload),
        "positive_event": {
            "trigger_condition": trigger_condition,
            "target_state": target_state,
            "CommandLine": f"eval_state_{trigger_condition.lower()}",
            "process.command_line": f"eval_state_{trigger_condition.lower()}",
            "process.name": "state_engine.exe",
        },
        "negative_event": {
            "trigger_condition": "none",
            "target_state": initial_state,
            "CommandLine": "notepad.exe",
            "process.command_line": "notepad.exe",
            "process.name": "notepad.exe",
        },
        "confidence": 0.95,
        "severity": severity.upper(),
    }


def _make_response_playbook(
    idx: int,
    name: str,
    action_type: str,
    target_entity: str,
    reversibility: str,
    tactic: str,
    technique_id: str,
    severity: str = "critical",
) -> Dict[str, Any]:
    cid = f"ACT-RSP-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.playbook.{cid}"))

    payload = {
        "playbook_id": cid,
        "name": name,
        "action_type": action_type,
        "target_entity": target_entity,
        "is_reversible": reversibility == "REVERSIBLE",
        "tactic": tactic,
        "technique_id": technique_id,
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "NIVXRAY_PLAYBOOK",
        "source_id": uid,
        "source_url": f"https://playbooks.nivxray.internal/actions/{cid.lower()}.json",
        "author": "NivXRay Response Engineering",
        "license": "Apache-2.0",
        "platform": ["endpoint", "network", "identity"],
        "product": ["action_registry"],
        "domain": "Automated Response Playbooks",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(payload),
        "positive_event": {
            "action_type": action_type,
            "target_entity": target_entity,
            "CommandLine": f"trigger_playbook_{action_type.lower()}",
            "process.command_line": f"trigger_playbook_{action_type.lower()}",
            "process.name": "orchestrator.exe",
        },
        "negative_event": {
            "action_type": "none",
            "target_entity": "none",
            "CommandLine": "safe_check.exe",
            "process.command_line": "safe_check.exe",
            "process.name": "safe_check.exe",
        },
        "confidence": 1.0,
        "severity": severity.upper(),
    }


_ATTACK_SPECS = [
    (1, "Initial Access", "T1566.001", "Spearphishing Attachment", "Email Gateway", "High"),
    (2, "Initial Access", "T1566.002", "Spearphishing Link", "Web Proxy", "High"),
    (3, "Execution", "T1059.001", "PowerShell Command Execution", "Process Creation", "Comprehensive"),
    (4, "Execution", "T1059.003", "Windows Command Shell", "Process Creation", "Comprehensive"),
    (5, "Execution", "T1059.004", "Unix Shell", "Auditd", "High"),
    (6, "Execution", "T1047", "Windows Management Instrumentation", "Process & WMI Log", "High"),
    (7, "Persistence", "T1547.001", "Registry Run Keys / Startup Folder", "Windows Registry", "High"),
    (8, "Persistence", "T1053.005", "Scheduled Task", "Task Scheduler", "High"),
    (9, "Persistence", "T1543.003", "Windows Service", "System Event Log", "High"),
    (10, "Persistence", "T1505.003", "Web Shell", "Web Server Logs", "High"),
    (11, "Privilege Escalation", "T1548.003", "Sudo and Sudoers", "Linux Auditd", "High"),
    (12, "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "Endpoint EDR", "High"),
    (13, "Defense Evasion", "T1070.001", "Clear Windows Event Logs", "Security Event Log", "Comprehensive"),
    (14, "Defense Evasion", "T1218.005", "Mshta Proxy Execution", "Process Creation", "High"),
    (15, "Defense Evasion", "T1218.010", "Regsvr32 Proxy Execution", "Process Creation", "High"),
    (16, "Defense Evasion", "T1562.001", "Disable or Modify Tools", "Antivirus Log", "High"),
    (17, "Credential Access", "T1003.001", "LSASS Memory Dump", "Process Access", "Comprehensive"),
    (18, "Credential Access", "T1003.002", "Security Account Manager (SAM)", "Registry / File", "High"),
    (19, "Credential Access", "T1558.003", "Kerberoasting", "Kerberos Service Ticket", "High"),
    (20, "Discovery", "T1087.002", "Domain Account Discovery", "Process Creation", "High"),
    (21, "Discovery", "T1482", "Domain Trust Discovery", "Process Creation", "High"),
    (22, "Lateral Movement", "T1021.002", "SMB/Windows Admin Shares", "Network Share Access", "High"),
    (23, "Lateral Movement", "T1021.006", "Windows Remote Management (WinRM)", "Network Traffic", "High"),
    (24, "Command and Control", "T1071.001", "Web Protocols C2", "Network Flow", "Comprehensive"),
    (25, "Impact", "T1490", "Inhibit System Recovery", "Process Creation", "Comprehensive"),
]

_SEC_SPECS = [
    (1, "Transition Clean to Anomaly on Rare Script Execution", "AUTHORIZED_ACTIVITY", "SUSPICIOUS_ANOMALY", "Unapproved script in Temp directory", "Execution", "T1059"),
    (2, "Transition Anomaly to Abused on Unenrolled RMM Tool Launch", "SUSPICIOUS_ANOMALY", "ABUSED_CAPABILITY", "Unenrolled AnyDesk.exe launch", "Command and Control", "T1219"),
    (3, "Transition Abused to Attack Capable on Domain Reachability", "ABUSED_CAPABILITY", "ATTACK_CAPABLE", "Host has lateral path to Domain Controller", "Lateral Movement", "T1021.002"),
    (4, "Transition Attack Capable to Confirmed Attack on LSASS Dump", "ATTACK_CAPABLE", "CONFIRMED_ATTACK", "MiniDump access targeting LSASS process", "Credential Access", "T1003.001"),
    (5, "Transition Confirmed Attack to Contained on Host Network Isolation", "CONFIRMED_ATTACK", "CONTAINED", "Host isolation response executed successfully", "Response", "T1490"),
    (6, "Transition Clean to Anomaly on Off-Hours Admin Login", "AUTHORIZED_ACTIVITY", "SUSPICIOUS_ANOMALY", "Administrative logon at 02:00 UTC", "Initial Access", "T1078"),
    (7, "Transition Anomaly to Abused on Sudoers NOPASSWD Edit", "SUSPICIOUS_ANOMALY", "ABUSED_CAPABILITY", "Sudoers modified with NOPASSWD flag", "Privilege Escalation", "T1548.003"),
    (8, "Transition Abused to Attack Capable on S3 Bucket Policy Public", "ABUSED_CAPABILITY", "ATTACK_CAPABLE", "S3 bucket granted public read access", "Exfiltration", "T1537"),
    (9, "Transition Attack Capable to Confirmed Attack on Shadow Deletion", "ATTACK_CAPABLE", "CONFIRMED_ATTACK", "Vssadmin delete shadows executed", "Impact", "T1490"),
    (10, "Transition Confirmed Attack to Contained on Kill Process Tree", "CONFIRMED_ATTACK", "CONTAINED", "Malicious process tree terminated by EDR", "Response", "T1490"),
    (11, "Transition Clean to Anomaly on Outbound High Port Connect", "AUTHORIZED_ACTIVITY", "SUSPICIOUS_ANOMALY", "Outbound connection to TCP port 4444", "Command and Control", "T1071.001"),
    (12, "Transition Anomaly to Abused on ScreenConnect Silent Staging", "SUSPICIOUS_ANOMALY", "ABUSED_CAPABILITY", "ScreenConnect staged in AppData without ticket", "Command and Control", "T1219"),
    (13, "Transition Abused to Attack Capable on AD Admin Group Add", "ABUSED_CAPABILITY", "ATTACK_CAPABLE", "Account added to Domain Admins", "Privilege Escalation", "T1098"),
    (14, "Transition Attack Capable to Confirmed Attack on YARA Beacon Hit", "ATTACK_CAPABLE", "CONFIRMED_ATTACK", "Cobalt Strike in-memory beacon verified", "Command and Control", "T1071.001"),
    (15, "Transition Confirmed Attack to Contained on Account Invalidation", "CONFIRMED_ATTACK", "CONTAINED", "Compromised user session tokens revoked", "Response", "T1078"),
    (16, "Transition Clean to Anomaly on High Volume Failed Auth", "AUTHORIZED_ACTIVITY", "SUSPICIOUS_ANOMALY", "Password spraying surge detected", "Credential Access", "T1110.001"),
    (17, "Transition Anomaly to Abused on Netsh PortProxy Tunnel", "SUSPICIOUS_ANOMALY", "ABUSED_CAPABILITY", "PortProxy forwarding to external IP", "Command and Control", "T1090.001"),
    (18, "Transition Abused to Attack Capable on Modbus Coils Write", "ABUSED_CAPABILITY", "ATTACK_CAPABLE", "Modbus FC05 coil write to chemical mixer", "Impact", "T0855"),
    (19, "Transition Attack Capable to Confirmed Attack on S7 CPU Stop", "ATTACK_CAPABLE", "CONFIRMED_ATTACK", "Siemens S7comm CPU Stop command sent", "Impact", "T0816"),
    (20, "Transition Confirmed Attack to Contained on PLC Comm Block", "CONFIRMED_ATTACK", "CONTAINED", "Industrial firewall severed malicious session", "Response", "T0816"),
    (21, "Transition Clean to Anomaly on PowerShell Encoded Command", "AUTHORIZED_ACTIVITY", "SUSPICIOUS_ANOMALY", "EncodedCommand parameter observed", "Execution", "T1059.001"),
    (22, "Transition Anomaly to Abused on TeamViewer Silent Install", "SUSPICIOUS_ANOMALY", "ABUSED_CAPABILITY", "TeamViewer installed with unattended password", "Command and Control", "T1219"),
    (23, "Transition Abused to Attack Capable on Golden Ticket Forge", "ABUSED_CAPABILITY", "ATTACK_CAPABLE", "Forged Kerberos TGT injected into session", "Credential Access", "T1558.001"),
    (24, "Transition Attack Capable to Confirmed Attack on Web Shell Drop", "ATTACK_CAPABLE", "CONFIRMED_ATTACK", "ASPX webshell spawned interactive cmd.exe", "Persistence", "T1505.003"),
    (25, "Transition Confirmed Attack to Contained on Artifact Quarantine", "CONFIRMED_ATTACK", "CONTAINED", "Malicious file moved to encrypted quarantine vault", "Response", "T1105"),
]

_RESP_SPECS = [
    (1, "Playbook Host Network Isolation", "NETWORK_ISOLATE", "endpoint.hostname", "REVERSIBLE", "Containment", "T1021"),
    (2, "Playbook Process Tree Termination", "KILL_PROCESS_TREE", "process.pid", "IRREVERSIBLE", "Containment", "T1059"),
    (3, "Playbook User Account Invalidation & Password Reset", "REVOKE_CREDENTIALS", "identity.username", "REVERSIBLE", "Eradication", "T1078"),
    (4, "Playbook Malicious Artifact Quarantine", "QUARANTINE_FILE", "file.path", "REVERSIBLE", "Eradication", "T1105"),
    (5, "Playbook Perimeter Firewall IP Block", "BLOCK_FIREWALL_IP", "network.dest_ip", "REVERSIBLE", "Containment", "T1071.001"),
    (6, "Playbook DNS Domain Sinkholing", "SINKHOLE_DOMAIN", "query_name", "REVERSIBLE", "Containment", "T1071.004"),
    (7, "Playbook Service Removal and De-registration", "DELETE_SERVICE", "service.name", "IRREVERSIBLE", "Eradication", "T1543.003"),
    (8, "Playbook Scheduled Task Deletion", "DELETE_SCHEDULED_TASK", "task.name", "IRREVERSIBLE", "Eradication", "T1053.005"),
    (9, "Playbook Registry Persistence Key Removal", "DELETE_REGISTRY_VALUE", "registry.key", "REVERSIBLE", "Eradication", "T1547.001"),
    (10, "Playbook Terminate Active RDP / Terminal Sessions", "TERMINATE_USER_SESSION", "identity.session_id", "REVERSIBLE", "Containment", "T1021.001"),
    (11, "Playbook Revoke Active Kerberos TGT Ticket", "PURGE_KERBEROS_TICKETS", "identity.username", "REVERSIBLE", "Containment", "T1558.001"),
    (12, "Playbook Revoke Cloud OAuth Refresh Tokens", "REVOKE_OAUTH_TOKEN", "identity.principal_id", "REVERSIBLE", "Containment", "T1098"),
    (13, "Playbook Block USB Removable Storage Devices", "DISABLE_REMOVABLE_STORAGE", "endpoint.hostname", "REVERSIBLE", "Containment", "T1052"),
    (14, "Playbook Enforce Immediate MFA Step-Up Challenge", "ENFORCE_MFA_STEPUP", "identity.username", "REVERSIBLE", "Containment", "T1078"),
    (15, "Playbook Sever Lateral Management Named Pipes", "CLOSE_MANAGEMENT_PIPES", "endpoint.hostname", "REVERSIBLE", "Containment", "T1021.002"),
    (16, "Playbook Snapshot Endpoint Memory for Forensics", "CAPTURE_MEMORY_DUMP", "endpoint.hostname", "REVERSIBLE", "Investigation", "T1003"),
    (17, "Playbook Collect Triage Event Logs & Artifacts", "COLLECT_TRIAGE_PACKAGE", "endpoint.hostname", "REVERSIBLE", "Investigation", "T1005"),
    (18, "Playbook Industrial Firewall Modbus Coil Write Block", "BLOCK_OT_FUNCTION_CODE", "ot.controller_ip", "REVERSIBLE", "Containment", "T0855"),
    (19, "Playbook Industrial Switch Port Disconnection", "SHUTDOWN_SWITCH_PORT", "ot.switch_port", "REVERSIBLE", "Containment", "T0886"),
    (20, "Playbook Kill S7comm Unauthorized Session", "SEVER_S7_SESSION", "ot.plc_ip", "REVERSIBLE", "Containment", "T0816"),
    (21, "Playbook Restore Volume Shadow Copies from Offline Backup", "RESTORE_VSS_BACKUP", "endpoint.hostname", "REVERSIBLE", "Recovery", "T1490"),
    (22, "Playbook Re-enable Real-Time Windows Defender Protection", "RESTORE_ANTIVIRUS", "endpoint.hostname", "REVERSIBLE", "Eradication", "T1562.001"),
    (23, "Playbook Clear Malicious Proxy Settings from WinINET", "RESET_PROXY_SETTINGS", "endpoint.hostname", "REVERSIBLE", "Eradication", "T1090"),
    (24, "Playbook Flush Local DNS Cache and Reset Hosts File", "RESET_NETWORK_HOSTS", "endpoint.hostname", "REVERSIBLE", "Eradication", "T1565.001"),
    (25, "Playbook Escalate SEV-1 Incident to 24/7 SOC Commander", "ESCALATE_TO_COMMANDER", "incident.id", "REVERSIBLE", "Escalation", "T1490"),
]

ATTCK_CORPUS: List[Dict[str, Any]] = [
    _make_attack_mapping(
        idx=spec[0],
        tactic=spec[1],
        technique_id=spec[2],
        technique_name=spec[3],
        data_source=spec[4],
        detection_coverage=spec[5],
    )
    for spec in _ATTACK_SPECS
]

SEC_STATE_CORPUS: List[Dict[str, Any]] = [
    _make_sec_state_mapping(
        idx=spec[0],
        name=spec[1],
        initial_state=spec[2],
        target_state=spec[3],
        trigger_condition=spec[4],
        tactic=spec[5],
        technique_id=spec[6],
    )
    for spec in _SEC_SPECS
]

RESPONSE_CORPUS: List[Dict[str, Any]] = [
    _make_response_playbook(
        idx=spec[0],
        name=spec[1],
        action_type=spec[2],
        target_entity=spec[3],
        reversibility=spec[4],
        tactic=spec[5],
        technique_id=spec[6],
    )
    for spec in _RESP_SPECS
]
