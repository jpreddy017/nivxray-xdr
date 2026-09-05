"""
NivXRay XDR — Adversarial Validation & End-to-End Simulation Corpus.
Covers 15+ multi-stage attack scenarios inspired by legitimate public defensive/offensive
security research (Atomic Red Team, Caldera, CISA alerts).

Encodes the authoritative full-lifecycle attack simulation chain:
Attack Scenario → Expected Evidence → Expected Telemetry → Detection →
Correlation → IUE → VEEE → IKG → Security State → Expected Response → Verification
"""
from __future__ import annotations

import json
from typing import Any, Dict, List
import uuid

def _make_adversarial_scenario(
    idx: int,
    name: str,
    threat_actor_style: str,
    initial_vector: str,
    execution_step: str,
    persistence_step: str,
    privilege_step: str,
    defense_evasion_step: str,
    credential_step: str,
    lateral_step: str,
    impact_step: str,
    expected_response: str,
    tactic: str = "Execution",
    technique_id: str = "T1059",
) -> Dict[str, Any]:
    cid = f"ADV-SCN-{idx:04d}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"nivxray.adv.{cid}"))

    chain_payload = {
        "scenario_id": cid,
        "name": name,
        "threat_actor_style": threat_actor_style,
        "chain": {
            "1_initial_access": initial_vector,
            "2_execution": execution_step,
            "3_persistence": persistence_step,
            "4_privilege_escalation": privilege_step,
            "5_defense_evasion": defense_evasion_step,
            "6_credential_access": credential_step,
            "7_lateral_movement": lateral_step,
            "8_impact_exfiltration": impact_step,
        },
        "engine_integration": {
            "iue_layer": "Extracts derived C2 IPs, decoded base64 payloads, and process ancestry",
            "veee_layer": "Extracts visual OCR text from phishing lure screenshots or PDF previews",
            "iedde_layer": "Recovers intermediate encoded commands and unrolled nested layers",
            "uaie_layer": "Analyzes dropped PE binaries, shellcode bytes, and archive artifacts",
            "ice_layer": "Correlates multi-step temporal sequence within sliding 15-minute window",
            "ikg_layer": "Connects host, user, process, file, and external IP into graph story",
            "verdict_layer": "Scores cumulative evidence confidence to emit Confirmed Threat verdict",
            "security_state": "Transitions state from Authorized to Abused to Confirmed Attack",
            "response_layer": expected_response,
            "verification_layer": "Asserts entity isolation, process kill, and zero residual persistence",
        }
    }

    return {
        "content_id": cid,
        "name": name,
        "source": "ADVERSARIAL_SIM",
        "source_id": uid,
        "source_url": f"https://adversarial.nivxray.internal/scenarios/{cid.lower()}.json",
        "author": "NivXRay Adversarial Simulation Team",
        "license": "Apache-2.0",
        "platform": ["windows", "linux", "cloud", "network"],
        "product": ["adversarial_simulator"],
        "domain": "Adversarial Validation Scenarios",
        "tactic": tactic,
        "technique_id": technique_id,
        "raw_source": json.dumps(chain_payload),
        "positive_event": {
            "CommandLine": f"simulate_scenario {cid} {execution_step}",
            "process.command_line": f"simulate_scenario {cid} {execution_step}",
            "process.name": "sim_runner.exe",
            "scenario_chain": chain_payload["chain"],
        },
        "negative_event": {
            "CommandLine": "sim_runner.exe --dry-run clean",
            "process.command_line": "sim_runner.exe --dry-run clean",
            "process.name": "sim_runner.exe",
        },
        "confidence": 1.0,
        "severity": "CRITICAL",
    }


_ADV_SPECS = [
    (1, "Scenario APT29 Cozy Bear Stealth Lateral Intrusion", "APT29", "Spearphishing Email with SVG Attachment", "PowerShell Memory Injection via Gzip Stream", "Scheduled Task running rundll32.exe", "Token Impersonation via SeDebugPrivilege", "Wevtutil System Log Wipe", "Mimikatz LSASS Memory Dump", "WinRM Remote Session Execution", "Cloud OneDrive Mass Document Staging", "Host Network Isolation & Revoke Kerberos TGT"),
    (2, "Scenario LockBit 3.0 Ransomware Fast Execution Chain", "LockBit", "Compromised External VPN Gateway Credentials", "PowerShell Base64 Cradle Downloading Locker", "Registry Run Key Addition in User Profile", "Elevate to LocalSystem via CVE-2022-0847", "Bcdedit Recovery Disabled & Defender Service Stopped", "Dump SAM & SYSTEM Registry Hives", "PsExec Mass Distribution across Admin Shares", "Vssadmin Delete Shadows & Salsa20 Encryption", "Emergency Network Isolation & Block WAN IP"),
    (3, "Scenario BlackCat ALPHV Dual Extortion Intrusion", "BlackCat", "Unpatched Public Facing Confluence Exploit", "Curl Piping Shell Script to Bash Interpreter", "Cron Reverse Shell Every 5 Minutes", "Sudoers File Injected with NOPASSWD: ALL", "Rm -rf /var/log/audit/audit.log", "Cat /etc/shadow for Offline Hash Cracking", "SSH Port Forwarding SOCKS Proxy Pivoting", "Rclone Sync of Customer DB to Mega.nz", "Terminate Web Server Process & Block Ingress Port"),
    (4, "Scenario Lazarus Group Cryptocurrency Bridge Compromise", "Lazarus", "Trojanized PDF Application via Job Phish", "Cscript Executing Obfuscated JScript Payload", "Startup Folder LNK Dropped via Explorer", "Named Pipe Impersonation to LocalSystem", "Cipher /w Free Space Data Sanitization", "Browser SQLite Cookie & Private Key Vault Theft", "Chisel Fast TCP Tunneling to Remote VPS", "Raw Memory Wiper Overwriting Master Boot Record", "Immediate Endpoint Isolation & Revoke Cloud Keys"),
    (5, "Scenario Volt Typhoon Living-off-the-Land Critical Infrastructure", "VoltTyphoon", "Fortinet VPN Zero-Day Authentication Bypass", "Wmic Process Call Create Spawning Cmd Shell", "WMI Event Consumer Permanent Subscription", "Scheduled Task Running as NT AUTHORITY\\SYSTEM", "Fsutil Deleting NTFS USN Journal Forensic Log", "Ntdsutil Creating VSS Full Media of NTDS.dit", "Netsh PortProxy Forwarding Remote SMB to C2", "Staging Compressed Archives in System32", "Kill PortProxy & Isolate Management Interface"),
    (6, "Scenario FIN7 Financial Endpoint POS Memory Scraper", "FIN7", "Malicious Word DOCX with VBA AutoOpen Macro", "Mshta Calling Remote Scriptlet URL", "AppCertDLLs Registry Injection Key", "UAC Bypass via ComputerDefaults.exe", "AmsiScanBuffer Memory Patching via Reflection", "Process Injection into POS Card Terminal Process", "SMB Admin Share C$ Lateral Traversal", "Exfiltration of Credit Card Tracks via HTTPS C2", "Isolate POS Network Segment & Invalidate Credentials"),
    (7, "Scenario Sandworm Ukraine Power Grid PLC Sabotage", "Sandworm", "Phishing Word Macro Dropping BlackEnergy Loader", "PowerShell Stager Downloading S7 Exploit Payload", "Service Creation with Malicious Driver Binary", "Kernel Driver Exploitation for Ring-0 Execution", "Service Disabling Industrial Firewall Agent", "Memory Extraction of SCADA HMI Credentials", "EtherNet/IP CIP Generic Forward Open to PLC", "Siemens S7comm CPU Stop & Firmware Overwrite", "Sever PLC Industrial Switch Port & Alert Commander"),
    (8, "Scenario Akira Ransomware ESXi Hypervisor Encryption", "Akira", "Compromised SonicWall SSL VPN Account", "SSH Session Launching Linux Encryptor ELF", "Cron Persistence Executing Encryption Batch", "Local Privilege Escalation via Sudo Exploit", "Kill ESXi VM Processes (vmkping & vmx)", "Extract ESXi Shadow Password Hashes", "Mass SSH Key Deployment across VM Hosts", "Symmetric Encryption of All .vmdk Virtual Disks", "Sever Hypervisor Management LAN & Restore Backup"),
    (9, "Scenario DarkGate Loader into AsyncRAT Deployment", "DarkGate", "Teams Meeting Phishing Message with MSI Dropper", "AutoIt Script Executing Encrypted Shellcode", "Userinit Registry Logon Persistence Value", "Process Hollowing of Svchost.exe", "Set-MpPreference Disabling Realtime Scanning", "LaZagne Multi-Browser Credential Harvest", "RDP Remote Desktop Session via Registry Enable", "AsyncRAT Remote Screen Capture & Audio Stream", "Quarantine DarkGate Stager & Terminate Child Tree"),
    (10, "Scenario SocGholish Fake Browser Update to C2 Beacon", "SocGholish", "Compromised News WordPress Site Waterhole", "Wscript Executing Obfuscated JavaScript File", "Scheduled Task Executing Rundll32 Entry Point", "CMSTP Profile Execution to Bypass AppLocker", "Fltdmc Unloading Antivirus Minifilter Driver", "Dump Chrome Saved Passwords & Login Data", "Plink Remote Port Forwarding Port 4444", "Cobalt Strike In-Memory Beacon Callback", "Sinkhole C2 Domain & Isolate Affected Workstation"),
    (11, "Scenario Qakbot Banking Trojan to Black Basta Deployment", "Qakbot", "Hijacked Email Reply-Chain Thread with ZIP URL", "Explorer Opening VBScript Dropping DLL", "Run Registry Key in CurrentVersion\\Run", "DLL Side-Loading via Legitimate Signed Executable", "Wevtutil Clearing Application Event Logs", "LSASS Memory Dump via Taskmgr MiniDump", "WMI Remote Process Call Create across Subnet", "Mass Ransomware Deployment via Group Policy", "Revoke Domain Admin Sessions & Isolate Primary DC"),
    (12, "Scenario AWS Cloud Account Takeover via Leaked Git Token", "CloudAttacker", "GitHub Public Repository Leaked AWS Access Key", "AWS CLI Assuming Role with Full Admin Access", "IAM User Created with AdministratorAccess", "IAM Backdoor Key Generated for Root Account", "Stop-Logging Command Sent to CloudTrail", "Dump Parameter Store & Secrets Manager DB Passwords", "VPC Peering to Adversary Controlled AWS Account", "Creation of 50 EC2 Monero Mining Instances", "Revoke AWS IAM Access Keys & Apply Quarantine Policy"),
    (13, "Scenario Azure AD Kerberoast to Global Admin Escalation", "IdentityAttacker", "Password Spraying Matching Single Enterprise User", "Rubeus Requesting Kerberos SPN Service Tickets", "Add-AzureADDirectoryRoleMember Elevation", "Service Principal Client Secret Injection", "Conditional Access Policy Disabled for Cloud App", "Dump Azure AD Connect Sync Service Account Passwords", "Lateral Pivot into On-Premises Active Directory", "Export All M365 Mailboxes via PowerShell API", "Revoke OAuth Tokens & Force Global MFA Reset"),
    (14, "Scenario OT Modbus Water Treatment Chemical Overdose", "ICSAttacker", "Compromised Contractor Laptop Connecting via RDP", "Python Modbus Script Initiating Master Connection", "Registry Service Persistence on Engineering Station", "Process Injection into HMI SCADA Interface", "Firewall Rule Added Permitting TCP Port 502", "Extract Plant Engineering Credentials from Config", "Lateral Pivot from Enterprise LAN to Purdue Level 2", "Modbus FC06 Write Holding Register Acid Pump High", "Engage Hardware Emergency Interlock & Block Modbus"),
    (15, "Scenario SolarWinds Style Software Supply Chain Injection", "NationState", "Compromised CI/CD Jenkins Build Server", "MSBuild Compiling Backdoored Dependency DLL", "Windows Service Creation with Valid Certificate", "Kernel Minifilter Driver Registration", "TimeStomping Modifying File Creation Timestamps", "In-Memory Token Theft via Direct System Calls", "DCOM Remote Interface Invocation across Tier-0", "C2 Beacon via Domain-Name-Resolution DNS Queries", "Revoke Code Signing Certificate & Kill Svc Tree"),
]

ADVERSARIAL_CORPUS: List[Dict[str, Any]] = [
    _make_adversarial_scenario(
        idx=spec[0],
        name=spec[1],
        threat_actor_style=spec[2],
        initial_vector=spec[3],
        execution_step=spec[4],
        persistence_step=spec[5],
        privilege_step=spec[6],
        defense_evasion_step=spec[7],
        credential_step=spec[8],
        lateral_step=spec[9],
        impact_step=spec[10],
        expected_response=spec[11],
    )
    for spec in _ADV_SPECS
]
