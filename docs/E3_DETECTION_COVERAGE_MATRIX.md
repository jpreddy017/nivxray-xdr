# E3 · DETECTION COVERAGE MATRIX (measured)

Corpus: `ten_f1a5479243e901cf159e230fa0` · 3299 canonical rows · 3299 evaluation-ledger entries.

Source event ids actually collected: `Sysmon:1`×16, `Sysmon:11`×107, `Sysmon:12`×766, `Sysmon:13`×2335, `Sysmon:22`×1, `Sysmon:3`×70, `Windows Security Log:4624`×2, `Windows Security Log:4672`×2

## Verdicts

| verdict | rules |
|---|---|
| SUPPORTED | 22 |
| PARTIAL | 1 |
| UNSUPPORTED | 0 |
| NOT_TESTED | 0 |
| NOT_APPLICABLE | 14 |

**This is NOT an ATT&CK coverage percentage.** A technique may require telemetry this sensor does not collect or an engine NivXForge does not yet have.

## By behaviour family

| family | SUPPORTED | PARTIAL | UNSUPPORTED | NOT_TESTED | NOT_APPLICABLE |
|---|---|---|---|---|---|
| Command and Control | 2 | 0 | 0 | 0 | 2 |
| Credential Access | 2 | 0 | 0 | 0 | 3 |
| Defense Evasion | 3 | 0 | 0 | 0 | 2 |
| Discovery | 1 | 0 | 0 | 0 | 0 |
| Execution | 6 | 0 | 0 | 0 | 2 |
| Impact | 2 | 0 | 0 | 0 | 1 |
| Initial Access | 1 | 0 | 0 | 0 | 0 |
| Lateral Movement | 1 | 1 | 0 | 0 | 0 |
| Persistence | 4 | 0 | 0 | 0 | 1 |
| Privilege Escalation | 0 | 0 | 0 | 0 | 3 |

## Per rule

| rule | technique | required telemetry | sensor can observe | collected | canonical field populated | +ctrl (fixture) | +ctrl (CANONICAL) | -ctrl | verdict | reason |
|---|---|---|---|---|---|---|---|---|---|---|
| DET-CR-004 Kerberoasting Service Principal Name Ticket Request | T1558.003 | security_event_4769, kerberos | yes | kerberos_service_ticket=0, kerberos_tgt_request=0 | identity.username=3299 | PASS(2/2) | PASS(2/2) | PASS(3/3) | **NOT_APPLICABLE** | a identity rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-CR-005 AS-REP Roasting for Accounts Without Preauthentication | T1558.004 | security_event_4768, kerberos | yes | kerberos_service_ticket=0, kerberos_tgt_request=0 | identity.username=3299 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a identity rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-CR-006 Cloud Instance Metadata Service (IMDS) Credential Theft | T1552.005 | network_traffic, command_line | yes | network_connect=70, process_create=16 | network.dest_ip=70, process.command_line=16 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a cloud rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-EM-001 Non-Human Identity Key Abuse | T1078.004 | cloud_audit, entra_id | NO | — | — | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a cloud rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-EX-006 Linux Pipe to Shell Execution | T1059.004 | process_creation, command_line, process.command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a linux rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-IM-003 VMware ESXi Mass Virtual Machine Destruction | T1485 | hypervisor_command_line, auditd | NO | process_create=16 | — | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a hypervisor rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-PE-002 Active Directory Certificate Services Template Misconfiguration Abuse | T1649 | active_directory_audit, ad_cs | NO | directory_change=0 | identity.username=3299 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **NOT_APPLICABLE** | a identity rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-PE-003 Cloud IAM Excessive Policy Assignment | T1098 | cloud_audit, iam | NO | — | — | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a cloud rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-PS-004 M365 Malicious Inbox Rule Creation | T1114.003 | cloud_audit, m365_exchange | NO | — | — | PASS(2/2) | PASS(2/2) | PASS(4/4) | **NOT_APPLICABLE** | a cloud rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| EDR-LNX-001 Base64-decoded payload piped into a shell | T1027 | process.command_line | yes | process_create=16 | process.command_line=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **NOT_APPLICABLE** | a linux rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| EDR-LNX-002 Execution from a world-writable directory | T1059 | process.executable_path, process.command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **NOT_APPLICABLE** | a linux rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| EDR-LNX-003 Remote content fetched and piped directly to an interpreter | T1105 | process.command_line | yes | process_create=16 | process.command_line=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **NOT_APPLICABLE** | a linux rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| EDR-LNX-004 Reverse-shell shaped command line | T1071 | process.command_line | yes | process_create=16 | process.command_line=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **NOT_APPLICABLE** | a linux rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| EDR-LNX-005 Execute permission granted to a file in a world-writable path | T1222.002 | process.command_line | yes | process_create=16 | process.command_line=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **NOT_APPLICABLE** | a linux rule; this acceptance corpus is a WINDOWS endpoint, so it is out of scope here rather than unsupported |
| DET-LM-001 PsExec Lateral Movement Service Creation | T1021.002 | service_creation, process_creation | yes | process_create=16, service_installed=0 | process.executable_path=3297, process.name=3297, registry.service_name=0 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **PARTIAL** | fires on canonical evidence, but these canonical fields are never populated in the real corpus: registry.service_name |
| DET-CC-001 Dual-Use RMM Remote Access Tool Execution | T1219 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-CC-002 DNS Tunneling Query Pattern | T1071.004 | dns_query | yes | dns_query=1 | network.dns_query=1 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-CR-001 LSASS Memory Dumping via Comsvcs/Procdump | T1003.001 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-CR-002 NTDS.dit Volume Shadow Copy Extraction | T1003.003 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-DE-001 Windows Defender Real-Time Monitoring Disabled | T1562.001 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-DE-002 Security Event Log Cleared via Wevtutil | T1070.001 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-DE-003 AMSI Memory Patch / Bypass | T1562.001 | script_block_logging, command_line | yes | powershell_script_block=0, process_create=16 | process.command_line=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-DS-001 Active Directory Reconnaissance via SharpHound/AdFind | T1087.002 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-EM-002 Autonomous AI-Agent Subprocess Shell Execution | T1059 | process_creation, identity | yes | logon_success=2, process_create=16 | identity.username=3299, process.executable_path=3297, process.name=3297 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-EX-001 Suspicious Encoded PowerShell Execution | T1059.001 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-EX-002 Certutil Ingress Tool Transfer (Download) | T1105 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-EX-003 Bitsadmin Remote File Transfer | T1105 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-EX-004 WMI Local/Remote Process Creation | T1047 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-EX-005 Regsvr32 Remote Scriptlet Execution (Squiblydoo) | T1218.010 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-IA-002 Office Application Spawning Script Host | T1566.001 | process_creation, parent_process | yes | process_create=16 | process.executable_path=3297, process.name=3297, process.parent_name=16, process.parent_process_guid=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-IM-001 Volume Shadow Copy Deletion | T1490 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-IM-004 High-Velocity Mass Ransomware Encryption | T1486 | file_activity, endpoint | yes | file_create=107, file_event=0, process_create=16 | file.path=107, process.name=3297 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-LM-002 WinRM Remote PowerShell Execution | T1021.006 | process_creation, parent_process | yes | process_create=16 | process.executable_path=3297, process.name=3297, process.parent_name=16, process.parent_process_guid=16 | PASS(1/1) | PASS(1/1) | PASS(1/1) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-PS-001 Registry Run Key Persistence | T1547.001 | registry_event, command_line | yes | process_create=16, registry_event=3101, registry_set=0 | process.command_line=16, registry.key_path=3101 | PASS(2/2) | PASS(2/2) | PASS(4/4) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-PS-002 Suspicious Scheduled Task Creation | T1053.005 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-PS-003 Windows Service Creation via SC.exe | T1543.003 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(2/2) | PASS(2/2) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
| DET-PS-005 Registry Run Key Persistence Requested via Command Line | T1547.001 | process_creation, command_line | yes | process_create=16 | process.command_line=16, process.executable_path=3297, process.name=3297 | PASS(1/1) | PASS(1/1) | PASS(2/2) | **SUPPORTED** | fires on canonical evidence AND the required evidence is actually collected on the real endpoint |
