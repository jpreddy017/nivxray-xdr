"""18-Category Golden Validation Corpus for NivXRay Security State Core.

Categories:
1. Benign administrative activity
2. Legitimate RMM
3. Abused RMM
4. PowerShell administration
5. Credential abuse
6. Lateral movement
7. Cloud identity abuse
8. SaaS abuse
9. Backup targeting
10. Hypervisor targeting
11. Persistence
12. Defense evasion
13. Multi-stage attack
14. Contradictory evidence
15. Missing evidence
16. False-positive scenarios
17. Counterfactual intervention scenarios
18. Response verification failures
"""
from __future__ import annotations

from typing import Any, Dict, List

GOLDEN_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "SCN-01-BENIGN-ADMIN",
        "category": "Benign administrative activity",
        "expected_classification": "AUTHORIZED_USE",
        "expected_attack_state": "NO_ATTACK_EVIDENCE",
        "events": [
            {"type": "process", "process_name": "powershell.exe", "command_line": "Get-Process | Sort-Object CPU -Descending", "user": "admin.alice", "is_admin": True, "business_hours": True}
        ],
    },
    {
        "id": "SCN-02-LEGIT-RMM",
        "category": "Legitimate RMM",
        "expected_classification": "AUTHORIZED_USE",
        "expected_attack_state": "NO_ATTACK_EVIDENCE",
        "events": [
            {"type": "process", "process_name": "AnyDesk.exe", "command_line": "AnyDesk.exe --service", "user": "it.support", "is_admin": True, "business_hours": True, "source_subnet": "10.0.1.0/24"}
        ],
    },
    {
        "id": "SCN-03-ABUSED-RMM",
        "category": "Abused RMM",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "EXECUTION",
        "events": [
            {"type": "process", "process_name": "AnyDesk.exe", "command_line": "AnyDesk.exe --install C:\\Temp --silent", "user": "contractor.temp", "is_admin": False, "business_hours": False, "tunnel": True}
        ],
    },
    {
        "id": "SCN-04-POWERSHELL-ADMIN",
        "category": "PowerShell administration",
        "expected_classification": "AUTHORIZED_USE",
        "expected_attack_state": "NO_ATTACK_EVIDENCE",
        "events": [
            {"type": "process", "process_name": "powershell.exe", "command_line": "Get-WindowsFeature | Where-Object Installed", "user": "sysadmin", "is_admin": True, "business_hours": True}
        ],
    },
    {
        "id": "SCN-05-CREDENTIAL-ABUSE",
        "category": "Credential abuse",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "CREDENTIAL_ACCESS",
        "events": [
            {"type": "process", "process_name": "rundll32.exe", "command_line": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full", "user": "attacker", "is_admin": False}
        ],
    },
    {
        "id": "SCN-06-LATERAL-MOVEMENT",
        "category": "Lateral movement",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "LATERAL_MOVEMENT",
        "events": [
            {"type": "process", "process_name": "psexec.exe", "command_line": "psexec.exe \\\\server-dc-01 -u DOMAIN\\admin cmd.exe", "user": "compromised.user", "is_admin": False}
        ],
    },
    {
        "id": "SCN-07-CLOUD-IDENTITY-ABUSE",
        "category": "Cloud identity abuse",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "PRIVILEGE_ESCALATION",
        "events": [
            {"type": "cloud_api", "service": "aws_sts", "command_line": "aws sts assume-role --role-arn arn:aws:iam::123:role/AdminRole", "user": "dev.contractor", "is_admin": False, "tunnel": True}
        ],
    },
    {
        "id": "SCN-08-SAAS-ABUSE",
        "category": "SaaS abuse",
        "expected_classification": "ABUSED_CAPABILITY",
        "expected_attack_state": "COLLECTION",
        "events": [
            {"type": "saas_api", "service": "m365_graph", "command_line": "GET https://graph.microsoft.com/v1.0/users?$select=mail,messages", "user": "guest", "is_admin": False}
        ],
    },
    {
        "id": "SCN-09-BACKUP-TARGETING",
        "category": "Backup targeting",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "IMPACT",
        "events": [
            {"type": "process", "process_name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet", "user": "attacker", "is_admin": False}
        ],
    },
    {
        "id": "SCN-10-HYPERVISOR-TARGETING",
        "category": "Hypervisor targeting",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "IMPACT",
        "events": [
            {"type": "process", "process_name": "esxcli", "command_line": "esxcli vm process kill --type=force --world-id=10923", "user": "root", "is_admin": False, "business_hours": False}
        ],
    },
    {
        "id": "SCN-11-PERSISTENCE",
        "category": "Persistence",
        "expected_classification": "ABUSED_CAPABILITY",
        "expected_attack_state": "PERSISTENCE",
        "events": [
            {"type": "process", "process_name": "schtasks.exe", "command_line": "schtasks /create /tn \"WindowsUpdateCheck\" /tr \"C:\\temp\\beacon.exe\" /sc onlogon", "user": "attacker", "is_admin": False}
        ],
    },
    {
        "id": "SCN-12-DEFENSE-EVASION",
        "category": "Defense evasion",
        "expected_classification": "ABUSED_CAPABILITY",
        "expected_attack_state": "DEFENSE_EVASION",
        "events": [
            {"type": "process", "process_name": "powershell.exe", "command_line": "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -enc aQB3AHIA...", "user": "unknown", "is_admin": False}
        ],
    },
    {
        "id": "SCN-13-MULTI-STAGE-ATTACK",
        "category": "Multi-stage attack",
        "expected_classification": "CONFIRMED_ATTACK",
        "expected_attack_state": "CREDENTIAL_ACCESS",
        "events": [
            {"type": "process", "process_name": "powershell.exe", "command_line": "powershell -enc downloadstring", "user": "user1"},
            {"type": "process", "process_name": "schtasks.exe", "command_line": "schtasks /create /tn updater /tr payload.exe", "user": "user1"},
            {"type": "process", "process_name": "rundll32.exe", "command_line": "rundll32 comsvcs.dll MiniDump lsass.exe", "user": "user1"}
        ],
    },
    {
        "id": "SCN-14-CONTRADICTORY-EVIDENCE",
        "category": "Contradictory evidence",
        "expected_classification": "SUSPICIOUS_USE",
        "expected_epistemic": "CONTRADICTED",
        "events": [
            {"type": "edr_alert", "process_name": "powershell.exe", "command_line": "powershell whoami", "conflicting_status": True}
        ],
    },
    {
        "id": "SCN-15-MISSING-EVIDENCE",
        "category": "Missing evidence",
        "expected_classification": "LEGITIMATE_CAPABILITY",
        "expected_epistemic": "UNSUPPORTED",
        "events": [],
    },
    {
        "id": "SCN-16-FALSE-POSITIVE",
        "category": "False-positive scenarios",
        "expected_classification": "AUTHORIZED_USE",
        "expected_attack_state": "NO_ATTACK_EVIDENCE",
        "events": [
            {"type": "process", "process_name": "powershell.exe", "command_line": "powershell.exe -file C:\\Program Files\\SCCM\\ccmexec.ps1", "user": "SYSTEM", "is_admin": True, "business_hours": True}
        ],
    },
    {
        "id": "SCN-17-COUNTERFACTUAL-INTERVENTION",
        "category": "Counterfactual intervention scenarios",
        "expected_plan_actions": ["endpoint.isolate"],
        "events": [
            {"type": "process", "process_name": "powershell.exe", "command_line": "powershell -enc downloadstring", "user": "hacked.user"}
        ],
    },
    {
        "id": "SCN-18-RESPONSE-VERIFICATION-FAILURE",
        "category": "Response verification failures",
        "expected_verified": False,
        "action_id": "endpoint.isolate",
        "post_telemetry": [
            {"type": "network_connection", "direction": "outbound", "destination_port": 4444, "dest_ip": "185.220.101.5"}
        ],
    },
]
