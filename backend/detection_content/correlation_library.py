"""
NivXRay XDR — Enterprise Multi-Stage Correlation Content Library.
Reuses the existing stateful 13-operator Correlation Engine (routers/xdr_correlation.py).
Provides high-value multi-stage attack scenarios across endpoint, identity, cloud, and ransomware kill chains.
"""
from __future__ import annotations

from typing import Any, Dict, List

ENTERPRISE_CORRELATION_SCENARIOS: List[Dict[str, Any]] = [
    # ── Scenario 1: Ransomware Kill Chain ──────────────────────────────────────
    {
        "id": "CORR-ENT-001",
        "name": "Multi-Stage Ransomware Pre-Encryption Kill Chain",
        "description": (
            "Multi-stage temporal correlation tracking the complete ransomware progression: "
            "Credential dumping -> Lateral pivot -> Volume Shadow Copy destruction -> Mass file encryption. "
            "Emits high-confidence correlation evidence."
        ),
        "severity_hint": "critical",
        "conditions": [
            {
                "id": "A_CRED",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-CR-001"},  # LSASS Dump
            },
            {
                "id": "B_LATERAL",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-LM-001"},  # PsExec / Service
            },
            {
                "id": "C_VSS_KILL",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-IM-001"},  # VSS Shadows Deleted
            },
            {
                "id": "D_ENCRYPT",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-IM-004"},  # Mass Encryption
            },
        ],
        "operators": {
            "type": "TEMPORAL_ORDERED",
            "sequence": ["A_CRED", "B_LATERAL", "C_VSS_KILL", "D_ENCRYPT"],
            "window_seconds": 1800,  # 30 minute window
        },
        "group_by": ["host_id"],
        "attack_techniques": ["T1003.001", "T1021.002", "T1490", "T1486"],
        "source": "NivXRay-Enterprise",
        "license": "NivXRay Proprietary Architecture",
    },

    # ── Scenario 2: Phishing to C2 ─────────────────────────────────────────────
    {
        "id": "CORR-ENT-002",
        "name": "Phishing-to-C2 Infection and Ingress Transfer Sequence",
        "description": (
            "Detects Office attachment execution spawning an encoded PowerShell session that downloads "
            "a next-stage payload via certutil and establishes persistent external C2 communication."
        ),
        "severity_hint": "high",
        "conditions": [
            {
                "id": "A_OFFICE",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-IA-002"},  # Office Spawning Shell
            },
            {
                "id": "B_POWERSHELL",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-EX-001"},  # Encoded PowerShell
            },
            {
                "id": "C_DOWNLOAD",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-EX-002"},  # Certutil Ingress
            },
        ],
        "operators": {
            "type": "TEMPORAL_ORDERED",
            "sequence": ["A_OFFICE", "B_POWERSHELL", "C_DOWNLOAD"],
            "window_seconds": 600,  # 10 minute window
        },
        "group_by": ["host_id"],
        "attack_techniques": ["T1566.001", "T1059.001", "T1105"],
        "source": "NivXRay-Enterprise",
        "license": "NivXRay Proprietary Architecture",
    },

    # ── Scenario 3: Valid Identity to RMM Dual-Use Lateral Movement ────────────
    {
        "id": "CORR-ENT-003",
        "name": "Valid Account to Dual-Use RMM Cross-Host Lateral Movement",
        "description": (
            "Tracks a privileged user credential authenticating to a host, immediately installing an "
            "unauthorized RMM binary (AnyDesk/ScreenConnect), followed by remote WinRM command execution."
        ),
        "severity_hint": "high",
        "conditions": [
            {
                "id": "A_AUTH",
                "operator": "EVENT_MATCH",
                "match": {"event_kind": "auth.privileged"},
            },
            {
                "id": "B_RMM",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-CC-001"},  # Unauthorized RMM
            },
            {
                "id": "C_WINRM",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-LM-002"},  # WinRM Remote Exec
            },
        ],
        "operators": {
            "type": "SEQUENCE",
            "sequence": ["A_AUTH", "B_RMM", "C_WINRM"],
            "window_seconds": 1200,  # 20 minutes
            "threshold": 1,
        },
        "group_by": ["user_id"],
        "attack_techniques": ["T1078.002", "T1219", "T1021.006"],
        "source": "NivXRay-Enterprise",
        "license": "NivXRay Proprietary Architecture",
    },

    # ── Scenario 4: Cloud Credential Theft to Privilege Escalation ─────────────
    {
        "id": "CORR-ENT-004",
        "name": "Cloud IMDS Credential Theft Followed by IAM Privilege Escalation",
        "description": (
            "Detects cloud instance metadata access (169.254.169.254) followed by an IAM PutUserPolicy "
            "granting administrator access from the stolen credential."
        ),
        "severity_hint": "critical",
        "conditions": [
            {
                "id": "A_IMDS",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-CR-006"},  # Cloud IMDS Theft
            },
            {
                "id": "B_ESCALATE",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-PE-003"},  # Cloud IAM Escalation
            },
        ],
        "operators": {
            "type": "TEMPORAL_ORDERED",
            "sequence": ["A_IMDS", "B_ESCALATE"],
            "window_seconds": 900,  # 15 minutes
        },
        "group_by": ["user_id"],
        "attack_techniques": ["T1552.005", "T1098"],
        "source": "NivXRay-Enterprise",
        "license": "NivXRay Proprietary Architecture",
    },

    # ── Scenario 5: Active Directory Recon to AD CS Template Abuse ─────────────
    {
        "id": "CORR-ENT-005",
        "name": "Domain Reconnaissance to AD CS Certificate Abuse and Lateral Movement",
        "description": (
            "Correlates Active Directory reconnaissance (BloodHound/SharpHound) with immediate AD CS "
            "vulnerable certificate template exploitation (ESC1/ESC8) and subsequent cross-host ticket usage."
        ),
        "severity_hint": "critical",
        "conditions": [
            {
                "id": "A_RECON",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-DS-001"},  # AD Recon
            },
            {
                "id": "B_ADCS",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-PE-002"},  # AD CS ESC1
            },
            {
                "id": "C_PIVOT",
                "operator": "EVENT_MATCH",
                "match": {"detection_id": "DET-LM-001"},  # PsExec Pivot
            },
        ],
        "operators": {
            "type": "TEMPORAL_ORDERED",
            "sequence": ["A_RECON", "B_ADCS", "C_PIVOT"],
            "window_seconds": 1800,  # 30 minutes
        },
        "group_by": ["host_id"],
        "attack_techniques": ["T1087.002", "T1649", "T1021.002"],
        "source": "NivXRay-Enterprise",
        "license": "NivXRay Proprietary Architecture",
    },
]


#: ── N1 · Network / DNS content ───────────────────────────────────────────
#: Both scenarios are seeded **DISABLED**. New network content must not
#: change detection behaviour for every tenant the moment it ships; it is
#: enabled explicitly for a controlled proof or by an operator decision.
#:
#: Signals come from `detection_content.telemetry.network_signals`, which
#: projects canonical network evidence one-signal-per-DNS-answer so that the
#: entity key itself (client address + peer address) carries the join.
NETWORK_DNS_CORRELATION_SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "CORR-NET-001",
        "name": "DNS Resolution Failure Burst (NXDOMAIN) From One Client",
        "description": (
            "A single client address produced a burst of NXDOMAIN answers "
            "inside the window. Evidence consistent with DGA behaviour, a "
            "misconfigured resolver or a dead C2 domain list — correlation "
            "evidence only, never a verdict. Each counted signal cites the "
            "canonical DNS event it came from."
        ),
        "severity_hint": "medium",
        "enabled": False,
        "state": "DISABLED",
        "conditions": [
            {
                "id": "A_NXDOMAIN",
                "operator": "EVENT_MATCH",
                "match": {"event_kind": "dns_query", "dns_rcode": "NXDOMAIN"},
            },
        ],
        "operators": {
            "type": "THRESHOLD",
            "window_seconds": 300,
            "threshold": 10,
        },
        "group_by": ["client_ip"],
        "attack_techniques": ["T1568.002"],
        "source": "NivXRay-Network-N1",
        "license": "NivXRay Public Content",
    },
    {
        "id": "CORR-NET-002",
        "name": "DNS Answer Followed By Connection To The Resolved Address",
        "description": (
            "The same client resolved a domain to an address and then "
            "connected to THAT address within the window. The relationship "
            "is established by three facts together — same client, same "
            "resolved address, DNS first — and the match cites both "
            "canonical event ids. A shared address alone is deliberately "
            "not sufficient."
        ),
        "severity_hint": "informational",
        "enabled": False,
        "state": "DISABLED",
        "conditions": [
            {
                "id": "A_DNS_ANSWER",
                "operator": "EVENT_MATCH",
                "match": {"event_kind": "dns_query",
                          "dns_answer_state": "ADDRESS_ANSWERED"},
            },
            {
                "id": "B_CONNECTION",
                "operator": "EVENT_MATCH",
                "match": {"event_kind": ["network_connect", "network_alert"]},
            },
        ],
        "operators": {
            "type": "SEQUENCE",
            "sequence": ["A_DNS_ANSWER", "B_CONNECTION"],
            "window_seconds": 900,
            "threshold": 1,
        },
        # The entity key IS the join: one client, one peer address.
        "group_by": ["client_ip", "network_peer_ip"],
        "attack_techniques": ["T1071.001"],
        "source": "NivXRay-Network-N1",
        "license": "NivXRay Public Content",
    },
]
