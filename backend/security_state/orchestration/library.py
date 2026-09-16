"""
NivXRay XDR — Enterprise Response Playbook Library.
Defines 22 initial enterprise response playbooks spanning endpoint, identity, network, cloud, SaaS, and ransomware.
All playbooks reference canonical action registry actions and enforce deterministic simulation and approval gates.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from .models import (
    PlaybookDefinition,
    PlaybookStep,
    PlaybookTrigger,
    TargetDomain,
)

ENTERPRISE_PLAYBOOKS: List[PlaybookDefinition] = [
    # ── 1. Endpoint Containment Playbooks ──────────────────────────────────────
    PlaybookDefinition(
        playbook_id="PB-END-01",
        name="Host Endpoint Isolation Playbook",
        description="Isolates compromised endpoint from the network while preserving live telemetry and forensic channels.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("threat_family", "family", "RANSOMWARE"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-EX-001"),
        ],
        required_capabilities=["edr.endpoint.isolate"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="COLLECT_FORENSIC_SNAPSHOT",
                name="Triage Forensic Snapshot",
                description="Capture volatile process, connection, and memory state prior to network isolation.",
                target_entity_kind="host",
                is_reversible=False,
                requires_dual_approval=False,
            ),
            PlaybookStep(
                step_number=2,
                action_id="ENDPOINT_ISOLATE",
                name="Network Isolation",
                description="Sever all non-security inbound/outbound network adapters on the endpoint.",
                target_entity_kind="host",
                is_reversible=True,
                requires_dual_approval=False,
                rollback_action_id="ENDPOINT_RELEASE_ISOLATION",
                verification_condition="endpoint_network_traffic_zero",
            ),
        ],
        risk_level="HIGH",
        approval_policy="APPROVAL_REQUIRED",
        rollback_playbook_id="PB-END-01-ROLLBACK",
        expected_residual_risk_reduction_pct=75,
        expected_business_disruption_score=60,
    ),

    PlaybookDefinition(
        playbook_id="PB-END-02",
        name="Malicious Process Termination Playbook",
        description="Terminates active malicious processes and child execution trees.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-EX-002"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-CR-001"),
        ],
        required_capabilities=["edr.process.kill"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="PROCESS_KILL",
                name="Terminate Malicious Process",
                description="Forcefully terminate the target malicious PID and sub-processes.",
                target_entity_kind="process",
                is_reversible=False,
                requires_dual_approval=False,
                verification_condition="process_exit_confirmed",
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=50,
        expected_business_disruption_score=15,
    ),

    PlaybookDefinition(
        playbook_id="PB-END-03",
        name="File Artifact Quarantine Playbook",
        description="Quarantines malicious file payload and strips execution permissions.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("threat_family", "family", "MALWARE"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-EX-003"),
        ],
        required_capabilities=["edr.file.quarantine"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="FILE_QUARANTINE",
                name="Quarantine Payload File",
                description="Move malicious file artifact to encrypted quarantine vault.",
                target_entity_kind="file",
                is_reversible=True,
                requires_dual_approval=False,
                verification_condition="file_path_inaccessible",
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=40,
        expected_business_disruption_score=10,
    ),

    PlaybookDefinition(
        playbook_id="PB-END-04",
        name="Volatile Memory & Forensic Snapshot Playbook",
        description="Collects memory dump, active socket list, and event logs for offline analysis.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("threat_family", "family", "INFOSTEALER"),
            PlaybookTrigger("threat_family", "family", "APT"),
        ],
        required_capabilities=["edr.forensics.collect"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="COLLECT_FORENSIC_SNAPSHOT",
                name="Extract Full Triage Package",
                description="Dump active memory triage, handle table, and auth cache to evidence store.",
                target_entity_kind="host",
                is_reversible=False,
                requires_dual_approval=False,
            ),
        ],
        risk_level="LOW",
        approval_policy="AUTO_APPROVE",
        expected_residual_risk_reduction_pct=10,
        expected_business_disruption_score=5,
    ),

    # ── 2. Network Containment Playbooks ───────────────────────────────────────
    PlaybookDefinition(
        playbook_id="PB-NET-01",
        name="Perimeter Edge C2 IP Block Playbook",
        description="Blocks malicious C2 communication at edge firewalls.",
        target_domain=TargetDomain.NETWORK,
        triggers=[
            PlaybookTrigger("threat_family", "family", "C2"),
            PlaybookTrigger("threat_family", "family", "BOTNET"),
        ],
        required_capabilities=["firewall.ip.block"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="IP_BLOCK",
                name="Firewall Drop Rule",
                description="Add drop rule for destination C2 IP on edge firewalls.",
                target_entity_kind="ip",
                is_reversible=True,
                requires_dual_approval=False,
                rollback_action_id="IP_UNBLOCK",
                verification_condition="firewall_rule_active",
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=60,
        expected_business_disruption_score=5,
    ),

    PlaybookDefinition(
        playbook_id="PB-NET-02",
        name="Malicious Domain DNS Sinkhole Playbook",
        description="Reroutes malicious DNS queries to sinkhole listener.",
        target_domain=TargetDomain.NETWORK,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-CC-002"),
        ],
        required_capabilities=["dns.domain.sinkhole"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="DNS_SINKHOLE_DOMAIN",
                name="DNS Sinkhole Rewrite",
                description="Inject sinkhole response for malicious domain on internal resolver.",
                target_entity_kind="domain",
                is_reversible=True,
                requires_dual_approval=False,
                verification_condition="dns_resolution_sinkholed",
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=55,
        expected_business_disruption_score=5,
    ),

    PlaybookDefinition(
        playbook_id="PB-NET-03",
        name="Lateral Subnet Micro-Segmentation Playbook",
        description="Restricts inter-workstation SMB and RPC traffic during active lateral spread.",
        target_domain=TargetDomain.NETWORK,
        triggers=[
            PlaybookTrigger("correlation_rule", "id", "CORR-ENT-003"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-LM-001"),
        ],
        required_capabilities=["firewall.rule.add"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="FIREWALL_RULE_ADD",
                name="Enforce Host Isolation Micro-Rule",
                description="Block TCP 445/135/5985 traffic across peer workstation subnets.",
                target_entity_kind="host",
                is_reversible=True,
                requires_dual_approval=True,
                verification_condition="lateral_ports_blocked",
            ),
        ],
        risk_level="HIGH",
        approval_policy="DUAL_APPROVAL",
        expected_residual_risk_reduction_pct=70,
        expected_business_disruption_score=30,
    ),

    # ── 3. Identity Containment Playbooks ──────────────────────────────────────
    PlaybookDefinition(
        playbook_id="PB-ID-01",
        name="Compromised Account Suspension Playbook",
        description="Suspends compromised Active Directory / Entra ID user account.",
        target_domain=TargetDomain.IDENTITY,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-CR-004"),
            PlaybookTrigger("threat_family", "family", "CREDENTIAL_THEFT"),
        ],
        required_capabilities=["identity.user.suspend"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_SUSPEND",
                name="Disable Account in Directory",
                description="Set userAccountControl to disabled / block sign-in in directory.",
                target_entity_kind="user",
                is_reversible=True,
                requires_dual_approval=True,
                verification_condition="user_account_disabled",
            ),
        ],
        risk_level="HIGH",
        approval_policy="DUAL_APPROVAL",
        expected_residual_risk_reduction_pct=80,
        expected_business_disruption_score=40,
    ),

    PlaybookDefinition(
        playbook_id="PB-ID-02",
        name="Active Kerberos TGT & Cloud Session Revocation Playbook",
        description="Revokes all active Kerberos TGT tickets and terminates Entra ID / M365 refresh tokens.",
        target_domain=TargetDomain.IDENTITY,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-CR-004"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-PE-002"),
        ],
        required_capabilities=["identity.session.revoke"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_FORCE_PASSWORD_RESET",
                name="Invalidate Active Authentication Sessions",
                description="Revoke all active session tokens and force immediate re-authentication.",
                target_entity_kind="user",
                is_reversible=False,
                requires_dual_approval=False,
                verification_condition="sessions_invalidated",
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=70,
        expected_business_disruption_score=15,
    ),

    PlaybookDefinition(
        playbook_id="PB-ID-03",
        name="Forced User Password Reset & MFA Re-Enrollment Playbook",
        description="Forces immediate password change at next logon and revokes existing MFA devices.",
        target_domain=TargetDomain.IDENTITY,
        triggers=[
            PlaybookTrigger("threat_family", "family", "PHISHING"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-CR-005"),
        ],
        required_capabilities=["identity.user.reset_password"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_FORCE_PASSWORD_RESET",
                name="Flag Account for Forced Password Change",
                description="Set pwdLastSet=0 and invalidate cached credentials.",
                target_entity_kind="user",
                is_reversible=False,
                requires_dual_approval=False,
                verification_condition="password_change_required",
            ),
        ],
        risk_level="LOW",
        approval_policy="AUTO_APPROVE",
        expected_residual_risk_reduction_pct=65,
        expected_business_disruption_score=10,
    ),

    PlaybookDefinition(
        playbook_id="PB-ID-04",
        name="Privileged Group Membership Emergency Revocation Playbook",
        description="Removes compromised identity from Domain Admins, Enterprise Admins, or Cloud Global Admins.",
        target_domain=TargetDomain.IDENTITY,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-PE-002"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-CR-003"),
        ],
        required_capabilities=["identity.group.modify"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_SUSPEND",
                name="Strip High-Privilege Group SIDs",
                description="Remove user from Tier-0 and Tier-1 security groups.",
                target_entity_kind="user",
                is_reversible=True,
                requires_dual_approval=True,
                verification_condition="admin_membership_removed",
            ),
        ],
        risk_level="HIGH",
        approval_policy="DUAL_APPROVAL",
        expected_residual_risk_reduction_pct=85,
        expected_business_disruption_score=35,
    ),

    # ── 4. Persistence & Malware Remediation Playbooks ─────────────────────────
    PlaybookDefinition(
        playbook_id="PB-PERS-01",
        name="Registry Run Key Persistence Removal Playbook",
        description="Removes malicious persistence keys from Windows Registry Run/RunOnce.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-PS-001"),
        ],
        required_capabilities=["edr.registry.delete"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="FILE_QUARANTINE",
                name="Delete Registry Run Key Value",
                description="Delete persistence value in CurrentVersion\\Run.",
                target_entity_kind="file",
                is_reversible=True,
                requires_dual_approval=False,
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=45,
        expected_business_disruption_score=5,
    ),

    PlaybookDefinition(
        playbook_id="PB-PERS-02",
        name="Scheduled Task & Malicious Service Removal Playbook",
        description="Deletes malicious scheduled tasks and unregisters backdoored services.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-PS-002"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-PS-003"),
        ],
        required_capabilities=["edr.service.delete"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="PROCESS_KILL",
                name="Stop Backdoor Service",
                description="Stop running malicious service binary.",
                target_entity_kind="process",
                is_reversible=False,
                requires_dual_approval=False,
            ),
            PlaybookStep(
                step_number=2,
                action_id="FILE_QUARANTINE",
                name="Delete Service & Associated Binaries",
                description="Unregister service entry and move binary to quarantine.",
                target_entity_kind="file",
                is_reversible=True,
                requires_dual_approval=False,
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=60,
        expected_business_disruption_score=10,
    ),

    PlaybookDefinition(
        playbook_id="PB-RMM-01",
        name="Unauthorized RMM Software Containment Playbook",
        description="Terminates unauthorized RMM processes, removes remote management services, and blocks RMM relay domains.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-CC-001"),
            PlaybookTrigger("correlation_rule", "id", "CORR-ENT-003"),
        ],
        required_capabilities=["edr.process.kill", "firewall.ip.block"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="PROCESS_KILL",
                name="Terminate RMM Agent Process",
                description="Kill active AnyDesk, ScreenConnect, or TeamViewer instance.",
                target_entity_kind="process",
                is_reversible=False,
                requires_dual_approval=False,
            ),
            PlaybookStep(
                step_number=2,
                action_id="DOMAIN_BLOCK",
                name="Block Vendor Relay Gateway",
                description="Block DNS resolution and egress to the specific RMM vendor relay infrastructure.",
                target_entity_kind="domain",
                is_reversible=True,
                requires_dual_approval=False,
            ),
        ],
        risk_level="HIGH",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=75,
        expected_business_disruption_score=15,
    ),

    PlaybookDefinition(
        playbook_id="PB-RAN-01",
        name="High-Velocity Ransomware Emergency Kill Switch Playbook",
        description="Emergency containment for active ransomware: immediate host network isolation, suspension of shadow copies access, process termination.",
        target_domain=TargetDomain.ENDPOINT,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-IM-001"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-IM-004"),
            PlaybookTrigger("correlation_rule", "id", "CORR-ENT-001"),
        ],
        required_capabilities=["edr.endpoint.isolate", "edr.process.kill"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="ENDPOINT_ISOLATE",
                name="Emergency Network Cut",
                description="Sever all communications immediately to halt network share traversal.",
                target_entity_kind="host",
                is_reversible=True,
                requires_dual_approval=False,
                rollback_action_id="ENDPOINT_RELEASE_ISOLATION",
            ),
            PlaybookStep(
                step_number=2,
                action_id="PROCESS_KILL",
                name="Kill Ransomware Encryptor Process Tree",
                description="Terminate encryptor processes identified in the active incident context.",
                target_entity_kind="process",
                is_reversible=False,
                requires_dual_approval=False,
            ),
        ],
        risk_level="CRITICAL",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=90,
        expected_business_disruption_score=70,
    ),

    PlaybookDefinition(
        playbook_id="PB-BAK-01",
        name="Backup Infrastructure & VSS Protection Lockdown Playbook",
        description="Restricts administrative access to Veeam/Commvault repositories and locks volume shadow copy services.",
        target_domain=TargetDomain.BACKUP,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-IM-001"),
            PlaybookTrigger("correlation_rule", "id", "CORR-ENT-001"),
        ],
        required_capabilities=["firewall.rule.add", "identity.user.suspend"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="FIREWALL_RULE_ADD",
                name="Isolate Backup Repository Network Segments",
                description="Enforce strict firewall rule dropping all inbound traffic to backup storage ports except dedicated management console.",
                target_entity_kind="host",
                is_reversible=True,
                requires_dual_approval=True,
            ),
        ],
        risk_level="HIGH",
        approval_policy="DUAL_APPROVAL",
        expected_residual_risk_reduction_pct=85,
        expected_business_disruption_score=25,
    ),

    # ── 5. Cloud & SaaS Containment Playbooks ──────────────────────────────────
    PlaybookDefinition(
        playbook_id="PB-CLD-01",
        name="Cloud IAM Temporary Credential Revocation Playbook",
        description="Revokes AWS/Azure STS temporary session credentials and invalidates active assume-role keys.",
        target_domain=TargetDomain.CLOUD,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-CR-006"),
            PlaybookTrigger("correlation_rule", "id", "CORR-ENT-004"),
        ],
        required_capabilities=["cloud.iam.revoke"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_SUSPEND",
                name="Attach RevokeOlderThan Inline Policy",
                description="Revoke all active IAM sessions issued prior to current UTC timestamp.",
                target_entity_kind="cloud_role",
                is_reversible=False,
                requires_dual_approval=False,
            ),
        ],
        risk_level="HIGH",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=80,
        expected_business_disruption_score=20,
    ),

    PlaybookDefinition(
        playbook_id="PB-CLD-02",
        name="Cloud Privileged Role Boundary Restriction Playbook",
        description="Enforces strict permission boundaries on escalated IAM roles.",
        target_domain=TargetDomain.CLOUD,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-PE-003"),
        ],
        required_capabilities=["cloud.iam.restrict"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_SUSPEND",
                name="Enforce Emergency Deny-All Permissions Boundary",
                description="Attach restrictive permission boundary preventing further resource modification.",
                target_entity_kind="cloud_role",
                is_reversible=True,
                requires_dual_approval=True,
            ),
        ],
        risk_level="HIGH",
        approval_policy="DUAL_APPROVAL",
        expected_residual_risk_reduction_pct=85,
        expected_business_disruption_score=35,
    ),

    PlaybookDefinition(
        playbook_id="PB-CLD-03",
        name="Malicious OAuth Application Revocation Playbook",
        description="Revokes consent and disables malicious enterprise OAuth applications in Entra ID / Google Workspace.",
        target_domain=TargetDomain.CLOUD,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-EM-001"),
        ],
        required_capabilities=["cloud.oauth.revoke"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="USER_SUSPEND",
                name="Disable Service Principal & Invalidate OAuth Grants",
                description="Set accountEnabled=false on the service principal and revoke delegated permissions.",
                target_entity_kind="cloud_role",
                is_reversible=True,
                requires_dual_approval=False,
            ),
        ],
        risk_level="HIGH",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=80,
        expected_business_disruption_score=15,
    ),

    PlaybookDefinition(
        playbook_id="PB-EML-01",
        name="Phishing Email Quarantine & Cluster Purge Playbook",
        description="Purges matching phishing email message IDs across all enterprise mailboxes in M365.",
        target_domain=TargetDomain.EMAIL,
        triggers=[
            PlaybookTrigger("threat_family", "family", "PHISHING"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-IA-002"),
        ],
        required_capabilities=["email.message.purge"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="FILE_QUARANTINE",
                name="Soft-Delete Phishing Messages Across Tenant",
                description="Purge delivered email messages sharing subject, hash, and sender from user inboxes.",
                target_entity_kind="file",
                is_reversible=True,
                requires_dual_approval=False,
            ),
        ],
        risk_level="MEDIUM",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=60,
        expected_business_disruption_score=5,
    ),

    PlaybookDefinition(
        playbook_id="PB-EML-02",
        name="Malicious Inbox Forwarding Rule Deletion Playbook",
        description="Removes unauthorized external email forwarding and redirect rules from compromised mailboxes.",
        target_domain=TargetDomain.EMAIL,
        triggers=[
            PlaybookTrigger("detection_rule", "rule_id", "DET-PS-004"),
        ],
        required_capabilities=["email.inbox_rule.delete"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="FILE_QUARANTINE",
                name="Delete Malicious Inbox Rule",
                description="Remove forwarding rule and notify mailbox owner.",
                target_entity_kind="file",
                is_reversible=False,
                requires_dual_approval=False,
            ),
        ],
        risk_level="LOW",
        approval_policy="AUTO_APPROVE",
        expected_residual_risk_reduction_pct=50,
        expected_business_disruption_score=5,
    ),

    PlaybookDefinition(
        playbook_id="PB-EXF-01",
        name="Outbound Data Exfiltration Channel Severance Playbook",
        description="Terminates high-volume outbound network sessions to external cloud storage or unauthorized C2 IPs.",
        target_domain=TargetDomain.NETWORK,
        triggers=[
            PlaybookTrigger("threat_family", "family", "EXFILTRATION"),
            PlaybookTrigger("detection_rule", "rule_id", "DET-CC-002"),
        ],
        required_capabilities=["firewall.ip.block"],
        steps=[
            PlaybookStep(
                step_number=1,
                action_id="IP_BLOCK",
                name="Drop Exfiltration IP",
                description="Block external IP at network edge.",
                target_entity_kind="ip",
                is_reversible=True,
                requires_dual_approval=False,
                rollback_action_id="IP_UNBLOCK",
            ),
            PlaybookStep(
                step_number=2,
                action_id="ENDPOINT_ISOLATE",
                name="Quarantine Exfiltrating Source Host",
                description="Isolate host performing mass egress.",
                target_entity_kind="host",
                is_reversible=True,
                requires_dual_approval=False,
                rollback_action_id="ENDPOINT_RELEASE_ISOLATION",
            ),
        ],
        risk_level="CRITICAL",
        approval_policy="APPROVAL_REQUIRED",
        expected_residual_risk_reduction_pct=85,
        expected_business_disruption_score=60,
    ),
]


class PlaybookRegistry:
    def __init__(self, playbooks: Optional[List[PlaybookDefinition]] = None):
        self._playbooks: Dict[str, PlaybookDefinition] = {}
        for pb in (playbooks or ENTERPRISE_PLAYBOOKS):
            self._playbooks[pb.playbook_id] = pb

    def get_playbook(self, playbook_id: str) -> Optional[PlaybookDefinition]:
        return self._playbooks.get(playbook_id)

    def list_playbooks(self) -> List[Dict[str, Any]]:
        return [pb.to_dict() for pb in self._playbooks.values()]

    def count(self) -> int:
        return len(self._playbooks)

    def resolve_for_trigger(self, trigger_kind: str, value: str) -> List[PlaybookDefinition]:
        matches: List[PlaybookDefinition] = []
        for pb in self._playbooks.values():
            for t in pb.triggers:
                if t.trigger_kind == trigger_kind and t.filter_value.lower() == value.lower():
                    matches.append(pb)
                    break
        return matches


# Authoritative singleton registry
PLAYBOOK_REGISTRY = PlaybookRegistry()
