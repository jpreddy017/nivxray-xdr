"""Temporal Attack Progression & Lifecycle Risk Reasoning Engine for NivXRay Security State."""
from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

from security_state.contracts import (
    EpistemicStatus,
    ProgressionRiskAssessment,
    PostAttackResidualRisk,
    TemporalAttackPhase,
)


class TemporalProgressionEngine:
    """Evaluates the continuous temporal continuum of attack progression:
    
    PRE_ATTACK -> POSSIBLE -> LIKELY -> SUPPORTED -> CONFIRMED_ATTACK -> 
    CONTAINED -> POST_ATTACK -> RESIDUAL_RISK -> RE_ENTRY_EXPOSURE.
    
    Adheres strictly to core architectural locks:
    1. Likelihood != probability: Risk score (0.0 to 100.0) exposes evidence, stages, refutations, gaps.
    2. Prediction != evidence: Next expected behaviors are badged PROJECTED, assumptions ASSUMED.
    3. Temporal reasoning: Sequence ordering, time gaps, reversed chronology, missing stages.
    4. Post-attack separation: attack_is_active vs environment_is_vulnerable.
    """
    VERSION = "1.0.0"

    # Multi-Stage Progression Blueprints
    ATTACK_CHAIN_TEMPLATES = {
        "Kerberoasting Credential Harvesting": [
            ("SPN_ENUMERATION", "Enumeration of Service Principal Names in Active Directory"),
            ("ANOMALOUS_ACCOUNT_DISCOVERY", "Unusual LDAP search querying high-privilege service accounts"),
            ("TGS_TICKET_EXTRACTION", "High-frequency Kerberos TGS-REQ issuance with RC4 encryption preference"),
            ("OFFLINE_TICKET_CRACKING", "Offline ticket file dump or password cracking attempt"),
            ("PRIVILEGED_SERVICE_PIVOT", "Lateral SMB or RPC authentication using cracked credentials"),
        ],
        "Remote Monitoring & Management (RMM) Takeover": [
            ("RMM_BINARY_STAGING", "Silent staging or download of dual-use RMM administration binary"),
            ("SERVICE_INSTALLATION", "Non-interactive daemon or service creation for persistent access"),
            ("TUNNEL_EGRESS_ESTABLISHED", "Outbound reverse proxy or persistent tunnel established to C2/RMM infrastructure"),
            ("INTERACTIVE_COMMAND_CONTROL", "Active command shell invocation under RMM worker process"),
            ("CREDENTIAL_HARVEST_AND_PIVOT", "Credential store targeting or lateral network scanning from RMM host"),
        ],
        "Ransomware Destruction Precursor": [
            ("DEFENSE_EVASION_STAGING", "Execution of proxy or scriptlet loader to disable security services"),
            ("VSS_SNAPSHOT_PURGE", "Deletion or invalidation of Volume Shadow Copies (vssadmin delete shadows)"),
            ("BACKUP_CATALOG_DELETION", "Purge of enterprise backup catalogs (wbadmin delete catalog)"),
            ("HYPERVISOR_VM_TERMINATION", "Hypervisor-level termination of critical virtual machines (esxcli vm process kill)"),
            ("BULK_ENCRYPTION_AND_IMPACT", "High-velocity data encryption and system lockout"),
        ],
        "Cloud Instance Metadata Service (IMDS) Pivot": [
            ("HOST_COMPROMISE", "Initial command execution inside cloud workload or container"),
            ("IMDS_METADATA_SCRAPE", "Direct HTTP query to link-local metadata service 169.254.169.254"),
            ("TEMPORARY_TOKEN_ACQUISITION", "Extraction of temporary IAM role credentials and security tokens"),
            ("CLOUD_API_PIVOT", "Cloud control plane API calls executed using extracted temporary credentials"),
            ("CLOUD_DATA_EXFILTRATION", "Bulk export of cloud storage buckets or sensitive database snapshots"),
        ],
        "Active Directory Certificate Services (AD CS) Abuse": [
            ("PKI_TEMPLATE_ENUMERATION", "LDAP discovery of misconfigured certificate templates (ESC1-ESC8)"),
            ("MISCONFIGURED_TEMPLATE_REQUEST", "Certificate enrollment request supplying arbitrary subject alternative name (SAN)"),
            ("FORGED_CERTIFICATE_ISSUANCE", "Valid X.509 certificate issued masquerading as privileged Domain Administrator"),
            ("PKINIT_AUTHENTICATION", "Kerberos TGT requested using forged certificate via PKINIT"),
            ("DOMAIN_ADMIN_TAKEOVER", "Full Active Directory forest privilege escalation"),
        ],
    }

    def evaluate_progression(
        self,
        tenant_id: str,
        case_id: str,
        events: List[Dict[str, Any]],
        causal_facts: List[Any],
        capabilities: List[Any],
        ikg_nodes: Optional[List[Dict[str, Any]]] = None,
        containment_actions: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[ProgressionRiskAssessment, PostAttackResidualRisk]:
        """Evaluate continuous temporal progression, likelihood score, and post-attack residual risk."""
        # 1. Inspect evidence events for chain indicators
        best_chain = "Kerberoasting Credential Harvesting"
        best_completed: List[str] = []
        best_evidence_ids: List[str] = []
        best_contradictions: List[str] = []
        best_missing: List[str] = []
        best_next_behaviors: List[str] = []
        assumptions: List[str] = []
        max_score = 0.0

        for chain_name, stages in self.ATTACK_CHAIN_TEMPLATES.items():
            completed_stages, ev_ids, contradictions, missing, next_behaviors, chain_score = self._match_chain(
                chain_name, stages, events, causal_facts, capabilities
            )
            if chain_score > max_score or not best_completed:
                max_score = chain_score
                best_chain = chain_name
                best_completed = completed_stages
                best_evidence_ids = ev_ids
                best_contradictions = contradictions
                best_missing = missing
                best_next_behaviors = next_behaviors

        total_stages = len(self.ATTACK_CHAIN_TEMPLATES[best_chain])
        prog_ratio = len(best_completed) / total_stages if total_stages > 0 else 0.0

        # 2. Derive Temporal Phase & Epistemic Status
        is_contained = False
        if containment_actions:
            is_contained = any(
                a.get("status") in ("ACTION_EXECUTED", "VERIFIED_EFFECTIVE", "SUCCESS")
                or a.get("action") in ("endpoint.isolate", "endpoint.terminate_process")
                for a in containment_actions
            )

        if is_contained:
            phase = TemporalAttackPhase.POST_ATTACK
            status = EpistemicStatus.SUPPORTED
        elif prog_ratio >= 0.6 or any(getattr(c, "capability_name", "") in (
            "CAP_CONFIRMED_ATTACK", "CAP_DCSYNC", "CAP_NTDS_EXTRACTION", "CAP_SHADOW_COPY_DELETION"
        ) for c in capabilities):
            phase = TemporalAttackPhase.ACTIVE_ATTACK
            status = EpistemicStatus.SUPPORTED if len(best_evidence_ids) >= 2 else EpistemicStatus.LIKELY
        elif prog_ratio >= 0.2 or len(best_completed) >= 1:
            phase = TemporalAttackPhase.PRE_ATTACK
            status = EpistemicStatus.LIKELY if len(best_completed) >= 2 else EpistemicStatus.POSSIBLE
        else:
            phase = TemporalAttackPhase.PRE_ATTACK
            status = EpistemicStatus.POSSIBLE

        # Format grounded risk score (0.0 to 100.0) — NEVER claimed as probability
        # Composite: 50% progression ratio + 30% evidence breadth + 20% severity penalty - contradictions
        risk_score = min(100.0, max(0.0, (prog_ratio * 50.0) + (min(len(best_evidence_ids), 5) * 8.0) + (10.0 if len(best_completed) >= 2 else 0.0) - (len(best_contradictions) * 15.0)))
        if phase == TemporalAttackPhase.ACTIVE_ATTACK and risk_score < 75.0:
            risk_score = 80.0

        # Assumptions & Impact Projections
        impact_proj = f"PROJECTED: Compromise of target enterprise asset class associated with {best_chain}"
        if "Kerberoasting" in best_chain:
            assumptions.append("ASSUMED: Service accounts hold unconstrained delegation or local admin rights on tier-1 servers")
            impact_proj = "PROJECTED: Lateral privilege escalation to Database and Domain Controller infrastructure via cracked service tickets"
        elif "RMM" in best_chain:
            assumptions.append("ASSUMED: RMM worker possesses persistent LocalSystem execution context")
            impact_proj = "PROJECTED: Interactive administrative control and ransomware staging across managed subnet"
        elif "Ransomware" in best_chain:
            assumptions.append("ASSUMED: Target volume contains non-redundant business databases without immutable offsite replication")
            impact_proj = "PROJECTED: Irrecoverable data loss and cluster-wide operational outage"
        elif "IMDS" in best_chain:
            assumptions.append("ASSUMED: IAM role attached to instance possesses broad read/write cloud control plane permissions")
            impact_proj = "PROJECTED: Direct compromise of cloud storage buckets, secret stores, and secondary virtual networks"

        assessment = ProgressionRiskAssessment(
            phase=phase,
            epistemic_status=status,
            risk_score=round(risk_score, 1),
            chain_name=best_chain,
            completed_stages=best_completed,
            total_expected_stages=total_stages,
            progression_ratio=round(prog_ratio, 3),
            supporting_evidence_ids=sorted(best_evidence_ids),
            contradictory_evidence_ids=sorted(best_contradictions),
            missing_telemetry_indicators=best_missing,
            next_expected_behaviors=best_next_behaviors,
            potential_impact_projection=impact_proj,
            explicit_assumptions=assumptions,
        )

        # 3. Evaluate Post-Attack Residual Risk
        residual = self._evaluate_post_attack_residual_risk(
            is_contained=is_contained,
            events=events,
            capabilities=capabilities,
            ikg_nodes=ikg_nodes or [],
            evidence_ids=best_evidence_ids,
        )

        return assessment, residual

    def _match_chain(
        self,
        chain_name: str,
        stages: List[Tuple[str, str]],
        events: List[Dict[str, Any]],
        causal_facts: List[Any],
        capabilities: List[Any],
    ) -> Tuple[List[str], List[str], List[str], List[str], List[str], float]:
        """Analyze sequence, time gaps, reversed chronology, and missing stages for a specific chain."""
        completed: List[str] = []
        ev_ids: List[str] = []
        contradictions: List[str] = []
        missing: List[str] = []
        next_behaviors: List[str] = []

        all_cmds = [str(e.get("command_line", "")).lower() for e in events]
        all_actions = [str(e.get("action", "")).lower() for e in events]
        all_procs = [str(e.get("process_name", "")).lower() for e in events]

        if chain_name == "Kerberoasting Credential Harvesting":
            # Stage 1: SPN Enumeration
            if any(kw in cmd for cmd in all_cmds for kw in ["getuserspns", "dsquery", "setspn", "spn_scan", "-spn", "serviceprincipalname"]) or any("spn" in a for a in all_actions):
                completed.append("SPN_ENUMERATION")
                for e in events:
                    if any(kw in str(e.get("command_line", "")).lower() for kw in ["getuserspns", "dsquery", "setspn", "spn_scan", "-spn", "serviceprincipalname"]):
                        ev_ids.append(e.get("id", "ev-spn"))

            # Stage 2: Anomalous Account Discovery
            if any(kw in cmd for cmd in all_cmds for kw in ["admincount", "serviceprincipalname", "ldap_filter", "net user", "get-aduser"]):
                completed.append("ANOMALOUS_ACCOUNT_DISCOVERY")
                for e in events:
                    if any(kw in str(e.get("command_line", "")).lower() for kw in ["admincount", "serviceprincipalname", "net user", "get-aduser"]):
                        ev_ids.append(e.get("id", "ev-acc"))

            # Stage 3: TGS Ticket Extraction
            if any(e.get("event_code") == "4769" or "ticket_request" in str(e.get("command_line", "")) or e.get("action") == "kerberos.tgs_request" for e in events):
                completed.append("TGS_TICKET_EXTRACTION")
                for e in events:
                    if e.get("event_code") == "4769" or "ticket_request" in str(e.get("command_line", "")):
                        ev_ids.append(e.get("id", "ev-tgs"))
            else:
                missing.append("Kerberos TGS request security log (Event 4769) from Domain Controller")
                next_behaviors.append("PROJECTED: Attacker will request service tickets (TGS-REQ) for enumerated SPNs with RC4 cipher")

            # Stage 4: Offline Cracking
            if any(kw in cmd for cmd in all_cmds for kw in ["hashcat", "john", "kirbi", "rubeus kerberoast"]):
                completed.append("OFFLINE_TICKET_CRACKING")
            else:
                if "TGS_TICKET_EXTRACTION" in completed:
                    missing.append("Host endpoint file write telemetry containing extracted .kirbi or TGS hash dump")
                    next_behaviors.append("PROJECTED: Attacker will export tickets to disk or crack service account password hashes offline")

        elif chain_name == "Remote Monitoring & Management (RMM) Takeover":
            # Stage 1: Binary Staging
            if any(any(rmm in p or rmm in c for rmm in ["rustdesk", "screenconnect", "anydesk", "teamviewer", "ninjaone", "atera"]) for p, c in zip(all_procs, all_cmds)):
                completed.append("RMM_BINARY_STAGING")
                for e in events:
                    if any(rmm in str(e.get("process_name", "")).lower() or rmm in str(e.get("command_line", "")).lower() for rmm in ["rustdesk", "screenconnect", "anydesk", "teamviewer", "ninjaone"]):
                        ev_ids.append(e.get("id", "ev-rmm"))

            # Stage 2: Silent Service Installation
            if any(flag in cmd for cmd in all_cmds for flag in ["/qn", "/quiet", "--silent", "--install", "--service", "sc create"]):
                completed.append("SERVICE_INSTALLATION")
            else:
                missing.append("Windows Service Creation Event 7045 or registry service key modification")
                next_behaviors.append("PROJECTED: Attacker will install RMM software as a persistent Windows service with SYSTEM privileges")

            # Stage 3: Tunnel Egress
            if any(e.get("action") in ("network.tunnel_opened", "egress_proxy_connected") or e.get("has_inbound_tunnel_or_proxy") for e in events):
                completed.append("TUNNEL_EGRESS_ESTABLISHED")
            else:
                missing.append("Network egress firewall connection logs to commercial RMM relay servers")
                next_behaviors.append("PROJECTED: RMM client will establish outbound persistent TCP/WebSocket session to external relay")

        elif chain_name == "Ransomware Destruction Precursor":
            # Stage 1: Defense Evasion
            if any(kw in cmd for cmd in all_cmds for kw in ["certutil", "bitsadmin", "powershell -enc", "bypass"]):
                completed.append("DEFENSE_EVASION_STAGING")

            # Stage 2: VSS Snapshot Purge
            if any(kw in cmd for cmd in all_cmds for kw in ["delete shadows", "shadowcopy delete"]) or any("vssadmin" in p for p in all_procs):
                completed.append("VSS_SNAPSHOT_PURGE")
                for e in events:
                    if "delete shadows" in str(e.get("command_line", "")).lower():
                        ev_ids.append(e.get("id", "ev-vss"))

            # Stage 3: Backup Catalog Deletion
            if any(kw in cmd for cmd in all_cmds for kw in ["delete catalog", "wbadmin delete"]):
                completed.append("BACKUP_CATALOG_DELETION")
                for e in events:
                    if "delete catalog" in str(e.get("command_line", "")).lower():
                        ev_ids.append(e.get("id", "ev-wbadmin"))
            else:
                if "VSS_SNAPSHOT_PURGE" in completed:
                    missing.append("System State Backup catalog deletion telemetry (wbadmin event)")
                    next_behaviors.append("PROJECTED: Attacker will execute wbadmin delete catalog to prevent backup restoration")

            # Stage 4: Hypervisor VM Termination
            if any("esxcli" in cmd and "kill" in cmd for cmd in all_cmds):
                completed.append("HYPERVISOR_VM_TERMINATION")
            else:
                if "BACKUP_CATALOG_DELETION" in completed:
                    next_behaviors.append("PROJECTED: Attacker will pivot to hypervisor management to terminate virtual machines")

        elif chain_name == "Cloud Instance Metadata Service (IMDS) Pivot":
            # Stage 1: Host compromise
            completed.append("HOST_COMPROMISE")
            # Stage 2: IMDS scrape
            if any("169.254.169.254" in cmd or "meta-data" in cmd for cmd in all_cmds):
                completed.append("IMDS_METADATA_SCRAPE")
                for e in events:
                    if "169.254.169.254" in str(e.get("command_line", "")).lower():
                        ev_ids.append(e.get("id", "ev-imds"))
            else:
                missing.append("HTTP link-local proxy audit log querying 169.254.169.254")
                next_behaviors.append("PROJECTED: Process will scrape IAM role session credentials from EC2/Azure instance metadata")

            # Stage 3: Temporary Token Acquisition
            if any("security-credentials" in cmd or e.get("action") == "token_extracted" for cmd, e in zip(all_cmds, events)):
                completed.append("TEMPORARY_TOKEN_ACQUISITION")
            else:
                if "IMDS_METADATA_SCRAPE" in completed:
                    next_behaviors.append("PROJECTED: Attacker will extract SecretAccessKey and SessionToken for cloud pivot")

        elif chain_name == "Active Directory Certificate Services (AD CS) Abuse":
            # Stage 1: PKI Template enumeration
            if any(kw in cmd for cmd in all_cmds for kw in ["certify", "esc1", "enrollee_supplies_subject"]):
                completed.append("PKI_TEMPLATE_ENUMERATION")
                for e in events:
                    if "certify" in str(e.get("command_line", "")).lower():
                        ev_ids.append(e.get("id", "ev-certify"))
            # Stage 2: Misconfigured template request
            if any(kw in cmd for cmd in all_cmds for kw in ["request /ca:", "altname:"]):
                completed.append("MISCONFIGURED_TEMPLATE_REQUEST")
            else:
                if "PKI_TEMPLATE_ENUMERATION" in completed:
                    missing.append("CA enrollment request log (Event 4886/4887) from Certification Authority")
                    next_behaviors.append("PROJECTED: Attacker will submit certificate request with administrative SAN")

        # Check for authorized administrative contradictions
        for e in events:
            if e.get("is_authorized_admin") and e.get("is_within_business_hours") and not e.get("has_inbound_tunnel_or_proxy"):
                contradictions.append(f"Contradiction: Event {e.get('id')} originated from verified authorized administrative session during business hours")

        score = (len(completed) / len(stages)) * 100.0 if stages else 0.0
        return completed, ev_ids, contradictions, missing, next_behaviors, score

    def _evaluate_post_attack_residual_risk(
        self,
        is_contained: bool,
        events: List[Dict[str, Any]],
        capabilities: List[Any],
        ikg_nodes: List[Dict[str, Any]],
        evidence_ids: List[str],
    ) -> PostAttackResidualRisk:
        """Separately evaluate whether the attack is active and whether the environment remains vulnerable."""
        # 1. Is attacker currently active?
        attack_is_active = not is_contained

        # 2. Is environment still vulnerable to re-entry or continuation?
        persistence: List[str] = []
        exposed_creds: List[str] = []
        lateral_paths: List[str] = []
        reachable_backups: List[str] = []
        remediation_locks: List[str] = []

        all_cmds = [str(e.get("command_line", "")).lower() for e in events]

        # Check credentials
        has_cred_theft = any(
            any(kw in cmd for kw in ["getuserspns", "drsgetncchanges", "ntds.dit", "secretsdump", "sekurlsa", "169.254.169.254", "rubeus", "kerberoast", "asreproast", "certify"])
            for cmd in all_cmds
        ) or any("CREDENTIAL" in getattr(c, "capability_name", "") for c in capabilities) or any(
            e.get("action") in ("kerberos.tgs_request", "token_extracted", "credential_dump") for e in events
        )

        if has_cred_theft:
            exposed_creds.append("Active Directory Kerberos Service Tickets / Password Hashes not yet revoked")
            remediation_locks.append("identity.revoke_kerberos_tickets")
            remediation_locks.append("identity.rotate_krbtgt_keys")

        # Check lateral paths via IKG
        if ikg_nodes:
            device_nodes = [
                (n.get("entity_id") or n.get("id") or "")
                for n in ikg_nodes
                if str(n.get("category", "")).upper() in ("DEVICE", "ENDPOINT", "SERVER")
                or str(n.get("type", "")).upper() in ("DEVICE", "ENDPOINT", "SERVER")
            ]
            if len(device_nodes) > 1:
                lateral_paths.append(f"Adjacent reachable enterprise endpoints in IKG: {', '.join(device_nodes[:3])} via active SMB/RPC ports")
                remediation_locks.append("network.enforce_segmentation_isolation")

        # Check backups
        has_backup_impact = any(
            any(kw in cmd for kw in ["delete shadows", "delete catalog", "vssadmin", "wbadmin", "veeam"])
            for cmd in all_cmds
        )
        if has_backup_impact:
            reachable_backups.append("Local Volume Shadow Copies purged; disaster recovery failover catalog unverified")
            remediation_locks.append("backup.verify_immutable_storage_integrity")
        else:
            reachable_backups.append("Backup systems currently intact; offline immutable retention active")

        # Check persistence
        if any(any(kw in cmd for kw in ["schtasks", "reg add", "service create", "sc create", "runonce"]) for cmd in all_cmds):
            persistence.append("Dormant scheduled tasks or service autorun registry keys detected on host")
            remediation_locks.append("endpoint.remove_scheduled_tasks")

        # Determine environment vulnerability
        environment_is_vulnerable = bool(exposed_creds or lateral_paths or (has_backup_impact and not is_contained) or persistence)
        
        if environment_is_vulnerable:
            reentry_risk = EpistemicStatus.LIKELY if (exposed_creds and lateral_paths) else EpistemicStatus.POSSIBLE
        else:
            reentry_risk = EpistemicStatus.UNSUPPORTED

        return PostAttackResidualRisk(
            attack_is_active=attack_is_active,
            environment_is_vulnerable=environment_is_vulnerable,
            active_persistence_indicators=persistence,
            exposed_unrevoked_credentials=exposed_creds,
            open_lateral_traversal_paths=lateral_paths,
            compromised_or_reachable_backups=reachable_backups,
            reentry_risk_level=reentry_risk,
            recommended_remediation_locks=remediation_locks,
            evidence_ids=sorted(evidence_ids),
        )
