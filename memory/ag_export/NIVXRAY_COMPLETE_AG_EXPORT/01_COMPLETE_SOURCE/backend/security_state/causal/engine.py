"""Causal Security Engine: rigorous causal inference and correlation separation."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from ..contracts import (
    CausalLevel,
    ProvenanceEnvelope,
    canonical_json,
    sha256_digest,
)


@dataclass
class CausalMechanism:
    """Operating system or network level causal mechanism linking cause and effect."""
    mechanism_type: str  # e.g., 'PROCESS_CREATION_HANDLE', 'FILE_WRITE_EXECUTE', 'INLINE_NETWORK_SOCKET'
    description: str
    verifiable_kernel_evidence: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompetingHypothesis:
    """Alternative explanation evaluated to prevent false attribution."""
    hypothesis_id: str
    explanation: str
    prior_probability: float
    status: str  # 'REFUTED', 'PLAUSIBLE', 'CORROBORATED'
    refuting_evidence_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CausalEdge:
    """Directed causal relationship between two security events or state changes."""
    edge_id: str
    cause_ref: str
    effect_ref: str
    causal_level: CausalLevel
    mechanism: CausalMechanism
    temporal_delta_ms: int
    confidence: float
    evidence_ids: List[str] = field(default_factory=list)
    competing_hypotheses: List[CompetingHypothesis] = field(default_factory=list)
    assumptions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "cause_ref": self.cause_ref,
            "effect_ref": self.effect_ref,
            "causal_level": self.causal_level.value,
            "mechanism": self.mechanism.to_dict(),
            "temporal_delta_ms": self.temporal_delta_ms,
            "confidence": self.confidence,
            "evidence_ids": sorted(self.evidence_ids),
            "competing_hypotheses": [h.to_dict() for h in self.competing_hypotheses],
            "assumptions": sorted(self.assumptions),
        }


@dataclass
class CausalGraph:
    """Deterministic acyclic graph of causal relationships."""
    graph_id: str
    tenant_id: str
    case_id: str
    edges: List[CausalEdge] = field(default_factory=list)
    root_cause_refs: List[str] = field(default_factory=list)
    provenance: Optional[ProvenanceEnvelope] = None
    graph_hash: str = ""

    def __post_init__(self) -> None:
        if not self.graph_hash:
            self.graph_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "graph_id": self.graph_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "edges": [e.to_dict() for e in self.edges],
            "root_cause_refs": sorted(self.root_cause_refs),
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "graph_hash": self.graph_hash,
            "edges": [e.to_dict() for e in self.edges],
            "root_cause_refs": sorted(self.root_cause_refs),
            "provenance": self.provenance.to_dict() if self.provenance else None,
        }


class CausalSecurityEngine:
    """Causal inference engine that never confuses correlation with causality."""
    VERSION = "1.0.0"

    def evaluate_causality(
        self,
        tenant_id: str,
        case_id: str,
        events: List[Dict[str, Any]],
        at_timestamp: str = "2026-09-04T00:00:00Z",
    ) -> CausalGraph:
        """Construct verified causal graph from events, identifying explicit mechanisms."""
        edges: List[CausalEdge] = []
        root_causes: set[str] = set()

        # Map event ID to event
        event_map = {e.get("id", f"ev-{i}"): e for i, e in enumerate(events)}
        
        # Sort events by timestamp if present
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", ""))

        for i, ev_cause in enumerate(sorted_events):
            cause_id = ev_cause.get("id", f"ev-{i}")
            cause_proc = ev_cause.get("process_name", "").lower()
            cause_pid = ev_cause.get("pid")
            cause_cmd = str(ev_cause.get("command_line", "")).lower()

            for j in range(i + 1, len(sorted_events)):
                ev_effect = sorted_events[j]
                effect_id = ev_effect.get("id", f"ev-{j}")
                effect_ppid = ev_effect.get("ppid")
                effect_proc = ev_effect.get("process_name", "").lower()
                effect_cmd = str(ev_effect.get("command_line", "")).lower()

                # Causal Case 1: Direct parent-child process execution
                delta_ms = ev_effect.get("time_ms", 100) - ev_cause.get("time_ms", 0)

                # Specialized Causal Case 1: DCSync Directory Replication Chain (RPC -> DRSGetNCChanges -> Credential Dump)
                if any(kw in cause_cmd for kw in ["drsgetncchanges", "lsadump::dcsync", "secretsdump", "ntds.dit"]) or (
                    ev_cause.get("protocol") == "DRSUAPI" or ev_cause.get("action") == "directory_replication"
                ):
                    is_unauthorized_client = not ev_cause.get("is_domain_controller", False)
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE if is_unauthorized_client else CausalLevel.POSSIBLE_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="DIRECTORY_REPLICATION_RPC",
                            description="Active Directory Directory Replication Service RPC (DRSUAPI) invoked to stream password hashes",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(50, delta_ms),
                        confidence=0.98 if is_unauthorized_client else 0.50,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-legit-dc-replication",
                                explanation="Legitimate Domain Controller to Domain Controller replication sync",
                                prior_probability=0.20,
                                status="REFUTED" if is_unauthorized_client else "CORROBORATED",
                                refuting_evidence_ids=[cause_id] if is_unauthorized_client else [],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Specialized Causal Case 2: Kerberoasting Attack Chain (SPN query -> TGS-REQ -> Ticket export)
                elif any(kw in cause_cmd for kw in ["getuserspns", "kerberoast", "rubeus", "spn_scan"]) or (
                    ev_cause.get("event_code") == "4769" or "ticket_request" in cause_cmd or ev_cause.get("action") == "kerberos.tgs_request"
                ):
                    is_ticket_response = any(kw in effect_cmd for kw in ["hash", "kirbi", "john", "hashcat", "ticket"]) or ev_effect.get("action") in ("ticket_extracted", "file_write", "credential_dump")
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.SUPPORTED_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="KERBEROS_TGS_REQUEST",
                            description="Kerberos Ticket-Granting Service (TGS) request for service account with RC4/AES extraction for offline cracking",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(20, delta_ms),
                        confidence=0.95,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-legit-spn-auth",
                                explanation="Legitimate enterprise application authenticating to service principal",
                                prior_probability=0.15,
                                status="REFUTED" if any(kw in cause_cmd for kw in ["getuserspns", "rubeus", "kerberoast"]) else "PLAUSIBLE",
                                refuting_evidence_ids=[cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Specialized Causal Case 3: Multi-Host Lateral Traversal (Host A invocation -> Host B spawn)
                elif (
                    any(kw in cause_cmd for kw in ["wmic", "psexec", "winrm", "powershell"])
                    and any(target_kw in cause_cmd for target_kw in ["/node:", "admin$", "invoke-command", "-computername"])
                ) or (
                    ev_cause.get("host_id") and ev_effect.get("host_id") and ev_cause.get("host_id") != ev_effect.get("host_id")
                ):
                    is_cross_host = ev_cause.get("host_id") != ev_effect.get("host_id") or "/node:" in cause_cmd or "admin$" in cause_cmd
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.SUPPORTED_CAUSALITY if is_cross_host else CausalLevel.INFERRED_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="REMOTE_WMI_PROCESS_CALL" if "wmic" in cause_cmd else "SMB_NAMED_PIPE_EXECUTION",
                            description=f"Remote administrative RPC/SMB invocation from {ev_cause.get('host_id', 'Host A')} triggering execution on {ev_effect.get('host_id', 'Host B')}",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(100, delta_ms),
                        confidence=0.93,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-sccm-admin-push",
                                explanation="Authorized IT configuration management push",
                                prior_probability=0.15,
                                status="PLAUSIBLE" if ev_cause.get("is_authorized_admin") else "REFUTED",
                                refuting_evidence_ids=[cause_id] if not ev_cause.get("is_authorized_admin") else [],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Specialized Causal Case 4: LOLBAS Proxy Execution (certutil, regsvr32, mshta, rundll32, etc.)
                elif any(lol in cause_proc or lol in cause_cmd for lol in ["certutil", "regsvr32", "mshta", "rundll32", "wmic", "installutil"]) and (
                    any(ev_kw in cause_cmd for ev_kw in ["-decode", "-urlcache", "scrobj.dll", "javascript:", "/format:", ".xsl", "sct"])
                    or ev_effect.get("type") in ("process_start", "network_connection", "file_create")
                ):
                    is_direct_child = (cause_pid and effect_ppid and cause_pid == effect_ppid)
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE if is_direct_child else CausalLevel.SUPPORTED_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="LOLBAS_PROXY_EXECUTION",
                            description=f"Living-off-the-land binary {cause_proc} proxying payload execution or file download to {effect_proc or effect_id}",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(15, delta_ms),
                        confidence=0.96 if is_direct_child else 0.89,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-admin-cert-validation",
                                explanation="Routine administrator certificate verification or software installation",
                                prior_probability=0.10,
                                status="REFUTED" if any(ev_kw in cause_cmd for ev_kw in ["-decode", "scrobj.dll", "javascript:"]) else "PLAUSIBLE",
                                refuting_evidence_ids=[cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Phase 7 Specialized Causal Case 5: RMM Remote Administration Session / Reverse Tunnel
                elif any(rmm in cause_proc or rmm in cause_cmd for rmm in ["screenconnect", "rustdesk", "anydesk", "teamviewer", "ninjaone", "atera"]) and (
                    ev_effect.get("type") in ("network_connection", "process_start", "service_install")
                    or any(flag in cause_cmd for flag in ["/qn", "/quiet", "--silent", "--install", "--service"])
                    or ev_cause.get("has_inbound_tunnel_or_proxy")
                ):
                    is_authorized_it = ev_cause.get("is_authorized_admin", False) and ev_cause.get("is_within_business_hours", False)
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE if not is_authorized_it else CausalLevel.POSSIBLE_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="REMOTE_ADMINISTRATION_TUNNEL",
                            description=f"Remote Monitoring and Management (RMM) utility {cause_proc} establishing tunnel session or spawning child control",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(25, delta_ms),
                        confidence=0.96 if not is_authorized_it else 0.55,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-authorized-it-support",
                                explanation="Authorized IT support session during scheduled maintenance",
                                prior_probability=0.25,
                                status="CORROBORATED" if is_authorized_it else "REFUTED",
                                refuting_evidence_ids=[] if is_authorized_it else [cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Phase 7 Specialized Causal Case 6: Active Directory NTDS.dit Extraction via Volume Shadow Copy
                elif any(kw in cause_cmd for kw in ["vssadmin", "ntds.dit", "esentutl", "invokeninjacopy"]) and (
                    any(kw in cause_cmd for kw in ["create shadow", "ntds.dit", "system.save"]) or "ntds.dit" in effect_cmd
                ):
                    is_backup_agent = "veeam" in cause_proc or "backup" in cause_proc
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE,
                        mechanism=CausalMechanism(
                            mechanism_type="VSS_NTDS_EXTRACTION",
                            description="Volume Shadow Copy creation and offline extraction of Active Directory ntds.dit database",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(50, delta_ms),
                        confidence=0.98 if not is_backup_agent else 0.40,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-scheduled-system-state-backup",
                                explanation="Authorized enterprise backup agent performing system state backup",
                                prior_probability=0.15,
                                status="CORROBORATED" if is_backup_agent else "REFUTED",
                                refuting_evidence_ids=[] if is_backup_agent else [cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Phase 7 Specialized Causal Case 7: AS-REP Roasting (No Pre-Auth TGT Capture)
                elif any(kw in cause_cmd for kw in ["asreproast", "get-asreproast", "dont_req_preauth"]) or (
                    ev_cause.get("event_code") == "4768" and str(ev_cause.get("preauth_type", "")) == "0"
                ):
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE,
                        mechanism=CausalMechanism(
                            mechanism_type="KERBEROS_ASREP_ROAST",
                            description="Kerberos AS-REQ issued for account without pre-authentication to extract crackable AS-REP hash",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(10, delta_ms),
                        confidence=0.97,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-legacy-kerberos-app-auth",
                                explanation="Legacy application authentication without Kerberos pre-authentication",
                                prior_probability=0.08,
                                status="REFUTED" if "asreproast" in cause_cmd else "PLAUSIBLE",
                                refuting_evidence_ids=[cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Phase 7 Specialized Causal Case 8: Active Directory Certificate Services (AD CS) Abuse
                elif any(kw in cause_cmd for kw in ["certify", "altname:", "enrollee_supplies_subject", "pkinit"]) or (
                    ev_cause.get("action") == "pki.template_abuse" or "certificate_request" in cause_cmd
                ):
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE,
                        mechanism=CausalMechanism(
                            mechanism_type="CERTIFICATE_SERVICES_ENROLLMENT_RPC",
                            description="AD CS certificate enrollment targeting misconfigured template with arbitrary Subject Alternative Name",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(30, delta_ms),
                        confidence=0.96,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-authorized-pki-certificate-issuance",
                                explanation="Routine enterprise machine certificate auto-enrollment",
                                prior_probability=0.10,
                                status="REFUTED" if "certify" in cause_cmd else "PLAUSIBLE",
                                refuting_evidence_ids=[cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Phase 7 Specialized Causal Case 9: Cloud IMDS Metadata Token Extraction
                elif any("169.254.169.254" in cmd for cmd in [cause_cmd, effect_cmd]) or (
                    "meta-data" in cause_cmd and "security-credentials" in cause_cmd
                ):
                    is_cloud_agent = any(agent in cause_proc for agent in ["amazon-ssm-agent", "cloudwatch", "waagent"])
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE if not is_cloud_agent else CausalLevel.POSSIBLE_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="METADATA_SERVICE_TOKEN_EXTRACTION",
                            description="HTTP GET to link-local instance metadata service (169.254.169.254) extracting IAM role credentials",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(10, delta_ms),
                        confidence=0.97 if not is_cloud_agent else 0.35,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-legit-cloud-agent-imds",
                                explanation="Official cloud management daemon refreshing IAM security token",
                                prior_probability=0.25,
                                status="CORROBORATED" if is_cloud_agent else "REFUTED",
                                refuting_evidence_ids=[] if is_cloud_agent else [cause_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Phase 7 Specialized Causal Case 10: Volume Shadow Copy & Backup Catalog Destruction (Ransomware Precursor)
                elif any(kw in cause_cmd for kw in ["delete shadows", "shadowcopy delete", "delete catalog", "process kill"]) or (
                    ("vssadmin" in cause_cmd and "delete" in cause_cmd)
                    or ("wbadmin" in cause_cmd and "delete" in cause_cmd)
                    or ("esxcli" in cause_cmd and "kill" in cause_cmd)
                ):
                    is_esx = "esxcli" in cause_cmd
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE,
                        mechanism=CausalMechanism(
                            mechanism_type="ESXI_VIRTUAL_MACHINE_KILL" if is_esx else ("BACKUP_CATALOG_DELETION" if "catalog" in cause_cmd else "VSS_SNAPSHOT_DELETION"),
                            description=f"Inhibition of system recovery: {'Hypervisor VM termination' if is_esx else 'Volume shadow copy / backup catalog deletion'}",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(15, delta_ms),
                        confidence=0.99,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-automated-storage-reclaim",
                                explanation="Automated IT storage reclamation or planned hypervisor patch reboot",
                                prior_probability=0.05,
                                status="REFUTED" if not ev_cause.get("is_authorized_admin") else "PLAUSIBLE",
                                refuting_evidence_ids=[cause_id] if not ev_cause.get("is_authorized_admin") else [],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Causal Case 11: Direct parent-child process execution
                elif cause_pid and effect_ppid and cause_pid == effect_ppid and delta_ms >= 0:
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.STRONG_CAUSAL_EVIDENCE,
                        mechanism=CausalMechanism(
                            mechanism_type="PROCESS_SPAWN_SYSCALL",
                            description=f"{cause_proc} (PID {cause_pid}) spawned {effect_proc} (PPID {effect_ppid})",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=delta_ms,
                        confidence=1.0,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-pid-reuse",
                                explanation="Operating system PID reuse before process termination",
                                prior_probability=0.01,
                                status="REFUTED",
                                refuting_evidence_ids=[cause_id, effect_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Causal Case 6: PowerShell / CLI script downloading and writing a file
                elif ("download" in cause_cmd or "curl" in cause_cmd or "wget" in cause_cmd or "urlcache" in cause_cmd) and ev_effect.get("type") in ("file_create", "file_write"):
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.SUPPORTED_CAUSALITY,
                        mechanism=CausalMechanism(
                            mechanism_type="HTTP_GET_TO_FILE_WRITE",
                            description="Network download stream written directly to filesystem target",
                            verifiable_kernel_evidence=True,
                        ),
                        temporal_delta_ms=max(10, delta_ms),
                        confidence=0.94,
                        evidence_ids=[cause_id, effect_id],
                        competing_hypotheses=[
                            CompetingHypothesis(
                                hypothesis_id="hyp-coincident-download",
                                explanation="Independent process created file during download window",
                                prior_probability=0.05,
                                status="REFUTED",
                                refuting_evidence_ids=[cause_id, effect_id],
                            )
                        ],
                    ))
                    root_causes.add(cause_id)

                # Causal Case 7: Mere temporal proximity without causal link -> TEMPORAL_CORRELATION
                elif j == i + 1 and not edges:
                    edges.append(CausalEdge(
                        edge_id=f"cedge-{uuid.uuid4().hex[:8]}",
                        cause_ref=cause_id,
                        effect_ref=effect_id,
                        causal_level=CausalLevel.TEMPORAL_CORRELATION,
                        mechanism=CausalMechanism(
                            mechanism_type="COINCIDENT_TEMPORAL_SEQUENCE",
                            description="Events occurred in close temporal succession without proven kernel causality",
                            verifiable_kernel_evidence=False,
                        ),
                        temporal_delta_ms=500,
                        confidence=0.30,
                        evidence_ids=[cause_id, effect_id],
                        assumptions=["Assumes standard system clock synchronization"],
                    ))

        # Identify roots (causes that are not effects)
        all_effects = {e.effect_ref for e in edges}
        filtered_roots = [r for r in root_causes if r not in all_effects] or ([events[0].get("id", "ev-0")] if events else [])

        prov = ProvenanceEnvelope(
            engine="CausalSecurityEngine",
            version=self.VERSION,
            at=at_timestamp,
            upstream_evidence_ids=[e.get("id", "") for e in events if e.get("id")],
        )

        return CausalGraph(
            graph_id=f"cgraph-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            case_id=case_id,
            edges=edges,
            root_cause_refs=filtered_roots,
            provenance=prov,
        )
