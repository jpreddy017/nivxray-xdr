"""Security State Evaluation Engine."""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from ..contracts import (
    CapabilityStatus,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
    ProvenanceEnvelope,
    sha256_digest,
)
from ..model.security_state import (
    DerivedFact,
    ObservedFact,
    SecurityState,
)


class SecurityStateEngine:
    """Deterministic Security State Evaluator.
    
    Transforms raw and canonical evidence into ground-truth observed facts,
    applies deterministic causal deduction to derive security state, and tracks
    epistemic confidence without collapsing into scalar floats.
    """
    VERSION = "1.0.0"

    def evaluate_entity(
        self,
        entity_ref: EntityRef,
        evidence_items: List[Dict[str, Any]],
        previous_state: Optional[SecurityState] = None,
        at_timestamp: str = "2026-09-04T00:00:00Z",
    ) -> SecurityState:
        """Convenience method delegating to evaluate_entity_state."""
        return self.evaluate_entity_state(
            tenant_id=entity_ref.tenant_id,
            entity_ref=entity_ref,
            evidence_items=evidence_items,
            previous_state=previous_state,
            at_timestamp=at_timestamp,
        )

    def evaluate_entity_state(
        self,
        tenant_id: str,
        entity_ref: EntityRef,
        evidence_items: List[Dict[str, Any]],
        previous_state: Optional[SecurityState] = None,
        at_timestamp: str = "2026-09-04T00:00:00Z",
    ) -> SecurityState:
        """Evaluate and produce an immutable SecurityState for an entity."""
        state_seed = f"{tenant_id}:{entity_ref.entity_id}:{at_timestamp}:{len(evidence_items)}"
        state_id = f"state-{sha256_digest(state_seed)[:12]}"
        prev_hash = previous_state.state_hash if previous_state else None
        
        observed_facts: List[ObservedFact] = list(previous_state.observed_facts) if previous_state else []
        derived_facts: List[DerivedFact] = list(previous_state.derived_facts) if previous_state else []
        evidence_refs: set[str] = set(previous_state.evidence_refs) if previous_state else set()
        active_caps: set[str] = set(previous_state.active_capabilities) if previous_state else set()
        assumptions: List[str] = list(previous_state.assumptions) if previous_state else []
        contradictions: List[str] = list(previous_state.contradictions) if previous_state else []
        missing_evidence: List[str] = list(previous_state.missing_evidence) if previous_state else []

        # Process new evidence
        for idx, ev in enumerate(evidence_items):
            ev_type = ev.get("type", "generic")
            source = ev.get("source", "sensor")
            ts = ev.get("timestamp", at_timestamp)
            payload = ev.get("payload") if isinstance(ev.get("payload"), dict) else (ev.get("data") if isinstance(ev.get("data"), dict) else ev)
            ev_id = ev.get("id") or ev.get("evidence_id") or f"ev-{sha256_digest(f'{idx}:{ev_type}:{ts}')[:8]}"
            evidence_refs.add(ev_id)

            fact_seed = f"{ev_id}:{ev_type}:{ts}:{idx}"
            fact = ObservedFact(
                fact_id=f"fact-{sha256_digest(fact_seed)[:10]}",
                property_name=ev_type,
                property_value=payload,
                observed_at=ts,
                source_sensor=source,
                evidence_id=ev_id,
            )
            observed_facts.append(fact)

            cmd = str(payload.get("command_line", "")).lower()
            proc = str(payload.get("process_name", "")).lower()
            user = str(payload.get("user", "")).lower()
            is_admin = payload.get("is_admin", True)
            has_tunnel = payload.get("tunnel", False)

            cap_val = payload.get("capability") or ev.get("capability")
            if cap_val:
                active_caps.add(str(cap_val))

            # Rule 1: Dual-use tools & CLI downloads
            if any(tool in proc or tool in cmd for tool in ["powershell", "cmd.exe", "wmic", "psexec", "anydesk", "teamviewer", "screenconnect", "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32"]):
                active_caps.add("CAP_ADMIN_EXECUTION")
                if "anydesk" in proc or "anydesk" in cmd:
                    if not is_admin or has_tunnel or "--install" in cmd:
                        active_caps.add("CAP_ABUSED_RMM")

                if "downloadstring" in cmd or "iwr" in cmd or "curl" in cmd or "wget" in cmd:
                    active_caps.add("CAP_PAYLOAD_DOWNLOAD")
                    derived_facts.append(DerivedFact(
                        fact_id=f"der-{sha256_digest(f'RULE_SUSPICIOUS_CLI_DOWNLOAD:{fact.fact_id}')[:10]}",
                        property_name="remote_payload_retrieval",
                        property_value=True,
                        derived_at=ts,
                        rule_or_model="RULE_SUSPICIOUS_CLI_DOWNLOAD",
                        confidence=0.95,
                        supporting_fact_ids=[fact.fact_id],
                    ))

            # Rule 1B: Living-off-the-Land (LOLBAS) Proxy Execution
            if any(lol in proc or lol in cmd for lol in ["certutil", "bitsadmin", "mshta", "regsvr32", "rundll32", "installutil", "msbuild"]):
                if any(ev_kw in cmd for ev_kw in ["-decode", "-urlcache", "scrobj.dll", "javascript:", "/format:", ".xsl", "sct"]):
                    active_caps.add("CAP_LOLBAS_EXECUTION")
                    derived_facts.append(DerivedFact(
                        fact_id=f"der-{sha256_digest(f'RULE_LOLBAS_PROXY_EXECUTION:{fact.fact_id}')[:10]}",
                        property_name="lolbas_proxy_execution",
                        property_value=True,
                        derived_at=ts,
                        rule_or_model="RULE_LOLBAS_PROXY_EXECUTION",
                        confidence=0.96,
                        supporting_fact_ids=[fact.fact_id],
                    ))

            # Rule 2: Persistence indicators
            if any(k in cmd for k in ["schtasks /create", "reg add", "currentversion\\run", "startup"]):
                active_caps.add("CAP_PERSISTENCE")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_PERSISTENCE_REGISTRATION:{fact.fact_id}')[:10]}",
                    property_name="persistence_mechanism_established",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_PERSISTENCE_REGISTRATION",
                    confidence=0.92,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Rule 3: Credential dumping / token manipulation
            if any(k in cmd for k in ["sekurlsa", "minidump", "lsass", "comsvcs.dll", "ntdsutil"]):
                active_caps.add("CAP_CREDENTIAL_DUMPING")
                active_caps.add("CAP_CREDENTIAL_ACCESS")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_CREDENTIAL_ACCESS:{fact.fact_id}')[:10]}",
                    property_name="credential_material_accessed",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_CREDENTIAL_ACCESS",
                    confidence=0.98,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Rule 3B: Kerberoasting Attack Chain
            if any(k in cmd for k in ["getuserspns", "kerberoast", "rubeus"]) or ev.get("action") == "kerberos.tgs_request" or payload.get("event_code") == "4769":
                active_caps.add("CAP_KERBEROASTING")
                active_caps.add("CAP_CREDENTIAL_ACCESS")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_KERBEROASTING_ACTIVITY:{fact.fact_id}')[:10]}",
                    property_name="kerberoasting_activity_detected",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_KERBEROASTING_ACTIVITY",
                    confidence=0.96,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Rule 3C: Active Directory DCSync Replication Abuse
            if any(k in cmd for k in ["drsgetncchanges", "lsadump::dcsync", "secretsdump"]) or payload.get("protocol") == "DRSUAPI":
                active_caps.add("CAP_DCSYNC")
                active_caps.add("CAP_AD_REPLICATION_ABUSE")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_DCSYNC_REPLICATION_ABUSE:{fact.fact_id}')[:10]}",
                    property_name="directory_replication_compromise",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_DCSYNC_REPLICATION_ABUSE",
                    confidence=0.99,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Rule 4: Lateral Movement & Multi-Host Traversal
            if (
                any(k in proc or k in cmd for k in ["psexec", "wmic", "winrm", "powershell"])
                and any(t_kw in cmd for t_kw in ["/node:", "admin$", "invoke-command", "-computername"])
            ) or (
                ev.get("host_id") and payload.get("target_host_id") and ev.get("host_id") != payload.get("target_host_id")
            ):
                active_caps.add("CAP_LATERAL_MOVEMENT")
                active_caps.add("CAP_MULTI_HOST_TRAVERSAL")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_MULTI_HOST_TRAVERSAL:{fact.fact_id}')[:10]}",
                    property_name="cross_host_propagation",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_MULTI_HOST_TRAVERSAL",
                    confidence=0.94,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Rule 5: Cloud Identity Abuse
            if "assume-role" in cmd or "sts" in cmd:
                active_caps.add("CAP_CLOUD_PRIV_ESC")

            # Rule 6: Backup Targeting
            if "delete shadows" in cmd or "vssadmin" in cmd or "wbadmin" in cmd:
                active_caps.add("CAP_BACKUP_TAMPERING")

            # Rule 7: Hypervisor Targeting
            if "esxcli" in cmd or "vm process kill" in cmd or "vim-cmd" in cmd:
                active_caps.add("CAP_HYPERVISOR_TAMPERING")

            # Phase 7 Rule 8: RMM Silent Staging & Takeover
            if any(rmm in proc or rmm in cmd for rmm in ["rustdesk", "screenconnect", "anydesk", "teamviewer", "ninjaone", "atera"]) and (
                not is_admin or has_tunnel or any(flag in cmd for flag in ["/qn", "/quiet", "--silent", "--install", "--service"])
            ):
                active_caps.add("CAP_RMM_REMOTE_CONTROL")
                active_caps.add("CAP_RMM_SESSION_STAGING")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_RMM_REMOTE_TAKEOVER:{fact.fact_id}')[:10]}",
                    property_name="rmm_remote_takeover",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_RMM_REMOTE_TAKEOVER",
                    confidence=0.96,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Phase 7 Rule 9: Active Directory NTDS.dit Extraction
            if any(kw in cmd for kw in ["ntds.dit", "esentutl", "invokeninjacopy"]) or ("vssadmin" in cmd and "create shadow" in cmd):
                active_caps.add("CAP_NTDS_EXTRACTION")
                active_caps.add("CAP_CREDENTIAL_ACCESS")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_NTDS_DATABASE_EXTRACTION:{fact.fact_id}')[:10]}",
                    property_name="ntds_dit_extracted",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_NTDS_DATABASE_EXTRACTION",
                    confidence=0.99,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Phase 7 Rule 10: AS-REP Roasting & Kerberos Forgery
            if any(kw in cmd for kw in ["asreproast", "get-asreproast", "dont_req_preauth"]) or (payload.get("event_code") == "4768" and str(payload.get("preauth_type", "")) == "0"):
                active_caps.add("CAP_ASREP_ROASTING")
                active_caps.add("CAP_CREDENTIAL_ACCESS")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_ASREP_ROASTING_HARVEST:{fact.fact_id}')[:10]}",
                    property_name="asrep_roasting_detected",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_ASREP_ROASTING_HARVEST",
                    confidence=0.97,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Phase 7 Rule 11: AD CS Certificate Template Abuse
            if any(kw in cmd for kw in ["certify", "altname:", "enrollee_supplies_subject", "pkinit"]):
                active_caps.add("CAP_ADCS_ABUSE")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_ADCS_TEMPLATE_EXPLOITATION:{fact.fact_id}')[:10]}",
                    property_name="adcs_template_abuse",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_ADCS_TEMPLATE_EXPLOITATION",
                    confidence=0.96,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Phase 7 Rule 12: Cloud IMDS Token Theft & Pivot
            if "169.254.169.254" in cmd or ("meta-data" in cmd and "security-credentials" in cmd):
                active_caps.add("CAP_CLOUD_METADATA_ACCESS")
                active_caps.add("CAP_CLOUD_TOKEN_THEFT")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_CLOUD_METADATA_HARVEST:{fact.fact_id}')[:10]}",
                    property_name="cloud_metadata_harvest",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_CLOUD_METADATA_HARVEST",
                    confidence=0.97,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Phase 7 Rule 13: Volume Shadow Copy & Backup Destruction
            if any(kw in cmd for kw in ["delete shadows", "shadowcopy delete", "delete catalog"]) or ("vssadmin" in cmd and "delete" in cmd) or ("wbadmin" in cmd and "delete" in cmd):
                active_caps.add("CAP_SHADOW_COPY_DELETION")
                active_caps.add("CAP_BACKUP_TAMPERING")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_VSS_BACKUP_DESTRUCTION:{fact.fact_id}')[:10]}",
                    property_name="backup_shadow_copy_destroyed",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_VSS_BACKUP_DESTRUCTION",
                    confidence=0.99,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Phase 7 Rule 14: Hypervisor VM Kill
            if "esxcli" in cmd and "kill" in cmd:
                active_caps.add("CAP_HYPERVISOR_COMPROMISE")
                derived_facts.append(DerivedFact(
                    fact_id=f"der-{sha256_digest(f'RULE_HYPERVISOR_VM_TERMINATION:{fact.fact_id}')[:10]}",
                    property_name="hypervisor_vm_terminated",
                    property_value=True,
                    derived_at=ts,
                    rule_or_model="RULE_HYPERVISOR_VM_TERMINATION",
                    confidence=0.99,
                    supporting_fact_ids=[fact.fact_id],
                ))

            # Check contradictions
            if payload.get("conflicting_status") or payload.get("contradiction"):
                contradictions.append(f"Contradictory evidence reported by {source} on {ev_type}")

        # Derive classification & epistemic status
        if contradictions:
            epistemic = EpistemicStatus.CONTRADICTED
        elif any(f.property_name in ("credential_material_accessed", "directory_replication_compromise", "ntds_dit_extracted", "backup_shadow_copy_destroyed") for f in derived_facts):
            epistemic = EpistemicStatus.SUPPORTED
        elif derived_facts:
            epistemic = EpistemicStatus.DERIVED
        elif observed_facts:
            epistemic = EpistemicStatus.OBSERVED
        else:
            epistemic = EpistemicStatus.UNSUPPORTED

        # Determine CapabilityStatus
        high_risk_caps = {
            "CAP_CREDENTIAL_DUMPING", "CAP_LATERAL_MOVEMENT", "CAP_CLOUD_PRIV_ESC",
            "CAP_BACKUP_TAMPERING", "CAP_HYPERVISOR_TAMPERING", "CAP_ABUSED_RMM",
            "CAP_KERBEROASTING", "CAP_DCSYNC", "CAP_AD_REPLICATION_ABUSE",
            "CAP_MULTI_HOST_TRAVERSAL", "CAP_LOLBAS_EXECUTION",
            # Phase 7
            "CAP_RMM_REMOTE_CONTROL", "CAP_NTDS_EXTRACTION", "CAP_ASREP_ROASTING",
            "CAP_ADCS_ABUSE", "CAP_CLOUD_METADATA_ACCESS", "CAP_SHADOW_COPY_DELETION",
            "CAP_HYPERVISOR_COMPROMISE",
        }
        if active_caps.intersection(high_risk_caps) or ("CAP_PAYLOAD_DOWNLOAD" in active_caps and "CAP_PERSISTENCE" in active_caps):
            classification = CapabilityStatus.CONFIRMED_ATTACK
        elif "CAP_PAYLOAD_DOWNLOAD" in active_caps or "CAP_PERSISTENCE" in active_caps:
            classification = CapabilityStatus.ABUSED_CAPABILITY
        elif "CAP_ADMIN_EXECUTION" in active_caps:
            if is_admin and not derived_facts and not has_tunnel:
                classification = CapabilityStatus.AUTHORIZED_USE
            else:
                classification = CapabilityStatus.SUSPICIOUS_USE
        elif observed_facts:
            classification = CapabilityStatus.AUTHORIZED_USE
        else:
            classification = CapabilityStatus.LEGITIMATE_CAPABILITY

        prov = ProvenanceEnvelope(
            engine="SecurityStateEngine",
            version=self.VERSION,
            at=at_timestamp,
            upstream_evidence_ids=sorted(list(evidence_refs)),
        )

        return SecurityState(
            state_id=state_id,
            tenant_id=tenant_id,
            entity_ref=entity_ref,
            timestamp=at_timestamp,
            provenance=prov,
            epistemic_status=epistemic,
            classification=classification,
            previous_state_hash=prev_hash,
            evidence_refs=sorted(list(evidence_refs)),
            observed_facts=observed_facts,
            derived_facts=derived_facts,
            active_capabilities=sorted(list(active_caps)),
            assumptions=assumptions,
            contradictions=contradictions,
            missing_evidence=missing_evidence,
        )
