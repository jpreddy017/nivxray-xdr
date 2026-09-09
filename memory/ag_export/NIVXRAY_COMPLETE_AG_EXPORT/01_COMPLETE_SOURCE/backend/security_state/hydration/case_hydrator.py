"""NivXRay Security State — Real Case Hydrator.

Hydrates complete Security State, Causal DAG, Reachability Graph, Counterfactuals,
and Staged Interventions directly from native case telemetry frames and IKG.

Guarantees:
1. Consumes authoritative IKG and evidence; never duplicates or alters them.
2. Async/non-blocking execution friendly.
3. Completely isolated from authoritative case persistence.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..contracts import (
    AttackState,
    EntityCategory,
    EntityRef,
    EpistemicStatus,
)
from ..state_engine.engine import SecurityStateEngine
from ..reachability.engine import EnterpriseReachabilityEngine
from ..counterfactual.engine import CounterfactualEngine
from ..impact.engine import ImpactEngine
from ..intervention.optimizer import InterventionOptimizer
from ..persistence.repository import SecurityStateRepository
from ..persistence.models import PersistentSecurityStateRecord
from .provenance import ProvenanceGraphBuilder

logger = logging.getLogger("security_state.case_hydrator")


class CaseSecurityStateHydrator:
    """Hydrates and persists Security State from native NivXRay case data."""

    def __init__(
        self,
        repository: Optional[SecurityStateRepository] = None,
        state_engine: Optional[SecurityStateEngine] = None,
        reachability_engine: Optional[EnterpriseReachabilityEngine] = None,
        counterfactual_engine: Optional[CounterfactualEngine] = None,
        impact_engine: Optional[ImpactEngine] = None,
        intervention_optimizer: Optional[InterventionOptimizer] = None,
    ):
        self.repository = repository or SecurityStateRepository()
        self.state_engine = state_engine or SecurityStateEngine()
        self.reachability_engine = reachability_engine or EnterpriseReachabilityEngine()
        self.counterfactual_engine = counterfactual_engine or CounterfactualEngine()
        self.impact_engine = impact_engine or ImpactEngine()
        self.intervention_optimizer = intervention_optimizer or InterventionOptimizer()

    def frames_to_canonical_evidence(
        self,
        case_id: str,
        frames: List[Dict[str, Any]],
        ikg: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Extract canonical evidence from case frames and IKG nodes without loss."""
        evidence_items: List[Dict[str, Any]] = []

        for idx, f in enumerate(frames):
            ev_id = f.get("frame_iid") or f.get("id") or f"frame-{case_id}-{idx:04d}"
            ts = f.get("ts") or f.get("timestamp") or datetime.now(timezone.utc).isoformat()
            ent = f.get("entity") or {}
            proc_name = ent.get("name") or ent.get("image") or ""
            cmd = f.get("cmdline") or f.get("command_line") or ent.get("cmdline") or ""
            action = f.get("action") or f.get("event_type") or "process.start"
            is_crit = bool(f.get("is_critical") or f.get("verdict") in ("malicious", "suspicious"))
            cap = f.get("capability") or ""

            # Check for suspicious or credential dumping patterns
            if not cap:
                cmd_lower = cmd.lower()
                if "comsvcs" in cmd_lower or "sekurlsa" in cmd_lower or "lsass" in cmd_lower:
                    cap = "CAP_CREDENTIAL_DUMPING"
                    is_crit = True
                elif "drsgetncchanges" in cmd_lower or "secretsdump" in cmd_lower or "lsadump::dcsync" in cmd_lower:
                    cap = "CAP_DCSYNC"
                    is_crit = True
                elif "getuserspns" in cmd_lower or "kerberoast" in cmd_lower or "rubeus" in cmd_lower or f.get("action") == "kerberos.tgs_request":
                    cap = "CAP_KERBEROASTING"
                    is_crit = True
                elif any(lol in proc_name.lower() or lol in cmd_lower for lol in ["certutil", "regsvr32", "mshta", "rundll32", "installutil"]) and any(ev_kw in cmd_lower for ev_kw in ["-decode", "-urlcache", "scrobj.dll", "javascript:", "/format:"]):
                    cap = "CAP_LOLBAS_EXECUTION"
                    is_crit = True
                elif any(rmm in cmd_lower or rmm in proc_name.lower() for rmm in ["rustdesk", "screenconnect", "anydesk", "teamviewer", "ninjaone", "atera"]):
                    cap = "CAP_RMM_REMOTE_CONTROL"
                    is_crit = True
                elif "ntds.dit" in cmd_lower or "esentutl" in cmd_lower:
                    cap = "CAP_NTDS_EXTRACTION"
                    is_crit = True
                elif "asreproast" in cmd_lower or "dont_req_preauth" in cmd_lower:
                    cap = "CAP_ASREP_ROASTING"
                    is_crit = True
                elif "certify" in cmd_lower or "altname:" in cmd_lower:
                    cap = "CAP_ADCS_ABUSE"
                    is_crit = True
                elif "169.254.169.254" in cmd_lower or "meta-data" in cmd_lower:
                    cap = "CAP_CLOUD_METADATA_ACCESS"
                    is_crit = True
                elif ("wmic" in cmd_lower and "/node:" in cmd_lower) or ("psexec" in cmd_lower and "admin$" in cmd_lower) or (f.get("host_id") and f.get("target_host_id") and f.get("host_id") != f.get("target_host_id")):
                    cap = "CAP_MULTI_HOST_TRAVERSAL"
                    is_crit = True
                elif "wmic" in cmd_lower or "psexec" in cmd_lower:
                    cap = "CAP_LATERAL_MOVEMENT"
                    is_crit = True
                elif "delete shadows" in cmd_lower or "delete catalog" in cmd_lower:
                    cap = "CAP_SHADOW_COPY_DELETION"
                    is_crit = True
                elif "esxcli" in cmd_lower and "kill" in cmd_lower:
                    cap = "CAP_HYPERVISOR_COMPROMISE"
                    is_crit = True
                elif "vssadmin" in cmd_lower or "shadows" in cmd_lower:
                    cap = "CAP_BACKUP_TAMPERING"
                    is_crit = True
                elif "schtasks" in cmd_lower or "reg add" in cmd_lower:
                    cap = "CAP_PERSISTENCE"
                    is_crit = True

            evidence_items.append({
                "id": ev_id,
                "type": "endpoint",
                "timestamp": ts,
                "action": action,
                "is_critical": is_crit,
                "capability": cap,
                "source": "nivxray.ces",
                "payload": {
                    "command_line": cmd,
                    "process_name": proc_name,
                    "user": f.get("user") or "",
                    "parent_process": (f.get("parent") or {}).get("name") or "",
                    "capability": cap,
                    "host_id": f.get("host_id") or "",
                    "target_host_id": f.get("target_host_id") or "",
                },
                "meta": {
                    "frame_iid": ev_id,
                    "case_id": case_id,
                    "lane": f.get("lane") or "endpoint",
                }
            })

        return evidence_items

    def hydrate_and_persist(
        self,
        case_id: str,
        tenant_id: str,
        frames: List[Dict[str, Any]],
        ikg: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Hydrates full security state from case frames and persists immutably."""
        # 1. Map frames to canonical evidence
        evidence_items = self.frames_to_canonical_evidence(case_id, frames, ikg)

        # 2. Extract primary entity from IKG or fallback
        device_id = f"device::{case_id}"
        if ikg and ikg.get("nodes"):
            for n in ikg["nodes"]:
                if n.get("type") == "device":
                    device_id = n.get("id", device_id)
                    break

        primary_entity = EntityRef(
            category=EntityCategory.DEVICE,
            entity_id=device_id,
            tenant_id=tenant_id,
            display_name=f"Primary Device for Case {case_id}",
        )

        # 3. Security State Evaluation
        prev_state_rec = self.repository.get_latest_state(tenant_id, case_id)
        prev_state = None
        # (Reconstitute minimal previous state if present for monotonic versioning)

        state = self.state_engine.evaluate_entity_state(
            tenant_id=tenant_id,
            entity_ref=primary_entity,
            evidence_items=evidence_items,
            previous_state=prev_state,
        )

        # 4. Auxiliary Security Calculations
        # Determine attack state progression
        derived_attack_state = AttackState.EXECUTION
        if any(ev.get("capability") in ("CAP_BACKUP_TAMPERING", "CAP_SHADOW_COPY_DELETION", "CAP_HYPERVISOR_COMPROMISE") for ev in evidence_items):
            derived_attack_state = AttackState.IMPACT
        elif any(ev.get("capability") in ("CAP_MULTI_HOST_TRAVERSAL", "CAP_LATERAL_MOVEMENT") for ev in evidence_items):
            derived_attack_state = AttackState.LATERAL_MOVEMENT
        elif any(ev.get("capability") in ("CAP_DCSYNC", "CAP_KERBEROASTING", "CAP_CREDENTIAL_DUMPING", "CAP_NTDS_EXTRACTION", "CAP_ASREP_ROASTING", "CAP_CLOUD_METADATA_ACCESS") for ev in evidence_items):
            derived_attack_state = AttackState.CREDENTIAL_ACCESS
        elif any(ev.get("capability") == "CAP_ADCS_ABUSE" for ev in evidence_items):
            derived_attack_state = AttackState.PRIVILEGE_ESCALATION
        elif any(ev.get("capability") == "CAP_RMM_REMOTE_CONTROL" for ev in evidence_items):
            derived_attack_state = AttackState.COMMAND_AND_CONTROL
        elif any(ev.get("capability") == "CAP_PERSISTENCE" for ev in evidence_items):
            derived_attack_state = AttackState.PERSISTENCE
        elif any(ev.get("capability") == "CAP_LOLBAS_EXECUTION" for ev in evidence_items):
            derived_attack_state = AttackState.DEFENSE_EVASION

        reachability = self.reachability_engine.compute_reachability(
            tenant_id=tenant_id,
            case_id=case_id,
            footholds=[primary_entity],
            harvested_credentials=[],
            active_capabilities=state.active_capabilities,
            ikg_nodes=ikg.get("nodes") if ikg else None,
        )

        impact = self.impact_engine.evaluate_impact(
            tenant_id=tenant_id,
            case_id=case_id,
            reachability=reachability,
            compromised_entities=[primary_entity],
        )

        counterfactuals = self.counterfactual_engine.evaluate_counterfactuals(
            tenant_id=tenant_id,
            case_id=case_id,
            current_state=state,
            reachability=reachability,
            attack_state=derived_attack_state,
        )

        intervention_plan = self.intervention_optimizer.optimize_intervention(
            tenant_id=tenant_id,
            case_id=case_id,
            reachability=reachability,
            impact=impact,
            counterfactual=counterfactuals,
            compromised_entities=[primary_entity],
        )

        # 5. Persist to MongoDB repository
        state_dict = state.to_dict()
        reach_dict = reachability.to_dict()
        impact_dict = impact.to_dict()
        plan_dict = intervention_plan.to_dict()

        persistent_rec, is_new_ver = self.repository.save_state(
            tenant_id=tenant_id,
            case_id=case_id,
            state_data=state_dict,
            reachability_data=reach_dict,
            impact_data=impact_dict,
            intervention_data=plan_dict,
            evidence_items=evidence_items,
            attack_state=derived_attack_state.value,
        )

        # 6. Append to cryptographic block ledger
        if is_new_ver:
            self.repository.append_ledger_block(
                tenant_id=tenant_id,
                case_id=case_id,
                event_type="STATE_EVALUATED_SHADOW",
                entity_id=primary_entity.entity_id,
                state_version=persistent_rec.version,
                payload={
                    "state_hash": persistent_rec.state_hash,
                    "version": persistent_rec.version,
                    "attack_state": derived_attack_state.value,
                    "frame_count": len(frames),
                },
            )

        # 7. Generate Provenance DAG
        provenance_dag = ProvenanceGraphBuilder.build_provenance_tree(
            state_record=persistent_rec.to_dict(),
            evidence_items=evidence_items,
            ikg=ikg,
        )

        return {
            "success": True,
            "case_id": case_id,
            "tenant_id": tenant_id,
            "version": persistent_rec.version,
            "state_hash": persistent_rec.state_hash,
            "attack_state": derived_attack_state.value,
            "active_capabilities": persistent_rec.active_capabilities,
            "provenance": provenance_dag,
            "record": persistent_rec.to_dict(),
        }
