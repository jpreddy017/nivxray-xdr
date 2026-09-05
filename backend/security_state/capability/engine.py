"""Trusted Capability Abuse Engine: generalized contextual detection of dual-use tools."""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..contracts import (
    CapabilityStatus,
    EntityRef,
    ProvenanceEnvelope,
    canonical_json,
    sha256_digest,
)


@dataclass
class CapabilityContext:
    """11-dimensional context for evaluating dual-use software abuse."""
    capability_name: str
    identity_ref: EntityRef
    is_authorized_admin: bool
    source_ip_or_subnet: str
    destination_ip_or_domain: str
    timestamp: str
    is_within_business_hours: bool
    command_line: str
    parent_process: str
    process_privilege_level: str  # 'USER', 'ADMIN', 'SYSTEM'
    prior_sequence_events: List[str] = field(default_factory=list)
    has_inbound_tunnel_or_proxy: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["identity_ref"] = self.identity_ref.to_dict()
        return d


@dataclass
class CapabilityAbuseEvaluation:
    """Detailed evaluation of capability usage."""
    evaluation_id: str
    tenant_id: str
    capability_name: str
    status: CapabilityStatus
    confidence: float
    context: CapabilityContext
    reasons: List[str]
    evidence_ids: List[str]
    reversal_action_recommendation: Optional[str]
    evaluation_hash: str = ""

    def __post_init__(self) -> None:
        if not self.evaluation_hash:
            self.evaluation_hash = self.compute_hash()

    def compute_hash(self) -> str:
        payload = {
            "evaluation_id": self.evaluation_id,
            "tenant_id": self.tenant_id,
            "capability_name": self.capability_name,
            "status": self.status.value,
            "confidence": self.confidence,
            "context": self.context.to_dict(),
            "reasons": sorted(self.reasons),
            "evidence_ids": sorted(self.evidence_ids),
            "reversal_action_recommendation": self.reversal_action_recommendation,
        }
        return sha256_digest(canonical_json(payload))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "tenant_id": self.tenant_id,
            "capability_name": self.capability_name,
            "status": self.status.value,
            "confidence": self.confidence,
            "context": self.context.to_dict(),
            "reasons": self.reasons,
            "evidence_ids": self.evidence_ids,
            "reversal_action_recommendation": self.reversal_action_recommendation,
            "evaluation_hash": self.evaluation_hash,
        }


class CapabilityCategory(str, Enum):
    """Broad categories of dual-use enterprise capabilities."""
    REMOTE_ADMINISTRATION = "REMOTE_ADMINISTRATION"
    SHELL_AND_SCRIPTING = "SHELL_AND_SCRIPTING"
    BINARY_PROXY_EXECUTION = "BINARY_PROXY_EXECUTION"
    DIRECTORY_AND_IDENTITY_SERVICE = "DIRECTORY_AND_IDENTITY_SERVICE"
    REMOTE_PROCESS_INVOCATION = "REMOTE_PROCESS_INVOCATION"
    CLOUD_INFRASTRUCTURE_MANAGEMENT = "CLOUD_INFRASTRUCTURE_MANAGEMENT"
    BACKUP_AND_STORAGE_SERVICE = "BACKUP_AND_STORAGE_SERVICE"
    VIRTUALIZATION_HYPERVISOR = "VIRTUALIZATION_HYPERVISOR"
    GENERAL_UTILITY = "GENERAL_UTILITY"


class TrustedCapabilityAbuseEngine:
    """Evaluates whether dual-use capabilities are operating legitimately or being abused.
    
    Adheres to the core strategic rule:
    Does NOT infer maliciousness solely from the presence of a LOLBin or dual-use tool.
    Evaluates 11 contextual dimensions to separate AUTHORIZED_USE from ABUSED_CAPABILITY.
    """
    VERSION = "3.0.0"

    # Known Remote Monitoring & Management Tools
    KNOWN_RMM_TOOLS = {
        "anydesk", "teamviewer", "screenconnect", "connectwise",
        "splashtop", "ninjarmm", "ninjaone", "kaseya", "logmein",
        "rustdesk", "atera", "meshcentral", "gotoassist", "tacticalrmm",
        "action1", "simplehelp", "remoteutilities"
    }

    # Living off the Land Binaries and Scripts (LOLBAS)
    KNOWN_LOLBAS_TOOLS = {
        "certutil.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "bitsadmin.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "mshta.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "rundll32.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "regsvr32.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "wmic.exe": CapabilityCategory.REMOTE_PROCESS_INVOCATION,
        "cscript.exe": CapabilityCategory.SHELL_AND_SCRIPTING,
        "wscript.exe": CapabilityCategory.SHELL_AND_SCRIPTING,
        "installutil.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "msbuild.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "cmstp.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "hh.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "msiexec.exe": CapabilityCategory.BINARY_PROXY_EXECUTION,
        "powershell.exe": CapabilityCategory.SHELL_AND_SCRIPTING,
        "pwsh.exe": CapabilityCategory.SHELL_AND_SCRIPTING,
        "cmd.exe": CapabilityCategory.SHELL_AND_SCRIPTING,
        "psexec.exe": CapabilityCategory.REMOTE_PROCESS_INVOCATION,
    }

    # AD Directory and Replication binaries
    KNOWN_AD_TOOLS = {
        "ntdsutil.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "dsquery.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "csvde.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "ldifde.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "rubeus.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "certify.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "whisker.exe": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "pywhisker.py": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
        "aadinternals.ps1": CapabilityCategory.DIRECTORY_AND_IDENTITY_SERVICE,
    }

    # Cloud Management Tools
    KNOWN_CLOUD_TOOLS = {
        "aws.exe": CapabilityCategory.CLOUD_INFRASTRUCTURE_MANAGEMENT,
        "az.exe": CapabilityCategory.CLOUD_INFRASTRUCTURE_MANAGEMENT,
        "gcloud.exe": CapabilityCategory.CLOUD_INFRASTRUCTURE_MANAGEMENT,
        "terraform.exe": CapabilityCategory.CLOUD_INFRASTRUCTURE_MANAGEMENT,
        "kubectl.exe": CapabilityCategory.CLOUD_INFRASTRUCTURE_MANAGEMENT,
    }

    # Backup & Storage Tools
    KNOWN_BACKUP_TOOLS = {
        "vssadmin.exe": CapabilityCategory.BACKUP_AND_STORAGE_SERVICE,
        "wbadmin.exe": CapabilityCategory.BACKUP_AND_STORAGE_SERVICE,
        "veeam.exe": CapabilityCategory.BACKUP_AND_STORAGE_SERVICE,
        "commvault.exe": CapabilityCategory.BACKUP_AND_STORAGE_SERVICE,
        "rubrik.exe": CapabilityCategory.BACKUP_AND_STORAGE_SERVICE,
    }

    # Hypervisor Utilities
    KNOWN_HYPERVISOR_TOOLS = {
        "esxcli": CapabilityCategory.VIRTUALIZATION_HYPERVISOR,
        "vmware.exe": CapabilityCategory.VIRTUALIZATION_HYPERVISOR,
        "vmrun.exe": CapabilityCategory.VIRTUALIZATION_HYPERVISOR,
        "virsh": CapabilityCategory.VIRTUALIZATION_HYPERVISOR,
        "hyper-v.exe": CapabilityCategory.VIRTUALIZATION_HYPERVISOR,
    }

    def categorize_tool(self, tool_name: str) -> CapabilityCategory:
        """Categorize binary or tool into its behavioral classification."""
        t_low = tool_name.lower().strip()
        if any(rmm in t_low for rmm in self.KNOWN_RMM_TOOLS):
            return CapabilityCategory.REMOTE_ADMINISTRATION
        for lol, cat in self.KNOWN_LOLBAS_TOOLS.items():
            if lol in t_low or t_low == lol.replace(".exe", ""):
                return cat
        for ad_tool, cat in self.KNOWN_AD_TOOLS.items():
            if ad_tool in t_low or t_low == ad_tool.replace(".exe", ""):
                return cat
        for cloud_tool, cat in self.KNOWN_CLOUD_TOOLS.items():
            if cloud_tool in t_low or t_low == cloud_tool.replace(".exe", ""):
                return cat
        for backup_tool, cat in self.KNOWN_BACKUP_TOOLS.items():
            if backup_tool in t_low or t_low == backup_tool.replace(".exe", ""):
                return cat
        for hyp_tool, cat in self.KNOWN_HYPERVISOR_TOOLS.items():
            if hyp_tool in t_low or t_low == hyp_tool.replace(".exe", ""):
                return cat
        return CapabilityCategory.GENERAL_UTILITY

    def evaluate_capability(
        self,
        tenant_id: str,
        context: CapabilityContext,
        evidence_ids: List[str],
    ) -> CapabilityAbuseEvaluation:
        """Evaluate dual-use capability under 11 contextual dimensions."""
        reasons: List[str] = []
        score = 0
        cap_lower = context.capability_name.lower()
        cmd_lower = context.command_line.lower()
        parent_lower = context.parent_process.lower()
        cat = self.categorize_tool(context.capability_name)
        if cat == CapabilityCategory.GENERAL_UTILITY and context.command_line:
            cmd_first = context.command_line.strip().split()[0].lower() if context.command_line.strip() else ""
            cat_cmd = self.categorize_tool(cmd_first)
            if cat_cmd != CapabilityCategory.GENERAL_UTILITY:
                cat = cat_cmd

        is_rmm = cat == CapabilityCategory.REMOTE_ADMINISTRATION or any(rmm in cap_lower or rmm in cmd_lower for rmm in self.KNOWN_RMM_TOOLS)
        is_lolbas = cat in (CapabilityCategory.BINARY_PROXY_EXECUTION, CapabilityCategory.SHELL_AND_SCRIPTING) or any(lol in cap_lower or lol in cmd_lower for lol in self.KNOWN_LOLBAS_TOOLS)
        is_admin_bin = is_lolbas or "admin" in cap_lower or "admin" in cmd_lower or cat != CapabilityCategory.GENERAL_UTILITY

        # Dimension 1: Identity & Authorization Context
        if not context.is_authorized_admin:
            score += 35
            reasons.append("Tool invoked by non-administrative / unauthorized identity")
        else:
            reasons.append("Invoked by authorized administrative identity")

        # Dimension 2: Parent Process Lineage
        suspicious_parents = ["word.exe", "excel.exe", "outlook.exe", "acrobat.exe", "wmiprvse.exe", "w3wp.exe", "httpd.exe"]
        if any(susp in parent_lower for susp in suspicious_parents):
            score += 45
            reasons.append(f"Suspicious parent process lineage: spawned by {context.parent_process}")

        # Dimension 3: Temporal Maintenance Context
        if not context.is_within_business_hours:
            score += 15
            reasons.append("Execution outside authorized business / maintenance window")

        # Dimension 4: Inbound Tunneling / Reverse Proxy
        if context.has_inbound_tunnel_or_proxy:
            score += 30
            reasons.append("Command channel established over inbound proxy or reverse tunnel")

        # Dimension 5: Command-Line Weaponization & Defense Evasion
        has_evasion = False
        evasion_keywords = [
            "downloadstring", "-enc", "frombase64string", "bypass", "hidden",
            "invoke-expression", "iex", "-urlcache", "-split", "scrobj.dll",
            "javascript:", "vbscript:", "/format:", "transform.xsl", "sct"
        ]
        if any(kw in cmd_lower for kw in evasion_keywords):
            score += 35
            has_evasion = True
            reasons.append("Command line exhibits payload staging, proxy scriptlet, or defense evasion parameters")

        # Dimension 6: Credential / Secret Store Interaction
        cred_keywords = ["lsass", "sekurlsa", "minidump", "sam", "system.save", "getuserspns", "rubeus", "kerberoast", "drsgetncchanges", "secretsdump"]
        has_cred_target = any(kw in cmd_lower for kw in cred_keywords)
        if has_cred_target:
            score += 50
            reasons.append("Command line actively targets identity secrets, Kerberos tickets, or password databases")

        # Dimension 7: AD Replication Abuse (DCSync) / Kerberoasting Primitives
        if "drsgetncchanges" in cmd_lower or "secretsdump" in cmd_lower or "lsadump::dcsync" in cmd_lower:
            score += 45
            reasons.append("Directory Replication Service RPC invoked from unauthorized client (DCSync primitive)")

        if "getuserspns" in cmd_lower or "kerberoast" in cmd_lower:
            score += 40
            reasons.append("Service Principal Name enumeration with ticket extraction preference (Kerberoasting primitive)")

        # Dimension 7b: Silent RMM Installation / Staging
        if is_rmm and any(flag in cmd_lower for flag in ["/qn", "/quiet", "--silent", "--install", "--service"]):
            score += 40
            reasons.append("Silent background installation / staging of Remote Administration tool")

        # Dimension 7c: Cloud IMDS / Metadata Service Querying
        if any(kw in cmd_lower for kw in ["169.254.169.254", "meta-data", "security-credentials"]):
            score += 45
            reasons.append("Process actively querying cloud link-local instance metadata service (IMDS)")

        # Dimension 7d: Backup / Shadow Copy / Hypervisor VM Destruction
        if (
            any(kw in cmd_lower for kw in ["delete shadows", "delete catalog", "process kill", "snapshot.remove"])
            or ("vssadmin" in cmd_lower and "delete" in cmd_lower)
            or ("wbadmin" in cmd_lower and "delete" in cmd_lower)
            or ("esxcli" in cmd_lower and "kill" in cmd_lower)
        ):
            score += 55
            reasons.append("Destruction or purge of volume shadow copies, backups, or hypervisor VMs (ransomware precursor)")

        # Dimension 7e: AD CS Certificate Template Abuse
        if any(kw in cmd_lower for kw in ["certify", "altname", "enrollee_supplies_subject", "pkinit"]):
            score += 45
            reasons.append("Active Directory Certificate Services (AD CS) template enumeration or enrollment exploitation")

        # Dimension 8: Process Privilege Level Mismatch
        if context.process_privilege_level == "SYSTEM" and not context.is_authorized_admin:
            score += 25
            reasons.append("Tool operating under SYSTEM token from non-administrative initiation")

        # Dimension 9: Competing Hypotheses Evaluation (Benign Admin Validation)
        # If authorized admin performing standard maintenance without evasion, score is lowered
        is_routine_admin = (
            context.is_authorized_admin
            and not has_evasion
            and not has_cred_target
            and not context.has_inbound_tunnel_or_proxy
            and context.is_within_business_hours
        )
        if is_routine_admin:
            score = max(0, score - 30)
            reasons.append("Competing hypothesis: routine administrative systems operation corroborated")

        # Derive final CapabilityStatus
        reversal = None
        if score >= 80:
            status = CapabilityStatus.CONFIRMED_ATTACK
            reversal = "endpoint.terminate_process"
            conf = min(0.99, 0.70 + score / 200)
        elif score >= 55:
            status = CapabilityStatus.ABUSED_CAPABILITY
            reversal = "endpoint.isolate" if is_rmm else "identity.revoke_sessions"
            conf = 0.88
        elif score >= 35:
            status = CapabilityStatus.SUSPICIOUS_USE
            reversal = "identity.step_up_auth"
            conf = 0.75
        elif score >= 15:
            status = CapabilityStatus.ANOMALOUS_USE
            conf = 0.60
        elif is_rmm or is_admin_bin:
            status = CapabilityStatus.AUTHORIZED_USE
            conf = 0.95
        else:
            status = CapabilityStatus.LEGITIMATE_CAPABILITY
            conf = 0.99

        return CapabilityAbuseEvaluation(
            evaluation_id=f"cap-eval-{uuid.uuid4().hex[:10]}",
            tenant_id=tenant_id,
            capability_name=context.capability_name,
            status=status,
            confidence=conf,
            context=context,
            reasons=reasons,
            evidence_ids=sorted(evidence_ids),
            reversal_action_recommendation=reversal,
        )
