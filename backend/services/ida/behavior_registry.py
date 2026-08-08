"""Behavior Registry · single source of truth for the semantic vocabulary.

Auto-composed from the frozen ADR-001 contracts:
    · The behavior vocabulary is ``BEHAVIOR_TO_MITRE.keys()``
      (canonical set — a behavior type only "exists" if it maps to
      at least one MITRE technique)
    · Projections come from the three projection modules
    · Producers come from static introspection of known producer
      modules (``services.ida.behaviors.generate_behaviors``,
      ``services.uaie.behavior_extractor.extract_behaviors``)
    · Supporting rules come from the rule library's ``mitre`` tuple
      overlap with the behavior's MITRE projection

The registry is a READ-ONLY view — it never invents behaviors and
its content is computed deterministically from the frozen contracts.
This is what the user described as "the internal ATT&CK-catalog
equivalent" — impact analysis becomes trivial:

    · Which rules depend on behavior X ?         → registry[x].supporting_rules
    · Which producers can emit behavior X ?      → registry[x].producers
    · Which framework projections does X have ?  → registry[x].projections

REGISTRY_SCHEMA_VERSION bumps when the shape below changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing      import Any, Dict, List, Sequence, Tuple

from services.ida.behaviors import (
    LOLBAS_BINARY_TO_BEHAVIORS, MALWARE_FAMILY_TO_BEHAVIORS,
    CVE_TO_BEHAVIORS,
)
from services.ida.projections.mitre       import BEHAVIOR_TO_MITRE
from services.ida.projections.kill_chain  import BEHAVIOR_TO_KILL_CHAIN
from services.ida.projections.impact      import BEHAVIOR_TO_IMPACTS
from services.mitigation.evidence_driven  import rule_library


REGISTRY_SCHEMA_VERSION = "1.0"


# Human-readable descriptions.  Extending is additive; missing
# entries fall back to a synthesized label.
_DESCRIPTIONS: Dict[str, str] = {
    "shadow_copy_deletion":         "Deletion of Volume Shadow Copies to prevent restore-based recovery.",
    "inhibit_recovery_wmic":        "Recovery inhibition via WMIC / wbadmin backup catalog deletion.",
    "inhibit_recovery_bcdedit":     "Boot-recovery policy tampering via bcdedit.",
    "data_encryption_for_impact":   "Ransomware encryption of user / system data.",
    "signed_binary_proxy_msi":      "Execution proxied through the signed msiexec / MSI binary.",
    "signed_binary_proxy_mshta":    "Execution proxied through the signed mshta binary.",
    "signed_binary_proxy_rundll32": "Execution proxied through the signed rundll32 binary.",
    "signed_binary_proxy_regsvr32": "Execution proxied through the signed regsvr32 binary.",
    "defense_evasion_disable_tool": "Disabling or uninstalling a security tool.",
    "remote_access_software":       "Named commercial remote-administration software observed on host.",
    "protocol_tunneling_ssh":       "SSH used as a tunnel / reverse-tunnel for C2 or lateral movement.",
    "ingress_tool_transfer":        "Fetching an additional payload from a remote resource.",
    "certutil_download":            "certutil.exe used to download / decode a remote payload.",
    "bitsadmin_transfer":           "BITSAdmin used to transfer files across the internet.",
    "remote_service_smb":           "Lateral movement via SMB / ADMIN$ share.",
    "remote_service_rdp":           "Remote-desktop lateral movement (RDP).",
    "lateral_movement_psexec":      "PsExec used for lateral command execution.",
    "lateral_movement_impacket":    "Impacket family (wmiexec / smbexec / atexec) lateral movement.",
    "powershell_execution":         "PowerShell interpreter execution observed.",
    "powershell_encoded_command":   "PowerShell -EncodedCommand base64 payload observed.",
    "powershell_download_execute":  "PowerShell download-and-execute cradle (DownloadString / WebClient).",
    "powershell_in_memory":         "PowerShell in-memory execution (Invoke-Expression / IEX).",
    "wmi_execution":                "Windows Management Instrumentation used for execution.",
    "scheduled_task_persistence":   "Scheduled task created / registered for persistence.",
    "scheduled_task_at":            "at.exe-style scheduled task persistence.",
    "credential_dumping_lsass":     "LSASS memory dump / credential harvesting.",
    "credential_dumping_mimikatz":  "Mimikatz-family credential harvesting.",
    "discovery_account":            "Local / domain account discovery.",
    "discovery_domain_trust":       "Domain-trust discovery (nltest).",
    "discovery_system_owner":       "Current user / logged-on user discovery.",
    "discovery_network_config":     "Network configuration discovery (ipconfig).",
    "discovery_host":               "Host name / role discovery.",
    "discovery_ad":                 "Active-Directory enumeration (BloodHound / SharpHound / AdFind).",
    "data_staging_exfil_rclone":    "Bulk data staging / exfiltration to cloud storage (rclone-style).",
    "registry_run_key_persistence": "Registry Run-key persistence.",
    "registry_modification":       "Registry value modification for defense evasion.",
    "phishing_service":             "Phishing via a service such as Microsoft Teams.",
    "phishing_email":               "Phishing email as initial access vector.",
    "exploit_public_app":           "Exploitation of a public-facing application.",
    "quickassist_it_impersonation": "IT-impersonation abuse of Quick Assist / remote-help tools.",
    "browser_extension_load":       "Browser extension side-load — 'Edgecution'-style abuse.",
    "browser_launch_headless":      "Browser launch in headless / drive-by mode.",
    "archive_extraction":           "Archive extraction of an obfuscated payload.",
    "self_deletion":                "Stager self-deletion / anti-forensics cleanup.",
}


@dataclass(frozen=True)
class BehaviorSpec:
    """One row in the registry.  All fields are derived — never
    author them by hand except ``description`` and ``introduced_in``."""
    id:                str            # stable == behavior_type today
    canonical_name:    str
    description:       str
    introduced_in:     str
    deprecated_in:     str = ""
    producers:         Tuple[str, ...] = ()
    consumers:         Tuple[str, ...] = ()
    projections:       Dict[str, List[str]] = field(default_factory=dict)
    supporting_rules:  Tuple[str, ...] = ()
    example_triggers:  Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _producers_for(btype: str) -> Tuple[str, ...]:
    """Which producer modules can emit this behavior_type."""
    prods: List[str] = []
    # Command classifier — every behavior_type is potentially emitted
    # by classify_command; determined by inspecting classify_command's
    # return targets is too coarse.  We instead mark it as a possible
    # producer for any type not exclusively surfaced by lookup tables.
    exclusively_lookup = (
        btype in {v[0] for v in MALWARE_FAMILY_TO_BEHAVIORS.values() if len(v) == 1}
        or btype in {v[0] for v in LOLBAS_BINARY_TO_BEHAVIORS.values() if len(v) == 1}
        or btype in {v[0] for v in CVE_TO_BEHAVIORS.values() if len(v) == 1}
    )
    if not exclusively_lookup or btype in {"powershell_execution",
                                                "signed_binary_proxy_msi",
                                                "wmi_execution",
                                                "certutil_download",
                                                "bitsadmin_transfer",
                                                "shadow_copy_deletion",
                                                "inhibit_recovery_wmic",
                                                "inhibit_recovery_bcdedit"}:
        prods.append("services.ida.behaviors.classify_command")
    # Malware lookup
    if any(btype in mapped for mapped in MALWARE_FAMILY_TO_BEHAVIORS.values()):
        prods.append("services.ida.behaviors.MALWARE_FAMILY_TO_BEHAVIORS")
    # LOLBAS lookup
    if any(btype in mapped for mapped in LOLBAS_BINARY_TO_BEHAVIORS.values()):
        prods.append("services.ida.behaviors.LOLBAS_BINARY_TO_BEHAVIORS")
    # CVE lookup
    if any(btype in mapped for mapped in CVE_TO_BEHAVIORS.values()):
        prods.append("services.ida.behaviors.CVE_TO_BEHAVIORS")
    # UAIE-side extractor uses classify_command + LOLBAS scan on
    # UAIE artifacts, so any behavior emitted via those paths is
    # also potentially UAIE-produced.
    if prods:
        prods.append("services.uaie.behavior_extractor.extract_behaviors")
    return tuple(prods)


def _consumers_for(btype: str) -> Tuple[str, ...]:
    """Fixed downstream consumers of every Behavior.  Uniform across
    the registry — enumerated so the UI / API can render a
    consumer matrix per behavior_type."""
    return (
        "services.ida.projections.mitre.project_to_mitre",
        "services.ida.projections.kill_chain.project_to_kill_chain",
        "services.ida.projections.impact.project_to_impacts",
        "services.mitigation.evidence_driven.engine.evidence_driven_recommendations",
        "services.uaie.ssot_projector.project",
        "routers.behavior_provenance.explain_behaviors",
    )


def _supporting_rules_for(btype: str) -> Tuple[str, ...]:
    """Recommendation rules whose ATT&CK tuple overlaps this
    behavior's MITRE projection."""
    b_mitre = set(BEHAVIOR_TO_MITRE.get(btype, ()))
    if not b_mitre:
        return ()
    rules: List[str] = []
    for group in ("INVESTIGATE_RULES", "HUNT_RULES", "CONTAIN_RULES",
                    "ERADICATE_RULES", "RECOVER_RULES", "HARDEN_RULES"):
        for r in getattr(rule_library, group, []):
            if set(getattr(r, "mitre", None) or ()) & b_mitre:
                rules.append(r.id)
    return tuple(sorted(rules))


def _example_triggers_for(btype: str) -> Tuple[str, ...]:
    ex: List[str] = []
    for fam, bs in MALWARE_FAMILY_TO_BEHAVIORS.items():
        if btype in bs:
            ex.append(f"malware_family:{fam}")
    for lb, bs in LOLBAS_BINARY_TO_BEHAVIORS.items():
        if btype in bs:
            ex.append(f"lolbas:{lb}")
    for cid, bs in CVE_TO_BEHAVIORS.items():
        if btype in bs:
            ex.append(f"cve:{cid}")
    return tuple(sorted(ex))


def build_registry() -> Dict[str, BehaviorSpec]:
    """Return the complete deterministic behavior registry."""
    registry: Dict[str, BehaviorSpec] = {}
    for btype in sorted(BEHAVIOR_TO_MITRE.keys()):
        registry[btype] = BehaviorSpec(
            id             = btype,
            canonical_name = btype.replace("_", " ").title(),
            description    = _DESCRIPTIONS.get(btype,
                                    "(canonical semantic behavior · "
                                    "description pending)"),
            introduced_in  = "P0.3",
            deprecated_in  = "",
            producers      = _producers_for(btype),
            consumers      = _consumers_for(btype),
            projections    = {
                "mitre":      list(BEHAVIOR_TO_MITRE.get(btype, ())),
                "kill_chain": list(BEHAVIOR_TO_KILL_CHAIN.get(btype, ())),
                "impact":     list(BEHAVIOR_TO_IMPACTS.get(btype, ())),
            },
            supporting_rules = _supporting_rules_for(btype),
            example_triggers = _example_triggers_for(btype),
        )
    return registry


__all__ = [
    "REGISTRY_SCHEMA_VERSION",
    "BehaviorSpec",
    "build_registry",
]
