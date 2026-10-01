"""Projection · Behavior → Cyber Kill-Chain / ATT&CK-tactic tags.

Coarse tactic-level tags the v2 Evidence-Driven Recommendation
Engine consumes on ``InvestigationOutcome.behaviors``.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple


BEHAVIOR_TO_KILL_CHAIN: Dict[str, Tuple[str, ...]] = {
    "shadow_copy_deletion":            ("impact",),
    "inhibit_recovery_wmic":           ("impact",),
    "inhibit_recovery_bcdedit":        ("impact",),
    "data_encryption_for_impact":      ("impact",),
    "signed_binary_proxy_msi":         ("defense_evasion", "execution"),
    "signed_binary_proxy_mshta":       ("defense_evasion", "execution"),
    "signed_binary_proxy_rundll32":    ("defense_evasion", "execution"),
    "signed_binary_proxy_regsvr32":    ("defense_evasion", "execution"),
    "defense_evasion_disable_tool":    ("defense_evasion",),
    "remote_access_software":          ("c2",),
    "protocol_tunneling_ssh":          ("c2", "lateral_movement"),
    "ingress_tool_transfer":           ("c2",),
    "certutil_download":               ("c2", "defense_evasion"),
    "bitsadmin_transfer":              ("c2",),
    "remote_service_smb":              ("lateral_movement",),
    "remote_service_rdp":              ("lateral_movement",),
    "lateral_movement_psexec":         ("lateral_movement", "execution"),
    "lateral_movement_impacket":       ("lateral_movement", "execution"),
    "powershell_execution":            ("execution",),
    "powershell_encoded_command":      ("execution", "defense_evasion"),
    "powershell_download_execute":     ("execution", "c2"),
    "powershell_in_memory":            ("execution", "defense_evasion"),
    "wmi_execution":                   ("execution",),
    "scheduled_task_persistence":      ("persistence", "execution"),
    "scheduled_task_at":               ("persistence", "execution"),
    "credential_dumping_lsass":        ("credential_access",),
    "credential_dumping_mimikatz":     ("credential_access",),
    "discovery_account":               ("discovery",),
    "discovery_domain_trust":          ("discovery",),
    "discovery_system_owner":          ("discovery",),
    "discovery_network_config":        ("discovery",),
    "discovery_host":                  ("discovery",),
    "discovery_ad":                    ("discovery",),
    "data_staging_exfil_rclone":       ("exfiltration", "collection"),
    "registry_run_key_persistence":    ("persistence",),
    "registry_modification":           ("defense_evasion",),
    "phishing_service":                ("recon",),
    "phishing_email":                  ("recon",),
    "exploit_public_app":              ("recon", "execution"),
    "quickassist_it_impersonation":    ("recon", "c2"),
    "browser_extension_load":          ("persistence", "execution"),
    "browser_launch_headless":         ("execution",),
    "archive_extraction":              ("defense_evasion",),
    "self_deletion":                   ("defense_evasion",),
}


def project_to_kill_chain(behaviors: Sequence[Any]) -> List[str]:
    """Return the sorted, deduplicated kill-chain tactic tag set."""
    tags: set = set()
    for b in behaviors:
        tags.update(BEHAVIOR_TO_KILL_CHAIN.get(b.behavior_type, ()))
    return sorted(tags)


def kill_chain_for(behavior_type: str) -> List[str]:
    """Return the kill-chain tag list mapped to a single
    ``behavior_type``."""
    return list(BEHAVIOR_TO_KILL_CHAIN.get(behavior_type, ()))


__all__ = ["BEHAVIOR_TO_KILL_CHAIN", "project_to_kill_chain",
             "kill_chain_for"]
