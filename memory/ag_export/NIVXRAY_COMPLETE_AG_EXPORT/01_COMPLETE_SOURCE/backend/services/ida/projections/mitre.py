"""Projection · Behavior → MITRE ATT&CK.

Pure deterministic lookup.  No inference, no LLM, no regex.  When
the Behavior vocabulary grows, add a row here.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple


# ATT&CK-published technique IDs per Behavior type.  Every ID is a
# published MITRE technique — nothing invented.
BEHAVIOR_TO_MITRE: Dict[str, Tuple[str, ...]] = {
    # Impact
    "shadow_copy_deletion":            ("T1490",),
    "inhibit_recovery_wmic":           ("T1490",),
    "inhibit_recovery_bcdedit":        ("T1490",),
    "data_encryption_for_impact":      ("T1486",),
    # Defense Evasion (signed-binary proxy)
    "signed_binary_proxy_msi":         ("T1218.007",),
    "signed_binary_proxy_mshta":       ("T1218.005",),
    "signed_binary_proxy_rundll32":    ("T1218.011",),
    "signed_binary_proxy_regsvr32":    ("T1218.010",),
    "defense_evasion_disable_tool":    ("T1562.001",),
    # C&C / Remote Access
    "remote_access_software":          ("T1219",),
    "protocol_tunneling_ssh":          ("T1572", "T1021.004"),
    "ingress_tool_transfer":           ("T1105",),
    "certutil_download":               ("T1105", "T1027"),
    "bitsadmin_transfer":              ("T1197", "T1105"),
    # Lateral Movement
    "remote_service_smb":              ("T1021.002",),
    "remote_service_rdp":              ("T1021.001",),
    "lateral_movement_psexec":         ("T1021.002", "T1570"),
    "lateral_movement_impacket":       ("T1021.002", "T1047"),
    # Execution
    "powershell_execution":            ("T1059.001",),
    "powershell_encoded_command":      ("T1059.001", "T1027"),
    "powershell_download_execute":     ("T1059.001", "T1105"),
    "powershell_in_memory":            ("T1059.001", "T1620"),
    "wmi_execution":                   ("T1047",),
    "scheduled_task_persistence":      ("T1053.005",),
    "scheduled_task_at":               ("T1053.002",),
    # Credential Access
    "credential_dumping_lsass":        ("T1003.001",),
    "credential_dumping_mimikatz":     ("T1003.001",),
    # Discovery
    "discovery_account":               ("T1087",),
    "discovery_domain_trust":          ("T1482",),
    "discovery_system_owner":          ("T1033",),
    "discovery_network_config":        ("T1016",),
    "discovery_host":                  ("T1082",),
    "discovery_ad":                    ("T1087.002",),
    # Exfiltration
    "data_staging_exfil_rclone":       ("T1567.002", "T1020"),
    # Persistence
    "registry_run_key_persistence":    ("T1547.001",),
    "registry_modification":           ("T1112",),
    # Initial Access
    "phishing_service":                ("T1566.003",),
    "phishing_email":                  ("T1566.001",),
    "exploit_public_app":              ("T1190",),
    "quickassist_it_impersonation":    ("T1219", "T1566.004"),
    # Browser
    "browser_extension_load":          ("T1176",),
    "browser_launch_headless":         ("T1189",),
    # Misc
    "archive_extraction":              ("T1140",),
    "self_deletion":                   ("T1070.004",),
}


def project_to_mitre(behaviors: Sequence[Any]) -> List[Dict[str, Any]]:
    """Dedupe ATT&CK technique list from a Behavior sequence.

    Returns ``[{'id': 'T1490', 'source': 'ida.behaviors:<type>',
                'evidence': <label>}, ...]``.  Each ID appears once;
    ``source`` retains provenance of the first Behavior contributing
    that ID so downstream UIs can display the origin.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    for b in behaviors:
        for tid in BEHAVIOR_TO_MITRE.get(b.behavior_type, ()):
            if tid in seen:
                continue
            seen[tid] = {
                "id":       tid,
                "source":   f"ida.behaviors:{b.behavior_type}",
                "evidence": b.label,
            }
    return list(seen.values())


def mitre_for(behavior_type: str) -> List[str]:
    """Return the ATT&CK technique list mapped to a single
    ``behavior_type``.  Public accessor so external callers never
    import the raw ``BEHAVIOR_TO_MITRE`` map directly."""
    return list(BEHAVIOR_TO_MITRE.get(behavior_type, ()))


__all__ = ["BEHAVIOR_TO_MITRE", "project_to_mitre", "mitre_for"]
