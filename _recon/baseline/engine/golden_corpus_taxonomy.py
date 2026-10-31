"""RC5 · Phase 9.5d · Golden Corpus taxonomy.

Canonical category taxonomy for the Golden Corpus. Every sample MUST
declare a `category` from this list. This makes coverage measurable per
class rather than by raw sample count — a much more honest signal for
both engineers and reviewers.

The taxonomy is deliberately closed (no free-form categories) so
category-drift can be caught by the CI corpus-shape test.

Sources & citations:
  * MITRE ATT&CK Enterprise Matrix (tactic taxonomy)
  * LOLBAS Project (lolbas-project.github.io) for LOLBAS entries
  * Vendor threat reports for named-family malware samples
"""
from __future__ import annotations

from typing import FrozenSet


# Every corpus sample's `category` field MUST be one of these.
CATEGORIES: FrozenSet[str] = frozenset({
    # Benign / enterprise workflows
    "enterprise_administration",   # generic Windows admin (Get-Service, wbadmin, etc.)
    "powershell_administration",   # PS cmdlet-heavy admin (AD, Exchange, Graph, etc.)
    "cloud_administration",        # Azure, AWS CLI, gcloud, Graph, cloud storage admin
    "devops_iac",                  # Terraform, Ansible, Puppet, Chef, GH Actions, Azure DevOps
    "developer_tooling",           # choco, winget, VS Code, git, package managers

    # Adversary behaviors (ATT&CK-tactic-aligned)
    "lolbas",                      # LOLBAS binary execution (regsvr32, mshta, msbuild, etc.)
    "persistence",                 # T1547, T1053, T1543, T1136 style
    "credential_access",           # T1003, T1552, T1558 (Kerberoasting/DCSync), LSASS access
    "lateral_movement",            # T1021, T1570, T1210
    "downloaders",                 # T1105 loaders (WebClient, iwr, curl, BITS, certutil)
    "packers_obfuscation",         # T1027, encoded-command, gzip, base64, char-array, format-op
    "ransomware",                  # T1490 (Inhibit Recovery), T1486, shadow-copy purge
    "living_off_the_land",         # generic LOLBIN chains not covered by lolbas category
    "defense_evasion",             # AMSI/ETW bypass, script-block-logging off, cert-decode

    # Meta
    "edge_case_regression",        # obfuscation edge cases, parser hardening samples
    "baseline_smoke",              # the original GC-001..GC-140 baseline set
})


def is_valid_category(cat: str) -> bool:
    return cat in CATEGORIES


__all__ = ["CATEGORIES", "is_valid_category"]
