"""RC5 · Phase 9.5d · Category-assignment for existing corpus samples.

Rather than touching all 82 sample dictionaries by hand, we assign the
canonical taxonomy category by ID prefix at import time. This keeps the
existing sample tuples untouched (preserving git-blame provenance) while
still giving us per-category coverage measurement.

New samples added AFTER Phase 9.5d SHOULD carry an explicit `category`
field directly in their dict — this mapping is fallback-only.
"""
from __future__ import annotations

from typing import Dict


# Explicit ID-prefix → category mapping. Kept alphabetical within each
# category for review-ability.
_ID_PREFIX_CATEGORY: Dict[str, str] = {
    # ── Baseline smoke set (original 15) ────────────────────────────
    "GC-001": "baseline_smoke",
    "GC-005": "baseline_smoke",
    "GC-010": "baseline_smoke",
    "GC-020": "baseline_smoke",
    "GC-030": "baseline_smoke",
    "GC-050": "baseline_smoke",
    "GC-060": "baseline_smoke",
    "GC-070": "baseline_smoke",
    "GC-080": "baseline_smoke",
    "GC-090": "packers_obfuscation",   # deep -enc decoding proof
    "GC-100": "persistence",
    "GC-110": "credential_access",
    "GC-120": "downloaders",
    "GC-130": "lolbas",
    "GC-140": "lolbas",

    # ── Round-1 benign enterprise (GC-150 → GC-167) ─────────────────
    "GC-150": "enterprise_administration",
    "GC-151": "enterprise_administration",   # DSC
    "GC-152": "enterprise_administration",   # SCCM
    "GC-153": "enterprise_administration",   # Intune
    "GC-154": "powershell_administration",   # Exchange
    "GC-155": "powershell_administration",   # AD
    "GC-156": "cloud_administration",        # MS Graph
    "GC-157": "developer_tooling",           # choco
    "GC-158": "developer_tooling",           # winget
    "GC-159": "enterprise_administration",   # Office deploy
    "GC-160": "enterprise_administration",   # SQL
    "GC-161": "enterprise_administration",   # IIS
    "GC-162": "enterprise_administration",   # PowerCLI
    "GC-163": "enterprise_administration",   # Hyper-V
    "GC-164": "enterprise_administration",   # wbadmin
    "GC-165": "devops_iac",                  # GH Actions
    "GC-166": "devops_iac",                  # Azure DevOps
    "GC-167": "enterprise_administration",   # -ExecutionPolicy Bypass

    # ── Round-1 malware (GC-200 → GC-210) ───────────────────────────
    "GC-200": "downloaders",                 # Emotet PS loader
    "GC-201": "lolbas",                      # Qakbot regsvr32
    "GC-202": "lolbas",                      # Cobalt Strike mshta
    "GC-203": "packers_obfuscation",         # Empire -enc
    "GC-204": "lateral_movement",            # WMIC remote
    "GC-205": "defense_evasion",             # certutil decode
    "GC-206": "persistence",                 # Winlogon Userinit
    "GC-207": "persistence",                 # schtasks SYSTEM
    "GC-208": "lolbas",                      # MSBuild inline
    "GC-209": "lolbas",                      # InstallUtil
    "GC-210": "ransomware",                  # vssadmin delete

    # ── Round-1 edge cases (GC-250 → GC-256) ────────────────────────
    "GC-250": "packers_obfuscation",
    "GC-251": "packers_obfuscation",
    "GC-252": "packers_obfuscation",
    "GC-253": "downloaders",
    "GC-254": "packers_obfuscation",
    "GC-255": "packers_obfuscation",
    "GC-256": "packers_obfuscation",

    # ── Round-2 benign enterprise (GC-260 → GC-274) ─────────────────
    "GC-260": "powershell_administration",   # Exchange EMS
    "GC-261": "enterprise_administration",   # ADFS
    "GC-262": "enterprise_administration",   # WSUS
    "GC-263": "enterprise_administration",   # DNS
    "GC-264": "enterprise_administration",   # PKI
    "GC-265": "enterprise_administration",   # Print
    "GC-266": "enterprise_administration",   # DHCP
    "GC-267": "enterprise_administration",   # GPO
    "GC-268": "enterprise_administration",   # VSS create
    "GC-269": "enterprise_administration",   # FSRM
    "GC-270": "enterprise_administration",   # WUA
    "GC-271": "enterprise_administration",   # LAPS
    "GC-272": "enterprise_administration",   # RDS
    "GC-273": "enterprise_administration",   # SCOM
    "GC-274": "enterprise_administration",   # Defender MpCmdRun

    # ── Round-2 malware (GC-275 → GC-286) ───────────────────────────
    "GC-275": "downloaders",                 # TrickBot
    "GC-276": "lateral_movement",            # Ryuk net view/user
    "GC-277": "ransomware",                  # LockBit shadow purge
    "GC-278": "downloaders",                 # BlackCat config fetch
    "GC-279": "credential_access",           # Conti esentutl NTDS
    "GC-280": "downloaders",                 # Bumblebee IEX WebClient
    "GC-281": "downloaders",                 # DarkGate curl
    "GC-282": "lolbas",                      # IcedID rundll32
    "GC-283": "downloaders",                 # Astaroth bitsadmin
    "GC-284": "packers_obfuscation",         # Snake KeyLogger reflection
    "GC-285": "lolbas",                      # SocGholish mshta
    "GC-286": "downloaders",                 # Latrodectus aliased IEX

    # ── Round-2 edge cases (GC-287 → GC-290) ────────────────────────
    "GC-287": "packers_obfuscation",         # Invoke-Obfuscation ticks
    "GC-288": "packers_obfuscation",         # format-op
    "GC-289": "packers_obfuscation",         # DOSfuscation caret
    "GC-290": "lolbas",                      # WMIC XSL LOLBAS
}


def category_for_sample_id(sample_id: str, fallback: str = "edge_case_regression") -> str:
    """Return the canonical category for a corpus sample ID.

    Lookup is by ID prefix (first 6 chars = "GC-NNN"). Unknown IDs
    return the fallback (`edge_case_regression`) so unclassified samples
    are visible in per-category coverage without breaking the run.
    """
    key = (sample_id or "")[:6]
    return _ID_PREFIX_CATEGORY.get(key, fallback)


__all__ = ["category_for_sample_id"]
