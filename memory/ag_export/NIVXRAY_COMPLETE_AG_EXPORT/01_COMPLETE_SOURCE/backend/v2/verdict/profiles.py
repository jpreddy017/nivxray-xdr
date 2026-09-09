"""v2/verdict/profiles.py · Adaptive Weight Profiles for Verdict Engine v3.1.

Six deterministic operator personas. Each profile is a *shallow overlay* on
top of the default `WEIGHTS`, `FAMILY_CAPS`, and correlation-bonus tables
in `weights.py`. Applying a profile never changes engine logic — only the
tuning constants — so every scoring rule remains reproducible.

Profiles:
    soc_balanced    (default)  — general SOC triage; balanced FP/FN.
    threat_hunting            — hunt for weak signals; lower persistence bar.
    dfir                       — post-breach forensics; heavier evidence weight.
    high_security             — critical-infra; aggressive on evasion/persist.
    cloud_workload            — Linux/container/K8s; downweights Windows-only.
    ot_ics                    — SCADA/OT; treat any admin activity as risky.

Public API:
    from v2.verdict.profiles import PROFILES, get_profile
    p = get_profile("dfir")
    p["weights"]              # dict[signal] → override
    p["family_caps"]          # dict[family]  → override
    p["bonus_multiplier"]     # float 0.5–1.5
"""
from __future__ import annotations
from typing import Any


PROFILES: dict[str, dict[str, Any]] = {
    "soc_balanced": {
        "label":            "SOC Balanced",
        "description":      "General-purpose SOC triage. Balanced sensitivity, low false-positive tolerance.",
        "weights":          {},
        "family_caps":      {},
        "bonus_multiplier": 1.0,
        "band_shift":       0,
    },
    "threat_hunting": {
        "label":            "Threat Hunting",
        "description":      "Hunt for weak signals; boost low-confidence evidence so subtle behaviour rises above the noise floor.",
        "weights": {
            "MITRE_OTHER":            +8,     # from +4
            "OBFUSCATION":            +12,    # from +8
            "LOLBAS_ABUSE":           +12,    # from +8
            "ENCODED_POWERSHELL":     +14,    # from +10
            "SUSPICIOUS_PARENT":      +22,    # from +18
        },
        "family_caps": {
            "artefact": 25,   # from 15 — surface weak evidence
            "evasion":  35,   # from 25
        },
        "bonus_multiplier": 1.15,
        "band_shift":       0,
    },
    "dfir": {
        "label":            "DFIR",
        "description":      "Post-breach forensics; every artefact matters. Heavier evidence weights, no corroboration ceiling on high-value signals.",
        "weights": {
            "CREDENTIAL_DUMPING":     +30,   # from +25
            "LSASS_ACCESS":           +22,   # from +18
            "PROCESS_INJECTION":      +22,   # from +18
            "REGISTRY_PERSISTENCE":   +18,   # from +15
            "SCHEDULED_TASK_CREATE":  +16,   # from +12
            "WMI_PERSISTENCE":        +22,   # from +18
        },
        "family_caps": {
            "credential":  45,   # from 30
            "persistence": 40,   # from 30
            "artefact":    25,
        },
        "bonus_multiplier": 1.25,
        "band_shift":       0,
    },
    "high_security": {
        "label":            "High Security",
        "description":      "Critical infrastructure. Aggressive on evasion, persistence, and impact. Zero tolerance for suspicious parents.",
        "weights": {
            "SUSPICIOUS_PARENT":      +26,   # from +18
            "AMSI_BYPASS":            +25,   # from +18
            "DEFENDER_TAMPERING":     +25,   # from +18
            "BACKUP_DESTRUCTION":     +30,
            "SHADOW_COPY_DELETE":     +28,   # from +20
            "OBFUSCATION":            +14,   # from +8
        },
        "family_caps": {
            "evasion":     35,   # from 25
            "impact":      50,   # from 40
            "persistence": 40,   # from 30
        },
        "bonus_multiplier": 1.30,
        "band_shift":       0,
    },
    "cloud_workload": {
        "label":            "Cloud Workload",
        "description":      "Linux / container / Kubernetes emphasis. Downweight Windows-only signals; upweight network + credential-access.",
        "weights": {
            # Windows-specific signals get partially neutralised.
            "REGISTRY_PERSISTENCE":   +6,    # from +15
            "WMI_PERSISTENCE":        +6,    # from +18
            "SHADOW_COPY_DELETE":     +6,    # from +20
            "BACKUP_DESTRUCTION":     +6,    # from +25
            "DEFENDER_TAMPERING":     +4,    # from +18
            # Boost network + credential signals — the cloud attack surface.
            "NETWORK_BEACONING":      +22,   # from +15
            "EXTERNAL_C2":            +25,   # from +18
            "DOWNLOAD_CRADLE":        +20,   # from +15
            "CREDENTIAL_DUMPING":     +30,   # from +25
        },
        "family_caps": {
            "network":     40,   # from 25 — the primary attack surface
            "credential":  40,
            "persistence": 15,   # from 30
        },
        "bonus_multiplier": 1.0,
        "band_shift":       0,
    },
    "ot_ics": {
        "label":            "OT / ICS",
        "description":      "Operational-technology and industrial control. Treat any interactive-shell or admin utility as high risk (baseline is nothing should ever run).",
        "weights": {
            "LOLBAS_ABUSE":           +25,   # from +8
            "SUSPICIOUS_PARENT":      +30,   # from +18
            "ENCODED_POWERSHELL":     +25,   # from +10
            "SCHEDULED_TASK_CREATE":  +22,   # from +12
            "DEFENDER_TAMPERING":     +25,   # from +18
            "OBFUSCATION":            +16,   # from +8
        },
        "family_caps": {
            "execution":   60,   # from 40 — OT baseline is "nothing runs"
            "evasion":     40,   # from 25
            "persistence": 40,   # from 30
        },
        "bonus_multiplier": 1.35,
        "band_shift":       5,   # shift all bands up by 5 points on the risk scale
    },
}

DEFAULT_PROFILE = "soc_balanced"


def get_profile(name: str | None) -> dict[str, Any]:
    """Return a profile config; falls back to soc_balanced when unknown."""
    if not name:
        return PROFILES[DEFAULT_PROFILE]
    return PROFILES.get(name.lower(), PROFILES[DEFAULT_PROFILE])


def apply_weights(base_weights: dict[str, int], profile: dict[str, Any]) -> dict[str, int]:
    """Return a NEW dict with the profile's per-signal overrides applied."""
    out = dict(base_weights)
    for k, v in (profile.get("weights") or {}).items():
        out[k] = v
    return out


def apply_family_caps(base_caps: dict[str, int], profile: dict[str, Any]) -> dict[str, int]:
    """Return a NEW dict with the profile's per-family cap overrides applied."""
    out = dict(base_caps)
    for k, v in (profile.get("family_caps") or {}).items():
        out[k] = v
    return out


def list_profiles() -> list[dict[str, Any]]:
    """Return every profile as a public summary — no internal tables leaked."""
    return [
        {"id": pid, "label": p["label"], "description": p["description"],
         "bonus_multiplier": p.get("bonus_multiplier", 1.0),
         "band_shift":       p.get("band_shift", 0),
         "is_default":       pid == DEFAULT_PROFILE}
        for pid, p in PROFILES.items()
    ]
