"""P1-02b · Evidence Classes + Deterministic Escalation Rules.

Replaces ad-hoc numeric weight tuning with a five-class tiered model:

    CRITICAL (5) — independently high-confidence malicious signals
    HIGH     (3) — abuse patterns (LOLBAS · IEX · BITS · encoded PS · staging)
    MEDIUM   (2) — MITRE technique · obfuscation · registry mod · scheduled task
    LOW      (1) — a single suspicious IOC · a single decoded layer
    CONTEXT (0.5) — YARA / Sigma pre-detection · reputation · TI hint

Deterministic escalation rules force verdict promotion when specific
evidence combinations fire, independent of the numeric score. This is
the analyst's intuition made machine-readable — analysts do not add
scores in their head; they recognise patterns.

Every escalation rule is a pure function of the active-contributor
kind set. No timing, no randomness, no persistent state — replayable
by construction.

Adding a new detection is 3 lines: add its kind to a class, optionally
add it to an escalation rule. No numeric retuning.
"""
from __future__ import annotations

from enum import Enum
from typing import Iterable, Optional, Set


# ─── Evidence classes ─────────────────────────────────────────────────

class EvidenceClass(str, Enum):
    CRITICAL = "critical"     # weight 5
    HIGH     = "high"         # weight 3
    MEDIUM   = "medium"       # weight 2
    LOW      = "low"          # weight 1
    CONTEXT  = "context"      # weight 0.5
    MITIGATING = "mitigating" # weight -1 (negative evidence)


CLASS_WEIGHT: dict[EvidenceClass, float] = {
    EvidenceClass.CRITICAL:   5.0,
    EvidenceClass.HIGH:       3.0,
    EvidenceClass.MEDIUM:     2.0,
    EvidenceClass.LOW:        1.0,
    EvidenceClass.CONTEXT:    0.5,
    EvidenceClass.MITIGATING: -1.0,
}


# Every kind the verdict engine can see is classified here.
# Adding a new kind is one line — no numeric tuning.
KIND_TO_CLASS: dict[str, EvidenceClass] = {
    # ── CRITICAL — dominant malicious signals ──────────────────────
    "custom_recipe_hit":       EvidenceClass.CRITICAL,
    "malware_family_match":    EvidenceClass.CRITICAL,   # sha → family
    "sha_matched_family":      EvidenceClass.CRITICAL,
    "malware_disposition":     EvidenceClass.CRITICAL,   # quarantined / blocked
    "quarantine_action":       EvidenceClass.CRITICAL,
    "child_process_execution": EvidenceClass.CRITICAL,   # confirmed execution
    "known_c2":                EvidenceClass.CRITICAL,
    "confirmed_malicious_ip":  EvidenceClass.CRITICAL,
    "confirmed_malicious_url": EvidenceClass.CRITICAL,
    "confirmed_malicious_hash":EvidenceClass.CRITICAL,
    # ── HIGH — abuse patterns ──────────────────────────────────────
    "lolbin":                  EvidenceClass.HIGH,
    "signed_binary_proxy":     EvidenceClass.HIGH,
    "encoded_powershell":      EvidenceClass.HIGH,
    "invoke_expression":       EvidenceClass.HIGH,       # IEX
    "bits_abuse":              EvidenceClass.HIGH,
    "rundll32_abuse":          EvidenceClass.HIGH,
    "regsvr32_abuse":          EvidenceClass.HIGH,
    "mshta_abuse":             EvidenceClass.HIGH,
    "wmi_abuse":               EvidenceClass.HIGH,
    # BUG-P4-01 architectural fix · discovery-only WMI queries are LOW.
    # `wmic ... get commandline`, `Get-WmiObject`, `Get-CimInstance` etc
    # are enumeration and MUST NOT drive attack-chain HIGH escalation.
    "wmi_discovery":           EvidenceClass.LOW,
    "network_beacon":          EvidenceClass.HIGH,
    "network_staging":         EvidenceClass.HIGH,
    "persistence":             EvidenceClass.HIGH,
    "credential_access":       EvidenceClass.HIGH,
    "lsass_access":            EvidenceClass.HIGH,
    "lateral_movement":        EvidenceClass.HIGH,
    "reflective_injection":    EvidenceClass.HIGH,
    "rule_hit":                EvidenceClass.HIGH,       # detection rule
    "sigma_hit":               EvidenceClass.HIGH,
    "external_ioc_ip":         EvidenceClass.HIGH,       # IP appearing in an execution context
    "hash_ioc":                EvidenceClass.HIGH,
    # Sprint 1 · graph-topology + temporal correlation signals
    "execution_chain_correlated": EvidenceClass.HIGH,
    "temporal_burst":             EvidenceClass.HIGH,
    "entity_chain_correlated":    EvidenceClass.HIGH,
    "shellcode_detected":         EvidenceClass.CRITICAL,   # confirmed x86/x64 shellcode landed
    # ── MITIGATING — negative evidence ─────────────────────────────
    "mitigating_signal":       EvidenceClass.MITIGATING,
    "signed_microsoft_binary": EvidenceClass.MITIGATING,
    "internal_ip":             EvidenceClass.MITIGATING,
    "enterprise_allowlist":    EvidenceClass.MITIGATING,
    "benign_parent":           EvidenceClass.MITIGATING,
    # ── MEDIUM — technique / context ───────────────────────────────
    "mitre_technique":         EvidenceClass.MEDIUM,
    "obfuscated_command":      EvidenceClass.MEDIUM,
    "registry_mod":            EvidenceClass.MEDIUM,
    "service_creation":        EvidenceClass.MEDIUM,
    "scheduled_task":          EvidenceClass.MEDIUM,
    "defender_bypass":         EvidenceClass.MEDIUM,
    "amsi_bypass":             EvidenceClass.MEDIUM,
    # ── LOW — single suspicious signal ─────────────────────────────
    "external_ioc_url":        EvidenceClass.LOW,
    "external_ioc_domain":     EvidenceClass.LOW,
    "base64_layer":            EvidenceClass.LOW,
    "hex_layer":               EvidenceClass.LOW,
    "compression_layer":       EvidenceClass.LOW,
    "archive_extract":         EvidenceClass.LOW,
    # ── CONTEXT — supporting metadata ──────────────────────────────
    "yara_hit":                EvidenceClass.CONTEXT,
    "reputation_hint":         EvidenceClass.CONTEXT,
    "threat_family_hint":      EvidenceClass.CONTEXT,
    "threat_intel_hint":       EvidenceClass.CONTEXT,
    "behavioural_note":        EvidenceClass.CONTEXT,
    "ti_layer":                EvidenceClass.CONTEXT,
    # ── Zero-weight overrides (kept for backward compat) ───────────
    "vendor_infrastructure":   None,   # → 0
    "certificate_infrastructure": None,
    "internal_asset":          EvidenceClass.CONTEXT,
    "vendor_metadata":         None,
    "schema_url":              None,
    "unknown":                 None,
}


def class_of(kind: str) -> Optional[EvidenceClass]:
    """Return the evidence class for a contributor kind, or None if
    the kind should not contribute (weight=0)."""
    return KIND_TO_CLASS.get(kind)


def weight_of(kind: str) -> float:
    """Return the numeric weight for a contributor kind."""
    cls = class_of(kind)
    return CLASS_WEIGHT[cls] if cls is not None else 0.0


# ─── Deterministic escalation rules ───────────────────────────────────
#
# Each rule is a *combination of contributor kinds* that MUST promote
# the verdict to `Malicious` regardless of the numeric score. Encodes
# the analyst's rule-of-thumb: pattern recognition beats scoring.
#
# Rules are ordered by specificity. First-match-wins on `apply()`.

_ESCALATIONS_TO_MALICIOUS: list[tuple[str, frozenset[str]]] = [
    ("encoded PS + IEX + network download",
     frozenset({"encoded_powershell", "invoke_expression"})),  # + any external URL/download
    ("BITS + network download",
     frozenset({"bits_abuse"})),
    ("LOLBIN + persistence + known C2",
     frozenset({"lolbin", "persistence", "known_c2"})),
    ("LOLBIN + malicious hash",
     frozenset({"lolbin", "confirmed_malicious_hash"})),
    ("custom recipe (confirmed)",
     frozenset({"custom_recipe_hit"})),
    ("malware family + execution",
     frozenset({"sha_matched_family", "child_process_execution"})),
    ("lateral movement + credential access",
     frozenset({"lateral_movement", "credential_access"})),
    ("reflective injection + LSASS",
     frozenset({"reflective_injection", "lsass_access"})),
]

_ESCALATIONS_TO_SUSPICIOUS: list[tuple[str, frozenset[str]]] = [
    ("encoded PS + IEX",
     frozenset({"encoded_powershell", "invoke_expression"})),
    ("LOLBIN + obfuscated command",
     frozenset({"lolbin", "obfuscated_command"})),
    ("MITRE persistence technique",
     frozenset({"persistence", "mitre_technique"})),
]


def apply_escalation(active_kinds: Iterable[str]) -> tuple[Optional[str], Optional[str]]:
    """Return `(new_label, rule_that_fired)` when a deterministic
    escalation rule applies, else `(None, None)`.

    `active_kinds` is the set of contributor kinds that fired for this
    investigation. First-match-wins in the order rules are declared.
    """
    kset: Set[str] = set(active_kinds)

    # Escalate to Malicious first — the strongest promotion wins.
    for reason, required in _ESCALATIONS_TO_MALICIOUS:
        if required.issubset(kset):
            # Special case: rules like "BITS + network download" need
            # at least one URL/hash IOC to actually confirm network use.
            if reason == "BITS + network download" and not kset & {
                "external_ioc_url", "confirmed_malicious_url",
                "external_ioc_ip", "external_ioc_domain",
                "confirmed_malicious_ip", "confirmed_malicious_hash",
                "hash_ioc",
            }:
                continue
            if reason == "encoded PS + IEX + network download" and not kset & {
                "external_ioc_url", "confirmed_malicious_url",
                "external_ioc_ip", "confirmed_malicious_ip",
                "external_ioc_domain",
            }:
                continue
            return "Malicious", reason

    for reason, required in _ESCALATIONS_TO_SUSPICIOUS:
        if required.issubset(kset):
            return "Suspicious", reason

    return None, None


# ── Attack-chain kinds: HIGH-class kinds that indicate actual
# attacker behaviour (not ambient tooling). At least one is required
# alongside another HIGH before the class distribution promotes to
# Malicious — this stops the "expand.exe + powershell + alias-normalize"
# false-positive stack from graduating benign shell noise to Malicious.
ATTACK_CHAIN_HIGH: Set[str] = {
    "invoke_expression",
    "bits_abuse",
    "rundll32_abuse", "regsvr32_abuse", "mshta_abuse", "wmi_abuse",
    "network_beacon", "network_staging",
    "persistence", "credential_access", "lsass_access",
    "lateral_movement", "reflective_injection",
    "rule_hit", "sigma_hit",
    "confirmed_malicious_url", "confirmed_malicious_ip",
    "confirmed_malicious_hash", "known_c2",
    "sha_matched_family", "signed_binary_proxy",
    # Sprint 1 · topology + temporal correlation
    "execution_chain_correlated",
    "temporal_burst",
    "shellcode_detected",
}


__all__ = [
    "EvidenceClass",
    "CLASS_WEIGHT",
    "KIND_TO_CLASS",
    "ATTACK_CHAIN_HIGH",
    "class_of",
    "weight_of",
    "apply_escalation",
]
