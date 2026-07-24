"""v2/verdict/weights.py · Verdict Engine v3 configuration.

Every weight, family cap, band boundary, and corroboration flag lives here
so operators can tune the engine without touching detector code.
"""
from __future__ import annotations

# MITRE technique families — deterministic lookup (no regex per event).
MITRE_CRITICAL = frozenset({"T1003", "T1055", "T1486", "T1489", "T1490", "T1620"})
MITRE_HIGH_RISK = frozenset({"T1218", "T1027", "T1547", "T1562", "T1053", "T1197"})

# Signals by family — used for anti-inflation caps.
FAMILY_OF = {
    "MITRE_CRITICAL":         "execution",
    "MITRE_HIGH_RISK":        "execution",
    "MITRE_OTHER":            "execution",
    "RULE_HIT":               "execution",
    "MITRE_CORRELATED":       "execution",
    "MULTI_STAGE":            "execution",
    "LOLBAS_ABUSE":           "execution",
    "SUSPICIOUS_PARENT":      "execution",
    "SERVICE_CREATED_PROC":   "execution",

    "REGISTRY_PERSISTENCE":   "persistence",
    "SCHEDULED_TASK_CREATE":  "persistence",
    "WMI_PERSISTENCE":        "persistence",

    "CREDENTIAL_DUMPING":     "credential",
    "LSASS_ACCESS":           "credential",

    "PROCESS_INJECTION":      "evasion",
    "AMSI_BYPASS":            "evasion",
    "DEFENDER_TAMPERING":     "evasion",
    "ENCODED_POWERSHELL":     "evasion",
    "OBFUSCATION":            "evasion",

    "BACKUP_DESTRUCTION":     "impact",
    "SHADOW_COPY_DELETE":     "impact",
    "RANSOM_NOTE_CREATION":   "impact",
    "MASS_FILE_ENCRYPTION":   "impact",

    "NETWORK_BEACONING":      "network",
    "EXTERNAL_C2":            "network",
    "DOWNLOAD_CRADLE":        "network",

    "NEWLY_DROPPED_EXECUTABLE":"artefact",
    "UNSIGNED_EXECUTABLE":     "artefact",
    "HIGH_ENTROPY_PAYLOAD":    "artefact",
    "CHAIN_COMPLEXITY":        "artefact",
}

WEIGHTS: dict[str, int] = {
    "MITRE_CRITICAL":           +25,
    "MITRE_HIGH_RISK":          +12,
    "MITRE_OTHER":              +4,
    "RULE_HIT":                 +10,
    "MITRE_CORRELATED":         +8,
    "MULTI_STAGE":              +8,
    "LOLBAS_ABUSE":             +8,
    "SUSPICIOUS_PARENT":        +18,
    "SERVICE_CREATED_PROC":     +12,
    "REGISTRY_PERSISTENCE":     +15,
    "SCHEDULED_TASK_CREATE":    +12,
    "WMI_PERSISTENCE":          +18,
    "CREDENTIAL_DUMPING":       +25,
    "LSASS_ACCESS":             +18,
    "PROCESS_INJECTION":        +18,
    "AMSI_BYPASS":              +18,
    "DEFENDER_TAMPERING":       +18,
    "ENCODED_POWERSHELL":       +10,
    "OBFUSCATION":              +8,
    "BACKUP_DESTRUCTION":       +25,
    "SHADOW_COPY_DELETE":       +20,
    "RANSOM_NOTE_CREATION":     +25,
    "MASS_FILE_ENCRYPTION":     +30,
    "NETWORK_BEACONING":        +15,
    "EXTERNAL_C2":              +18,
    "DOWNLOAD_CRADLE":          +15,
    "NEWLY_DROPPED_EXECUTABLE": +8,
    "UNSIGNED_EXECUTABLE":      +4,
    "HIGH_ENTROPY_PAYLOAD":     +6,
    "CHAIN_COMPLEXITY":         +6,
}

DECAY_WEIGHTS: dict[str, int] = {
    "SIGNED_MICROSOFT_BINARY":  -4,
    "EXPECTED_PARENT_CHILD":    -4,
    "NO_MITRE_TAGS":            -4,
}

# Signals that alone cap the final score at 70 unless another unrelated
# family also fires (see engine.corroboration_rule).
CORROBORATION_REQUIRED = frozenset({
    "MITRE_CRITICAL", "LSASS_ACCESS", "PROCESS_INJECTION",
    "AMSI_BYPASS", "MASS_FILE_ENCRYPTION", "BACKUP_DESTRUCTION",
})

# Anti-inflation caps per family — no family may contribute more than this.
FAMILY_CAPS: dict[str, int] = {
    "execution":   40,
    "persistence": 30,
    "credential":  30,
    "evasion":     25,
    "impact":      40,
    "network":     25,
    "artefact":    15,
}

# Band edges (inclusive lower, inclusive upper).
BANDS: list[tuple[str, int, int]] = [
    ("benign",         0,  15),
    ("informational", 16,  35),
    ("low",           36,  55),
    ("suspicious",    56,  70),
    ("malicious",     71,  85),
    ("critical",      86, 100),
]

# Score capped by corroboration rule when only one high-value signal fired.
CORROBORATION_CAP = 70


def band_of(score: int) -> str:
    for name, lo, hi in BANDS:
        if lo <= score <= hi:
            return name
    return "critical" if score > 100 else "benign"
