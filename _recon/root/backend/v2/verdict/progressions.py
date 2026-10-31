"""v2/verdict/progressions.py · Deterministic Attack Progression Bonus.

**Generic** kill-chain graphs — NOT campaign-specific signatures. A progression
is an ordered set of *stages*, where each stage is a predicate over a set of
signals / families / MITRE-tactic bases. We match a progression against the
UNION of signals fired anywhere in a chain (or the device), so temporal order
along the attack graph doesn't matter — only that each stage has evidence
somewhere in the process tree.

A progression contributes a bonus proportional to the fraction of stages it
covers (thresholded at ≥5/7 minimum). Two thresholds:

    ≥ 5/N stages covered  →  +8    (partial progression)
    ≥ 7/N or all stages   → +14    (full progression)

Progressions currently modelled:

    KC_INITIAL_ACCESS_KILL   office_parent → lolbas → download → persistence
                             → evasion → credential → impact
    KC_DOWNLOAD_EXECUTE      shell → download_cradle → persistence → evasion
    KC_CREDENTIAL_TO_LATERAL shell → credential → evasion → network
    KC_PS_RUNKEY_BEACON      office → powershell → encoded → webclient →
                             runkey → beacon

No hard-coded family names. All matchers are pure functions of the aggregated
signal / family / tactic sets.
"""
from __future__ import annotations
from typing import Callable


# ─── Stage predicates ─────────────────────────────────────────────────

def _stage(name: str, predicate: Callable[[set, set, set], bool]) -> dict:
    return {"name": name, "predicate": predicate}


# Each predicate receives (signals, families, tactics) — all sets.
def _has_signal(*keys: str):
    keys_s = set(keys)
    return lambda s, f, t: bool(s & keys_s)

def _has_family(fam: str):
    return lambda s, f, t: fam in f

def _has_tactic(*tacs: str):
    tacs_s = set(tacs)
    return lambda s, f, t: bool(t & tacs_s)

def _has_any(*preds):
    return lambda s, f, t: any(p(s, f, t) for p in preds)

def _has_all(*preds):
    return lambda s, f, t: all(p(s, f, t) for p in preds)


# ─── Progressions ────────────────────────────────────────────────────

PROGRESSIONS: list[dict] = [
    {
        "id": "KC_INITIAL_ACCESS_KILL",
        "label": "Initial Access Kill-chain",
        "description": "Office → LOLBIN → Download → Persistence → Evasion → Credential → Impact",
        "stages": [
            _stage("suspicious_parent", _has_signal("SUSPICIOUS_PARENT")),
            _stage("lolbin_abuse",      _has_signal("LOLBAS_ABUSE", "ENCODED_POWERSHELL")),
            _stage("download",          _has_signal("DOWNLOAD_CRADLE", "EXTERNAL_C2", "NETWORK_BEACONING")),
            _stage("persistence",       _has_family("persistence")),
            _stage("defense_evasion",   _has_family("evasion")),
            _stage("credential_access", _has_any(_has_family("credential"),
                                                 _has_tactic("credential_access"))),
            _stage("impact",            _has_family("impact")),
        ],
    },
    {
        "id": "KC_DOWNLOAD_EXECUTE",
        "label": "Download-and-Execute Chain",
        "description": "Shell → Download Cradle → Persistence → Defense Evasion",
        "stages": [
            _stage("shell_or_lolbin", _has_signal("LOLBAS_ABUSE", "ENCODED_POWERSHELL", "SUSPICIOUS_PARENT")),
            _stage("download",        _has_signal("DOWNLOAD_CRADLE", "EXTERNAL_C2")),
            _stage("persistence",     _has_family("persistence")),
            _stage("evasion",         _has_family("evasion")),
        ],
    },
    {
        "id": "KC_CREDENTIAL_TO_LATERAL",
        "label": "Credential-to-Lateral Chain",
        "description": "Shell → Credential Access → Defense Evasion → Network / C2",
        "stages": [
            _stage("shell_or_lolbin", _has_signal("LOLBAS_ABUSE", "ENCODED_POWERSHELL")),
            _stage("credential",      _has_family("credential")),
            _stage("evasion",         _has_family("evasion")),
            _stage("network",         _has_family("network")),
        ],
    },
    {
        "id": "KC_PS_RUNKEY_BEACON",
        "label": "PowerShell RunKey Beacon Chain",
        "description": "Office → PowerShell → Encoded → WebClient → RunKey → Beacon",
        "stages": [
            _stage("office_parent",   _has_signal("SUSPICIOUS_PARENT")),
            _stage("encoded_ps",      _has_signal("ENCODED_POWERSHELL")),
            _stage("web_download",    _has_signal("DOWNLOAD_CRADLE")),
            _stage("run_key_persist", _has_signal("REGISTRY_PERSISTENCE", "SCHEDULED_TASK_CREATE",
                                                  "WMI_PERSISTENCE")),
            _stage("beacon",          _has_signal("EXTERNAL_C2", "NETWORK_BEACONING")),
        ],
    },
    {
        "id": "KC_RANSOM_PROGRESSION",
        "label": "Ransomware Progression",
        "description": "Execution → Persistence → Defense Evasion → Backup Destruction → Mass Encryption → Ransom Note",
        "stages": [
            _stage("execution",       _has_family("execution")),
            _stage("persistence",     _has_family("persistence")),
            _stage("evasion",         _has_family("evasion")),
            _stage("backup_destroy",  _has_signal("BACKUP_DESTRUCTION", "SHADOW_COPY_DELETE")),
            _stage("mass_encrypt",    _has_signal("MASS_FILE_ENCRYPTION")),
            _stage("ransom_note",     _has_signal("RANSOM_NOTE_CREATION")),
        ],
    },
]

# Score contributions per progression.
PROGRESSION_PARTIAL_THRESHOLD = 5     # min stages matched to count as partial
PROGRESSION_PARTIAL_BONUS     = 8
PROGRESSION_FULL_BONUS        = 14    # awarded when ≥7 stages OR all stages match


def match_progressions(signals: set[str], families: set[str],
                       tactics: set[str]) -> list[dict]:
    """Return a list of matched progressions with their bonus contribution.

    Deterministic. Order-preserving. Pure function of the input sets.
    """
    matched: list[dict] = []
    for prog in PROGRESSIONS:
        stages = prog["stages"]
        hits = [s["name"] for s in stages if s["predicate"](signals, families, tactics)]
        n_stages = len(stages)
        n_hits = len(hits)
        if n_hits == 0:
            continue

        # Small progressions (4 stages) — require ≥3 stages for partial.
        partial_th = min(PROGRESSION_PARTIAL_THRESHOLD, max(3, n_stages - 1))
        if n_hits < partial_th:
            continue

        full = (n_hits >= 7) or (n_hits == n_stages)
        weight = PROGRESSION_FULL_BONUS if full else PROGRESSION_PARTIAL_BONUS

        matched.append({
            "signal":      f"ATTACK_PROGRESSION_{prog['id']}",
            "id":          prog["id"],
            "label":       prog["label"],
            "description": prog["description"],
            "stages_matched": hits,
            "stages_total":   n_stages,
            "weight":         weight,
            "full":           full,
            "reason":         f"{n_hits}/{n_stages} stages of "
                              f"{prog['label']} matched: {', '.join(hits)}",
        })
    return matched
