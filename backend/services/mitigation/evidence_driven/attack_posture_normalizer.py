"""Attack-Posture Normalizer · downstream of the Workspace Projector.

STRICT contract per user directive (2026-02-05):

    "The projector must be pure field-copy.  Any derivation from
    already-asserted MITRE techniques — even the deterministic
    MITRE-published technique→tactic parent relationship — must
    live in a downstream module so the projector boundary stays
    unambiguous."

Architecture:

    SSOT → Workspace Projector (pure copy) → InvestigationOutcome
                                                   │
                                                   ▼
                                      Attack Posture Normalizer  ← this module
                                                   │
                                                   ▼
                                    InvestigationOutcome (posture filled)
                                                   │
                                                   ▼
                                     Evidence-Driven Engine

Rules this module MUST obey:
    · Read ONLY the ``mitre_techniques`` field on the outcome.
    · NEVER read ``output_text``, ``processes``, ``commands`` or any
      raw evidence field.
    · NEVER regex, string-match, or invoke external services.
    · NEVER add or drop a MITRE technique — the input's
      ``mitre_techniques`` list passes through unchanged.
    · Use the static MITRE-published technique→tactic parent
      relationship as the sole normalization source.
    · Techniques not in the published map leave every tactic at
      whatever the outcome already has (default: ``not_observed``).
    · Deterministic + idempotent — running the normalizer twice
      yields the same outcome.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, Iterable


# ── MITRE ATT&CK · technique → parent tactic ─────────────────────
# This mapping is the ATT&CK-published parent relationship for every
# technique the rule library or Workspace currently references.  It
# is a static lookup of published truth (e.g. T1486 IS an Impact
# technique — MITRE says so); it is NOT inference.
#
# When the Workspace starts emitting a new technique, add a row
# here.  We do NOT invent techniques the Workspace didn't produce.
TECHNIQUE_TO_TACTIC: Dict[str, str] = {
    # Initial Access
    "T1566":        "initial_access",   "T1566.001": "initial_access",
    "T1566.002":    "initial_access",   "T1656":     "initial_access",
    "T1219":        "initial_access",   "T1219.002": "initial_access",
    # Execution
    "T1053":        "execution",        "T1053.005": "execution",
    "T1059":        "execution",        "T1059.001": "execution",
    "T1047":        "execution",        "T1569":     "execution",
    "T1569.002":    "execution",        "T1218":     "execution",
    "T1218.007":    "execution",
    # Persistence
    "T1547":        "persistence",      "T1543":     "persistence",
    "T1543.003":    "persistence",      "T1136":     "persistence",
    # Privilege Escalation
    "T1548":        "privilege_escalation",
    "T1548.002":    "privilege_escalation",
    # Defense Evasion
    "T1027":        "defense_evasion",  "T1140":     "defense_evasion",
    "T1112":        "defense_evasion",  "T1070":     "defense_evasion",
    "T1070.001":    "defense_evasion",  "T1562":     "defense_evasion",
    "T1562.001":    "defense_evasion",  "T1620":     "defense_evasion",
    # Credential Access
    "T1003":        "credential_access","T1003.001": "credential_access",
    "T1056":        "credential_access","T1056.003": "credential_access",
    # Discovery
    "T1016":        "discovery",        "T1018":     "discovery",
    "T1033":        "discovery",        "T1082":     "discovery",
    "T1087":        "discovery",
    # Lateral Movement
    "T1021":        "lateral_movement", "T1021.001": "lateral_movement",
    "T1021.002":    "lateral_movement",
    # Collection
    "T1039":        "collection",       "T1005":     "collection",
    # Command and Control
    "T1071":        "command_and_control",
    "T1071.001":    "command_and_control",
    "T1090":        "command_and_control",
    "T1090.002":    "command_and_control",
    "T1055":        "command_and_control",   # process-injection C2
    "T1105":        "command_and_control",   # ingress tool transfer
    # Exfiltration
    "T1041":        "exfiltration",     "T1567":     "exfiltration",
    # Impact
    "T1486":        "impact",           "T1490":     "impact",
    "T1531":        "impact",           "T1485":     "impact",
}


def derive_posture_from_mitre(techniques: Iterable[Any]) -> Dict[str, str]:
    """Return ``{tactic: "confirmed"}`` for each supplied technique
    that maps to a MITRE-published parent tactic.

    Techniques absent from the published map contribute nothing —
    they neither add a tactic nor invalidate one.  This function
    NEVER reads raw evidence; its only input is the technique list
    the outcome already contains.
    """
    out: Dict[str, str] = {}
    for tech in (techniques or ()):
        tactic = TECHNIQUE_TO_TACTIC.get(str(tech))
        if tactic:
            out[tactic] = "confirmed"
    return out


def normalize_attack_posture(outcome: Dict[str, Any]) -> Dict[str, Any]:
    """Return a NEW outcome with ``attack_posture`` derived from
    the already-asserted ``mitre_techniques`` field.

    · Input is not mutated (deep-copied for safety).
    · ``mitre_techniques`` passes through untouched.
    · Every other outcome field passes through untouched.
    · Idempotent — running twice yields the same outcome.
    · If the outcome has no ``mitre_techniques``, every tactic that
      was ``not_observed`` stays ``not_observed`` (nothing changes).
    · A tactic already marked ``confirmed`` / ``strong`` / etc.
      stays as-is — the normalizer only *upgrades* tactics whose
      current value is falsy or ``not_observed`` to ``confirmed``.
    """
    if not isinstance(outcome, dict):
        return outcome
    o = copy.deepcopy(outcome)

    techniques = o.get("mitre_techniques") or ()
    derived    = derive_posture_from_mitre(techniques)

    posture = dict(o.get("attack_posture") or {})
    for tactic, status in derived.items():
        # Preserve any pre-existing meaningful status (e.g. an
        # already-set ``confirmed``/``strong`` from an upstream
        # engine); only upgrade ``not_observed`` / falsy values.
        current = posture.get(tactic)
        if not current or current == "not_observed":
            posture[tactic] = status
    o["attack_posture"] = posture
    return o


__all__ = [
    "TECHNIQUE_TO_TACTIC",
    "derive_posture_from_mitre",
    "normalize_attack_posture",
]
