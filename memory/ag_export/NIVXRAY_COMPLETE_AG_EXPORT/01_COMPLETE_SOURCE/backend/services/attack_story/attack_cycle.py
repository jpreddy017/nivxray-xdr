"""Round 33 · NivXRay XDR · Attack Cycle (centralised).

The 14-stage Attack Cycle is the shared vocabulary for:
  * Round 33 · Attack Story + AttackFlow (this round)
  * Round 34 · Threat Model Engine (Executive Threat Model coverage)

**Do not duplicate this list**.  Every consumer must import STAGES.
"""
from __future__ import annotations

from typing import Dict, List, Literal, Tuple


# Owner-locked 14-stage cycle (AUTONOMOUS_INVESTIGATION.md §17).
STAGES: Tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command & Control",
    "Exfiltration",
    "Impact",
)

STAGE_INDEX: Dict[str, int] = {s: i for i, s in enumerate(STAGES)}


# Attack Path state grammar (§17).
StageState = Literal["OBSERVED", "SUPPORTED", "POSSIBLE", "NOT_OBSERVED"]


# MITRE tactic → stage.  Both by tactic id (TA****) and by short slug.
TACTIC_TO_STAGE: Dict[str, str] = {
    # Tactic ids
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command & Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
    # Slugs
    "reconnaissance":         "Reconnaissance",
    "resource-development":   "Resource Development",
    "resource_development":   "Resource Development",
    "initial-access":         "Initial Access",
    "initial_access":         "Initial Access",
    "execution":              "Execution",
    "persistence":            "Persistence",
    "privilege-escalation":   "Privilege Escalation",
    "privilege_escalation":   "Privilege Escalation",
    "defense-evasion":        "Defense Evasion",
    "defense_evasion":        "Defense Evasion",
    "credential-access":      "Credential Access",
    "credential_access":      "Credential Access",
    "discovery":              "Discovery",
    "lateral-movement":       "Lateral Movement",
    "lateral_movement":       "Lateral Movement",
    "collection":             "Collection",
    "command-and-control":    "Command & Control",
    "command_and_control":    "Command & Control",
    "c2":                     "Command & Control",
    "exfiltration":           "Exfiltration",
    "impact":                 "Impact",
}


# Deterministic technique → tactic hints for common techniques when the
# incident's mitre records carry technique_id but no tactic.  These
# are drawn from ATT&CK Enterprise — never invented.
TECHNIQUE_TO_TACTIC: Dict[str, Tuple[str, ...]] = {
    "T1059":     ("TA0002",),                # Command and Scripting Interpreter
    "T1059.001": ("TA0002",),                # PowerShell
    "T1059.003": ("TA0002",),                # Windows Command Shell
    "T1105":     ("TA0011",),                # Ingress Tool Transfer
    "T1218":     ("TA0005",),                # System Binary Proxy Execution
    "T1218.011": ("TA0005",),                # rundll32
    "T1140":     ("TA0005",),                # Deobfuscate/Decode Files
    "T1027":     ("TA0005",),                # Obfuscated Files
    "T1071":     ("TA0011",),                # Application Layer Protocol
    "T1071.001": ("TA0011",),                # Web Protocols (C2)
    "T1571":     ("TA0011",),                # Non-Standard Port
    "T1547":     ("TA0003", "TA0004"),       # Boot/Logon Autostart
    "T1053":     ("TA0003", "TA0002"),       # Scheduled Task
    "T1078":     ("TA0001", "TA0003", "TA0004", "TA0005"),  # Valid Accounts
    "T1021":     ("TA0008",),                # Remote Services
    "T1550":     ("TA0006", "TA0008"),       # Use Alternate Authentication
    "T1003":     ("TA0006",),                # OS Credential Dumping
    "T1055":     ("TA0005", "TA0004"),       # Process Injection
    "T1041":     ("TA0010",),                # Exfiltration over C2
}


def normalize_tactic(tactic: str | None) -> str | None:
    """Return the canonical stage name for a tactic id / slug, or None."""
    if not tactic:
        return None
    return TACTIC_TO_STAGE.get(str(tactic).strip().upper()) \
              or TACTIC_TO_STAGE.get(str(tactic).strip().lower())


def stages_for_technique(technique_id: str) -> List[str]:
    """Deterministic tactic → stage mapping for a technique id.

    Returns the list of stages the technique is documented to belong
    to (Enterprise ATT&CK).  Empty list = unmapped; the caller must
    honestly leave the stage as POSSIBLE / NOT_OBSERVED rather than
    invent one.
    """
    tid = str(technique_id or "").upper().strip()
    tactics = TECHNIQUE_TO_TACTIC.get(tid, ())
    if not tactics:
        # Try the family prefix (e.g. T1218.011 → T1218).
        if "." in tid:
            tactics = TECHNIQUE_TO_TACTIC.get(tid.split(".")[0], ())
    return [s for s in (normalize_tactic(t) for t in tactics) if s]
