"""
P0 · Round 20 · Furthest-Confirmed-Activity Closure Classification
──────────────────────────────────────────────────────────────────

**Deterministic, evidence-only.** No LLM. No family-based defaults.

Locked rule (PRD § Round 20):

    Incident closure classification MUST be derived from the deepest
    confirmed adversary phase in the investigation — NOT from the
    original alert stage.

Example: original Snort alert = Delivery (network signature), but the
investigation confirmed a C2 channel → the closure classification
becomes **Command & Control**, not Delivery.

Phase ladder (locked; ordered from earliest to furthest):

    RECONNAISSANCE
    ↓
    RESOURCE_DEVELOPMENT
    ↓
    INITIAL_ACCESS
    ↓
    EXECUTION
    ↓
    PERSISTENCE
    ↓
    PRIVILEGE_ESCALATION
    ↓
    DEFENSE_EVASION
    ↓
    CREDENTIAL_ACCESS
    ↓
    DISCOVERY
    ↓
    LATERAL_MOVEMENT
    ↓
    COLLECTION
    ↓
    COMMAND_AND_CONTROL
    ↓
    EXFILTRATION
    ↓
    IMPACT

The classifier examines confirmed evidence (canonical events, IUE
capability tags, VEEE verdict inputs, framework mappings that ACTIVE-
resolved, and closed-loop observations) and returns the FURTHEST
phase supported by the evidence.  It never fabricates phases.
"""
from __future__ import annotations
from typing import Any


CLASSIFIER_ENGINE_ID = "nivxray::xdr::furthest_confirmed_activity"
CLASSIFIER_VERSION   = "1.0.0"


# ── Phase ladder ────────────────────────────────────────────────
PHASE_ORDER: list[str] = [
    "RECONNAISSANCE",
    "RESOURCE_DEVELOPMENT",
    "INITIAL_ACCESS",
    "EXECUTION",
    "PERSISTENCE",
    "PRIVILEGE_ESCALATION",
    "DEFENSE_EVASION",
    "CREDENTIAL_ACCESS",
    "DISCOVERY",
    "LATERAL_MOVEMENT",
    "COLLECTION",
    "COMMAND_AND_CONTROL",
    "EXFILTRATION",
    "IMPACT",
]

PHASE_INDEX = {p: i for i, p in enumerate(PHASE_ORDER)}


# ── MITRE tactic → phase mapping ────────────────────────────────
# Every MITRE tactic maps to exactly one phase. Locked.

_MITRE_TACTIC_TO_PHASE: dict[str, str] = {
    "reconnaissance":         "RECONNAISSANCE",
    "resource-development":   "RESOURCE_DEVELOPMENT",
    "initial-access":         "INITIAL_ACCESS",
    "execution":              "EXECUTION",
    "persistence":            "PERSISTENCE",
    "privilege-escalation":   "PRIVILEGE_ESCALATION",
    "defense-evasion":        "DEFENSE_EVASION",
    "credential-access":      "CREDENTIAL_ACCESS",
    "discovery":              "DISCOVERY",
    "lateral-movement":       "LATERAL_MOVEMENT",
    "collection":             "COLLECTION",
    "command-and-control":    "COMMAND_AND_CONTROL",
    "exfiltration":           "EXFILTRATION",
    "impact":                 "IMPACT",
}


# ── Family → floor phase ────────────────────────────────────────
# When family classification is CONFIRMED but no framework map fires
# the phase floor keeps the closure honest (never below family
# semantics).

_FAMILY_PHASE_FLOOR: dict[str, str] = {
    "C2":                     "COMMAND_AND_CONTROL",
    "BOTNET":                 "COMMAND_AND_CONTROL",
    "LOADER":                 "EXECUTION",
    "MALWARE":                "EXECUTION",
    "RANSOMWARE":             "IMPACT",
    "WORM":                   "LATERAL_MOVEMENT",
    "INFOSTEALER":            "COLLECTION",
    "CREDENTIAL_THEFT":       "CREDENTIAL_ACCESS",
    "LATERAL_MOVEMENT":       "LATERAL_MOVEMENT",
    "PERSISTENCE":            "PERSISTENCE",
    "PHISHING":               "INITIAL_ACCESS",
    "PUA_ADWARE":             "EXECUTION",
    "SUSPICIOUS_APPLICATION": "EXECUTION",
    "UNKNOWN":                None,
}


def _phase_from_alert_category(canonical: dict) -> str | None:
    """The original Snort/Suricata alert category maps to a phase for
    provenance — this is the *initial alert phase*, NOT the closure."""
    cat = ((canonical or {}).get("security") or {}).get("category") or ""
    lc = cat.lower()
    if "command" in lc and "control" in lc:
        return "COMMAND_AND_CONTROL"
    if "exec" in lc:            return "EXECUTION"
    if "recon" in lc:           return "RECONNAISSANCE"
    if "lateral" in lc:         return "LATERAL_MOVEMENT"
    if "creden" in lc:          return "CREDENTIAL_ACCESS"
    if "persist" in lc:         return "PERSISTENCE"
    if "exfil" in lc:           return "EXFILTRATION"
    if "impact" in lc or "encrypt" in lc:
        return "IMPACT"
    # Suricata "potentially bad traffic" / generic network signal is
    # the initial-alert stage only.
    return None


def _bump(current: str | None, candidate: str | None,
              *, source: str, evidence_id: str | None,
              phases: list[dict]) -> str | None:
    """Return the greater of current and candidate; record the
    supporting evidence when the candidate is actually deeper."""
    if not candidate:
        return current
    if current is None or PHASE_INDEX[candidate] > PHASE_INDEX[current]:
        phases.append({"phase": candidate, "source": source,
                              "evidence_id": evidence_id})
        return candidate
    if candidate == current:
        phases.append({"phase": candidate, "source": source,
                              "evidence_id": evidence_id})
    return current


async def classify(db, incident_id: str) -> dict:
    """
    Return the deterministic closure classification for one incident.

    Every phase citation carries provenance so the analyst can trace
    WHY the classifier concluded the incident advanced that far.
    """
    inc = await db["workspace_cases"].find_one({"id": incident_id},
                                                                {"_id": 0})
    if not inc:
        return {"state":       "MISSING",
                    "incident_id": incident_id,
                    "engine_id":   CLASSIFIER_ENGINE_ID,
                    "reason":      f"incident {incident_id} not found"}

    prov = inc.get("xdr_pipeline") or {}
    canon_id = prov.get("canonical_event_id")
    canon = None
    if canon_id:
        canon = await db["xdr_canonical_evidence"].find_one(
            {"event_id": canon_id}, {"_id": 0})

    citations: list[dict] = []
    initial_alert_phase = _phase_from_alert_category(canon or {})
    furthest: str | None = initial_alert_phase
    if initial_alert_phase:
        citations.append({"phase":       initial_alert_phase,
                                "source":      "initial_alert.category",
                                "evidence_id": canon_id})

    # 1. Framework mappings — every ACTIVE MITRE tactic lifts the
    #    phase to at least the tactic's phase.
    from .xdr_framework_mapping import resolve_mappings as _resolve_fw
    fw = await _resolve_fw(db, incident_id)
    for m in (fw.get("mappings") or {}).get("mitre_attack", []) or []:
        if m.get("status") != "ACTIVE":
            continue
        tactic = (m.get("tactic") or "").lower()
        phase = _MITRE_TACTIC_TO_PHASE.get(tactic)
        furthest = _bump(furthest, phase,
                                source=f"mitre_attack:{m.get('object_id')}",
                                evidence_id=canon_id,
                                phases=citations)

    # 2. Threat family floor — a CONFIRMED family provides a
    #    minimum-phase guarantee even in the absence of framework
    #    mappings.
    from .xdr_threat_family import classify as _classify_family
    family = await _classify_family(db, incident_id)
    fam_id = (family or {}).get("family") or "UNKNOWN"
    fam_conf = ((family or {}).get("confidence") or "").upper()
    fam_floor = _FAMILY_PHASE_FLOOR.get(fam_id)
    # Only trust the family floor when the classifier's confidence is
    # not LOW — LOW/UNKNOWN families never push phase forward on their
    # own.
    if fam_floor and fam_conf in ("MEDIUM", "HIGH"):
        furthest = _bump(furthest, fam_floor,
                                source=f"threat_family:{fam_id}({fam_conf})",
                                evidence_id=canon_id,
                                phases=citations)

    # 3. Closed-loop OSINT observations — a MALICIOUS/SUSPICIOUS
    #    observation for the destination IP reinforces C2 (not deeper).
    obs_pushed_c2 = False
    async for o in db["xdr_intelligence_observations"].find(
        {"incident_id": incident_id,
          "verdict": {"$in": ["malicious", "suspicious"]}}, {"_id": 0}
    ):
        obs_pushed_c2 = True
        furthest = _bump(furthest, "COMMAND_AND_CONTROL",
                                source=f"osint:{o.get('provider')}",
                                evidence_id=o.get("id"),
                                phases=citations)
        break

    # 4. VEEE verdict INPUT that references a correlation match →
    #    push at least to EXECUTION (rules only fire on observed
    #    execution/behaviour).
    veee = prov.get("veee") or {}
    if any(c.get("source") == "detection"
              for c in veee.get("contributors") or []):
        furthest = _bump(furthest, "EXECUTION",
                                source="veee.detection_match",
                                evidence_id=canon_id, phases=citations)

    # ── Distinguish initial alert vs closure ──────────────────
    lifted = (furthest is not None and initial_alert_phase is not None
                    and PHASE_INDEX[furthest] > PHASE_INDEX[initial_alert_phase])

    return {
        "engine_id":                CLASSIFIER_ENGINE_ID,
        "engine_version":           CLASSIFIER_VERSION,
        "state":                    "READY",
        "incident_id":              incident_id,
        "initial_alert_phase":      initial_alert_phase,
        "furthest_confirmed_phase": furthest,
        "phase_advanced_by_investigation": bool(lifted),
        "citations":                citations,
        "family":                   fam_id,
        "family_confidence":        fam_conf,
        "honesty_note":
            "Closure classification is derived from the deepest phase "
            "supported by confirmed evidence (framework mappings, family "
            "floor, OSINT observations, VEEE contributors).  It NEVER "
            "advances past the evidence.  When only the initial alert "
            "phase is known, closure == initial_alert_phase and "
            "phase_advanced_by_investigation is False.",
    }
