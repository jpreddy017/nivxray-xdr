"""Workspace → InvestigationOutcome PROJECTOR.

STRICT contract per user directive (2026-02-04):

    "The Outcome Projector must be a projection/normalization layer
    only.  Do NOT perform new detection, new decoding, new IOC
    extraction, or new MITRE inference."

This module reads whatever the Workspace SSOT already contains and
maps its fields into the ``InvestigationOutcome`` shape.  If a field
isn't in the SSOT, the projector leaves the outcome's default (empty
/ ``not_observed``) alone.

Any temptation to "derive" a MITRE technique or a behavior from the
raw output text belongs upstream in the investigation engine, NOT
here.  The projector's job is field mapping, nothing more.
"""
from __future__ import annotations

from typing import Any, Dict, Set

from .investigation_outcome import empty_outcome


# ── ATT&CK technique → tactic (deterministic map, MITRE-published) ─
# Only techniques the Workspace commonly surfaces are listed.  We
# add rows here when the Workspace starts emitting new techniques —
# we do NOT invent techniques the Workspace didn't produce.
_TECHNIQUE_TO_TACTIC: Dict[str, str] = {
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


def _derive_posture_from_mitre(techniques) -> Dict[str, str]:
    """Deterministic ATT&CK-published mapping only.  Any technique
    the Workspace produced with confirmed evidence upgrades its
    tactic to ``confirmed``; anything not in the technique set stays
    ``not_observed``.  This is projection, not inference."""
    out: Dict[str, str] = {}
    for tech in (techniques or ()):
        tactic = _TECHNIQUE_TO_TACTIC.get(str(tech))
        if tactic:
            out[tactic] = "confirmed"
    return out


def project_workspace_ssot(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """Map Workspace SSOT → InvestigationOutcome dict.

    Input shape (best-effort — projector tolerates missing keys):

        {
          "verdict":            {"severity": str, "one_liner": str},
          "decode_result":      {...},    # analysis_core output
          "investigation":      {"artifacts": [...], "evidence": [...]},
          "mitre":              [T-ids] | [{"id": ...}],
          "iocs":               {"ip": [...], "url": [...], ...},
          "behaviors":          [str, ...]        # if already tagged
          "malware":            {"family": ..., "capabilities": [...]},
          "apt":                {"group": ..., "confidence": ...},
          "impacts":            [str, ...]
          "scope":              {...},
          "detection_confidence": str,
        }

    Never invents fields.  If the SSOT didn't have it, the outcome
    doesn't get it.
    """
    o = empty_outcome()
    if not ssot:
        return o

    # ── Verdict ──
    if isinstance(ssot.get("verdict"), dict):
        o["verdict"] = dict(ssot["verdict"])

    # ── Observed evidence (best-effort passthroughs) ──
    for k in ("processes", "commands", "files", "registry_keys",
                "users", "hosts", "artifacts"):
        v = ssot.get(k)
        if isinstance(v, (list, tuple)):
            o[k] = list(v)
    ot = ssot.get("output_text") or (ssot.get("decode_result") or {}).get("output")
    if ot:
        o["output_text"] = str(ot)

    # ── Behaviors ──  (Workspace-tagged, never derived here)
    beh = ssot.get("behaviors")
    if isinstance(beh, (list, tuple)):
        o["behaviors"] = list(beh)

    # ── MITRE techniques ──
    mitre = ssot.get("mitre") or []
    mitre_ids: Set[str] = set()
    if isinstance(mitre, (list, tuple)):
        for m in mitre:
            if isinstance(m, str):
                mitre_ids.add(m)
            elif isinstance(m, dict) and m.get("id"):
                mitre_ids.add(str(m["id"]))
    o["mitre_techniques"] = sorted(mitre_ids)

    # ── Attack Posture · derived deterministically from MITRE IDs ──
    posture = dict(o["attack_posture"])   # start from all-not_observed
    posture.update(_derive_posture_from_mitre(mitre_ids))
    o["attack_posture"] = posture

    # ── Malware / APT / LOLBAS / IOCs ──
    if isinstance(ssot.get("malware"), dict):
        o["malware"] = dict(ssot["malware"])
    if isinstance(ssot.get("apt"), dict):
        o["apt"] = dict(ssot["apt"])
    lolbas = ssot.get("lolbas_hits") or ssot.get("lolbas") or []
    if isinstance(lolbas, (list, tuple)):
        o["lolbas_hits"] = list(lolbas)

    iocs_in = ssot.get("iocs") or (ssot.get("decode_result") or {}).get("iocs") or {}
    o["iocs"] = {
        "ips":     list((iocs_in.get("ips")     or iocs_in.get("ip")     or [])),
        "domains": list((iocs_in.get("domains") or iocs_in.get("domain") or [])),
        "urls":    list((iocs_in.get("urls")    or iocs_in.get("url")    or [])),
        "hashes":  list((iocs_in.get("hashes")  or [])),
    }

    # ── Attack pattern + impact + scope + confidence ──
    ap = ssot.get("attack_pattern") or {}
    if isinstance(ap, dict):
        o["attack_pattern"]["obfuscation_layers"] = int(
            ap.get("obfuscation_layers") or 0)
        kcp = ap.get("kill_chain_phases") or []
        if isinstance(kcp, (list, tuple)):
            o["attack_pattern"]["kill_chain_phases"] = list(kcp)

    imp = ssot.get("impacts") or []
    if isinstance(imp, (list, tuple)):
        o["impacts"] = list(imp)
    if "reached_shellcode" in ssot:
        o["reached_shellcode"] = bool(ssot["reached_shellcode"])
    elif "reached_shellcode" in (ssot.get("decode_result") or {}):
        o["reached_shellcode"] = bool(
            ssot["decode_result"]["reached_shellcode"])

    sc = ssot.get("scope") or {}
    if isinstance(sc, dict):
        for k in ("affected_hosts", "privileged_users_affected",
                    "critical_assets_affected"):
            if k in sc:
                o["scope"][k] = int(sc[k] or 0)

    if ssot.get("detection_confidence"):
        o["detection_confidence"] = str(ssot["detection_confidence"])
    fpi = ssot.get("false_positive_indicators") or []
    if isinstance(fpi, (list, tuple)):
        o["false_positive_indicators"] = list(fpi)

    return o


__all__ = ["project_workspace_ssot", "_TECHNIQUE_TO_TACTIC"]
