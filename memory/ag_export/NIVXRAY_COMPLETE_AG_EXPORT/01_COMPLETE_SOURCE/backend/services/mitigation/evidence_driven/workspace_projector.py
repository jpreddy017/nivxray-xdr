"""Workspace → InvestigationOutcome PROJECTOR.

STRICT contract per user directive (2026-02-05):

    "The Workspace Projector must be PURE field-copy / normalization
    only.  Do NOT derive tactics.  Do NOT infer MITRE techniques.
    Do NOT inspect raw output_text.  Do NOT perform regex/string
    matching.  Do NOT perform new detection.  Do NOT decode anything."

Architecture:

    SSOT  →  Workspace Projector (this module — pure copy)
          →  InvestigationOutcome
          →  Attack Posture Normalizer  (technique → tactic lookup)
          →  Evidence-Driven Engine     (rules + correlation)

This module reads whatever the Workspace SSOT already contains and
maps its fields into the ``InvestigationOutcome`` shape.  If a field
isn't in the SSOT, the projector leaves the outcome's default (empty
/ ``not_observed``) alone.  No derivation of any kind.
"""
from __future__ import annotations

from typing import Any, Dict, Set

from .investigation_outcome import empty_outcome


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
          "attack_posture":     {tactic: status, ...}   # optional; if
                                                        # the SSOT
                                                        # already
                                                        # asserts a
                                                        # posture we
                                                        # pass it
                                                        # through
                                                        # verbatim.
        }

    Never invents fields.  If the SSOT didn't have it, the outcome
    doesn't get it.  Tactic derivation is a downstream concern
    (see ``attack_posture_normalizer.py``).
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

    # ── MITRE techniques ── (pass through, no invention)
    mitre = ssot.get("mitre") or []
    mitre_ids: Set[str] = set()
    if isinstance(mitre, (list, tuple)):
        for m in mitre:
            if isinstance(m, str):
                mitre_ids.add(m)
            elif isinstance(m, dict) and m.get("id"):
                mitre_ids.add(str(m["id"]))
    o["mitre_techniques"] = sorted(mitre_ids)

    # ── Attack Posture ── (pass-through only — no derivation).
    # If the SSOT already asserts a posture we preserve it verbatim.
    # Tactic derivation from MITRE lives downstream in the
    # attack_posture_normalizer module.
    if isinstance(ssot.get("attack_posture"), dict):
        posture = dict(o["attack_posture"])
        for tactic, status in ssot["attack_posture"].items():
            if tactic in posture and isinstance(status, str):
                posture[tactic] = status
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


__all__ = ["project_workspace_ssot"]
