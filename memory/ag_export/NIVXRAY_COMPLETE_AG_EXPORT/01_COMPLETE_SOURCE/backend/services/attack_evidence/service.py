"""Round 38.1 · AttackTechniqueEvidence — canonical ATT&CK SSOT.

The single service that determines the state of every ATT&CK
technique for a given incident.  Every view (MITRE, Attack Story,
Attack Graph, Report) MUST consume this contract and MUST NOT
recompute ATT&CK state locally.  Owner rule §6, §16.

Contract
--------

    AttackTechniqueEvidence {
        technique_id     · str  (TXXXX or TXXXX.YYY)
        technique_name   · str
        tactic_id        · str  (TAxxxx, uppercase)
        tactic_name      · str
        state            · OBSERVED | SUPPORTED | HYPOTHESIZED
                              | SUPPRESSED | NOT_OBSERVED
        confidence       · float [0, 1]
        evidence_ids     · list[str]   (canonical:<eid>, finding:<id>, …)
        finding_ids      · list[str]
        event_ids        · list[str]
        process_ids      · list[str]
        provenance       · list[{source, evidence_id, note}]
        first_observed_at · str | None
        last_observed_at  · str | None
    }

State rules (deterministic · non-fabrication · owner rule §11)
--------------------------------------------------------------
  OBSERVED     — direct detection: incident.mitre[] + canonical event
                    with the process/command that triggered it.
  SUPPORTED    — attributed by correlation match, ATT&CK-mapped
                    framework mapping, or IUE understanding.
  HYPOTHESIZED — surfaced by heuristic pivot but not evidenced.
  SUPPRESSED   — explicitly excluded (analyst override).
  NOT_OBSERVED — no evidence at all (never emitted; absence is
                    represented by omission from the list).

Same inputs → byte-identical output.  Never fabricates a technique
that has no evidence.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

# Canonical ATT&CK tactic ID ↔ name (Enterprise).
_TACTIC_ID_TO_NAME = {
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
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}
_TACTIC_SLUG_TO_ID = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}
# Curated technique-name hints for common Enterprise techniques.  The
# incident.mitre[] payload usually carries the correct name; this map
# is only a fallback so a bare `T1059.001` is never rendered
# name-less.
_TECHNIQUE_NAME_HINTS = {
    "T1059":     "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1082":     "System Information Discovery",
    "T1105":     "Ingress Tool Transfer",
    "T1140":     "Deobfuscate/Decode Files or Information",
    "T1197":     "BITS Jobs",
    "T1218":     "Signed Binary Proxy Execution",
    "T1218.011": "Signed Binary Proxy Execution: Rundll32",
    "T1497":     "Virtualization/Sandbox Evasion",
    "T1566":     "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1027":     "Obfuscated Files or Information",
    "T1053":     "Scheduled Task/Job",
    "T1055":     "Process Injection",
    "T1547":     "Boot or Logon Autostart Execution",
}


def _resolve_tactic(raw: str) -> tuple:
    if not raw:
        return ("", "", "")
    s = raw.strip()
    lower = s.lower().replace("_", "-").replace(" ", "-")
    if lower.startswith("ta") and lower[2:].isdigit():
        tid = lower.upper()
        return (lower, tid, _TACTIC_ID_TO_NAME.get(tid, ""))
    if lower in _TACTIC_SLUG_TO_ID:
        tid = _TACTIC_SLUG_TO_ID[lower]
        return (lower, tid, _TACTIC_ID_TO_NAME.get(tid, ""))
    return ("unknown", s, s)


def _technique_key(tid: str) -> str:
    return (tid or "").upper().strip()


def _empty_record(tid: str, tactic_raw: str, name: Optional[str]) -> Dict[str, Any]:
    tactic_slug, tactic_id, tactic_name = _resolve_tactic(tactic_raw or "")
    return {
        "technique_id":     tid,
        "technique_name":   name or _TECHNIQUE_NAME_HINTS.get(tid) or tid,
        "tactic_id":        tactic_id,
        "tactic_name":      tactic_name,
        "state":            "NOT_OBSERVED",
        "confidence":       0.0,
        "evidence_ids":     [],
        "finding_ids":      [],
        "event_ids":        [],
        "process_ids":      [],
        "provenance":       [],
        "first_observed_at": None,
        "last_observed_at":  None,
    }


def _promote_state(current: str, candidate: str) -> str:
    """State lattice — OBSERVED > SUPPORTED > HYPOTHESIZED > SUPPRESSED > NOT_OBSERVED."""
    order = {"NOT_OBSERVED": 0, "SUPPRESSED": 1, "HYPOTHESIZED": 2,
                "SUPPORTED": 3, "OBSERVED": 4}
    return candidate if order.get(candidate, 0) > order.get(current, 0) else current


async def compose_attack_evidence(db, incident_id: str) -> Dict[str, Any]:
    """Return the canonical ATT&CK evidence list for an incident.

    Reads exclusively from governed collections — never inventing
    a technique that has no supporting evidence.
    """
    inc = await db["workspace_cases"].find_one({"id": incident_id},
                                                                {"_id": 0})
    if not inc:
        return {"incident_id": incident_id, "state": "MISSING",
                    "techniques": []}

    pipe = inc.get("xdr_pipeline") or {}
    canon = None
    if pipe.get("canonical_event_id"):
        canon = await db["xdr_canonical_evidence"].find_one(
            {"event_id": pipe["canonical_event_id"]}, {"_id": 0})

    canon_evt_id = (canon or {}).get("event_id")
    canon_ts     = (canon or {}).get("timestamp")

    proc_names: List[str] = []
    if canon and (canon.get("process") or {}).get("name"):
        proc_names.append(canon["process"]["name"])
    if canon and ((canon.get("process") or {}).get("parent") or {}).get("name"):
        proc_names.append(canon["process"]["parent"]["name"])

    # ── Bucket ──────────────────────────────────────────────
    records: Dict[str, Dict[str, Any]] = {}

    def _get_or_create(tid: str, tactic: str, name: Optional[str]):
        key = _technique_key(tid)
        if not key:
            return None
        rec = records.get(key)
        if rec is None:
            rec = _empty_record(key, tactic, name)
            records[key] = rec
        else:
            # Enrich missing tactic/name fields.
            if not rec.get("tactic_id"):
                _, tid_up, tname = _resolve_tactic(tactic or "")
                if tid_up:
                    rec["tactic_id"] = tid_up
                    rec["tactic_name"] = tname
            if (rec["technique_name"] == rec["technique_id"]) and name:
                rec["technique_name"] = name
        return rec

    # 1 · Detection engine (incident.mitre[]) — OBSERVED when
    #     canonical evidence is present, else SUPPORTED.
    for m in (inc.get("mitre") or []):
        if not isinstance(m, dict):
            continue
        tid = _technique_key(m.get("technique_id") or m.get("technique") or "")
        if not tid:
            continue
        name = m.get("name") or m.get("technique_name")
        tactic = m.get("tactic_id") or m.get("tactic") or ""
        rec = _get_or_create(tid, tactic, name)
        candidate_state = "OBSERVED" if canon_evt_id else "SUPPORTED"
        rec["state"] = _promote_state(rec["state"], candidate_state)
        rec["confidence"] = max(rec["confidence"],
                                          0.95 if candidate_state == "OBSERVED"
                                          else 0.70)
        if canon_evt_id:
            ref = f"canonical:{canon_evt_id}"
            if ref not in rec["evidence_ids"]:
                rec["evidence_ids"].append(ref)
                rec["event_ids"].append(canon_evt_id)
            rec["first_observed_at"] = (rec["first_observed_at"] or canon_ts)
            rec["last_observed_at"]  = canon_ts or rec["last_observed_at"]
        for pn in proc_names:
            if pn not in rec["process_ids"]:
                rec["process_ids"].append(pn)
        rec["provenance"].append({
            "source":       "detection_engine",
            "evidence_id":  f"incident:{incident_id}",
            "note":         "incident.mitre[] attribution from detection content",
        })

    # 2 · Correlation matches — SUPPORTED.
    ice_ids = list(pipe.get("ice_matches") or [])
    if ice_ids:
        async for cm in db["xdr_correlation_matches"].find(
            {"match_id": {"$in": ice_ids}}, {"_id": 0}
        ):
            for tech in (cm.get("mitre") or []):
                tid = _technique_key(
                    (tech.get("technique_id") or tech.get("technique"))
                    if isinstance(tech, dict) else str(tech))
                if not tid:
                    continue
                name = tech.get("name") if isinstance(tech, dict) else None
                tactic = (tech.get("tactic_id") or tech.get("tactic")
                              if isinstance(tech, dict) else "")
                rec = _get_or_create(tid, tactic or "", name)
                rec["state"] = _promote_state(rec["state"], "SUPPORTED")
                rec["confidence"] = max(rec["confidence"], 0.60)
                ref = f"match:{cm.get('match_id')}"
                if ref not in rec["evidence_ids"]:
                    rec["evidence_ids"].append(ref)
                rec["provenance"].append({
                    "source":      "correlation_engine",
                    "evidence_id": ref,
                    "note":        cm.get("rule_name") or cm.get("rule_id"),
                })

    # 3 · Framework mapping — HYPOTHESIZED unless already covered.
    fw = await db["xdr_framework_mappings"].find_one(
        {"incident_id": incident_id}, {"_id": 0}) or {}
    for m in ((fw.get("mappings") or {}).get("mitre_attack") or []):
        tid = _technique_key(m.get("object_id") or "")
        if not tid:
            continue
        name = m.get("object_name")
        tactic = m.get("tactic") or ""
        rec = _get_or_create(tid, tactic, name)
        # Framework mapping heuristics never promote above SUPPORTED.
        rec["state"] = _promote_state(rec["state"], "HYPOTHESIZED")
        rec["confidence"] = max(rec["confidence"], 0.45)
        rec["provenance"].append({
            "source":      "framework_mapping",
            "evidence_id": f"framework:{incident_id}",
            "note":        m.get("rationale") or "",
        })

    # 4 · Investigation findings that carry mitre attribution.
    async for f in db["xdr_investigation_findings"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        mitre = f.get("mitre") or []
        fid = f.get("finding_id") or f.get("id") or ""
        for tech in mitre:
            tid = _technique_key(
                (tech.get("technique_id") or tech.get("technique"))
                if isinstance(tech, dict) else str(tech))
            if not tid:
                continue
            rec = _get_or_create(tid, "", None)
            rec["state"] = _promote_state(rec["state"], "SUPPORTED")
            rec["confidence"] = max(rec["confidence"], 0.65)
            ref = f"finding:{fid}"
            if fid and ref not in rec["evidence_ids"]:
                rec["evidence_ids"].append(ref)
                rec["finding_ids"].append(fid)
            rec["provenance"].append({
                "source":      "investigation_finding",
                "evidence_id": ref,
                "note":        f.get("kind") or f.get("summary") or "",
            })

    # Deterministic ordering.
    techniques = sorted(records.values(),
                              key=lambda r: (r["tactic_id"] or "zzz",
                                                r["technique_id"]))
    return {
        "incident_id":   incident_id,
        "tenant_id":     inc.get("tenant_id") or "default",
        "generated_at":  canon_ts,
        "techniques":    techniques,
        "counts": {
            "total":         len(techniques),
            "observed":      sum(1 for t in techniques if t["state"] == "OBSERVED"),
            "supported":     sum(1 for t in techniques if t["state"] == "SUPPORTED"),
            "hypothesized":  sum(1 for t in techniques if t["state"] == "HYPOTHESIZED"),
            "suppressed":    sum(1 for t in techniques if t["state"] == "SUPPRESSED"),
        },
        "tactics_present": sorted({t["tactic_id"] for t in techniques
                                              if t["tactic_id"]}),
    }
