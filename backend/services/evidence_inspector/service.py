"""Round 38.3 · Shared Evidence Inspector — single resolver.

Every governed object in NivXRay — technique, process, event,
commandline, finding, host, user, ip, signature, detection,
correlation match, capability, incident — resolves through this
one service.  MITRE, Attack Story and Attack Graph MUST call this
resolver with canonical IDs and MUST NOT ship arbitrary
display-only payloads to their inspectors.

Envelope
--------

    {
        kind, ref_id, incident_id,
        identity:     {label, subtitle, badges[]},
        evidence:     [{id, kind, label, source_ref}],
        attack:       {techniques[]},
        context:      {relationships[]},
        provenance:   [{source, evidence_id, note}],
        actions:      [{id, label, description, capability}],
    }

Non-fabrication (owner rule §11): every field returned MUST be
traceable to a governed source (canonical evidence, findings,
correlation matches, incident record) — never invented.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from services.attack_evidence import compose_attack_evidence


# Which INVESTIGATE actions apply to each object kind.  These are
# hints for the frontend; every action still executes through the
# existing capability endpoints.  Owner rule §22 · capability tools
# never render as graph nodes — they live on the inspector.
_ACTIONS_BY_KIND = {
    "process": [
        {"id": "process_ancestry",     "label": "Process Ancestry",
          "description": "Reveal parent → child execution lineage."},
        {"id": "commandline_decode",   "label": "Decode Command",
          "description": "Deobfuscate encoded / base64 command lines."},
        {"id": "file_reputation",      "label": "File Reputation",
          "description": "Look up SHA-256 / signer reputation."},
        {"id": "mitre_expansion",      "label": "MITRE Expansion",
          "description": "Expand ATT&CK techniques for this artifact."},
    ],
    "commandline": [
        {"id": "commandline_decode",   "label": "Decode Command",
          "description": "Deobfuscate encoded / base64 command lines."},
        {"id": "lolbas_lookup",        "label": "LOLBAS Check",
          "description": "Check binary against LOLBAS project."},
    ],
    "ip":  [
        {"id": "network_pivot",        "label": "Network Pivot",
          "description": "Related events / hosts / connections."},
        {"id": "ioc_pivot",            "label": "IOC Pivot",
          "description": "Cross-case IOC correlation."},
    ],
    "hash":  [
        {"id": "file_reputation",      "label": "File Reputation",
          "description": "SHA-256 / VT / MDA enrichment."},
        {"id": "ioc_pivot",            "label": "IOC Pivot",
          "description": "Cross-case IOC correlation."},
    ],
    "user": [
        {"id": "identity_pivot",       "label": "Identity Pivot",
          "description": "Related sessions, hosts, and actions."},
    ],
    "host": [
        {"id": "historical_correlation", "label": "Historical Correlation",
          "description": "Prior incidents / detections on this host."},
    ],
    "event": [
        {"id": "detection_intel",      "label": "Detection Intel",
          "description": "Rule / signature that fired."},
    ],
    "finding": [],
    "technique": [
        {"id": "mitre_expansion",      "label": "MITRE Expansion",
          "description": "Related techniques / procedures."},
    ],
    "match":     [],
    "detection": [],
    "capability":[],
    "signature": [
        {"id": "detection_intel",      "label": "Detection Intel",
          "description": "Signature ownership / origin."},
    ],
    "incident":  [],
}


async def _load_incident(db, incident_id: str) -> Optional[Dict[str, Any]]:
    return await db["workspace_cases"].find_one({"id": incident_id},
                                                              {"_id": 0})


async def _load_canonical(db, incident: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    ev_id = ((incident or {}).get("xdr_pipeline") or {}).get("canonical_event_id")
    if not ev_id:
        return None
    return await db["xdr_canonical_evidence"].find_one(
        {"event_id": ev_id}, {"_id": 0})


async def resolve(db, incident_id: str, kind: str, ref_id: str
                       ) -> Dict[str, Any]:
    """Resolve a canonical object into the shared inspector envelope.

    Returns {..., "state": "MISSING"} when the referenced object
    cannot be found in the governed stores — owner rule §11: no
    fabrication of unfound data.
    """
    kind = (kind or "").lower()
    inc  = await _load_incident(db, incident_id)
    if not inc:
        return {"state": "MISSING", "kind": kind, "ref_id": ref_id,
                    "reason": f"incident {incident_id} not found"}

    canonical = await _load_canonical(db, inc)
    canonical_id = (canonical or {}).get("event_id")

    identity    = {"label": ref_id, "subtitle": kind.upper(), "badges": []}
    evidence:    List[Dict[str, Any]] = []
    context:     Dict[str, Any] = {"relationships": []}
    provenance:  List[Dict[str, Any]] = []
    attack:      Dict[str, Any] = {"techniques": []}
    actions      = _ACTIONS_BY_KIND.get(kind, [])

    # ── TECHNIQUE ────────────────────────────────────────────────
    if kind == "technique":
        atk = await compose_attack_evidence(db, incident_id)
        tech = next((t for t in atk["techniques"]
                        if (t["technique_id"] or "").upper() == ref_id.upper()),
                       None)
        if not tech:
            return {"state": "MISSING", "kind": kind, "ref_id": ref_id,
                        "reason": "technique not present in AttackTechniqueEvidence"}
        identity = {
            "label":    f"{tech['technique_id']} · {tech['technique_name']}",
            "subtitle": (f"{tech['tactic_id']} · {tech['tactic_name']}"
                             if tech['tactic_id'] else "ATT&CK Technique"),
            "badges": [{"label": tech['state'], "tone": "state"},
                          {"label": f"conf {tech.get('confidence', 0):.2f}",
                            "tone": "info"}],
        }
        evidence = [{"id": eid, "kind": eid.split(":")[0] if ":" in eid else "ref",
                          "label": eid, "source_ref": eid}
                        for eid in tech.get("evidence_ids", [])]
        attack = {"techniques": [tech]}
        provenance = tech.get("provenance", [])

    # ── PROCESS ──────────────────────────────────────────────────
    elif kind == "process":
        # Canonical process or its parent.
        procs = []
        if canonical:
            p = canonical.get("process") or {}
            if p.get("name"): procs.append({"role": "child", **p})
            parent = p.get("parent") or {}
            if parent.get("name"): procs.append({"role": "parent", **parent})
        match = next((pp for pp in procs if pp.get("name") == ref_id
                            or (pp.get("id") == ref_id)), None)
        if not match:
            return {"state": "MISSING", "kind": kind, "ref_id": ref_id,
                        "reason": "process not present in canonical evidence"}
        identity = {
            "label": match["name"], "subtitle": f"PROCESS · {match.get('role','')}",
            "badges": [{"label": (match.get("role") or "child").upper(),
                            "tone": "kind"}],
        }
        rows = []
        for k in ("pid", "commandline", "path", "hash", "user", "host"):
            if match.get(k) or (k in ("user", "host") and (canonical or {}).get(k)):
                v = match.get(k) or (canonical or {}).get(k, {}).get("name")
                if v: rows.append({"label": k.upper(), "value": str(v)})
        context = {"relationships": rows}
        if canonical_id:
            evidence.append({"id": f"canonical:{canonical_id}",
                                  "kind": "event", "label": canonical_id,
                                  "source_ref": canonical_id})
        provenance.append({"source": "canonical_evidence",
                                "evidence_id": f"canonical:{canonical_id}",
                                "note": "Process observed on canonical event."})

    # ── EVENT ────────────────────────────────────────────────────
    elif kind == "event":
        if canonical and canonical.get("event_id") == ref_id:
            identity = {
                "label": ref_id,
                "subtitle": (canonical.get("dsm") or {}).get("id") or "EVENT",
                "badges": [{"label": "CANONICAL", "tone": "kind"}],
            }
            rows = []
            for k in ("timestamp",):
                if canonical.get(k):
                    rows.append({"label": k.upper(), "value": str(canonical[k])})
            sig = (canonical.get("security") or {}).get("signature") or {}
            if sig:
                rows.append({"label": "SIGNATURE",
                                  "value": f"{sig.get('id','?')} · {sig.get('name','')}"})
            context = {"relationships": rows}
            evidence.append({"id": f"canonical:{ref_id}", "kind": "event",
                                  "label": ref_id, "source_ref": ref_id})
            provenance.append({"source": "canonical_evidence",
                                    "evidence_id": f"canonical:{ref_id}",
                                    "note": "Canonical detection event."})
        else:
            return {"state": "MISSING", "kind": kind, "ref_id": ref_id}

    # ── FINDING ──────────────────────────────────────────────────
    elif kind == "finding":
        f = await db["xdr_investigation_findings"].find_one(
            {"$or": [{"finding_id": ref_id}, {"id": ref_id}],
              "incident_id": incident_id}, {"_id": 0})
        if not f:
            return {"state": "MISSING", "kind": kind, "ref_id": ref_id}
        identity = {
            "label":    f.get("kind") or "Finding",
            "subtitle": f.get("summary") or "Investigation Finding",
            "badges":   [{"label": (f.get("state") or "").upper(),
                              "tone": "state"}],
        }
        for r in (f.get("evidence_refs") or []):
            evidence.append({"id": r, "kind": "ref", "label": r,
                                  "source_ref": r})
        provenance.append({"source": "investigation_finding",
                                "evidence_id": f"finding:{ref_id}",
                                "note": f.get("capability") or ""})

    # ── COMMANDLINE ──────────────────────────────────────────────
    elif kind == "commandline":
        if canonical and (canonical.get("process") or {}).get("commandline"):
            cli = canonical["process"]["commandline"]
            identity = {
                "label":    cli[:80],
                "subtitle": "COMMAND LINE",
                "badges":   [{"label": "OBSERVED", "tone": "state"}],
            }
            context = {"relationships": [
                {"label": "FULL",    "value": cli},
                {"label": "PROCESS", "value": canonical["process"].get("name")},
            ]}
            if canonical_id:
                evidence.append({"id": f"canonical:{canonical_id}",
                                      "kind": "event", "label": canonical_id,
                                      "source_ref": canonical_id})
            provenance.append({"source": "canonical_evidence",
                                    "evidence_id": f"canonical:{canonical_id}",
                                    "note": "Command line captured on process creation."})
        else:
            return {"state": "MISSING", "kind": kind, "ref_id": ref_id}

    # ── INCIDENT ─────────────────────────────────────────────────
    elif kind == "incident":
        identity = {
            "label":    inc.get("title") or inc.get("name") or incident_id,
            "subtitle": f"INCIDENT · {inc.get('incident_priority')}",
            "badges":   [{"label": (inc.get("verdict_card") or {}).get("verdict",
                                                                                        "unknown").upper(),
                              "tone": "state"}],
        }
        context = {"relationships": [
            {"label": "HOST", "value": ((canonical or {}).get("host") or {}).get("name")},
            {"label": "USER", "value": ((canonical or {}).get("user") or {}).get("name")},
            {"label": "STATE", "value": inc.get("incident_state")},
        ]}
        if canonical_id:
            evidence.append({"id": f"canonical:{canonical_id}",
                                  "kind": "event", "label": canonical_id,
                                  "source_ref": canonical_id})
        provenance.append({"source": "incident",
                                "evidence_id": f"incident:{incident_id}",
                                "note": (inc.get("verdict_card") or {}).get("engine")})

    else:
        # Generic fallback: derive identity but do not fabricate.
        identity = {"label": ref_id, "subtitle": kind.upper(), "badges": []}

    # Filter out empty relationships.
    context["relationships"] = [r for r in context["relationships"]
                                        if r.get("value") not in (None, "")]

    return {
        "kind":       kind,
        "ref_id":     ref_id,
        "incident_id": incident_id,
        "identity":   identity,
        "evidence":   evidence,
        "attack":     attack,
        "context":    context,
        "provenance": provenance,
        "actions":    actions,
    }
