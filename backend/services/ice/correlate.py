"""
ICE · Investigation Correlation Engine
──────────────────────────────────────
Frozen 2026-03-01 · P0 · Rule R21.

Rule R21 · **Correlation Happens Once**

    Between recursive investigation and any projection, the platform
    MUST run a single deterministic correlation pass that turns
    isolated per-artifact investigations into coherent higher-order
    objects: behavior clusters, attack phases, kill-chain ordering,
    a unified timeline, and an incident graph.  Every downstream
    projection (Evidence Explorer, Attack Story, Timeline, Knowledge
    Graph, NIST IR Report, exports) reads from ICE — never from raw
    per-artifact investigations directly.

Analysis happens once.  Projection happens many times.

This module is that engine.  It is:
  · Deterministic (no LLM, no network)
  · Read-only w.r.t. its inputs (the SSOT block emitted upstream)
  · Additive — every consumer keeps working; ICE just adds richer
    correlated objects alongside the raw artifacts.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional


# ══════════════════════════════════════════════════════════════════
# 1. MITRE ATT&CK technique → tactic mapping (deterministic pack)
# ══════════════════════════════════════════════════════════════════
# Covers the techniques the platform currently produces from IDA-4
# and per-command investigation.  Grows organically; downstream
# projections rely on this table to place a technique into a phase.
_TECHNIQUE_TO_TACTIC: Dict[str, str] = {
    "T1059":     "execution",
    "T1059.001": "execution",              # PowerShell
    "T1059.003": "execution",              # Windows Command Shell
    "T1059.005": "execution",              # Visual Basic
    "T1059.006": "execution",              # Python
    "T1053.005": "execution",              # Scheduled Task
    "T1204":     "execution",              # User Execution
    "T1078":     "initial_access",         # Valid Accounts
    "T1566":     "initial_access",         # Phishing
    "T1105":     "command_and_control",    # Ingress Tool Transfer
    "T1140":     "defense_evasion",        # Deobfuscate / Decode
    "T1027":     "defense_evasion",        # Obfuscated Files or Info
    "T1218":     "defense_evasion",        # Signed Binary Proxy Exec
    "T1218.005": "defense_evasion",        # Mshta
    "T1218.010": "defense_evasion",        # Regsvr32
    "T1218.011": "defense_evasion",        # Rundll32
    "T1562":     "defense_evasion",
    "T1562.001": "defense_evasion",        # Disable or Modify Tools
    "T1564":     "defense_evasion",
    "T1564.003": "defense_evasion",        # Hidden Window
    "T1070":     "defense_evasion",        # Indicator Removal
    "T1070.004": "defense_evasion",        # File Deletion
    "T1176":     "persistence",            # Browser Extensions
    "T1547":     "persistence",
    "T1547.001": "persistence",            # Registry Run Keys
    "T1543":     "persistence",
    "T1057":     "discovery",              # Process Discovery
    "T1082":     "discovery",              # System Info Discovery
    "T1016":     "discovery",              # System Network Config
    "T1087":     "discovery",              # Account Discovery
    "T1003":     "credential_access",      # OS Credential Dumping
    "T1555":     "credential_access",
    "T1021":     "lateral_movement",
    "T1021.001": "lateral_movement",       # RDP
    "T1021.002": "lateral_movement",       # SMB
    "T1005":     "collection",             # Data from Local System
    "T1114":     "collection",             # Email Collection
    "T1041":     "exfiltration",           # Exfil over C2
    "T1567":     "exfiltration",
    "T1486":     "impact",                 # Data Encrypted for Impact
    "T1490":     "impact",                 # Inhibit System Recovery
    "T1219":     "command_and_control",    # Remote Access Tools
    "T1071":     "command_and_control",    # Application Layer Protocol
}

# Kill-chain ordering — the analyst-facing sequence.
_TACTIC_ORDER: List[str] = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact",
]

_TACTIC_LABEL: Dict[str, str] = {
    "initial_access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion":      "Defense Evasion",
    "credential_access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral_movement":     "Lateral Movement",
    "collection":           "Collection",
    "command_and_control":  "Command and Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


def tactic_for(technique_id: str) -> Optional[str]:
    """Return the ATT&CK tactic id for a technique.  Handles the
    parent-technique fallback (e.g., T1059.999 → T1059) so future
    unknown sub-techniques still get placed."""
    if not technique_id:
        return None
    tid = technique_id.upper()
    if tid in _TECHNIQUE_TO_TACTIC:
        return _TECHNIQUE_TO_TACTIC[tid]
    parent = tid.split(".", 1)[0]
    return _TECHNIQUE_TO_TACTIC.get(parent)


# ══════════════════════════════════════════════════════════════════
# 2. Correlator
# ══════════════════════════════════════════════════════════════════
def correlate(ssot: Dict[str, Any]) -> Dict[str, Any]:
    """Run the deterministic correlation pass over a canonical
    investigation object.  Returns the ICE block that lives at
    `SSOT.ice`.
    """
    ext = (ssot or {}).get("report_extraction") or {}
    commands       = ext.get("commands") or []
    investigations = ext.get("command_investigations") or []

    behavior_clusters = _build_behavior_clusters(commands, investigations)
    attack_phases     = _build_attack_phases(behavior_clusters)
    mitre_matrix      = _build_mitre_matrix(ssot, investigations)
    timeline          = _build_timeline(commands, ext.get("timeline") or [])
    incident_graph    = _build_incident_graph(ssot, behavior_clusters)
    completeness      = _build_completeness(ssot, ext, investigations)

    return {
        "behavior_clusters": behavior_clusters,
        "attack_phases":     attack_phases,
        "mitre_matrix":      mitre_matrix,
        "timeline":          timeline,
        "incident_graph":    incident_graph,
        "evidence_completeness": completeness,
        "totals": {
            "clusters":     len(behavior_clusters),
            "phases":       len(attack_phases),
            "mitre":        len(mitre_matrix),
            "timeline":     len(timeline),
            "graph_nodes":  len(incident_graph.get("nodes", [])),
            "graph_edges":  len(incident_graph.get("edges", [])),
        },
    }


# ══════════════════════════════════════════════════════════════════
# 3. Individual correlators
# ══════════════════════════════════════════════════════════════════
def _build_behavior_clusters(commands: List[Dict[str, Any]],
                              investigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group commands by their per-command purpose label (assigned by
    IDA-4's classifier).  Each cluster carries:
        · label            — the purpose name
        · commands[]        — the raw command list
        · mitre[]           — technique ids (deduped)
        · lolbins[]         — lolbin names (deduped)
        · languages[]       — languages seen in the cluster
        · primary_tactic    — the tactic most techniques resolve to
        · confidence        — high / medium / low
    Ordering is insertion order (which is reading order of the source
    document — deterministic and analyst-friendly).
    """
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for i, cmd in enumerate(commands):
        key = cmd.get("purpose") or "Uncategorised"
        if key not in groups:
            order.append(key)
            groups[key] = {
                "label":           key,
                "commands":        [],
                "mitre":           [],
                "lolbins":         [],
                "languages":       set(),
                "sources":         [],
            }
        g = groups[key]
        g["commands"].append(cmd)
        ci = investigations[i] if i < len(investigations) else {}
        for t in (ci.get("techniques") or []):
            tid = (t.get("id") or "").upper()
            if tid and tid not in [m["id"] for m in g["mitre"]]:
                g["mitre"].append({
                    "id":     tid,
                    "name":   t.get("name") or "",
                    "tactic": tactic_for(tid),
                })
        for lb in (ci.get("lolbins") or []):
            name = (lb.get("binary") or "").lower()
            if name and name not in g["lolbins"]:
                g["lolbins"].append(name)
        if ci.get("language"):
            g["languages"].add(ci["language"])
        if cmd.get("source"):
            g["sources"].append(cmd["source"])

    out: List[Dict[str, Any]] = []
    for k in order:
        g = groups[k]
        # Primary tactic = most common tactic across the cluster's mitre.
        tactic_counts: Dict[str, int] = {}
        for m in g["mitre"]:
            if m["tactic"]:
                tactic_counts[m["tactic"]] = tactic_counts.get(m["tactic"], 0) + 1
        primary_tactic = max(tactic_counts, key=tactic_counts.get) if tactic_counts else None
        conf = "high" if g["mitre"] else ("medium" if g["lolbins"] else "low")
        out.append({
            "label":          g["label"],
            "commands":       g["commands"],
            "command_count":  len(g["commands"]),
            "mitre":          g["mitre"],
            "lolbins":        g["lolbins"],
            "languages":      sorted(g["languages"]),
            "primary_tactic": primary_tactic,
            "confidence":     conf,
            "sources":        g["sources"],
        })
    return out


def _build_attack_phases(clusters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group behavior clusters into MITRE kill-chain phases and
    return them in canonical kill-chain order.  Each phase carries
    the clusters + a union of MITRE ids.
    """
    by_tactic: Dict[str, Dict[str, Any]] = {}
    for c in clusters:
        tactic = c.get("primary_tactic")
        if not tactic:
            continue
        if tactic not in by_tactic:
            by_tactic[tactic] = {
                "tactic":         tactic,
                "label":          _TACTIC_LABEL.get(tactic, tactic),
                "clusters":       [],
                "mitre":          [],
                "command_count":  0,
            }
        entry = by_tactic[tactic]
        entry["clusters"].append(c["label"])
        entry["command_count"] += c["command_count"]
        for m in c["mitre"]:
            if m["id"] not in entry["mitre"]:
                entry["mitre"].append(m["id"])

    out: List[Dict[str, Any]] = []
    for tactic in _TACTIC_ORDER:
        if tactic in by_tactic:
            out.append(by_tactic[tactic])
    return out


def _build_mitre_matrix(ssot: Dict[str, Any],
                         investigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Dedupe MITRE hits across vendor-published + command-derived,
    tagging every entry with `source ∈ {vendor, command}` and its
    parent tactic.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    # Vendor-published (from top-level SSOT.mitre — filled by IDA-4
    # over article text).
    for t in (ssot.get("mitre") or []):
        tid = (t.get("id") or "").upper()
        if not tid:
            continue
        src = t.get("source") or "vendor"
        # Normalise: `ida.command_investigation` → `command`
        if src == "ida.command_investigation":
            src = "command"
        elif src == "ida.report.mitre":
            src = "vendor"
        seen[tid] = {
            "id":     tid,
            "name":   t.get("name") or "",
            "tactic": tactic_for(tid),
            "source": src,
        }
    # Command-derived (from recursive investigations)
    for ci in investigations:
        for t in (ci.get("techniques") or []):
            tid = (t.get("id") or "").upper()
            if not tid:
                continue
            if tid not in seen:
                seen[tid] = {
                    "id":     tid,
                    "name":   t.get("name") or "",
                    "tactic": tactic_for(tid),
                    "source": "command",
                }
    return sorted(seen.values(), key=lambda m: (
        _TACTIC_ORDER.index(m["tactic"]) if m.get("tactic") in _TACTIC_ORDER else 999,
        m["id"],
    ))


def _build_timeline(commands: List[Dict[str, Any]],
                     article_timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Combine article-published timeline events with a per-command
    "execution order" pseudo-timeline (line-number based).  Article
    events come first (they carry real dates), then command order.
    """
    out: List[Dict[str, Any]] = []
    for e in article_timeline or []:
        out.append({
            "kind":  "article",
            "date":  e.get("date"),
            "event": e.get("event"),
            "source": e.get("source"),
        })
    for i, c in enumerate(commands or [], start=1):
        out.append({
            "kind":    "execution",
            "step":    i,
            "event":   c.get("purpose") or "Command execution",
            "command": c.get("command"),
            "source":  c.get("source"),
        })
    return out


def _build_incident_graph(ssot: Dict[str, Any],
                           clusters: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic incident graph.  Nodes:
        · incident (root)
        · actor(s)
        · malware(s)
        · behavior cluster(s)
    Edges connect the incident to actors, actors to behaviors, and
    behaviors to malware (when the article mentions them).  Kept
    small and deterministic — the Knowledge Graph projection
    (IDA-6) will grow this later.
    """
    ext = (ssot or {}).get("report_extraction") or {}
    actors  = ext.get("threat_actors") or []
    malware = ext.get("malware_families") or []
    prof    = ssot.get("document_profile") or {}
    vendor  = prof.get("vendor") or ""
    title   = prof.get("title") or ""

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    incident_id = "incident:root"
    nodes.append({"id": incident_id, "kind": "incident",
                   "label": title or "Incident", "vendor": vendor})

    for a in actors:
        aid = f"actor:{a['name']}"
        nodes.append({"id": aid, "kind": "actor", "label": a["name"]})
        edges.append({"from": incident_id, "to": aid, "kind": "attributed_to"})
    for m in malware:
        mid = f"malware:{m['name']}"
        nodes.append({"id": mid, "kind": "malware", "label": m["name"]})
        edges.append({"from": incident_id, "to": mid, "kind": "involves"})
    for c in clusters:
        cid = f"behavior:{c['label']}"
        nodes.append({
            "id":              cid,
            "kind":            "behavior",
            "label":           c["label"],
            "primary_tactic":  c.get("primary_tactic"),
            "command_count":   c["command_count"],
            "mitre":           [m["id"] for m in c["mitre"]],
        })
        edges.append({"from": incident_id, "to": cid, "kind": "observed"})

    return {"nodes": nodes, "edges": edges}


def _build_completeness(ssot: Dict[str, Any],
                         ext: Dict[str, Any],
                         investigations: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Deterministic evidence-completeness surface.  Same shape as
    the SSOT-carried block described in IR_REPORT_CONTRACT.md:
        state ∈ {complete, relative, missing, not_available}
    """
    totals = ext.get("totals") or {}
    commands = ext.get("commands") or []
    okc = sum(1 for ci in investigations if ci.get("language") and not ci.get("error"))
    errc = sum(1 for ci in investigations if ci.get("error"))

    def _state(count: int, applicable: bool = True) -> str:
        if not applicable:
            return "not_available"
        if count > 0:
            return "complete"
        return "missing"

    dims: List[Dict[str, Any]] = [
        {"dim": "Commands",  "state": _state(len(commands)),
         "found": len(commands), "investigated": okc, "errors": errc},
        {"dim": "MITRE",     "state": _state(totals.get("mitre", 0)),
         "found": totals.get("mitre", 0)},
        {"dim": "LOLBAS",    "state": _state(len({(lb.get("binary") or "").lower()
                                                    for ci in investigations
                                                    for lb in (ci.get("lolbins") or [])})),
         "found": len({(lb.get("binary") or "").lower()
                       for ci in investigations for lb in (ci.get("lolbins") or [])})},
        {"dim": "IOCs (URLs+Hashes+IPs+Domains)",
         "state": _state(sum(len(ext.get(k) or []) for k in ("urls", "hashes", "ips", "domains"))),
         "found": totals.get("artifacts", 0)},
        {"dim": "Registry",  "state": _state(totals.get("artifacts", 0))},
        {"dim": "Timeline",  "state": "complete" if totals.get("timeline", 0) > 0
                                        else "relative"},
        {"dim": "YARA",      "state": _state(totals.get("yara", 0))},
        {"dim": "Sigma",     "state": _state(totals.get("sigma", 0))},
        {"dim": "Threat Actor", "state": _state(totals.get("actors", 0))},
        {"dim": "Malware",   "state": _state(totals.get("malware", 0))},
    ]
    applicable = [d for d in dims if d["state"] != "not_available"]
    complete   = sum(1 for d in applicable if d["state"] == "complete")
    relative   = sum(1 for d in applicable if d["state"] == "relative")
    pct = int(round((complete + 0.5 * relative) / max(1, len(applicable)) * 100))
    return {
        "dimensions": dims,
        "overall_percent": pct,
        "complete_count":  complete,
        "relative_count":  relative,
        "applicable":      len(applicable),
    }
