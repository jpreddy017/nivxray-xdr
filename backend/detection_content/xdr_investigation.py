"""
P0.6 · Round 12 · XDR Investigation Fabric Convergence
──────────────────────────────────────────────────────

**Golden rule (owner-locked, 2026-02-14):**
    This module is a *pure projection* over data already produced by
    Rounds 8-11.  It DOES NOT introduce a second investigation
    engine — it consumes `workspace_cases.xdr_pipeline` provenance
    and existing NivXRay evidence stores, and emits the six lanes
    the Investigation UI needs:

        Timeline · Process Tree · Evidence Graph · Device Trajectory ·
        Attack Story · ATT&CK

**HONEST STATE (§37, §42):**
  * Every lane can be empty.  An empty lane MUST carry `state=EMPTY`
    with the exact `reason` why (missing telemetry class, no
    correlation matches, no MITRE data, etc.) — never fabricate.
  * The Fabric never invents entities, techniques, or process
    ancestry.  If the source evidence doesn't carry it, the lane is
    honestly empty.

**Determinism (§3):**
  * Pure function of the incident document + linked canonical
    evidence + linked correlation matches.  No clock reads, no
    randomness, no LLM.

Inputs:
  * `workspace_cases` document (must carry the `xdr_pipeline`
    sub-doc — Round 11 provenance).
  * `xdr_canonical_evidence` (linked via `canonical_event_id`).
  * `xdr_correlation_matches` (linked via `ice_matches[]` list).
"""
from __future__ import annotations
from typing import Any


FABRIC_ENGINE_ID = "nivxray::xdr::investigation_fabric"
FABRIC_ENGINE_VERSION = "1.0.0"

# Six lanes required by the Investigation UI.
LANE_TIMELINE          = "timeline"
LANE_PROCESS_TREE      = "process_tree"
LANE_EVIDENCE_GRAPH    = "evidence_graph"
LANE_DEVICE_TRAJECTORY = "device_trajectory"
LANE_ATTACK_STORY      = "attack_story"
LANE_ATTCK             = "attck"


# ── Lane projections ────────────────────────────────────────────

def _timeline_lane(incident: dict, canonical: dict | None,
                     ice_matches: list[dict]) -> dict:
    """
    Emit chronologically ordered events from the provenance chain.
    Every event carries `source_stage` + `at` timestamp.
    """
    prov = incident.get("xdr_pipeline") or {}
    events: list[dict] = []

    can_ts = (canonical or {}).get("timestamp")
    if can_ts:
        events.append({
            "at":            can_ts,
            "stage":         "canonical_evidence",
            "kind":          "raw_event_normalised",
            "event_id":      (canonical or {}).get("event_id"),
            "summary":       "Suricata-EVE alert normalised into canonical schema",
        })

    veee = prov.get("veee") or {}
    if veee.get("label"):
        events.append({
            "at":       incident.get("created_at"),
            "stage":    "verdict",
            "kind":     "verdict_computed",
            "summary":  f"VEEE label={veee.get('label')} score={veee.get('score')}",
            "reason":   veee.get("reason"),
        })

    for m in ice_matches:
        events.append({
            "at":            m.get("emitted_at"),
            "stage":         "correlation",
            "kind":          "correlation_match",
            "rule_id":       m.get("rule_id"),
            "rule_name":     m.get("rule_name"),
            "summary":       f"ICE match on rule {m.get('rule_name') or m.get('rule_id')}",
        })

    if incident.get("created_at"):
        events.append({
            "at":       incident.get("created_at"),
            "stage":    "incident",
            "kind":     "incident_created",
            "summary":  f"Incident {incident.get('id')} materialised — priority "
                          f"{incident.get('incident_priority')} state="
                          f"{incident.get('incident_state')}",
        })

    events.sort(key=lambda e: str(e.get("at") or ""))

    if not events:
        return {"state": "EMPTY", "events": [],
                    "reason": "no timestamped events in provenance"}
    return {"state": "READY", "events": events, "count": len(events)}


def _process_tree_lane(canonical: dict | None) -> dict:
    """
    Honest process-tree projection.  For network-only Snort alerts
    there is no host-side process context available, so the lane
    reports EMPTY with the exact reason.
    """
    if not canonical:
        return {"state": "EMPTY", "nodes": [],
                    "reason": "no canonical evidence linked to incident"}
    # Canonical schema (Round 10 normalizer) exposes no process fields
    # for a network alert.  Emit honest EMPTY.
    if canonical.get("event_type") == "network_alert":
        return {
            "state":  "EMPTY",
            "nodes":  [],
            "reason": "network_alert has no host-side process telemetry; "
                        "attach an EDR data source to populate this lane",
        }
    proc = canonical.get("process") or {}
    if not proc:
        return {"state": "EMPTY", "nodes": [],
                    "reason": "canonical evidence carries no process context"}
    node = {
        "pid":        proc.get("pid"),
        "image":      proc.get("image"),
        "cmdline":    proc.get("cmdline"),
        "parent_pid": proc.get("ppid"),
    }
    return {"state": "READY", "nodes": [node], "count": 1}


def _evidence_graph_lane(incident: dict, canonical: dict | None,
                              ice_matches: list[dict]) -> dict:
    """
    Build a deterministic evidence-graph:  every node/edge is a real
    reference to a persisted document — no fabricated edges.
    """
    prov = incident.get("xdr_pipeline") or {}
    nodes: list[dict] = [{
        "id":     f"incident:{incident.get('id')}",
        "kind":   "incident",
        "label":  incident.get("title"),
        "attrs":  {"priority": incident.get("incident_priority"),
                       "state":     incident.get("incident_state")},
    }]
    edges: list[dict] = []

    if canonical:
        ce_id = f"canonical:{canonical.get('event_id')}"
        nodes.append({
            "id":    ce_id,
            "kind":  "canonical_evidence",
            "label": (canonical.get("security") or {}).get("signature", {}).get("name")
                        or canonical.get("event_type"),
            "attrs": {"vendor": (canonical.get("source") or {}).get("vendor"),
                          "at":     canonical.get("timestamp")},
        })
        edges.append({"from": f"incident:{incident.get('id')}",
                          "to":   ce_id,
                          "kind": "derived_from"})
        # Entity nodes come from IUE output preserved on the case doc
        # provenance (canonical.provenance is authoritative).
        network = canonical.get("network") or {}
        for role, host in (("src", (network.get("src") or {}).get("ip")),
                                    ("dst", (network.get("dst") or {}).get("ip"))):
            if host:
                nid = f"host:{host}"
                nodes.append({"id": nid, "kind": "host",
                                    "label": host, "attrs": {"role": role}})
                edges.append({"from": ce_id, "to": nid,
                                    "kind": f"network_{role}"})

    if prov.get("detection_rule_id"):
        rid = f"detection_rule:{prov['detection_rule_id']}"
        nodes.append({"id": rid, "kind": "detection_rule",
                            "label": prov["detection_rule_id"],
                            "attrs": {"engine": "nivxray_native_sigma"}})
        edges.append({"from": f"incident:{incident.get('id')}",
                          "to":   rid, "kind": "triggered_by"})

    for m in ice_matches:
        mid = f"correlation_match:{m.get('match_id')}"
        nodes.append({"id": mid, "kind": "correlation_match",
                            "label": m.get("rule_name") or m.get("rule_id"),
                            "attrs": {"level": m.get("evidence_level")}})
        edges.append({"from": f"incident:{incident.get('id')}",
                          "to":   mid, "kind": "correlated_by"})

    if len(nodes) == 1:
        return {"state": "MINIMAL", "nodes": nodes, "edges": [],
                    "reason": "only the incident node exists — no canonical "
                                "evidence linked to this incident"}
    return {"state": "READY", "nodes": nodes, "edges": edges,
                "count": {"nodes": len(nodes), "edges": len(edges)}}


def _device_trajectory_lane(canonical: dict | None) -> dict:
    """
    Device trajectory requires per-endpoint telemetry.  A Snort
    network-alert incident lacks it — honestly EMPTY.
    """
    if not canonical:
        return {"state": "EMPTY", "waypoints": [],
                    "reason": "no canonical evidence linked to incident"}
    if canonical.get("event_type") == "network_alert":
        return {"state": "EMPTY", "waypoints": [],
                    "reason": "network_alert has no endpoint telemetry; "
                                "connect an EDR data source to populate this lane"}
    return {"state": "EMPTY", "waypoints": [],
                "reason": "canonical evidence carries no host trajectory"}


def _attack_story_lane(incident: dict, canonical: dict | None,
                             ice_matches: list[dict]) -> dict:
    """
    Deterministic prose derived from the honest facts already in
    provenance.  Never invents attack narrative.
    """
    prov = incident.get("xdr_pipeline") or {}
    veee = prov.get("veee") or {}
    sig = (canonical or {}).get("security", {}).get("signature") or {}
    net = (canonical or {}).get("network") or {}
    src = (net.get("src") or {}).get("ip")
    dst = (net.get("dst") or {}).get("ip")

    chapters: list[dict] = []
    if sig.get("name"):
        chapters.append({
            "title":   "Trigger",
            "content": f"Signature '{sig.get('name')}' (id={sig.get('id')}) "
                          f"fired on traffic from {src} → {dst}.",
        })
    if ice_matches:
        chapters.append({
            "title":   "Correlation",
            "content": f"{len(ice_matches)} correlation match(es) elevated "
                          f"the signal above the single-event threshold.",
        })
    if veee.get("label"):
        chapters.append({
            "title":   "Verdict",
            "content": f"NivXRay verdict engine (VEEE) rendered "
                          f"'{veee['label']}' with score {veee.get('score')} · "
                          f"{veee.get('reason')}.",
        })
    if not chapters:
        return {"state": "EMPTY", "chapters": [],
                    "reason": "no signature, correlation, or verdict evidence "
                                "available to compose a story"}
    return {"state": "READY", "chapters": chapters, "count": len(chapters)}


def _attck_lane(ice_matches: list[dict]) -> dict:
    """
    ATT&CK techniques are surfaced ONLY from ICE match `attack_techniques`.
    Never inferred from signature names.
    """
    tids: list[str] = []
    for m in ice_matches:
        for t in (m.get("attack_techniques") or []):
            if isinstance(t, str) and t not in tids:
                tids.append(t)
    if not tids:
        return {"state": "EMPTY", "techniques": [],
                    "reason": "no ATT&CK techniques on any correlation match"}
    return {"state": "READY",
                "techniques": [{"id": t} for t in tids],
                "count": len(tids)}


# ── Public entry point ─────────────────────────────────────────

async def project_investigation(db, incident_id: str) -> dict:
    """
    Round 12 · Investigation Fabric entry point.  Reads persisted
    state; emits the six honest lanes.
    """
    inc = await db["workspace_cases"].find_one({"id": incident_id}, {"_id": 0})
    if not inc:
        return {"state": "MISSING",
                    "reason": f"incident {incident_id} not found",
                    "engine_id": FABRIC_ENGINE_ID}

    prov = inc.get("xdr_pipeline") or {}
    canonical_id = prov.get("canonical_event_id")
    canonical = None
    if canonical_id:
        canonical = await db["xdr_canonical_evidence"].find_one(
            {"event_id": canonical_id}, {"_id": 0})

    ice_ids: list[str] = prov.get("ice_matches") or []
    ice_matches: list[dict] = []
    if ice_ids:
        async for m in db["xdr_correlation_matches"].find(
            {"match_id": {"$in": ice_ids}}, {"_id": 0}
        ):
            ice_matches.append(m)

    lanes = {
        LANE_TIMELINE:          _timeline_lane(inc, canonical, ice_matches),
        LANE_PROCESS_TREE:      _process_tree_lane(canonical),
        LANE_EVIDENCE_GRAPH:    _evidence_graph_lane(inc, canonical,
                                                                     ice_matches),
        LANE_DEVICE_TRAJECTORY: _device_trajectory_lane(canonical),
        LANE_ATTACK_STORY:      _attack_story_lane(inc, canonical, ice_matches),
        LANE_ATTCK:             _attck_lane(ice_matches),
    }
    ready = sum(1 for l in lanes.values()
                    if l.get("state") in ("READY", "MINIMAL"))

    return {
        "engine_id":       FABRIC_ENGINE_ID,
        "engine_version":  FABRIC_ENGINE_VERSION,
        "incident_id":     incident_id,
        "lanes":           lanes,
        "lanes_ready":     ready,
        "lanes_total":     len(lanes),
        "state":           "READY" if ready > 0 else "EMPTY",
        "provenance": {
            "trace_id":          prov.get("trace_id"),
            "canonical_event_id": canonical_id,
            "iue_id":            prov.get("iue_id"),
            "detection_rule_id": prov.get("detection_rule_id"),
            "ice_match_count":   len(ice_matches),
        },
        "honesty_note":
            "Every lane is a projection of persisted data.  EMPTY lanes "
            "state the exact reason (missing telemetry class / no matches "
            "/ no MITRE data) — nothing is fabricated.  No second "
            "investigation engine was introduced; this module is a "
            "pure Fabric composer over Rounds 8-11 outputs.",
    }
