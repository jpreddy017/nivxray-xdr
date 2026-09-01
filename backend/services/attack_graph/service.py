"""Round 35 · NivXRay XDR · Operational Attack Graph service.

Projects the entire governed state (Round 30 IUE + Round 31
investigation state + Round 32 findings ledger + Round 33 AttackFlow
+ Round 34 Threat Model + Event Intelligence) onto a real graph:

    nodes[]  · deterministic stable ids
    edges[]  · semantic, evidence-anchored
    primary_path[]        · strongest observed chain
    alternative_paths[]   · other observed chains
    timeline[]            · temporal ordering of provable events
    metrics{}             · chain-completeness / evidence / MITRE coverage
    investigation_gaps[]  · from IUE

**Owner-locked rules**
  * Deterministic node/edge IDs (sha256 slug — no ``uuid.uuid4``).
  * Zero fabricated relationships — every edge has ``evidence_refs``.
  * NOT_OBSERVED stages are exposed as gap nodes, never rendered as
    if they had happened.
  * Reuses ``attack_cycle.STAGES`` and ``TECHNIQUE_TO_TACTIC`` SSOT.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional, Tuple

from services.attack_story.attack_cycle import (
    STAGES, STAGE_INDEX, normalize_tactic, stages_for_technique,
    TECHNIQUE_TO_TACTIC,
)
from services.attack_graph.projections import (
    project_mitre_chain, project_process_tree, project_activity_graph,
)
from services.iue.service import IUEService
from services.investigator.orchestrator import InvestigatorService
from services.attack_graph.event_intel import get_event_intel, infer_event_id


ENGINE_ID = "nivxray::attack_graph::v1"
ENGINE_VERSION = "1.0.0"
SCHEMA_VERSION = "attack-graph.v1"

INCIDENTS_COLLECTION = "workspace_cases"
CANONICAL_COLLECTION = "xdr_canonical_evidence"
CORRELATION_MATCHES_COLLECTION = "xdr_correlation_matches"


# ── Deterministic id helper ─────────────────────────────────────────

def _nid(kind: str, *parts: str) -> str:
    seed = "|".join([kind, *(str(p) for p in parts if p is not None)])
    return f"{kind}:" + hashlib.sha256(seed.encode()).hexdigest()[:20]


def _eid(src: str, rel: str, dst: str, *extras: str) -> str:
    seed = "|".join([src, rel, dst, *(str(x) for x in extras)])
    return "edge:" + hashlib.sha256(seed.encode()).hexdigest()[:20]


# ── Service ─────────────────────────────────────────────────────────

class AttackGraphService:
    """Deterministic Attack Graph composer."""

    engine_id      = ENGINE_ID
    engine_version = ENGINE_VERSION
    schema_version = SCHEMA_VERSION

    @classmethod
    async def compose(cls, db, incident_id: str) -> Dict[str, Any]:
        incident = await db[INCIDENTS_COLLECTION].find_one(
            {"id": incident_id}, {"_id": 0})
        if not incident:
            raise ValueError(f"incident_not_found: {incident_id}")

        pipe = incident.get("xdr_pipeline") or {}
        canonical_id = pipe.get("canonical_event_id")
        canonical = None
        if canonical_id:
            canonical = await db[CANONICAL_COLLECTION].find_one(
                {"event_id": canonical_id}, {"_id": 0})

        ice_ids = pipe.get("ice_matches") or []
        ice_matches: List[Dict[str, Any]] = []
        if ice_ids:
            async for m in db[CORRELATION_MATCHES_COLLECTION].find(
                {"match_id": {"$in": ice_ids}}, {"_id": 0}
            ):
                ice_matches.append(m)
        ice_matches.sort(key=lambda m: str(m.get("match_id") or ""))

        understanding = await IUEService.latest_valid(db, incident_id)
        if understanding is None:
            understanding = await IUEService.understand_incident(
                db, incident_id, persist=True)
        findings   = await InvestigatorService.get_findings(db, incident_id)
        executions = await InvestigatorService.get_executions(db, incident_id)

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        def _add_node(node: Dict[str, Any]) -> str:
            nodes.setdefault(node["id"], node)
            return node["id"]

        def _add_edge(src: str, rel: str, dst: str, *, state: str,
                          evidence_refs: List[str], reason: str,
                          finding_ids: List[str] = None,
                          technique_id: Optional[str] = None,
                          event_id: Optional[str] = None,
                          timestamp: Optional[str] = None,
                          source: str = "governed") -> str:
            eid = _eid(src, rel, dst, *(evidence_refs or []),
                            technique_id or "", event_id or "")
            edges.append({
                "id":            eid,
                "src":           src,
                "rel":           rel,
                "dst":           dst,
                "state":         state,
                "evidence_refs": sorted(set(evidence_refs or [])),
                "finding_ids":   sorted(set(finding_ids or [])),
                "technique_id":  technique_id,
                "event_id":      event_id,
                "timestamp":     timestamp,
                "source":        source,
                "reason":        reason,
            })
            return eid

        # ── Root: incident node ─────────────────────────────────
        incident_nid = _add_node({
            "id":     _nid("incident", incident_id),
            "kind":   "incident",
            "label":  incident_id,
            "state":  "OBSERVED",
            "attrs":  {
                "verdict":       (incident.get("verdict_card") or {}).get("verdict"),
                "verdict_score": (incident.get("verdict_stage2") or {}).get("risk_score"),
                "trace_id":      pipe.get("trace_id"),
            },
        })

        # ── Attack-cycle stage nodes (14) ────────────────────────
        stage_by_name: Dict[str, str] = {}
        for idx, stage in enumerate(STAGES):
            nid = _add_node({
                "id":     _nid("stage", stage),
                "kind":   "stage",
                "label":  stage,
                "state":  "NOT_OBSERVED",
                "attrs":  {"index": idx + 1, "order": idx + 1},
            })
            stage_by_name[stage] = nid

        # ── Canonical entity nodes ───────────────────────────────
        canonical_evt_nid: Optional[str] = None
        host_nid = user_nid = process_nid = parent_nid = None
        src_ip_nid = dst_ip_nid = None
        cli_nid: Optional[str] = None
        sig_nid: Optional[str] = None
        event_id_str: Optional[str] = None
        event_intel: Optional[Dict[str, Any]] = None
        canonical_ts = None

        if canonical:
            canonical_ts = canonical.get("timestamp")
            # Canonical event node.
            canonical_evt_nid = _add_node({
                "id":     _nid("event", canonical.get("event_id") or ""),
                "kind":   "event",
                "label":  f"canonical:{canonical.get('event_id') or '—'}",
                "state":  "OBSERVED",
                "attrs":  {"timestamp": canonical_ts,
                             "provider": (canonical.get("dsm") or {}).get("id")},
            })
            _add_edge(incident_nid, "DETECTED_BY", canonical_evt_nid,
                          state="OBSERVED",
                          evidence_refs=[canonical.get("event_id")],
                          reason="Incident materialised from this canonical event.",
                          timestamp=canonical_ts)

            # Event id intelligence node.
            event_id_str = infer_event_id(canonical)
            event_intel  = get_event_intel(event_id_str) if event_id_str else None
            if event_id_str and event_intel:
                evt_nid = _add_node({
                    "id":     _nid("event_id", event_id_str),
                    "kind":   "event_id",
                    "label":  f"{event_id_str} · {event_intel['name']}",
                    "state":  "OBSERVED",
                    "attrs":  {
                        "significance": event_intel["significance"],
                        "category":     event_intel["category"],
                        "provider":     event_intel["provider"],
                        "fields":       event_intel["fields"],
                        "capabilities": event_intel["capabilities"],
                        "attack_hints": event_intel["attack_hints"],
                        "related_events": event_intel["related_events"],
                    },
                })
                _add_edge(canonical_evt_nid, "BELONGS_TO", evt_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              event_id=event_id_str,
                              timestamp=canonical_ts,
                              reason=(
                                  f"Event id {event_id_str} · "
                                  f"{event_intel['name']} recognised."
                              ))

            # Host / user / process / parent / ip entities.
            host_name = (canonical.get("host") or {}).get("name") \
                              or (canonical.get("host") or {}).get("hostname")
            if host_name:
                host_nid = _add_node({
                    "id": _nid("host", host_name), "kind": "host",
                    "label": host_name, "state": "OBSERVED", "attrs": {}})
                _add_edge(canonical_evt_nid, "OBSERVED_ON", host_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              timestamp=canonical_ts,
                              reason="Event observed on this host.")

            u = (canonical.get("user") or {}).get("name")
            if u:
                user_nid = _add_node({
                    "id": _nid("user", u), "kind": "user",
                    "label": u, "state": "OBSERVED", "attrs": {}})
                _add_edge(user_nid, "AUTHENTICATED_TO", host_nid or incident_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              timestamp=canonical_ts,
                              reason="User identity observed on canonical event.")

            proc = canonical.get("process") or {}
            proc_name = proc.get("name")
            if proc_name:
                process_nid = _add_node({
                    "id": _nid("process", proc_name, host_name or ""),
                    "kind": "process", "label": proc_name,
                    "state": "OBSERVED",
                    "attrs": {"commandline": proc.get("commandline"),
                                "user": u, "host": host_name}})
                _add_edge(host_nid or incident_nid, "EXECUTED", process_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              event_id=event_id_str,
                              timestamp=canonical_ts,
                              reason="Process observed on the host.")
                parent = proc.get("parent") or {}
                if isinstance(parent, str):
                    parent_name = parent
                else:
                    parent_name = parent.get("name") or proc.get("parent_name")
                if parent_name:
                    parent_nid = _add_node({
                        "id": _nid("process", parent_name, host_name or ""),
                        "kind": "process", "label": parent_name,
                        "state": "OBSERVED",
                        "attrs": {"role": "parent", "host": host_name}})
                    if host_nid:
                        _add_edge(host_nid, "EXECUTED", parent_nid,
                                      state="OBSERVED",
                                      evidence_refs=[canonical.get("event_id")],
                                      event_id=event_id_str,
                                      timestamp=canonical_ts,
                                      reason="Parent process observed on host.")
                    _add_edge(parent_nid, "SPAWNED", process_nid,
                                  state="OBSERVED",
                                  evidence_refs=[canonical.get("event_id")],
                                  event_id=event_id_str,
                                  timestamp=canonical_ts,
                                  reason="Parent→child process relationship observed.")
                # Commandline node.
                if proc.get("commandline"):
                    cli_nid = _add_node({
                        "id": _nid("commandline", proc_name,
                                     hashlib.sha1(str(proc["commandline"])
                                                        .encode()).hexdigest()[:10]),
                        "kind": "commandline",
                        "label": str(proc["commandline"])[:80],
                        "state": "OBSERVED",
                        "attrs": {"full": str(proc["commandline"])[:400]}})
                    _add_edge(process_nid, "EXECUTED", cli_nid,
                                  state="OBSERVED",
                                  evidence_refs=[canonical.get("event_id")],
                                  timestamp=canonical_ts,
                                  reason="Command line captured on process creation.")

            net = canonical.get("network") or {}
            src_ip = (net.get("src") or {}).get("ip")
            dst_ip = (net.get("dst") or {}).get("ip")
            if src_ip:
                src_ip_nid = _add_node({
                    "id": _nid("ip", src_ip), "kind": "ip",
                    "label": src_ip, "state": "OBSERVED",
                    "attrs": {"role": "source"}})
                _add_edge(canonical_evt_nid, "OBSERVED_ON", src_ip_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              timestamp=canonical_ts,
                              reason="Source IP observed on canonical event.")
            if dst_ip:
                dst_ip_nid = _add_node({
                    "id": _nid("ip", dst_ip), "kind": "ip",
                    "label": dst_ip, "state": "OBSERVED",
                    "attrs": {"role": "destination"}})
                _add_edge(process_nid or host_nid or incident_nid,
                              "CONNECTED_TO", dst_ip_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              timestamp=canonical_ts,
                              reason="Outbound connection observed.")

            sig = (canonical.get("security") or {}).get("signature") or {}
            if sig.get("id") is not None:
                sig_nid = _add_node({
                    "id": _nid("signature", str(sig["id"])),
                    "kind": "signature",
                    "label": f"sig:{sig['id']} · {sig.get('name') or ''}",
                    "state": "OBSERVED", "attrs": {}})
                _add_edge(sig_nid, "TRIGGERED", canonical_evt_nid,
                              state="OBSERVED",
                              evidence_refs=[canonical.get("event_id")],
                              timestamp=canonical_ts,
                              reason="Detection signature fired on this event.")

        # ── Detection intermediate node ──────────────────────────
        # Anchor for incident.mitre techniques.  Routes causality
        # through the DETECTION step so techniques never dangle
        # directly off the incident.
        # Deepest available evidence node = commandline > process >
        # canonical event > signature > incident.
        deepest_evidence_nid = (cli_nid or process_nid or canonical_evt_nid
                                       or sig_nid or incident_nid)
        detection_nid: Optional[str] = None
        detection_rule_id = pipe.get("detection_rule_id") or (
            (incident.get("verdict_card") or {}).get("engine"))
        if incident.get("mitre") and deepest_evidence_nid:
            det_seed = str(detection_rule_id or incident_id)
            det_label = ("Detection · " + str(detection_rule_id)) if detection_rule_id \
                                else "Detection · rule"
            detection_nid = _add_node({
                "id":    _nid("detection", det_seed),
                "kind":  "detection",
                "label": det_label,
                "state": "OBSERVED",
                "attrs": {
                    "rule_id":     detection_rule_id,
                    "verdict":     (incident.get("verdict_card") or {}).get("verdict"),
                    "engine":      (incident.get("verdict_card") or {}).get("engine"),
                    "trace_id":    pipe.get("trace_id"),
                },
            })
            _add_edge(deepest_evidence_nid, "DETECTED_BY", detection_nid,
                          state="OBSERVED",
                          evidence_refs=[(canonical or {}).get("event_id")] if canonical else [],
                          timestamp=canonical_ts,
                          reason=(
                              f"Detection rule {detection_rule_id or 'rule'} "
                              f"fired on this evidence."
                          ),
                          source="detection")

        # ── MITRE technique nodes ────────────────────────────────
        # Evidence-derived (incident.mitre → OBSERVED).  Routed
        # through the detection node — NOT directly off the incident.
        tech_anchor = detection_nid or deepest_evidence_nid or incident_nid
        for m in (incident.get("mitre") or []):
            if not isinstance(m, dict):
                continue
            tid = m.get("technique_id") or m.get("technique")
            if not tid:
                continue
            tid = str(tid).upper()
            tech_nid = _add_node({
                "id": _nid("technique", tid), "kind": "technique",
                "label": tid, "state": "OBSERVED",
                "attrs": {"source": "incident.mitre",
                             "tid": tid,
                             "tactic_id": m.get("tactic_id") or m.get("tactic"),
                             "name":      m.get("name") or m.get("technique_name")}})
            _add_edge(tech_anchor, "MAPPED_TO", tech_nid,
                          state="OBSERVED",
                          evidence_refs=[canonical.get("event_id")] if canonical else [],
                          technique_id=tid,
                          timestamp=canonical_ts,
                          reason=(
                              f"Technique {tid} attributed by "
                              f"{'detection rule' if detection_nid else 'evidence'}."
                          ))
            # Technique → stage(s).
            for st in stages_for_technique(tid) or []:
                stage_nid = stage_by_name.get(st)
                if stage_nid:
                    _add_edge(tech_nid, "BELONGS_TO", stage_nid,
                                  state="OBSERVED",
                                  evidence_refs=[canonical.get("event_id")] if canonical else [],
                                  technique_id=tid,
                                  reason=f"Technique {tid} belongs to {st}.")
                    nodes[stage_nid]["state"] = "OBSERVED"

        # Correlation-derived MITRE (SUPPORTED) — routed through a
        # per-match Correlation Match node (never straight off incident).
        for m in ice_matches:
            mid = str(m.get("match_id") or m.get("id") or "")
            if not mid:
                continue
            match_nid = _add_node({
                "id":    _nid("match", mid),
                "kind":  "match",
                "label": (f"Correlation · "
                             f"{m.get('rule_name') or m.get('rule_id') or mid[:12]}"),
                "state": "SUPPORTED",
                "attrs": {
                    "match_id":   mid,
                    "rule_id":    m.get("rule_id"),
                    "rule_name":  m.get("rule_name"),
                    "engine":     m.get("engine_id"),
                    "kind":       m.get("kind"),
                },
            })
            _add_edge(deepest_evidence_nid or incident_nid,
                          "CORRELATED_WITH", match_nid,
                          state="SUPPORTED",
                          evidence_refs=[mid],
                          reason=(
                              f"Correlation match {m.get('rule_name') or mid[:12]} "
                              f"anchored on this evidence."
                          ),
                          source="correlation")
            for tech in (m.get("mitre") or []):
                tid = (tech.get("technique_id") or tech.get("technique")
                          if isinstance(tech, dict) else str(tech))
                if not tid:
                    continue
                tid = str(tid).upper()
                if _nid("technique", tid) not in nodes:
                    _add_node({
                        "id": _nid("technique", tid), "kind": "technique",
                        "label": tid, "state": "SUPPORTED",
                        "attrs": {"source": "correlation", "tid": tid}})
                tech_nid_here = _nid("technique", tid)
                _add_edge(match_nid, "MAPPED_TO", tech_nid_here,
                              state="SUPPORTED",
                              evidence_refs=[mid],
                              technique_id=tid,
                              reason=(
                                  f"Technique {tid} attributed by "
                                  f"correlation match."
                              ))
                for st in stages_for_technique(tid) or []:
                    stage_nid = stage_by_name.get(st)
                    if stage_nid:
                        _add_edge(tech_nid_here, "BELONGS_TO", stage_nid,
                                      state="SUPPORTED",
                                      evidence_refs=[mid],
                                      technique_id=tid,
                                      reason=(
                                          f"Technique {tid} belongs "
                                          f"to {st} (correlation)."
                                      ))
                        if nodes[stage_nid]["state"] == "NOT_OBSERVED":
                            nodes[stage_nid]["state"] = "SUPPORTED"

        # ── Finding nodes ────────────────────────────────────────
        # Normalise finding grammar → graph 4-state grammar.
        _FIND_TO_GRAPH = {
            "OBSERVED":     "OBSERVED",
            "SUPPORTED":    "SUPPORTED",
            "CORRELATED":   "SUPPORTED",
            "INFERRED":     "SUPPORTED",
            "HYPOTHESIS":   "POSSIBLE",
            "UNKNOWN":      "POSSIBLE",
            "NOT_OBSERVED": "NOT_OBSERVED",
            "CONTRADICTED": "NOT_OBSERVED",
        }
        for f in findings:
            graph_state = _FIND_TO_GRAPH.get(f.get("state") or "", "POSSIBLE")
            f_nid = _add_node({
                "id":     _nid("finding", f["finding_id"]),
                "kind":   "finding",
                "label":  f.get("summary") or f["finding_id"],
                "state":  graph_state,
                "attrs":  {
                    "capability":       f.get("capability"),
                    "confidence":       f.get("confidence"),
                    "kind":             f.get("kind"),
                    "subject":          f"{f.get('subject_kind')}:{f.get('subject_value')}",
                    "finding_state":    f.get("state"),
                },
            })
            # Anchor findings to their subject / anchor node.
            anchor = incident_nid
            if f.get("subject_kind") == "process" and process_nid:
                anchor = process_nid
            elif f.get("subject_kind") in ("ipv4", "ipv6"):
                anchor = _nid("ip", f.get("subject_value") or "")
                if anchor not in nodes: anchor = incident_nid
            elif f.get("subject_kind") == "user" and user_nid:
                anchor = user_nid
            elif f.get("subject_kind") == "hash":
                hash_nid = _add_node({
                    "id": _nid("hash", f.get("subject_value") or ""),
                    "kind": "hash", "label": str(f.get("subject_value") or "")[:20]+"…",
                    "state": "OBSERVED", "attrs": {}})
                anchor = hash_nid
            _add_edge(anchor, "SUPPORTED_BY", f_nid,
                          state=graph_state,
                          evidence_refs=f.get("evidence_refs") or [],
                          finding_ids=[f["finding_id"]],
                          reason=f.get("reasoning") or "Finding produced by capability.",
                          source="finding")

            # Capability execution node.
            if f.get("capability"):
                cap_nid = _add_node({
                    "id":    _nid("capability", f["capability"]),
                    "kind":  "capability",
                    "label": f["capability"],
                    "state": "OBSERVED",
                    "attrs": {"engine": f.get("engine")},
                })
                _add_edge(cap_nid, "INVESTIGATED_BY", f_nid,
                              state="OBSERVED",
                              evidence_refs=f.get("evidence_refs") or [],
                              finding_ids=[f["finding_id"]],
                              reason=f"{f['capability']} produced this finding.")

        # ── Investigation gap nodes ──────────────────────────────
        gaps: List[Dict[str, Any]] = []
        for g in understanding.artifacts.gaps.gaps:
            gap_nid = _add_node({
                "id":    _nid("gap", g.key),
                "kind":  "gap",
                "label": g.description,
                "state": "NOT_OBSERVED",
                "attrs": {"key": g.key,
                            "suggested_capability": g.suggested_capability,
                            "why_it_matters": g.why_it_matters},
            })
            _add_edge(incident_nid, "PIVOTED_TO", gap_nid,
                          state="POSSIBLE",
                          evidence_refs=[],
                          reason=g.why_it_matters,
                          source="iue.gap")
            gaps.append({"id": gap_nid, "key": g.key,
                            "description": g.description,
                            "suggested_capability": g.suggested_capability})

        # ── Primary + alternative paths ─────────────────────────
        primary_path, alt_paths = cls._compute_paths(
            nodes, edges, stage_by_name, incident_nid,
            process_nid, parent_nid, dst_ip_nid)

        # ── Timeline (temporally ordered edges/events) ──────────
        timeline: List[Dict[str, Any]] = []
        seen_ts: set = set()
        for e in edges:
            if not e.get("timestamp"):
                continue
            key = (e["timestamp"], e["src"], e["rel"], e["dst"])
            if key in seen_ts:
                continue
            seen_ts.add(key)
            timeline.append({
                "at":           e["timestamp"],
                "src":          e["src"],
                "rel":          e["rel"],
                "dst":          e["dst"],
                "state":        e["state"],
                "event_id":     e.get("event_id"),
                "technique_id": e.get("technique_id"),
                "reason":       e["reason"],
            })
        timeline.sort(key=lambda x: (x["at"], x["src"], x["rel"], x["dst"]))

        # ── Metrics ─────────────────────────────────────────────
        total_stages = len(STAGES)
        observed_stages = sum(1 for s in stage_by_name.values()
                                    if nodes[s]["state"] == "OBSERVED")
        supported_stages = sum(1 for s in stage_by_name.values()
                                    if nodes[s]["state"] == "SUPPORTED")
        techs = [n for n in nodes.values() if n["kind"] == "technique"]
        obs_techs = [n for n in techs if n["state"] == "OBSERVED"]
        metrics = {
            "attack_chain_completeness": round(
                (observed_stages * 100 + supported_stages * 60) / (total_stages * 100) * 100, 1),
            "evidence_coverage": min(100, round(
                sum(1 for e in edges if e["evidence_refs"]) * 100 /
                max(len(edges), 1))),
            "mitre_coverage": round(len(obs_techs) * 100 / max(len(techs), 1)) if techs else 0,
            "telemetry_coverage": round(
                (1 if canonical else 0) * 40
                + (1 if ice_matches else 0) * 30
                + (30 if findings else 0)),
            "unknown_coverage": round(len(understanding.artifacts.known_unknown.unknown)
                                              * 100 /
                                              max(len(understanding.artifacts.known_unknown.observed)
                                                       + len(understanding.artifacts.known_unknown.unknown)
                                                       + len(understanding.artifacts.known_unknown.not_observed), 1)),
            "correlation_strength": min(100, round(len(ice_matches) * 20)),
            "temporal_consistency": 100 if timeline == sorted(
                timeline, key=lambda x: x["at"]) else 0,
        }

        return {
            "engine_id":      ENGINE_ID,
            "engine_version": ENGINE_VERSION,
            "schema_version": SCHEMA_VERSION,
            "incident_id":    incident_id,
            "tenant_id":      incident.get("tenant_id") or "default",
            "generated_at":   understanding.generated_at,
            "iue_fingerprint": understanding.evidence_fingerprint,
            "nodes":          list(nodes.values()),
            "edges":          edges,
            "primary_path":   primary_path,
            "alternative_paths": alt_paths,
            "attack_stages":  [
                {"stage": s, "state": nodes[stage_by_name[s]]["state"],
                  "id": stage_by_name[s]}
                for s in STAGES
            ],
            "timeline":       timeline,
            "metrics":        metrics,
            # Round 36 · Three deterministic projections over the same
            # SSOT.  Each answers a single analytical question.
            "views": {
                "mitre_chain":    project_mitre_chain(
                                          list(nodes.values()), edges),
                "process_tree":   project_process_tree(
                                          list(nodes.values()), edges),
                "activity_graph": project_activity_graph(
                                          list(nodes.values()), edges),
            },
            "evidence_summary": {
                "canonical_event_id": (canonical or {}).get("event_id"),
                "event_id":           event_id_str,
                "event_intel":        event_intel,
                "correlation_match_ids": [str(m.get("match_id") or m.get("id"))
                                                for m in ice_matches
                                                if m.get("match_id") or m.get("id")],
                "findings_count":     len(findings),
                "executions_count":   len(executions),
            },
            "mitre_summary": {
                "observed":  sorted({n["label"] for n in techs if n["state"] == "OBSERVED"}),
                "supported": sorted({n["label"] for n in techs if n["state"] == "SUPPORTED"}),
            },
            "investigation_gaps": gaps,
            "counts": {
                "nodes":  len(nodes),
                "edges":  len(edges),
                "stages_observed":  observed_stages,
                "stages_supported": supported_stages,
                "gaps":   len(gaps),
            },
            "honesty_note": (
                "Every edge carries evidence_refs.  NOT_OBSERVED stages "
                "are exposed as gap nodes, never rendered as if they had "
                "happened.  Node/edge ids are deterministic across runs."
            ),
        }

    # ── Path computation ────────────────────────────────────────

    @classmethod
    def _compute_paths(cls, nodes: Dict[str, Dict[str, Any]],
                            edges: List[Dict[str, Any]],
                            stage_by_name: Dict[str, str],
                            incident_nid: str,
                            process_nid: Optional[str],
                            parent_nid: Optional[str],
                            dst_ip_nid: Optional[str]
                          ) -> Tuple[List[str], List[List[str]]]:
        """Primary path = strongest evidence-backed *walkable* chain.

        We construct a real graph walk: every consecutive node in the
        returned list is connected by an edge that exists in ``edges``.

        Preference order (edge relations + node kinds):
          incident → (canonical event) → (parent process) →
          (process) → (commandline) → (detection) → (technique) → (stage)

        Only observed/supported evidence-backed transitions are used.
        Never fabricates a path.  Owner rule §11.
        """
        # Build directed adjacency: src → [(dst, rel, state, priority)]
        # Priority favors the causal spine.
        REL_PRIORITY = {
            "DETECTED_BY":       10,   # incident/event → detection or finding
            "SPAWNED":            9,   # parent → child process
            "EXECUTED":           9,   # process → commandline
            "TRIGGERED":          8,
            "MAPPED_TO":          8,   # detection/match/commandline → technique
            "BELONGS_TO":         7,   # technique → stage
            "CORRELATED_WITH":    6,
            "CONNECTED_TO":       5,
            "OBSERVED_ON":        3,
            "AUTHENTICATED_TO":   3,
            "SUPPORTED_BY":       4,
            "INVESTIGATED_BY":    2,
            "PIVOTED_TO":         1,
        }
        STATE_PRIORITY = {"OBSERVED": 3, "SUPPORTED": 2,
                             "POSSIBLE": 1, "NOT_OBSERVED": 0}
        KIND_TIER = {
            "incident":    0,
            "event":       1, "signature": 1, "event_id": 1,
            "host":        2, "user": 2,
            "process":     3,
            "commandline": 4,
            "finding":     5, "capability": 5,
            "detection":   6, "match": 6,
            "technique":   7,
            "stage":       8,
            "ip":          4, "hash": 4,
            "gap":         -1,   # dead-end · never part of primary chain
        }
        adj: Dict[str, List[Tuple[str, str, str, int]]] = {}
        for e in edges:
            src, dst, rel, state = e["src"], e["dst"], e["rel"], e["state"]
            if state == "NOT_OBSERVED":
                continue
            # PIVOTED_TO and gap targets are investigation hints, not
            # causal transitions — exclude from primary chain walk.
            if rel == "PIVOTED_TO":
                continue
            if nodes.get(dst, {}).get("kind") == "gap":
                continue
            score = (STATE_PRIORITY.get(state, 0) * 100
                        + REL_PRIORITY.get(rel, 0) * 10
                        + KIND_TIER.get(nodes.get(dst, {}).get("kind", ""), 0))
            adj.setdefault(src, []).append((dst, rel, state, score))
        for lst in adj.values():
            lst.sort(key=lambda t: (-t[3], t[1], t[0]))

        # Best-first DFS from incident preferring higher-tier
        # destination kinds — we want to reach a Stage.  Returns the
        # deterministic longest evidence-backed walk from ``start``.
        def _walk_forward(start: str) -> List[str]:
            best_path: List[str] = [start]
            best_tier = KIND_TIER.get(nodes.get(start, {}).get("kind", ""), 0)

            def _dfs(cur: str, path: List[str], visited: set) -> None:
                nonlocal best_path, best_tier
                cur_tier = KIND_TIER.get(nodes.get(cur, {}).get("kind", ""), 0)
                # Track the deepest-tier walk (prefer longer on ties).
                if (cur_tier > best_tier
                        or (cur_tier == best_tier and len(path) > len(best_path))):
                    best_tier = cur_tier
                    best_path = list(path)
                for dst, rel, state, score in adj.get(cur, []):
                    if dst in visited:
                        continue
                    dst_tier = KIND_TIER.get(nodes.get(dst, {}).get("kind", ""), 0)
                    # Never retreat below current tier (except into stage which is terminal).
                    if dst_tier < cur_tier:
                        continue
                    visited.add(dst)
                    path.append(dst)
                    _dfs(dst, path, visited)
                    path.pop()
                    visited.remove(dst)

            _dfs(start, [start], {start})
            return best_path

        primary_clean = _walk_forward(incident_nid)

        # Validate walkability — assert every adjacent pair has an edge.
        edge_pairs = {(e["src"], e["dst"]) for e in edges
                          if e["state"] != "NOT_OBSERVED"}
        for i in range(len(primary_clean) - 1):
            assert (primary_clean[i], primary_clean[i + 1]) in edge_pairs, (
                f"primary_path not walkable at "
                f"{primary_clean[i]} → {primary_clean[i + 1]}")

        # Alternative paths: walk from every unvisited OBSERVED/SUPPORTED
        # match/detection node forward (deterministic, evidence-backed).
        alt: List[List[str]] = []
        visited_all = set(primary_clean)
        for start in sorted(nodes.keys()):
            n = nodes[start]
            if n["kind"] not in ("detection", "match"):
                continue
            if start in visited_all:
                continue
            walk = _walk_forward(start)
            if len(walk) >= 2:
                alt.append(walk)
                visited_all.update(walk)
        return primary_clean, alt
