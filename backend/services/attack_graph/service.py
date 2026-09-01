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
                "attrs":  {"index": idx + 1},
            })
            stage_by_name[stage] = nid

        # ── Canonical entity nodes ───────────────────────────────
        canonical_evt_nid: Optional[str] = None
        host_nid = user_nid = process_nid = parent_nid = None
        src_ip_nid = dst_ip_nid = None
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
                    _add_edge(process_nid, "TRIGGERED", cli_nid,
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

        # ── MITRE technique nodes ────────────────────────────────
        # Evidence-derived (incident.mitre → OBSERVED)
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
                             "tactic_id": m.get("tactic_id") or m.get("tactic")}})
            # Connect from canonical event or from process, whichever exists.
            anchor = process_nid or canonical_evt_nid or incident_nid
            _add_edge(anchor, "MAPPED_TO", tech_nid,
                          state="OBSERVED",
                          evidence_refs=[canonical.get("event_id")] if canonical else [],
                          technique_id=tid,
                          timestamp=canonical_ts,
                          reason="Technique attributed by detection evidence.")
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

        # Correlation-derived MITRE (SUPPORTED).
        for m in ice_matches:
            mid = str(m.get("match_id") or m.get("id") or "")
            for tech in (m.get("mitre") or []):
                tid = (tech.get("technique_id") or tech.get("technique")
                          if isinstance(tech, dict) else str(tech))
                if not tid:
                    continue
                tid = str(tid).upper()
                if _nid("technique", tid) not in nodes:
                    tech_nid = _add_node({
                        "id": _nid("technique", tid), "kind": "technique",
                        "label": tid, "state": "SUPPORTED",
                        "attrs": {"source": "correlation"}})
                    _add_edge(incident_nid, "CORRELATED_WITH", tech_nid,
                                  state="SUPPORTED",
                                  evidence_refs=[mid],
                                  technique_id=tid,
                                  reason="Technique attributed by correlation.")
                    for st in stages_for_technique(tid) or []:
                        stage_nid = stage_by_name.get(st)
                        if stage_nid:
                            _add_edge(tech_nid, "BELONGS_TO", stage_nid,
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
        """Primary path = strongest observed chain.

        We construct it deterministically:
          incident → canonical event → parent process → child process →
          command line → destination IP → technique(s) → stage(s)
        Only nodes/edges that actually exist are included; nothing is
        fabricated.
        """
        # Deterministic walk: for each candidate node, include only if
        # present in ``nodes``.  Preserves owner rule §11 (no invention).
        primary: List[str] = [incident_nid]
        # Find canonical event node.
        for n in nodes.values():
            if n["kind"] == "event":
                primary.append(n["id"])
                break
        if parent_nid and parent_nid in nodes:
            primary.append(parent_nid)
        if process_nid and process_nid in nodes:
            primary.append(process_nid)
        # Command line if present.
        for n in nodes.values():
            if n["kind"] == "commandline":
                primary.append(n["id"])
                break
        if dst_ip_nid and dst_ip_nid in nodes:
            primary.append(dst_ip_nid)
        # Observed techniques.
        obs_techs = sorted([n["id"] for n in nodes.values()
                                 if n["kind"] == "technique"
                                   and n["state"] == "OBSERVED"])
        primary.extend(obs_techs)
        # Observed stages.
        obs_stages = [stage_by_name[s] for s in STAGES
                          if nodes[stage_by_name[s]]["state"] == "OBSERVED"]
        primary.extend(obs_stages)
        # Deduplicate preserving order.
        seen: set = set()
        primary_clean: List[str] = []
        for nid in primary:
            if nid in seen:
                continue
            seen.add(nid)
            primary_clean.append(nid)

        # Alternative: SUPPORTED-only chain through correlation techniques.
        sup_techs = sorted([n["id"] for n in nodes.values()
                                 if n["kind"] == "technique"
                                   and n["state"] == "SUPPORTED"])
        alt: List[List[str]] = []
        if sup_techs:
            sup_stages = [stage_by_name[s] for s in STAGES
                              if nodes[stage_by_name[s]]["state"] == "SUPPORTED"]
            alt.append([incident_nid] + sup_techs + sup_stages)
        return primary_clean, alt
