"""v2/investigation/builder.py · Compose an Investigation from telemetry.

Pipeline:
    telemetry frames  →  IRG enrichment  →  IKG assembly
                                        →  verdict engine (event)
                                        →  correlation engine (aggregate)

Output = an `Investigation` object carrying:
    · header         — case-level status (severity, device / incident score, verdict)
    · ikg            — Investigation Knowledge Graph (single source of truth)
    · verdicts       — per-event + aggregate verdicts (already deterministic)
    · profile        — the Adaptive Weight Profile applied
    · engine_version — versions of every subsystem used

Every future view (Summary, Trajectory, Attack Story, Evidence Graph,
Verdict, ATT&CK, Explainability, Reports) reads from THIS object. No
view calculates its own version of the truth.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any

from .ikg import InvestigationKnowledgeGraph, Node
from v2.shadow.irg import enrich as irg_enrich
from v2.verdict import correlate
from .attack_story import build_attack_story
from .attack_mapping import build_attack_mapping
from .explainability import why_is_this, why_is_this_not, list_patterns as list_negative_patterns


ENGINE_VERSION = {
    "ikg":         "1.0",
    "irg":         "1.0",
    "verdict":     "3.1b",
    "correlation": "3.1b",
    "investigation_builder": "1.0",
}


@dataclass
class Investigation:
    case_id: str
    header: dict[str, Any] = field(default_factory=dict)
    ikg:     dict[str, Any] = field(default_factory=dict)
    verdicts: dict[str, Any] = field(default_factory=dict)
    story:    list[dict]    = field(default_factory=list)      # Phase 2 view
    attack_mapping: dict[str, Any] = field(default_factory=dict)  # Phase 2 view
    explainability: dict[str, Any] = field(default_factory=dict)  # Phase 2 view
    profile: str = "soc_balanced"
    engine_version: dict[str, str] = field(default_factory=lambda: dict(ENGINE_VERSION))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fmt_ts(ts: Any) -> str:
    return str(ts) if ts is not None else ""


def build_investigation(frames: list[dict], case_id: str,
                        profile: str | None = None) -> Investigation:
    """Assemble the full Investigation object from raw telemetry frames.

    Deterministic. Every projection downstream must read this object
    rather than re-scanning frames.
    """
    prof = (profile or "soc_balanced").lower()

    # 1 · Enrich with IRG canonical relationships.
    enriched = irg_enrich(frames)

    # 2 · Run correlation (which internally scores every event with v3).
    corr = correlate(enriched, case_id=case_id, profile=prof)

    # 3 · Assemble the IKG.
    ikg = InvestigationKnowledgeGraph(case_id=case_id)

    # 3a · Device + incident anchors.
    device_id   = f"device::{case_id}"
    incident_id = f"incident::{case_id}"
    ikg.add_node(Node(id=incident_id, type="incident",
                      label=case_id, attrs={"case_id": case_id}))
    ikg.add_node(Node(id=device_id, type="device",
                      label=case_id, attrs={"case_id": case_id}))
    ikg.add_edge(device_id, incident_id, "part_of")

    # 3b · Entities from every frame (process / file / registry / network / …).
    for f in enriched:
        ent = f.get("entity") or {}
        parent = f.get("parent") or {}

        ent_id, ent_type = ent.get("iid"), (ent.get("type") or "").lower()
        if ent_id and ent_type:
            ikg.add_node(Node(id=ent_id, type=ent_type,
                              label=ent.get("name") or ent_id,
                              attrs={"lane": f.get("lane"),
                                     "first_seen": _fmt_ts(f.get("ts"))}))
            ikg.add_edge(ent_id, device_id, "hosted_on")

        # Parent process node (create even if never itself surfaced as entity).
        pid, ptype = parent.get("iid"), (parent.get("type") or "process").lower()
        if pid:
            ikg.add_node(Node(id=pid, type=ptype,
                              label=parent.get("name") or pid,
                              attrs={}))
            ikg.add_edge(pid, device_id, "hosted_on")

    # 3c · Event / relationship edges from every frame.
    for f in enriched:
        fid = f.get("frame_iid") or f.get("id")
        lane = str(f.get("lane") or "").lower()
        ent = f.get("entity") or {}
        parent = f.get("parent") or {}
        rel = (f.get("relationship") or {}).get("type") or ""
        rel = rel.lower()
        pid = parent.get("iid")
        ent_id = ent.get("iid")

        # Every event becomes a node too (frame-level provenance for stories).
        if fid:
            ikg.add_node(Node(
                id=fid, type="event",
                label=str(f.get("label") or f.get("action") or lane),
                attrs={"ts":      _fmt_ts(f.get("ts")),
                       "lane":    lane,
                       "action":  f.get("action") or "",
                       "cmdline": f.get("cmdline") or "",
                       "rule_id": f.get("rule_id") or "",
                       "mitre":   list(f.get("mitre") or [])},
            ))
            if ent_id:
                ikg.add_edge(fid, ent_id, "executed_by",
                             attrs={"ts": _fmt_ts(f.get("ts"))})

        # Parent → entity structural relationship.
        if pid and ent_id and pid != ent_id:
            if ent.get("type") == "process":
                ikg.add_edge(pid, ent_id, "spawned",
                             attrs={"ts": _fmt_ts(f.get("ts"))})
            elif lane == "file":
                verb = "created" if "creat" in (f.get("action") or "").lower() \
                       else "deleted" if "delet" in (f.get("action") or "").lower() \
                       else "modified"
                ikg.add_edge(pid, ent_id, verb, attrs={"ts": _fmt_ts(f.get("ts"))})
            elif lane == "registry":
                ikg.add_edge(pid, ent_id, "modified", attrs={"ts": _fmt_ts(f.get("ts"))})
            elif lane == "network":
                ikg.add_edge(pid, ent_id, "contacted", attrs={"ts": _fmt_ts(f.get("ts"))})
            elif lane == "module":
                ikg.add_edge(pid, ent_id, "loaded", attrs={"ts": _fmt_ts(f.get("ts"))})
            elif lane in ("service", "task"):
                ikg.add_edge(pid, ent_id, "installed",
                             attrs={"ts": _fmt_ts(f.get("ts"))})

        # MITRE technique nodes and mapping edges.
        for tech in (f.get("mitre") or []):
            tech_id = f"technique::{tech}"
            base = str(tech).split(".", 1)[0]
            ikg.add_node(Node(id=tech_id, type="technique",
                              label=str(tech),
                              attrs={"technique_id": str(tech), "base": base}))
            if fid:
                ikg.add_edge(fid, tech_id, "maps_to")

    # 3d · Aggregate verdict nodes (event → process → chain → device → incident).
    def _add_verdict_node(v: dict, layer: str, parent_id: str | None) -> str:
        vid = f"verdict::{layer}::{v.get('id')}"
        ikg.add_node(Node(id=vid, type="verdict",
                          label=f"{layer.title()} · {v.get('band')}",
                          attrs={"layer":       layer,
                                 "score":       v.get("score"),
                                 "band":        v.get("band"),
                                 "confidence":  v.get("confidence"),
                                 "explanation": v.get("explanation")}))
        if parent_id:
            ikg.add_edge(vid, parent_id, "rollup_of")
        return vid

    incident_v = corr.incident.to_dict() if corr.incident else None
    device_v   = corr.device.to_dict()   if corr.device else None

    incident_vid = None
    if incident_v:
        incident_vid = _add_verdict_node(incident_v, "incident", None)
        ikg.add_edge(incident_vid, incident_id, "contributes_to")

    device_vid = None
    if device_v:
        device_vid = _add_verdict_node(device_v, "device", incident_vid)
        ikg.add_edge(device_vid, device_id, "contributes_to")

    for cid, chain in corr.chains.items():
        cvid = _add_verdict_node(chain.to_dict(), "chain", device_vid)
        if cid in ikg.nodes:
            ikg.add_edge(cvid, cid, "contributes_to")

    for pid, proc in corr.processes.items():
        if proc.score == 0:
            continue
        pvid = _add_verdict_node(proc.to_dict(), "process", device_vid)
        if pid in ikg.nodes:
            ikg.add_edge(pvid, pid, "contributes_to")

    # 4 · Header — the persistent case status bar.
    dv = corr.device
    header = {
        "case_id":        case_id,
        "engine":         "v3.1b",
        "profile":        prof,
        "severity":       dv.band if dv else "benign",
        "device_score":   dv.score if dv else 0,
        "incident_score": corr.incident.score if corr.incident else 0,
        "confidence":     dv.confidence if dv else 0,
        "verdict_band":   dv.band if dv else "benign",
        "event_count":    len(enriched),
        "process_count":  len([n for n in ikg.by_type("process")]),
        "chain_count":    len(corr.chains),
        "tactic_coverage": dv.tactic_coverage if dv else {},
        "progressions":    [p["id"] for p in (dv.progressions if dv else [])],
        "correlation_bonuses": [b["signal"] for b in (dv.correlation_bonuses if dv else [])],
    }

    return Investigation(
        case_id=case_id,
        header=header,
        ikg=ikg.to_dict(),
        verdicts=corr.to_dict(),
        story=build_attack_story(enriched, ikg.to_dict(), corr.to_dict()),
        attack_mapping=build_attack_mapping(ikg.to_dict(),
                                            corr.device.to_dict() if corr.device else None),
        explainability={
            "positive":         why_is_this(corr.device.to_dict() if corr.device else {},
                                            ikg.stats()),
            "negative_patterns": list_negative_patterns(),
        },
        profile=prof,
    )
