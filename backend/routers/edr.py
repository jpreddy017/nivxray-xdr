"""NivXForge EDR — Detections + Process Tree projection APIs.

Owner-locked rules (Slice 2 · P0 · 2026-08-29):
  - No native ``detections`` collection exists in the repository — we
    verified this by inspection.  Therefore Detections is a READ-ONLY
    projection derived from ``workspace_cases.verdict_stage2.evidence[]``.
    Every projected detection carries provenance so the analyst always
    knows the rule/source that generated it.
  - Process Tree reuses the existing canonical
    ``services.activity.ActivityInventory`` (parent_entity_id +
    child_entity_ids) that already backs Device Trajectory.  We do
    NOT introduce a second process-correlation model.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user, sync_collection
from services.activity.projector import build_inventory
from services.dashboard_lenses import resolve_tenant_scope
from services.edr import device_identity as dir_svc
from services.edr import observation_narrative as narrative_svc
from services.edr import file_trajectory as file_traj_svc
from services.edr.endpoint_health import resolve_endpoint_health

router = APIRouter(prefix="/edr", tags=["edr"])

_col = sync_collection("workspace_cases")


def _case_scope(user) -> Optional[Dict[str, Any]]:
    """Tenant-authorised case filter for the EDR projections.

    P0 · 2026-09-05: the EDR routes previously filtered on
    ``user_email``, which is an ownership gate, not an authorisation
    gate — the same defect that hid 180 of 198 incidents from the queue.
    They now share ``resolve_tenant_scope()`` with the incident plane.

    Returns ``None`` when the caller is not authorised (honest empty).
    """
    scope = resolve_tenant_scope((user or {}).get("email"))
    if not scope.get("authorized"):
        return None
    q: Dict[str, Any] = {"name": {"$exists": True, "$ne": ""}}
    if not scope.get("all_tenants"):
        q["tenant_id"] = {"$in": scope["tenant_ids"]}
    return q


def _is_cross_tenant(user) -> Any:
    """The principal's authorisation scope.

    Returns the scope object the EDR identity plane needs, not a bare
    boolean: a customer-scoped analyst must be able to see ITS OWN
    endpoints, which a boolean cannot express. Kept under the original
    name so every existing call site passes the scope unchanged.
    """
    scope = resolve_tenant_scope((user or {}).get("email"))
    if not scope.get("authorized"):
        return {"all_tenants": False, "tenant_ids": []}
    return {"all_tenants": bool(scope.get("all_tenants")),
            "tenant_ids": list(scope.get("tenant_ids") or [])}


def _extract_host(doc: Dict[str, Any]) -> Optional[str]:
    """Deterministic host extraction from ``workspace_cases.ssot``.
    Returns None when the case has no endpoint context yet — never
    fabricated (rule #13)."""
    ssot = doc.get("ssot") or {}
    if not isinstance(ssot, dict):
        return None
    inv_obj = ssot.get("investigation_object") or {}
    if not isinstance(inv_obj, dict):
        return None
    host = inv_obj.get("host")
    if not host:
        dev = inv_obj.get("device")
        if isinstance(dev, dict):
            host = dev.get("hostname")
    return str(host) if host else None


# ── Detections projection ────────────────────────────────────────────
# Deterministic mapping: Stage-2 rule → detection row.  Every field is
# either present in the source evidence or omitted (rule #13 · no
# fabrication).  ``detected_by`` is the analyst-facing "which engine
# raised this" field surfaced explicitly per owner spec.
_RULE_SEVERITY: Dict[str, str] = {
    "PROC-SUSPICIOUS-PARENT":       "high",
    "CMD-OBFUSCATION":              "high",
    "FILE-DROP-EXECUTABLE":         "high",
    "NETWORK-SUSPICIOUS":           "medium",
    "MITRE-IMPACT":                 "critical",
    "MITRE-EXFILTRATION":           "critical",
    "OBJECTIVE-DOUBLE-EXTORTION":   "critical",
    "V3X-VERDICT-CARRY":            "medium",
    "SIGNED-BENIGN-COUNTERWEIGHT":  "info",
}


def _project_detections(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    stage2 = doc.get("verdict_stage2") or {}
    evidence = stage2.get("evidence") or []
    if not isinstance(evidence, list):
        return []
    case_id = doc.get("id")
    ssot = doc.get("ssot") or {}
    inv_obj = (ssot.get("investigation_object") or {}) if isinstance(ssot, dict) else {}
    host = None
    if isinstance(inv_obj, dict):
        host = (inv_obj.get("host") or (inv_obj.get("device") or {}).get("hostname"))
    user_email = doc.get("user_email")
    created = doc.get("created_at") or doc.get("updated_at")

    rows: List[Dict[str, Any]] = []
    for idx, ev in enumerate(evidence):
        if not isinstance(ev, dict):
            continue
        rule_id = ev.get("rule_id") or ev.get("rule") or f"RULE-{idx}"
        weight = ev.get("weight")
        rows.append({
            "detection_id":     f"{case_id}::rule::{rule_id}",
            "detection":        rule_id.replace("-", " ").title(),
            "rule_id":          rule_id,
            "detected_by":      "NivXRay Verdict Engine · Stage-2",
            "detection_source": "workspace_cases.verdict_stage2.evidence[]",
            "severity":         _RULE_SEVERITY.get(rule_id, "medium"),
            "weight":           weight,
            "timestamp":        ev.get("timestamp") or created,
            "device":           host,
            "user":             user_email,
            "process":          ev.get("process"),
            "file":             ev.get("file"),
            "disposition":      (stage2.get("label") or "unknown"),
            "incident_id":      case_id,
            "evidence_ref": {
                "type":     "stage2_rule_evidence",
                "rule_id":  rule_id,
                "index":    idx,
            },
        })
    return rows


# ── Process Tree projection ──────────────────────────────────────────
def _project_process_tree(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Reuse the existing canonical ActivityInventory.  Returns a
    root-first tree with pivot metadata; if the case has no timeline
    yet, we return an empty tree honestly (never fabricated)."""
    ssot = doc.get("ssot") or {}
    timeline = None
    if isinstance(ssot, dict):
        # Look for a canonical timeline attached to the case.  If the
        # analyst has not run a timeline projection yet we simply
        # return an empty tree — no synthesis.
        timeline = ssot.get("timeline") or ssot.get("canonical_timeline")
    if not (isinstance(timeline, dict) and timeline.get("events")):
        return {"case_id": doc.get("id"), "nodes": [], "roots": [],
                  "reason": "no_matching_evidence",
                  "note":   "No canonical timeline attached to this incident."}

    inv = build_inventory(case_id=doc.get("id"),
                             tenant_id=doc.get("tenant_id") or doc.get("user_email"),
                             timeline=timeline)
    d = inv.to_dict()
    processes = (d.get("entities") or {}).get("process") or []
    by_id = {p["entity_id"]: p for p in processes}
    roots = [p["entity_id"] for p in processes if not p.get("parent_entity_id")
              or p.get("parent_entity_id") not in by_id]

    nodes: List[Dict[str, Any]] = []
    for p in processes:
        # Deterministic node — only fields backed by the inventory.
        nodes.append({
            "entity_id":   p["entity_id"],
            "process":     p.get("name") or p.get("process") or "process",
            "path":        p.get("path"),
            "command_line": p.get("command_line"),
            "user":        p.get("user"),
            "host":        p.get("host"),
            "first_seen":  p.get("first_seen"),
            "last_seen":   p.get("last_seen"),
            "parent_id":   p.get("parent_entity_id"),
            "child_ids":   p.get("child_entity_ids") or [],
            "event_ids":   p.get("event_ids") or [],
            "pivots": {
                # Contextual pivots surfaced in the UI — every target
                # is an existing NivXRay route.  No duplicate engines.
                "trajectory":       "/edr/trajectory",
                "command_intel":    "/analyze" if p.get("command_line") else None,
            },
        })
    return {
        "case_id": doc.get("id"),
        "nodes":   nodes,
        "roots":   roots,
        "reason":  "ok",
        "source":  "services.activity.ActivityInventory",
    }


def _project_endpoint_process_tree(endpoint_id: str,
                                   hours: int,
                                   scope: Any = None) -> Dict[str, Any]:
    """Build ancestry from the REAL sensor evidence for one endpoint.

    Every node is one observed process. Links are the canonical
    `process_iid` / `parent_iid` identities minted by the existing
    canonical layer — nothing is inferred from pid alone, because Linux
    reuses pids.

    A parent that was referenced but never observed becomes an explicit
    GHOST root: it is NOT dropped (that would silently reparent a child
    to the wrong place) and it is NOT invented (it carries no name,
    command line or user). `lineage_state` on each node says exactly
    which case it is.
    """
    # Ownership is the caller's scope, never an unconditional bypass.
    identity = dir_svc.resolve(endpoint_id, scope or {"all_tenants": False,
                                                      "tenant_ids": []})
    if not identity:
        return {"engine_id": "nivxray::edr_plane::process_tree",
                "endpoint_id": endpoint_id, "nodes": [], "edges": [],
                "epistemic_state": {
                    "state": "ENDPOINT_NOT_RESOLVED",
                    "message": ("no endpoint you are authorised for "
                                "resolves to this reference")}}
    since = (datetime.now(timezone.utc)
             - timedelta(hours=max(1, min(hours, 24 * 30)))).isoformat()
    needles = {endpoint_id}
    if identity:
        needles |= {v for v in (identity.get("device_iid"),
                                identity.get("hostname")) if v}
    docs = list(sync_collection("v2_shadow_observations").find(
        {"kind": {"$regex": "process"},
         "$or": [{"device_iid": {"$in": list(needles)}},
                 {"event.computer": {"$in": list(needles)}},
                 {"collector_id": endpoint_id}],
         "captured_at": {"$gte": since}},
        {"_id": 0, "event": 1, "captured_at": 1, "adapter": 1}))

    nodes: Dict[str, Dict[str, Any]] = {}
    for d in docs:
        ev = d.get("event") or {}
        proc = ev.get("process") or {}
        iid = (proc.get("iid") or proc.get("process_iid")
               or ev.get("process_iid"))
        if not iid:
            continue
        raw = ev.get("raw") or {}
        node = nodes.setdefault(iid, {
            "process_iid": iid, "parent_iid": proc.get("parent_iid") or None,
            "process": proc.get("name") or proc.get("image"),
            "path": raw.get("image_path") or proc.get("image"),
            "pid": raw.get("pid"),
            "ppid": raw.get("ppid"),
            "command_line": raw.get("command_line"),
            "user": raw.get("user"), "sha256": raw.get("sha256"),
            "first_seen": d.get("captured_at"),
            "last_seen": d.get("captured_at"),
            "observed": True, "child_ids": [],
            "lineage_state": (raw.get("parent_lookup_state")
                              or ev.get("lineage_state")
                              or "PARENT_NOT_OBSERVED"),
            "event_iids": [],
            "detections": sorted({r for r in (ev.get("rule_ids") or [])}),
        })
        node["last_seen"] = max(str(node["last_seen"] or ""),
                                str(d.get("captured_at") or ""))
        if ev.get("iid"):
            node["event_iids"].append(ev["iid"])

    ghosts = 0
    for node in list(nodes.values()):
        pid_iid = node["parent_iid"]
        if pid_iid and pid_iid not in nodes:
            ghosts += 1
            nodes[pid_iid] = {
                "process_iid": pid_iid, "parent_iid": None,
                "process": None, "path": None, "pid": node.get("ppid"),
                "ppid": None, "command_line": None, "user": None,
                "sha256": None, "first_seen": None, "last_seen": None,
                "observed": False, "child_ids": [], "event_iids": [],
                "detections": [],
                "lineage_state": "GHOST_PARENT_NOT_OBSERVED",
                "note": ("Referenced as a parent by observed evidence but "
                         "never observed itself. Nothing about it is "
                         "claimed."),
            }
    for node in nodes.values():
        if node["parent_iid"] in nodes:
            nodes[node["parent_iid"]]["child_ids"].append(node["process_iid"])

    roots = sorted(n["process_iid"] for n in nodes.values()
                   if not n["parent_iid"])
    return {
        "endpoint_id": endpoint_id,
        "identity": {"resolved": identity is not None,
                     "hostname": (identity or {}).get("hostname"),
                     "device_iid": (identity or {}).get("device_iid"),
                     "resolved_via": (identity or {}).get("resolved_via")},
        "window_hours": hours,
        "nodes": sorted(nodes.values(),
                        key=lambda n: (str(n.get("first_seen") or ""),
                                       n["process_iid"])),
        "roots": roots,
        "counts": {"observed": sum(1 for n in nodes.values()
                                   if n["observed"]),
                   "ghost_parents": ghosts, "roots": len(roots)},
        "reason": "ok" if nodes else "no_matching_evidence",
        "source": "v2_shadow_observations · canonical process_iid/parent_iid",
        "note": ("Links are canonical process identities, never pid alone — "
                 "Linux reuses pids. A ghost root is a real gap in "
                 "visibility, not a process that did not exist."),
    }


# ── HTTP surfaces ────────────────────────────────────────────────────
def _load(incident_id: str) -> Dict[str, Any]:
    doc = _col.find_one({"id": incident_id})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found",
                                       "id": incident_id})
    return doc


@router.get("/detections")
async def list_detections(incident_id: str,
                             user=Depends(get_current_user)):
    doc = _load(incident_id)
    rows = _project_detections(doc)
    return {
        "incident_id": incident_id,
        "detections":  rows,
        "count":       len(rows),
        "source":      "workspace_cases.verdict_stage2.evidence[]",
        "note":        "Read-only projection · rule_id is the detection source (no native detection engine)."
                          if rows else "no_matching_evidence",
    }


@router.get("/endpoint-detections")
async def list_endpoint_detections(endpoint_id: str, hours: int = 24,
                                   user=Depends(get_current_user)):
    """P0-F · read-only projection of the AUTHORITATIVE detection records.

    It creates no detection store and holds no detection state: every row
    is a derivation written by the XDR detection fabric onto the immutable
    raw endpoint event, so a detection cannot exist here without the real
    evidence that produced it. `/detections` (incident-keyed, case-derived)
    is deliberately left untouched.
    """
    since = (datetime.now(timezone.utc)
             - timedelta(hours=max(1, min(hours, 24 * 30)))).isoformat()
    rows = []
    evaluated = 0
    not_evaluated = 0
    for raw in sync_collection("edr_raw_events").find(
            {"endpoint_ref": endpoint_id, "ingest_time": {"$gte": since}},
            {"_id": 0, "raw_id": 1, "payload": 1, "derivations": 1,
             "ingest_time": 1, "trust_state": 1}):
        for d in (raw.get("derivations") or ()):
            outcome = d.get("outcome")
            if outcome in ("DETECTION_MATCHED",
                           "DETECTION_EVALUATED_NO_MATCH"):
                evaluated += 1
            elif outcome == "DETECTION_NOT_EVALUATED":
                not_evaluated += 1
            if outcome != "DETECTION_MATCHED":
                continue
            try:
                p = json.loads(raw.get("payload") or "{}")
            except ValueError:
                p = {}
            rows.append({
                "raw_id": raw["raw_id"],
                "canonical_event_id": d.get("event_id"),
                "rule_ids": [r.strip() for r in
                             str(d.get("reason") or "").replace("rules:", "")
                             .split(",") if r.strip()],
                "detection_engine": d.get("detection_content_version"),
                "verdict": d.get("verdict_version"),
                "incident_ids": d.get("evidence_ids") or [],
                "activity": p.get("activity"),
                "command_line": p.get("command_line"),
                "image_path": p.get("image_path") or p.get("path"),
                "observed_at": p.get("observed_at"),
                "detected_at": d.get("derived_at"),
                "trust_state": raw.get("trust_state"),
            })
    rows.sort(key=lambda r: str(r.get("detected_at") or ""), reverse=True)
    return {
        "endpoint_id": endpoint_id,
        "window_hours": hours,
        "detections": rows,
        "count": len(rows),
        "events_evaluated": evaluated,
        "events_not_evaluated": not_evaluated,
        "source": "edr_raw_events.derivations[] · written by "
                  "detection_content.xdr_pipeline",
        "note": ("Read-only projection of authoritative detection "
                 "derivations. `events_not_evaluated` is a DETECTION GAP, "
                 "not an absence of malicious activity."),
    }



@router.get("/process-tree")
async def get_process_tree(incident_id: str | None = None,
                           endpoint_id: str | None = None,
                           hours: int = 24,
                           user=Depends(get_current_user)):
    """Root-first process ancestry.

    Two pivots, one projection contract:
      * `incident_id` — the original case-derived tree (unchanged).
      * `endpoint_id` — REAL sensor lineage from canonical evidence
        (P0-F.4). This is the pivot an analyst actually has after a
        detection fires on an endpoint.
    """
    if endpoint_id:
        return _project_endpoint_process_tree(endpoint_id, hours,
                                              _is_cross_tenant(user))
    if not incident_id:
        raise HTTPException(
            status_code=422,
            detail={"error": "pivot_required",
                    "reason": "supply either endpoint_id or incident_id",
                    "note": "No tree is invented without a pivot."})
    doc = _load(incident_id)
    return _project_process_tree(doc)


@router.get("/campaign-story")
async def campaign_story(incident_id: str, user=Depends(get_current_user)):
    """P0-F.7 · one intrusion, told once, from the authoritative records.

    A read model: endpoint → process activity → detection → evidence →
    verdict → incident → response → response verification, with the
    provenance chain preserved on every step and every missing link named
    as a gap rather than filled in.
    """
    from deps import db as _db
    from edr_plane.campaign_story import build_story
    story = await build_story(
        _db, tenant_id=(user.get("tenant_id") or "default"),
        incident_id=incident_id)
    if story.get("error"):
        raise HTTPException(status_code=404, detail=story)
    return story



@router.get("/observation-narrative")
async def observation_narrative(device: str, event_iid: str,
                                user=Depends(get_current_user)):
    """Evidence-gated prose for a single persisted observation.

    Returns ``resolved: false`` rather than an invented sentence when the
    device reference or the ``event.iid`` does not resolve.
    """
    doc = dir_svc.find_observation(device, event_iid, _is_cross_tenant(user))
    if not doc:
        return {"resolved": False, "device": device, "event_iid": event_iid,
                "reason": "observation_unresolved",
                "note": "No persisted observation matches this event_iid on "
                        "this device. No narrative is composed."}
    return {"resolved": True, "device": device, "event_iid": event_iid,
            **narrative_svc.compose(doc)}


@router.get("/file-trajectory")
async def file_trajectory(key: str, key_type: str = "name",
                          user=Depends(get_current_user)):
    """P1.8 · Fleet (multi-endpoint) artifact trajectory.

    `key_type` is one of `sha256` (content digest over
    `artefacts.file[].sha256`), `name` (process name / file-path leaf) or
    `path` (exact image or file path).  The response always states which
    fields were matched and why a content-digest correlation may be
    impossible on this substrate.
    """
    return file_traj_svc.fleet_trajectory(key_type, key)


@router.get("/fleet-spread-index")
async def fleet_spread_index(user=Depends(get_current_user)):
    """Every observable artifact and the number of endpoints it appears on."""
    return file_traj_svc.spread_index()


# ── XDR Endpoints projection (Slice 6 · read-only) ───────────────────
# Deterministic aggregation of workspace_cases by extracted host.  This
# is a pure projection — no new store, no new engine.  The XDR
# Endpoints screen consumes this list; every row's `latest_incident_id`
# points back into the existing incident record.
@router.get("/endpoints")
async def list_endpoints(user=Depends(get_current_user)):
    q = _case_scope(user)
    if q is None:
        return {"endpoints": [], "count": 0,
                "source": "v2_shadow_observations · workspace_cases",
                "reason": "not_authorized",
                "note": "no_matching_evidence"}
    projection = {
        "_id": 0, "id": 1, "name": 1, "user_email": 1, "tenant_id": 1,
        "created_at": 1, "updated_at": 1, "ssot": 1,
        "verdict_stage2": 1, "engine": 1,
    }
    cur = _col.find(q, projection).sort("updated_at", -1).limit(500)

    by_host: Dict[str, Dict[str, Any]] = {}
    for d in cur:
        host = _extract_host(d)
        if not host:
            continue
        stage2 = d.get("verdict_stage2") or {}
        label = (stage2.get("label") or "").lower() or "unknown"
        risk = stage2.get("risk_score")
        updated = d.get("updated_at") or d.get("created_at")
        det_count = 0
        ev = stage2.get("evidence") if isinstance(stage2, dict) else None
        if isinstance(ev, list):
            det_count = len(ev)

        row = by_host.get(host)
        if not row:
            row = {
                "host":                 host,
                "incident_count":       0,
                "detection_count":      0,
                "last_seen":            updated,
                "worst_label":          label,
                "worst_risk":           risk if isinstance(risk, (int, float)) else 0,
                "latest_incident_id":   d.get("id"),
                "tenant":               d.get("tenant_id") or d.get("user_email"),
                "engine":               d.get("engine"),
            }
            by_host[host] = row
        row["incident_count"]  += 1
        row["detection_count"] += det_count
        if updated and (not row["last_seen"] or updated > row["last_seen"]):
            row["last_seen"] = updated
            row["latest_incident_id"] = d.get("id")
        # Track the worst-known label/risk for the row's severity chip.
        sev_rank = {"malicious": 3, "suspicious": 2, "benign": 1, "unknown": 0}
        if sev_rank.get(label, 0) > sev_rank.get(row["worst_label"], 0):
            row["worst_label"] = label
        if isinstance(risk, (int, float)) and risk > (row["worst_risk"] or 0):
            row["worst_risk"] = risk

    # Case-derived rows carry no device IID — they are hostname strings,
    # so their identity is INFERRED by contract.
    rows: List[Dict[str, Any]] = []
    for host, row in by_host.items():
        row["device_ref"] = host
        row["device_iid"] = None
        row["hostname"] = host
        row["identity_confidence"] = dir_svc.INFERRED
        row["observation_count"] = 0
        row["source"] = "workspace_cases.ssot.investigation_object"
        rows.append(row)

    # ── IRG substrate projection (authoritative device identity) ─────
    # See services/edr/device_identity.py.  This is the substrate that
    # actually carries `device_iid`; the SSOT host field is empty in
    # every persisted case.
    for dev in dir_svc.list_devices(_is_cross_tenant(user)):
        rows.append({
            "host":                dev.get("hostname") or dev.get("device_iid"),
            "device_ref":          dev.get("device_ref"),
            "device_iid":          dev.get("device_iid"),
            "hostname":            dev.get("hostname"),
            "identity_confidence": dev.get("identity_confidence"),
            "observation_count":   dev.get("observation_count"),
            "lane_counts":         dev.get("lane_counts"),
            "incident_count":      len(dev.get("case_ids") or []),
            "detection_count":     0,
            "first_seen":          dev.get("first_seen"),
            "last_seen":           dev.get("last_seen"),
            "worst_label":         "unknown",
            "worst_risk":          None,
            "latest_incident_id":  (dev.get("case_ids") or [None])[0],
            # Ownership as the server resolved it, plus the state that
            # says how much that ownership is worth.
            "tenant":              dev.get("tenant_id"),
            "tenant_id":           dev.get("tenant_id"),
            "tenant_attribution":  dev.get("tenant_attribution"),
            "attribution_basis":   dev.get("attribution_basis"),
            "owning_endpoint_ids": dev.get("owning_endpoint_ids"),
            "engine":              None,
            "users":               dev.get("users"),
            "provenance":          dev.get("provenance"),
            # P0-A.1 · both health dimensions, never collapsed. There is no
            # agent plane yet, so `agent=None` yields NO_AGENT /
            # NEVER_ENROLLED honestly rather than defaulting to OFFLINE.
            "health":              resolve_endpoint_health(
                                       agent=None,
                                       last_telemetry_at=dev.get("last_seen"),
                                       observation_count=int(
                                           dev.get("observation_count") or 0)),
            "source":              "v2_shadow_observations",
        })

    rows.sort(key=lambda r: r.get("last_seen") or "", reverse=True)
    return {
        "endpoints": rows,
        "count":     len(rows),
        "source":    "v2_shadow_observations · workspace_cases.ssot.investigation_object",
        "identity_contract": {
            "authoritative": "event.device_iid",
            "inferred":      "hostname string with no bound IID",
        },
        "note":      "Read-only projection · a device exists here only because an observation exists."
                        if rows else "no_matching_evidence",
    }


# ── Device Trajectory aggregation (Slice 6 · read-only) ──────────────
# Aggregates detections + activity-inventory entries for a device
# across all incidents on that host within a time window.  Consumes the
# same primitives that back `/edr/detections` and `/edr/process-tree`.
_LANE_ORDER = ("system", "process", "file", "network", "registry")


def _map_lane_from_rule(rule_id: str) -> str:
    r = (rule_id or "").upper()
    if r.startswith("NETWORK") or "NET-" in r:            return "network"
    if r.startswith("FILE"):                                 return "file"
    if r.startswith("REG") or "REGISTRY" in r:             return "registry"
    if r.startswith("PROC") or "CMD" in r:                 return "process"
    if r.startswith("MITRE") or "OBJECTIVE" in r:          return "system"
    return "system"


def _map_lane_from_entity(kind: str) -> str:
    k = (kind or "").lower()
    if k == "process":                       return "process"
    if k in ("file", "artifact"):            return "file"
    if k in ("network", "url", "domain",
              "ip", "connection"):            return "network"
    if k == "registry":                       return "registry"
    return "system"


def _iso_ok(ts: Optional[str]) -> Optional[str]:
    if not ts:
        return None
    return str(ts)


@router.get("/endpoints/{endpoint_id}/trajectory")
async def endpoint_trajectory_window(
    endpoint_id: str,
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
    lane_start: int = 0,
    lane_end: int = 40,
    cursor: Optional[str] = None,
    limit: int = 500,
    kinds: Optional[str] = None,
    q: Optional[str] = None,
    dispositions: Optional[str] = None,
    hist_day: Optional[str] = None,
    user=Depends(get_current_user),
):
    """A WINDOWED, endpoint-scoped trajectory read.

    Endpoint-centric on purpose: it needs no case, incident, verdict or
    investigation state. It is a projection over the existing canonical
    evidence and creates no telemetry store of its own.
    """
    from deps import db as _db
    from edr_plane import trajectory_window as tw

    identity = dir_svc.resolve(endpoint_id, _is_cross_tenant(user))
    if not identity:
        return {"engine_id": tw.ENGINE_ID, "endpoint": None, "events": [],
                "lane_axis": {"total_lanes": 0, "lanes": []},
                "computer": None,
                "epistemic_state": tw.empty_state(
                    identity=None, enrolled=False, observations_all_time=0,
                    observations_in_window=0)}
    out = await tw.query_window(
        _db, identity=identity, time_start=time_start, time_end=time_end,
        lane_start=max(0, lane_start), lane_end=max(1, lane_end),
        cursor=cursor, limit=limit, kinds=kinds, q=q,
        dispositions=dispositions, hist_day=hist_day)
    ep = await _db["edr_endpoints"].find_one(
        {"$or": [{"endpoint_id": endpoint_id},
                 {"device_iid": identity.get("device_iid")},
                 {"hostname": identity.get("hostname")}]},
        {"_id": 0})
    out["epistemic_state"] = tw.empty_state(
        identity=identity,
        enrolled=bool(ep and ep.get("enrollment_state") == "ENROLLED"),
        observations_all_time=out["observations_all_time"],
        observations_in_window=out["matched_in_window"])
    out["computer"] = _computer_header(identity, ep, out)
    return out


def _computer_header(identity: Dict[str, Any], ep: Optional[Dict[str, Any]],
                     out: Dict[str, Any]) -> Dict[str, Any]:
    """The AMP-equivalent computer summary, from persisted fields only.

    Every field NivXForge does not collect is returned as an explicit
    ``NOT_COLLECTED`` rather than an empty string, so the header can
    never read as "no groups" when the truth is "groups are not a
    concept this sensor reports".
    """
    ep = ep or {}
    NC = {"state": "NOT_COLLECTED",
          "reason": "not reported by the NivXForge Linux sensor"}
    return {
        "hostname": identity.get("hostname"),
        "device_iid": identity.get("device_iid"),
        "identity_confidence": identity.get("identity_confidence"),
        "operating_system": ep.get("platform") or NC,
        "connector_version": ep.get("sensor_version") or NC,
        "enrollment_state": ep.get("enrollment_state") or "NOT_ENROLLED",
        "sensor_state": ep.get("sensor_state") or NC,
        "last_telemetry_at": ep.get("last_telemetry_at")
        or out["time_range"].get("observed_end"),
        "endpoint_id": ep.get("endpoint_id") or NC,
        "tenant": ep.get("tenant_id") or identity.get("tenant") or NC,
        "group": NC,
        "policy": NC,
        "definitions_version": NC,
        "internal_ip": NC,
        "external_ip": NC,
        "observations_all_time": out.get("observations_all_time"),
        "first_observed": out["time_range"].get("observed_start"),
        "last_observed": out["time_range"].get("observed_end"),
        "lane_total": out["lane_axis"].get("total_lanes"),
        "group_counts": out["lane_axis"].get("group_counts"),
    }


@router.get("/device-trajectory")
async def get_device_trajectory(
    device: str,
    hours: int = 24,
    all_time: bool = False,
    user=Depends(get_current_user),
):
    """Return a device-scoped trajectory aggregation for the XDR
    3-pane canvas.  Aggregates, in this order of authority:

      1. IRG observations resolved via ``event.device_iid`` (the only
         substrate that carries a real device identity).
      2. Detection markers derived from Stage-2 evidence (per incident).
      3. Activity nodes derived from the canonical ActivityInventory.

    ``device`` accepts an authoritative ``device_iid`` or a hostname;
    hostname matching is case-insensitive and the resolved identity is
    reported back so the UI can mark it INFERRED.
    """
    if not device:
        raise HTTPException(status_code=400,
                              detail={"error": "device_required"})
    if hours <= 0 or hours > 24 * 365:
        hours = 24
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    since_iso = None if all_time else since.isoformat()

    cross_tenant = _is_cross_tenant(user)
    identity = dir_svc.resolve(device, cross_tenant)

    events: List[Dict[str, Any]] = []
    lane_counts: Dict[str, int] = {k: 0 for k in _LANE_ORDER}
    incident_index: Dict[str, Dict[str, Any]] = {}

    # 1) IRG observations — authoritative device identity.
    for obs in dir_svc.observations(device, cross_tenant, since_iso,
                                     identity=identity):
        lane_counts[obs["lane"]] = lane_counts.get(obs["lane"], 0) + 1
        events.append(obs)
        cid = obs.get("incident_id")
        if cid and cid not in incident_index:
            incident_index[cid] = {"incident_id": cid, "name": cid,
                                    "verdict": "unknown", "risk": None,
                                    "source": "v2_shadow_observations"}

    # 2/3) Case-derived detections + activity, matched on hostname.
    q = _case_scope(user)
    docs: List[Dict[str, Any]] = []
    if q is not None:
        host_needle = (identity or {}).get("hostname") or device
        host_needle = str(host_needle).strip().lower()
        for d in _col.find(q, {"_id": 0}):
            h = _extract_host(d)
            if h and h.strip().lower() == host_needle:
                docs.append(d)
    for d in docs:
        case_id = d.get("id")
        incident_index[case_id] = {
            "incident_id": case_id,
            "name":        d.get("name"),
            "verdict":     ((d.get("verdict_stage2") or {}).get("label") or "unknown"),
            "risk":        (d.get("verdict_stage2") or {}).get("risk_score"),
            "created_at":  d.get("created_at"),
            "updated_at":  d.get("updated_at"),
        }
        # 1) Detection markers (from Stage-2 evidence)
        for det in _project_detections(d):
            ts = det.get("timestamp")
            if not ts or (since_iso and ts < since_iso):
                continue
            lane = _map_lane_from_rule(det.get("rule_id") or "")
            lane_counts[lane] = lane_counts.get(lane, 0) + 1
            events.append({
                "id":           det.get("detection_id"),
                "kind":         "detection",
                "lane":         lane,
                "timestamp":    ts,
                "title":        det.get("detection") or det.get("rule_id"),
                "severity":     det.get("severity") or "info",
                "detected_by":  det.get("detected_by"),
                "rule_id":      det.get("rule_id"),
                "process":      det.get("process"),
                "file":         det.get("file"),
                "user":         det.get("user"),
                "device":       det.get("device") or device,
                "incident_id":  case_id,
                "disposition":  det.get("disposition"),
            })

        # 2) Activity nodes (from the canonical ActivityInventory)
        ssot = d.get("ssot") or {}
        timeline = None
        if isinstance(ssot, dict):
            timeline = ssot.get("timeline") or ssot.get("canonical_timeline")
        if not (isinstance(timeline, dict) and timeline.get("events")):
            continue
        try:
            inv = build_inventory(case_id=case_id,
                                     tenant_id=d.get("tenant_id") or d.get("user_email"),
                                     timeline=timeline)
        except Exception:
            continue
        d_inv = inv.to_dict()
        for kind, entities in ((d_inv.get("entities") or {}).items()):
            lane = _map_lane_from_entity(kind)
            for ent in entities:
                first = ent.get("first_seen")
                if not first or (since_iso and first < since_iso):
                    continue
                lane_counts[lane] = lane_counts.get(lane, 0) + 1
                # HONEST STATE: only a PROCESS entity may populate the
                # `process` field.  Falling back to `name` for a network
                # / file / registry entity put a remote endpoint into
                # the process lane, so the Device Trajectory rendered an
                # IP address as if it were a running process.
                is_process = (kind or "").lower() == "process"
                entity_name = (ent.get("name") or ent.get("process")
                               or ent.get("file") or ent.get("host") or kind)
                events.append({
                    "id":           f"{case_id}::{kind}::{ent.get('entity_id')}",
                    "kind":         "activity",
                    "entity_kind":  kind,
                    "lane":         lane,
                    "timestamp":    first,
                    "last_seen":    ent.get("last_seen"),
                    "title":        entity_name,
                    "severity":     "info",
                    "process":      (ent.get("process") or ent.get("name")
                                     if is_process else None),
                    "process_state": "OBSERVED" if is_process else "UNKNOWN",
                    "file":         ent.get("file") or ent.get("path"),
                    "target":       entity_name if not is_process else None,
                    "user":         ent.get("user"),
                    "command_line": ent.get("command_line"),
                    "path":         ent.get("path"),
                    "device":       ent.get("host") or device,
                    "parent_id":    ent.get("parent_entity_id"),
                    "child_ids":    ent.get("child_entity_ids") or [],
                    "incident_id":  case_id,
                })

    events.sort(key=lambda e: str(e.get("timestamp") or ""))

    if identity is None and not docs:
        # Distinguish the three ways a reference can fail to resolve. An
        # operator seeing an empty canvas must be able to tell "we have
        # never heard from this endpoint" from "this endpoint is revoked"
        # from "that reference is not an endpoint at all".
        reason = "identity_unresolved"
        if str(device).startswith("ep_"):
            row = sync_collection("edr_endpoints").find_one(
                {"endpoint_id": str(device).strip()},
                {"_id": 0, "enrollment_state": 1}) or {}
            if not row:
                reason = "identity_unresolved_endpoint_not_enrolled"
            elif row.get("enrollment_state") == "REVOKED":
                reason = "identity_unresolved_endpoint_enrolment_revoked"
            else:
                reason = "identity_unresolved_endpoint_never_reported"
    elif not events:
        reason = "no_matching_evidence"
    else:
        reason = "ok"

    # Honest window hint: the analyst must be able to tell "nothing
    # happened in this window" apart from "nothing was ever observed".
    observed_first = (identity or {}).get("first_seen")
    observed_last = (identity or {}).get("last_seen")

    return {
        "device":       device,
        "identity": {
            "resolved":            identity is not None,
            "device_iid":          (identity or {}).get("device_iid"),
            "hostname":            (identity or {}).get("hostname"),
            "identity_confidence": (identity or {}).get("identity_confidence"),
            # Which reference actually resolved, and the authoritative
            # platform-minted endpoint_id when the pivot came from it.
            "resolved_via":        (identity or {}).get("resolved_via"),
            "endpoint_id":         (identity or {}).get("endpoint_id"),
            "observation_count":   (identity or {}).get("observation_count", 0),
            "observed_first_seen": observed_first,
            "observed_last_seen":  observed_last,
            # Incidents actually promoted from this endpoint's
            # observations.  Surfaced so the endpoint header can offer a
            # real pivot instead of an action that can never enable.
            "case_ids":            list((identity or {}).get("case_ids") or []),
            "incident_count":      len((identity or {}).get("case_ids") or []),
            "latest_incident_id":  ((identity or {}).get("case_ids") or [None])[0],
            "users":               list((identity or {}).get("users") or []),
            "provenance":          list((identity or {}).get("provenance") or []),
            "health":              resolve_endpoint_health(
                                       agent=None,
                                       last_telemetry_at=observed_last,
                                       observation_count=int(
                                           (identity or {}).get(
                                               "observation_count") or 0)),
        },
        "window_hours": None if all_time else hours,
        "all_time":     all_time,
        "window_start": (since_iso if not all_time
                          else (str(events[0].get("timestamp")) if events else None)),
        "window_end":   now.isoformat(),
        "events":       events,
        "lane_counts":  lane_counts,
        "lanes":        list(_LANE_ORDER),
        "incidents":    list(incident_index.values()),
        "reason":       reason,
        "source":       "v2_shadow_observations · workspace_cases.verdict_stage2.evidence[] · services.activity.ActivityInventory",
        "note":         "Read-only aggregation. No native trajectory store."
                            if events else
                        ("No endpoint identity could be resolved for this reference."
                         if identity is None
                         else "No observations for this device in the selected window."),
    }


# ═══════════════════════════════════════════════════════════════════
# ENTRY CONTEXT  ·  P0-F.13.3
#
# There are two legitimate ways into the NivXForge EDR plane and they
# are NOT the same thing:
#
#   DIRECT_EDR  — the analyst signed into the EDR plane. Tenant context
#                 is whatever the principal is authorised for.
#   XDR_PIVOT   — the analyst arrived from an XDR incident. Tenant is
#                 INHERITED from that incident, and the investigation
#                 context travels with the view.
#
# Tenant context answers WHO OWNS THE DATA. Investigation context
# answers WHY THE ANALYST IS HERE. They are reported separately and the
# server never accepts either of them from the browser: the client may
# name an incident, the server decides whether it may be seen and what
# it actually references.
# ═══════════════════════════════════════════════════════════════════
@router.get("/context")
async def edr_entry_context(endpoint_id: Optional[str] = None,
                            incident_id: Optional[str] = None,
                            user=Depends(get_current_user)) -> Dict[str, Any]:
    from services.session_context import authorised_incident, tenant_context

    errors: List[str] = []
    investigation: Optional[Dict[str, Any]] = None
    inherited: Optional[str] = None

    identity = (dir_svc.resolve(endpoint_id, _is_cross_tenant(user))
                if endpoint_id else None)

    if incident_id:
        got = authorised_incident(incident_id, (user or {}).get("email"))
        if got["state"] != "AUTHORIZED":
            errors.append(got["state"])
        else:
            doc = got["doc"]
            inherited = got["tenant"]
            camp = doc.get("endpoint_campaign") or {}
            inc_host = camp.get("hostname")
            host = (identity or {}).get("hostname")
            if not endpoint_id:
                ref_state = "ENDPOINT_NOT_REQUESTED"
            elif identity is None:
                ref_state = "ENDPOINT_UNRESOLVED"
            elif not inc_host:
                ref_state = "INCIDENT_CARRIES_NO_ENDPOINT_REFERENCE"
            elif str(inc_host) == str(host):
                ref_state = "REFERENCES_THIS_ENDPOINT"
            else:
                ref_state = "ENDPOINT_NOT_REFERENCED_BY_INCIDENT"

            dets = [d for d in (camp.get("detections") or [])
                    if isinstance(d, dict)]
            investigation = {
                "incident_id":     doc.get("id"),
                "incident_number": doc.get("incident_number"),
                "title":           doc.get("title") or None,
                "tenant_id":       inherited,
                "state":           doc.get("incident_state"),
                "priority":        doc.get("incident_priority"),
                "verdict":         ((doc.get("verdict_stage2") or {})
                                    .get("label")
                                    or (doc.get("verdict_card") or {})
                                    .get("label")),
                "endpoint_reference": {
                    "state":    ref_state,
                    "basis":    "workspace_cases.endpoint_campaign.hostname",
                    "incident_endpoint_id": camp.get("endpoint_id"),
                    "incident_hostname":    inc_host,
                    "resolved_hostname":    (identity or {}).get("hostname"),
                },
                "detection_window": {
                    "first_activity_at": camp.get("first_activity_at"),
                    "last_activity_at":  camp.get("last_activity_at"),
                },
                "detection_raw_event_ids": [d.get("raw_event_id")
                                            for d in dets
                                            if d.get("raw_event_id")],
                "detection_count": len(dets),
                "rule_ids": list(camp.get("rule_ids") or []),
                "href": f"/xdr/incidents/{doc.get('id')}",
            }

    ctx = tenant_context((user or {}).get("email"), inherited_tenant=inherited)
    ctx.update({
        "engine_id": "nivxray::edr_plane::entry_context",
        "entry_context": "XDR_PIVOT" if investigation else "DIRECT_EDR",
        "endpoint": ({"endpoint_id": endpoint_id,
                      "device_iid": (identity or {}).get("device_iid"),
                      "hostname": (identity or {}).get("hostname"),
                      "identity_confidence":
                          (identity or {}).get("identity_confidence"),
                      "state": "RESOLVED" if identity else "UNRESOLVED"}
                     if endpoint_id else None),
        "investigation": investigation,
        "tenant_switch_policy": (
            "Switching customer while an investigation context is held "
            "would create an invalid state (tenant B + incident from "
            "tenant A). The investigation context must be left first."
            if investigation else
            "Customer switching is permitted for the authorised tenants."),
        "errors": errors,
    })
    return ctx



def _ms_iso(ms: int) -> str:
    from datetime import datetime, timezone
    return (datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
            .isoformat().replace("+00:00", "Z"))

# ═══════════════════════════════════════════════════════════════════
# DETECTION HANDOFF  ·  P0-F.13.5
#
# Cisco-observable behaviour, implemented independently: opening the
# Device Trajectory from a detection must land on the EXACT observation
# that produced it — not merely on the right machine.
#
# Resolution is by stable identifier only. Hostname, process name, pid
# and timestamp proximity are NOT resolution keys here; if the exact
# identifier cannot be found, this endpoint says so and the trajectory
# refuses to pretend.
# ═══════════════════════════════════════════════════════════════════
@router.get("/endpoints/{endpoint_id}/trajectory/focus")
async def trajectory_focus(endpoint_id: str,
                           raw_event_id: Optional[str] = None,
                           canonical_event_id: Optional[str] = None,
                           event_iid: Optional[str] = None,
                           detection_id: Optional[str] = None,
                           incident_id: Optional[str] = None,
                           user=Depends(get_current_user)) -> Dict[str, Any]:
    from services.session_context import authorised_incident
    from deps import db as _db
    from edr_plane import trajectory_window as tw


    scope = _is_cross_tenant(user)
    identity = dir_svc.resolve(endpoint_id, scope)
    if not identity:
        return {"engine_id": "nivxray::edr_plane::trajectory_focus",
                "state": "ENDPOINT_NOT_RESOLVED",
                "reason": ("no endpoint you are authorised for resolves "
                           "to this reference"),
                "focus": None}

    wanted_raw = {raw_event_id} if raw_event_id else set()
    wanted_cev = {canonical_event_id} if canonical_event_id else set()
    rule_ids: List[str] = []
    inc_id = incident_id

    # A detection_id from the XDR case surface is `case::rule::RULE`.
    # The case's endpoint_campaign is the only place that carries the
    # authoritative raw/canonical event ids for its detections.
    if detection_id and "::rule::" in detection_id:
        case_id, _, rule = detection_id.partition("::rule::")
        inc_id = inc_id or case_id
        rule_ids = [rule]
    if inc_id:
        got = authorised_incident(inc_id, (user or {}).get("email"))
        if got["state"] != "AUTHORIZED":
            return {"engine_id": "nivxray::edr_plane::trajectory_focus",
                    "state": got["state"], "focus": None,
                    "reason": "the incident is not within your tenant scope"}
        camp = (got["doc"].get("endpoint_campaign") or {})
        for d in (camp.get("detections") or []):
            if not isinstance(d, dict):
                continue
            if rule_ids and not (set(d.get("rule_ids") or []) & set(rule_ids)):
                continue
            if d.get("raw_event_id"):
                wanted_raw.add(d["raw_event_id"])
            if d.get("canonical_event_id"):
                wanted_cev.add(d["canonical_event_id"])

    if not (wanted_raw or wanted_cev or event_iid):
        return {"engine_id": "nivxray::edr_plane::trajectory_focus",
                "state": "NO_IDENTIFIER_SUPPLIED", "focus": None,
                "reason": ("supply raw_event_id, canonical_event_id, "
                           "event_iid or detection_id — this surface does "
                           "not guess from a timestamp")}

    # The window projection is paged; follow the cursor rather than
    # asking for an unbounded read, so a detection late in the corpus is
    # still found.
    hit = None
    cursor = None
    searched = 0
    pages = 0
    MAX_PAGES = 8
    for _ in range(MAX_PAGES):
        out = await tw.query_window(
            _db, identity=identity, time_start=None, time_end=None,
            lane_start=0, lane_end=100000, cursor=cursor, limit=4000)
        page = out.get("events") or []
        searched += len(page)
        pages += 1
        for e in page:
            prov = e.get("provenance") or {}
            if (event_iid and e.get("event_iid") == event_iid) \
               or (prov.get("raw_event_id") in wanted_raw) \
               or (prov.get("canonical_event_id") in wanted_cev):
                hit = e
                break
        # The projection returns `next_cursor` at the top level. Reading
        # it from a nested "page" object silently stopped the search at
        # the FIRST 4000 observations and then reported an honest-looking
        # but WRONG "missing link" for every detection later in the
        # corpus. The search state is now reported so a regression of
        # exactly that shape is visible to the analyst.
        cursor = out.get("next_cursor")
        if hit or not cursor:
            break

    # What the pivot must carry through, so the EDR surface never has to
    # re-derive the XDR context from the URL.
    context = {
        "endpoint_id": endpoint_id,
        "device_iid": identity.get("device_iid"),
        "tenant_id": identity.get("tenant_id"),
        "tenant_attribution": identity.get("tenant_attribution"),
        "organization_id": identity.get("organization_id"),
        "incident_id": inc_id,
        "detection_id": detection_id,
        "rule_ids": rule_ids,
    }
    search = {
        "identities_searched": {
            "raw_event_ids": sorted(wanted_raw),
            "canonical_event_ids": sorted(wanted_cev),
            "event_iid": event_iid},
        "observations_examined": searched,
        "pages_searched": pages,
        "page_size": 4000,
        "cursor_state": ("EXHAUSTED_SEARCH_COMPLETED" if not cursor
                         else ("STOPPED_ON_MATCH" if hit
                               else f"PAGE_BUDGET_REACHED_{MAX_PAGES}")),
        "basis": ("counts of observations actually examined by this "
                  "resolver — diagnostic only, never evidence that the "
                  "requested observation exists"),
    }

    if not hit:
        return {
            "engine_id": "nivxray::edr_plane::trajectory_focus",
            "state": "OBSERVATION_NOT_RESOLVED",
            "focus": None,
            "searched": search["identities_searched"],
            "search": search,
            "context": context,
            "endpoint": {"endpoint_id": endpoint_id,
                         "device_iid": identity.get("device_iid"),
                         "hostname": identity.get("hostname")},
            "observations_searched": searched,
            "resolution_reason": ("no observation examined on this "
                                  "endpoint carries the requested "
                                  "identifier"),
            "missing_link": (
                "no observation on this endpoint carries the requested "
                "identifier. This surface will not substitute hostname, "
                "process-name or timestamp proximity for an exact "
                "identifier match, so nothing is focused."),
        }

    ts = hit.get("timestamp")
    ms = None
    try:
        from datetime import datetime
        ms = int(datetime.fromisoformat(str(ts)).timestamp() * 1000)
    except Exception:                                       # noqa: BLE001
        ms = None
    half = 30 * 60 * 1000
    return {
        "engine_id": "nivxray::edr_plane::trajectory_focus",
        "state": "FOCUS_RESOLVED",
        "endpoint": {"endpoint_id": endpoint_id,
                     "device_iid": identity.get("device_iid"),
                     "hostname": identity.get("hostname")},
        "context": context,
        "search": search,
        "focus": {
            "event_iid":     hit.get("event_iid"),
            "timestamp":     ts,
            "event_type":    hit.get("event_type"),
            "is_detection":  bool(hit.get("is_detection")),
            "disposition":   hit.get("disposition"),
            "detection":     hit.get("detection"),
            "assessment_state": hit.get("assessment_state"),
            "process_iid":   hit.get("process_iid"),
            "lane_index":    hit.get("lane_index"),
            "lane_id":       hit.get("lane_id"),
            "provenance":    hit.get("provenance"),
            "window": ({"time_start": _ms_iso(ms - half),
                        "time_end":   _ms_iso(ms + half)}
                       if ms is not None else None),
        },
        "resolved_by": ("event_iid" if event_iid and
                        hit.get("event_iid") == event_iid
                        else "provenance identifier"),
        "note": ("exact identifier match over the canonical projection — "
                 "no hostname, process-name or timestamp inference"),
    }
