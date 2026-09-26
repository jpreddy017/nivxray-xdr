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

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user, sync_collection
from services.activity.projector import build_inventory

router = APIRouter(prefix="/edr", tags=["edr"])

_col = sync_collection("workspace_cases")


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


@router.get("/process-tree")
async def get_process_tree(incident_id: str,
                              user=Depends(get_current_user)):
    doc = _load(incident_id)
    return _project_process_tree(doc)


# ── XDR Endpoints projection (Slice 6 · read-only) ───────────────────
# Deterministic aggregation of workspace_cases by extracted host.  This
# is a pure projection — no new store, no new engine.  The XDR
# Endpoints screen consumes this list; every row's `latest_incident_id`
# points back into the existing incident record.
@router.get("/endpoints")
async def list_endpoints(user=Depends(get_current_user)):
    email = (user or {}).get("email")
    q: Dict[str, Any] = {"name": {"$exists": True, "$ne": ""}}
    if email:
        q["user_email"] = email
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

    rows = sorted(by_host.values(), key=lambda r: r.get("last_seen") or "",
                    reverse=True)
    return {
        "endpoints": rows,
        "count":     len(rows),
        "source":    "workspace_cases.ssot.investigation_object",
        "note":      "Read-only projection · endpoints are extracted from saved cases."
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


@router.get("/device-trajectory")
async def get_device_trajectory(
    device: str,
    hours: int = 24,
    user=Depends(get_current_user),
):
    """Return a device-scoped trajectory aggregation for the XDR
    3-pane canvas.  Aggregates:

      - Detection markers derived from Stage-2 evidence (per incident).
      - Activity nodes derived from the canonical ActivityInventory.

    Both are timestamped, tagged with the source incident, and mapped
    to a UI lane (system / process / file / network / registry).
    """
    if not device:
        raise HTTPException(status_code=400,
                              detail={"error": "device_required"})
    if hours <= 0 or hours > 24 * 30:
        hours = 24
    email = (user or {}).get("email")
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    since_iso = since.isoformat()

    q: Dict[str, Any] = {"name": {"$exists": True, "$ne": ""}}
    if email:
        q["user_email"] = email

    docs: List[Dict[str, Any]] = []
    for d in _col.find(q, {"_id": 0}):
        if _extract_host(d) == device:
            docs.append(d)

    events: List[Dict[str, Any]] = []
    lane_counts: Dict[str, int] = {k: 0 for k in _LANE_ORDER}
    incident_index: Dict[str, Dict[str, Any]] = {}

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
            if not ts or ts < since_iso:
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
                if not first or first < since_iso:
                    continue
                lane_counts[lane] = lane_counts.get(lane, 0) + 1
                events.append({
                    "id":           f"{case_id}::{kind}::{ent.get('entity_id')}",
                    "kind":         "activity",
                    "entity_kind":  kind,
                    "lane":         lane,
                    "timestamp":    first,
                    "last_seen":    ent.get("last_seen"),
                    "title":        ent.get("name") or ent.get("process")
                                        or ent.get("file") or ent.get("host") or kind,
                    "severity":     "info",
                    "process":      ent.get("process") or ent.get("name"),
                    "file":         ent.get("file") or ent.get("path"),
                    "user":         ent.get("user"),
                    "command_line": ent.get("command_line"),
                    "path":         ent.get("path"),
                    "device":       ent.get("host") or device,
                    "parent_id":    ent.get("parent_entity_id"),
                    "child_ids":    ent.get("child_entity_ids") or [],
                    "incident_id":  case_id,
                })

    events.sort(key=lambda e: e.get("timestamp") or "")

    if not events:
        reason = "no_matching_evidence"
    else:
        reason = "ok"

    return {
        "device":       device,
        "window_hours": hours,
        "window_start": since_iso,
        "window_end":   now.isoformat(),
        "events":       events,
        "lane_counts":  lane_counts,
        "lanes":        list(_LANE_ORDER),
        "incidents":    list(incident_index.values()),
        "reason":       reason,
        "source":       "workspace_cases.verdict_stage2.evidence[] · services.activity.ActivityInventory",
        "note":         "Read-only aggregation. No native trajectory store."
                            if events else "No trajectory evidence for this device in the selected window.",
    }
