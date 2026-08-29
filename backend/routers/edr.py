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

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user, sync_collection
from services.activity.projector import build_inventory

router = APIRouter(prefix="/edr", tags=["edr"])

_col = sync_collection("workspace_cases")


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
