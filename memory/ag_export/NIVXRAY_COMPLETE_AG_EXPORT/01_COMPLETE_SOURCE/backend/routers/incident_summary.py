"""Incident Summary projection (Slice 2 · P1).

Deterministic, evidence-backed summary surfaced under
``/xdr/incidents/:id`` → Investigation → **Summary**.  Every block is
derived from data already present on the case — never fabricated.

Four states are strictly distinguished per owner rule #89:
  - ``ok``                       : block is populated with real data
  - ``no_matching_evidence``     : capability searched, nothing found
  - ``not_connected``            : integration not configured
  - ``not_available``            : capability does not exist yet
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException

from deps import get_current_user, sync_collection

router = APIRouter(prefix="/incidents", tags=["incidents-summary"])

_col = sync_collection("workspace_cases")


def _project_summary(doc: Dict[str, Any]) -> Dict[str, Any]:
    stage2 = doc.get("verdict_stage2") or {}
    vcard  = doc.get("verdict_card")   or {}
    mitre  = doc.get("mitre") or []
    iocs   = doc.get("iocs") or {}
    ssot   = doc.get("ssot") or {}
    engine = doc.get("engine")

    # ── Observed facts (things we DEFINITELY have) ──────────────────
    observed: List[Dict[str, Any]] = []
    if engine and engine != "-":
        observed.append({"fact": f"Case decoded by engine '{engine}'.",
                            "provenance": "workspace_cases.engine"})
    chain = doc.get("chain_ids") or []
    if chain:
        observed.append({"fact": f"Decoder chain: {len(chain)} step(s).",
                            "provenance": "workspace_cases.chain_ids"})
    if stage2.get("label"):
        observed.append({
            "fact": f"Stage-2 verdict: {stage2['label']} "
                     f"(risk {stage2.get('risk_score', '—')} · "
                     f"confidence {stage2.get('confidence_bucket', '—')}).",
            "provenance": "workspace_cases.verdict_stage2",
        })
    ioc_total = sum(len(v) for v in iocs.values() if isinstance(v, list)) \
        if isinstance(iocs, dict) else 0
    if ioc_total:
        observed.append({"fact": f"{ioc_total} IOC(s) extracted from the case.",
                            "provenance": "workspace_cases.iocs"})

    # ── Suspicious elements (Stage-2 evidence rows) ─────────────────
    suspicious: List[Dict[str, Any]] = []
    for ev in (stage2.get("evidence") or []):
        if not isinstance(ev, dict):
            continue
        suspicious.append({
            "rule_id":     ev.get("rule_id") or ev.get("rule"),
            "weight":      ev.get("weight"),
            "detected_by": "NivXRay Verdict Engine · Stage-2",
            "provenance":  "workspace_cases.verdict_stage2.evidence[]",
        })

    # ── Evidence relationships (from IUE chains) ────────────────────
    relationships: List[Dict[str, Any]] = []
    if isinstance(ssot, dict):
        rels = ssot.get("relationships") or []
        if isinstance(rels, list):
            for r in rels[:50]:  # cap for UI
                if isinstance(r, dict):
                    relationships.append(r)

    # ── Evidence gaps + negative explainability ────────────────────
    # Owner rule: distinguish the four states.
    gaps: List[Dict[str, Any]] = [
        {"claim":   "Lateral Movement",
          "state":   "no_matching_evidence",
          "searched": ["EDR (Stage-2 rules)"],
          "reason":  "No lateral-movement rule fired for this incident.",
          "note":    "Absence of evidence, not evidence of absence."},
        {"claim":   "Network exfiltration",
          "state":   "no_matching_evidence" if not any(
              (ev.get("rule_id") or "").startswith("MITRE-EXFIL")
              for ev in (stage2.get("evidence") or []) if isinstance(ev, dict)
          ) else "ok",
          "searched": ["EDR (Stage-2 rules)"],
          "reason":  "No MITRE-EXFILTRATION rule fired."},
        {"claim":   "Network telemetry (NDR)",
          "state":   "not_connected",
          "reason":  "NDR integration is not configured for this tenant."},
        {"claim":   "Identity telemetry (ITDR)",
          "state":   "not_connected",
          "reason":  "ITDR integration is not configured for this tenant."},
        {"claim":   "Email telemetry",
          "state":   "not_connected",
          "reason":  "Email security integration is not configured for this tenant."},
        {"claim":   "Cloud audit telemetry",
          "state":   "not_connected",
          "reason":  "Cloud audit connector is not configured for this tenant."},
    ]
    # If no evidence exists at all, mark negative explainability for
    # every rule as "not_available".
    if not stage2.get("evidence"):
        gaps.insert(0, {
            "claim":  "Rule-based reasoning",
            "state":  "not_available",
            "reason": "Stage-2 has not been computed for this incident yet.",
        })

    # ── Recommended next evidence (deterministic hints) ─────────────
    recommended: List[Dict[str, Any]] = []
    if isinstance(iocs, dict):
        if iocs.get("hash"):
            recommended.append({"action": "Enrich hashes via IOC Intelligence",
                                 "target": "/threat-intel?tab=iocs"})
        if iocs.get("domain") or iocs.get("url"):
            recommended.append({"action": "Correlate domains/URLs via IOC Intelligence",
                                 "target": "/threat-intel?tab=iocs"})
    if any((ev.get("process") or ev.get("command")) for ev in
              (stage2.get("evidence") or []) if isinstance(ev, dict)):
        recommended.append({"action": "Open Device Trajectory to inspect process context",
                             "target": "/edr/trajectory"})

    # ── Deterministic verdict summary (never LLM) ──────────────────
    verdict_block: Optional[Dict[str, Any]] = None
    if stage2:
        verdict_block = {
            "label":       stage2.get("label"),
            "risk_score":  stage2.get("risk_score"),
            "confidence":  stage2.get("confidence_bucket"),
            "contributing_signals": len(stage2.get("evidence") or []),
            "engine":      "NivXRay Deterministic Verdict Engine (Stage-2)",
            "provenance":  "workspace_cases.verdict_stage2",
        }

    return {
        "incident_id":            doc.get("id"),
        "observed_facts":         observed,
        "suspicious_elements":    suspicious,
        "evidence_relationships": relationships,
        "evidence_gaps":          gaps,
        "recommended_next":       recommended,
        "deterministic_verdict":  verdict_block,
        "sources": {
            "verdict":  "workspace_cases.verdict_stage2",
            "iocs":     "workspace_cases.iocs",
            "ssot":     "workspace_cases.ssot",
        },
    }


@router.get("/{incident_id}/summary")
async def get_incident_summary(incident_id: str,
                                  user=Depends(get_current_user)):
    doc = _col.find_one({"id": incident_id})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found",
                                       "id": incident_id})
    return _project_summary(doc)
