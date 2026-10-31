"""
NivXRay XDR Narration Gateway HTTP surface.

    GET  /api/narration/providers   — list configured providers
    POST /api/narration/render      — generate a narration
    GET  /api/narration/incident/{id}/executive-summary
                                     — proof surface for Phase 1
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import get_current_user, db
from routers.xdr_rbac import _principal
from services.intelligence_policy import IntelligencePolicyService
from services.narration import (
    NarrationContext, NarrationKind, NarrationRequest,
    get_gateway,
)


router = APIRouter()


class NarrationContextIn(BaseModel):
    incident_id:   str
    evidence_ids:  list[str] = Field(default_factory=list)
    finding_ids:   list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    entities:      list[str] = Field(default_factory=list)
    verdict:       str | None = None
    severity:      str | None = None
    confidence:    float | None = None
    provenance:    list[dict[str, Any]] = Field(default_factory=list)
    composer_input: dict[str, Any] = Field(default_factory=dict)


class NarrationRenderIn(BaseModel):
    kind: str
    context: NarrationContextIn
    preferred_provider: str | None = None
    session_id: str | None = None


def _as_context(payload: NarrationContextIn) -> NarrationContext:
    return NarrationContext(
        incident_id    = payload.incident_id,
        evidence_ids   = tuple(payload.evidence_ids),
        finding_ids    = tuple(payload.finding_ids),
        technique_ids  = tuple(payload.technique_ids),
        entities       = tuple(payload.entities),
        verdict        = payload.verdict,
        severity       = payload.severity,
        confidence     = payload.confidence,
        provenance     = tuple(payload.provenance),
        composer_input = dict(payload.composer_input),
    )


def _serialise(result) -> dict[str, Any]:
    return {
        "kind":            result.kind.value,
        "text":            result.text,
        "paragraphs":      [{
            "text":          p.text,
            "evidence_ids":  list(p.evidence_ids),
            "finding_ids":   list(p.finding_ids),
            "technique_ids": list(p.technique_ids),
        } for p in result.paragraphs],
        "evidence_ids":    list(result.evidence_ids),
        "finding_ids":     list(result.finding_ids),
        "technique_ids":   list(result.technique_ids),
        "entities":        list(result.entities),
        "verdict":         result.verdict,
        "severity":        result.severity,
        "confidence":      result.confidence,
        "provenance":      list(result.provenance),
        "generation_mode": result.generation_mode.value,
        "provider":        result.provider,
        "provider_priority": list(result.fallback_chain),   # semantic alias
        "fallback_chain":  list(result.fallback_chain),     # legacy alias
        "grounded":        result.grounded,
        "caveats":         list(result.caveats),
    }


@router.get("/narration/providers")
async def list_providers(user = Depends(get_current_user)):
    return get_gateway().describe()


@router.post("/narration/render")
async def render_narration(payload: NarrationRenderIn,
                                             user = Depends(get_current_user)):
    try:
        kind = NarrationKind(payload.kind)
    except ValueError:
        raise HTTPException(status_code=400,
                            detail=f"unknown narration kind: {payload.kind!r}")
    result = await get_gateway().render(NarrationRequest(
        kind               = kind,
        context            = _as_context(payload.context),
        preferred_provider = payload.preferred_provider,
        session_id         = payload.session_id,
    ))
    return _serialise(result)


# --------------------------------------------------------------------
# Consumer-shared: build a governed NarrationContext for one
# incident.  Used by every Gateway-backed endpoint below so all
# consumers see IDENTICAL governed facts — providers only differ
# in wording.
# --------------------------------------------------------------------
async def _build_incident_context(incident_id: str) -> NarrationContext:
    inc = await db["workspace_cases"].find_one(
        {"id": incident_id}, {"_id": 0})
    if not inc:
        raise HTTPException(status_code=404,
                            detail=f"incident {incident_id} not found")

    v_raw = inc.get("verdict")
    if isinstance(v_raw, dict):
        verdict = v_raw.get("classification") or v_raw.get("verdict")
    else:
        verdict = v_raw
    verdict = verdict or inc.get("classification") or None

    prio = inc.get("priority")
    if isinstance(prio, dict):
        severity = prio.get("code")
    else:
        severity = prio
    severity = severity or inc.get("severity") or None

    confidence = None
    try:
        v2 = inc.get("verdict_stage2") or {}
        conf_raw = v2.get("confidence") if isinstance(v2, dict) else None
        if conf_raw is None and isinstance(v_raw, dict):
            conf_raw = v_raw.get("confidence")
        confidence = float(conf_raw) if conf_raw is not None else None
    except (TypeError, ValueError):
        confidence = None

    ev_ids: list[str] = []
    for e in inc.get("evidence") or []:
        if not isinstance(e, dict):
            continue
        eid = e.get("evidence_id") or e.get("id")
        if eid:
            ev_ids.append(str(eid))
    for e in ((inc.get("verdict_stage2") or {}).get("evidence") or []):
        if not isinstance(e, dict):
            continue
        eid = e.get("evidence_id") or e.get("id")
        if eid:
            ev_ids.append(str(eid))

    from services.attack_evidence import compose_attack_evidence
    ae = await compose_attack_evidence(db, incident_id)
    technique_ids = [t.get("technique_id") for t in ae.get("techniques") or []
                                    if isinstance(t, dict) and t.get("technique_id")]

    entities: list[str] = []
    for e in inc.get("entities") or []:
        if isinstance(e, dict):
            val = e.get("value") or e.get("id") or e.get("name")
        else:
            val = e
        if val:
            entities.append(str(val))

    # Phase-2 · Cognis cross-lane extension.  If the incident
    # carries CanonicalEvent-shaped rows from Identity or Cloud
    # lanes, feed their canonical_ids as governed evidence.
    # Cognis then reasons across Endpoint + Identity + Cloud in
    # one narration.  We NEVER let Cognis promote a technique to
    # OBSERVED because of a cross-lane hint — the grounding
    # validator still rejects any technique_id not already in
    # AttackTechniqueEvidence.
    cross_lane_ids: list[str] = []
    lanes_present: set[str] = set()
    for e in inc.get("canonical_events") or []:
        if not isinstance(e, dict):
            continue
        cid = e.get("canonical_id")
        sk  = e.get("source_kind")
        if cid:
            cross_lane_ids.append(str(cid))
            ev_ids.append(str(cid))     # allow grounding validator to accept
        if sk:
            lanes_present.add(str(sk))

    return NarrationContext(
        incident_id    = incident_id,
        evidence_ids   = tuple(dict.fromkeys(ev_ids)),
        finding_ids    = (),
        technique_ids  = tuple(dict.fromkeys(technique_ids)),
        entities       = tuple(dict.fromkeys(entities)),
        verdict        = verdict,
        severity       = severity,
        confidence     = confidence,
        provenance     = (
            {"source": "workspace_cases", "field": "verdict"},
            {"source": "AttackTechniqueEvidence",
                "field": f"incident:{incident_id}"},
        ),
        composer_input = {
            "incident_id":   incident_id,
            "name":          inc.get("name"),
            "number":        inc.get("number"),
            "cross_lane": {
                "lanes":            sorted(lanes_present),
                "cross_lane_ids":   cross_lane_ids,
            },
        },
    )


# --------------------------------------------------------------------
# Phase-1 proof surface — Incident Overview Executive Summary.
# --------------------------------------------------------------------
async def _incident_policy_snapshot(request, incident_id: str) -> dict:
    """Capture the effective NivXRay XDR Intelligence policy for
    the given incident at the moment this narration request STARTS.
    The gateway then honours that snapshot for the entire request
    lifetime, so an administrator toggling policy mid-flight cannot
    mutate an already-running narration (per FINAL Intelligence
    Controls spec §2)."""
    try:
        ten, _, _ = _principal(request)
        svc = IntelligencePolicyService(db)
        eff = await svc.effective_for_incident(ten, incident_id)
        return {
            "online_ai":  eff.online_ai,
            "online_llm": eff.online_llm,
            "scope":      "incident",
            "scope_id":   incident_id,
        }
    except Exception:      # policy layer must NEVER 500 narration.
        return {"online_ai": "on", "online_llm": "on",
                "scope": "fallback", "scope_id": incident_id}


@router.get("/narration/incident/{incident_id}/executive-summary")
async def incident_executive_summary(
    incident_id: str,
    request: Request,
    user = Depends(get_current_user),
):
    ctx = await _build_incident_context(incident_id)
    snap = await _incident_policy_snapshot(request, incident_id)
    result = await get_gateway().render(NarrationRequest(
        kind    = NarrationKind.EXECUTIVE_SUMMARY,
        context = ctx,
        policy_snapshot = snap,
    ))
    return _serialise(result)


# --------------------------------------------------------------------
# Phase-1.5 consumer migrations — Attack Story, R46 overlay, R48 PDF.
# All three share `_build_incident_context()` so semantic invariance
# across consumers and providers is guaranteed by construction.
# --------------------------------------------------------------------
@router.get("/narration/incident/{incident_id}/attack-story")
async def incident_attack_story(
    incident_id: str,
    request: Request,
    user = Depends(get_current_user),
):
    ctx  = await _build_incident_context(incident_id)
    snap = await _incident_policy_snapshot(request, incident_id)
    result = await get_gateway().render(NarrationRequest(
        kind    = NarrationKind.ATTACK_STORY,
        context = ctx,
        policy_snapshot = snap,
    ))
    return _serialise(result)


@router.get("/narration/incident/{incident_id}/r46-overlay-summary")
async def incident_r46_overlay_summary(
    incident_id: str,
    request: Request,
    user = Depends(get_current_user),
):
    """R46 Analyst Overlay base text.  The overlay layer edits
    *interpretation* on top of this Gateway output; it never
    mutates machine truth."""
    ctx  = await _build_incident_context(incident_id)
    snap = await _incident_policy_snapshot(request, incident_id)
    result = await get_gateway().render(NarrationRequest(
        kind    = NarrationKind.R46_OVERLAY_SUMMARY,
        context = ctx,
        policy_snapshot = snap,
    ))
    return _serialise(result)


@router.get("/narration/incident/{incident_id}/report-narration")
async def incident_report_narration(
    incident_id: str,
    request: Request,
    user = Depends(get_current_user),
):
    """R48 PDF Investigation Report narration.  The PDF composer
    owns layout; this endpoint supplies prose only, so no PDF-
    specific narration logic ever gets built."""
    ctx  = await _build_incident_context(incident_id)
    snap = await _incident_policy_snapshot(request, incident_id)
    result = await get_gateway().render(NarrationRequest(
        kind    = NarrationKind.R48_REPORT_NARRATION,
        context = ctx,
        policy_snapshot = snap,
    ))
    return _serialise(result)


@router.get("/narration/incident/{incident_id}/cross-lane-story")
async def incident_cross_lane_story(
    incident_id: str,
    request: Request,
    user = Depends(get_current_user),
):
    """Phase-2 Cognis Cross-Lane Story.

    Narrates correlated Endpoint + Identity + Cloud activity
    from the incident's canonical_events (populated by the
    Telemetry Adapter Framework).  The Gateway grounding rules
    still apply: this endpoint never promotes an ATT&CK
    technique to OBSERVED, never inflates confidence, and
    honestly narrates the coverage gap when no cross-lane
    evidence is present."""
    ctx  = await _build_incident_context(incident_id)
    snap = await _incident_policy_snapshot(request, incident_id)
    result = await get_gateway().render(NarrationRequest(
        kind    = NarrationKind.CROSS_LANE_STORY,
        context = ctx,
        policy_snapshot = snap,
    ))
    return _serialise(result)
