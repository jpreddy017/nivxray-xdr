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

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user, db
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
        "fallback_chain":  list(result.fallback_chain),
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
# Phase-1 proof surface — Incident Overview Executive Summary.
# --------------------------------------------------------------------
@router.get("/narration/incident/{incident_id}/executive-summary")
async def incident_executive_summary(
    incident_id: str,
    user = Depends(get_current_user),
):
    """Build a governed NarrationContext for the incident, then
    route through the Narration Gateway.  All governed truth is
    read from `workspace_cases` — the LLM never gets to invent
    an evidence id, finding id, technique id, entity, verdict,
    severity or confidence."""
    inc = await db["workspace_cases"].find_one(
        {"id": incident_id}, {"_id": 0})
    if not inc:
        raise HTTPException(status_code=404,
                            detail=f"incident {incident_id} not found")

    # Extract governed context — deliberately conservative.
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

    # Techniques — reuse the canonical ATT&CK evidence composer.
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

    ctx = NarrationContext(
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
            "incident_id": incident_id,
            "name":        inc.get("name"),
            "number":      inc.get("number"),
        },
    )
    result = await get_gateway().render(NarrationRequest(
        kind    = NarrationKind.EXECUTIVE_SUMMARY,
        context = ctx,
    ))
    return _serialise(result)
