"""Round 38.3 · Shared Evidence Inspector REST API.

S1 (2026-06-21) · this router carried NO authentication dependency and no
tenant predicate: any caller could resolve any incident's canonical objects
(canonical events, findings, executions, mappings) by id. It now resolves the
incident through the ONE incident authority before inspecting anything.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends

from services.evidence_inspector import resolve
from deps import db, get_current_user
from routers.incidents import authorized_incident

router = APIRouter(prefix="/incidents", tags=["evidence-inspector"])


@router.get("/{incident_id}/inspector/{kind}/{ref_id:path}")
async def get_inspector(incident_id: str, kind: str, ref_id: str,
                        user=Depends(get_current_user)):
    """Resolve any canonical object into the shared inspector envelope.

    ``ref_id`` may contain slashes (e.g., a path or nested id) — the
    ``:path`` converter passes it through unchanged.
    """
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    return await resolve(db, incident_id, kind, ref_id)
