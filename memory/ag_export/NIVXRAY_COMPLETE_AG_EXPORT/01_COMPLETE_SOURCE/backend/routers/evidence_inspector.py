"""Round 38.3 · Shared Evidence Inspector REST API."""
from __future__ import annotations
from fastapi import APIRouter

from services.evidence_inspector import resolve
from deps import db

router = APIRouter(prefix="/incidents", tags=["evidence-inspector"])


@router.get("/{incident_id}/inspector/{kind}/{ref_id:path}")
async def get_inspector(incident_id: str, kind: str, ref_id: str):
    """Resolve any canonical object into the shared inspector envelope.

    ``ref_id`` may contain slashes (e.g., a path or nested id) — the
    ``:path`` converter passes it through unchanged.
    """
    return await resolve(db, incident_id, kind, ref_id)
