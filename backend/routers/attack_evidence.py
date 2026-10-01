"""Round 38.1 · Canonical ATT&CK evidence REST API.

    GET /api/incidents/{id}/attack-evidence

Returns the single ATT&CK evidence contract that MITRE, Attack Story,
Attack Graph and the Report generator all MUST consume.

S1 (2026-06-21) · this router carried NO authentication dependency and no
tenant predicate — the same defect class as the five sub-resources named in
the consolidation inventory. It now resolves the incident through the ONE
incident authority first.
"""
from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter, Depends

from services.attack_evidence import compose_attack_evidence
from deps import db, get_current_user
from routers.incidents import authorized_incident

router = APIRouter(prefix="/incidents", tags=["attack-evidence"])


@router.get("/{incident_id}/attack-evidence")
async def get_attack_evidence(incident_id: str,
                              user=Depends(get_current_user)) -> Dict[str, Any]:
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    return await compose_attack_evidence(db, incident_id)
