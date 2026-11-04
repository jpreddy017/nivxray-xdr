"""Round 38.1 · Canonical ATT&CK evidence REST API.

    GET /api/incidents/{id}/attack-evidence

Returns the single ATT&CK evidence contract that MITRE, Attack Story,
Attack Graph and the Report generator all MUST consume.
"""
from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter

from services.attack_evidence import compose_attack_evidence
from deps import db

router = APIRouter(prefix="/incidents", tags=["attack-evidence"])


@router.get("/{incident_id}/attack-evidence")
async def get_attack_evidence(incident_id: str) -> Dict[str, Any]:
    return await compose_attack_evidence(db, incident_id)
