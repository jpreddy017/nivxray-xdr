"""Round 34 · NivXRay XDR · Incident Threat Model Engine · read-only API.

Distinct from the legacy ``threat_model`` router (which parses Mermaid
threat-model diagrams).  This router exposes the Round 34
``ThreatModelService`` composer per-incident.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorClient

from deps import get_current_user, sync_collection
from routers.incidents import authorized_incident
from services.threat_model import ThreatModelService

router = APIRouter(prefix="/incidents", tags=["incident-threat-model"])
_col = sync_collection("workspace_cases")


def _new_async_client():
    return AsyncIOMotorClient(os.environ["MONGO_URL"])


@router.get("/{incident_id}/threat-model")
async def get_incident_threat_model(incident_id: str,
                                          user=Depends(get_current_user)) -> Dict[str, Any]:
    # S1 · authenticated principal → server-resolved tenant → incident.
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        return await ThreatModelService.compose(async_db, incident_id)
    finally:
        client.close()
