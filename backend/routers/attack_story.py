"""Round 33 · Attack Story · read-only API.

Consumes governed state (Round 30 IUE + Round 31 investigation +
Round 32 findings ledger).  Never writes.  Never fabricates.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient

from deps import get_current_user, sync_collection
from routers.incidents import authorized_incident
from services.attack_story import AttackStoryService

router = APIRouter(prefix="/incidents", tags=["attack-story"])
_col = sync_collection("workspace_cases")


def _new_async_client():
    return AsyncIOMotorClient(os.environ["MONGO_URL"])


@router.get("/{incident_id}/attack-story")
async def get_attack_story(incident_id: str,
                                 user=Depends(get_current_user)) -> Dict[str, Any]:
    # S1 · the incident record's own authority decides whether this
    # principal may address this incident at all. Anonymous never reaches
    # here; cross-tenant reads 404 without disclosing existence.
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        return await AttackStoryService.compose(async_db, incident_id)
    finally:
        client.close()
