"""Round 33 · Attack Story · read-only API.

Consumes governed state (Round 30 IUE + Round 31 investigation +
Round 32 findings ledger).  Never writes.  Never fabricates.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient

from deps import get_current_user_optional, sync_collection
from services.attack_story import AttackStoryService

router = APIRouter(prefix="/incidents", tags=["attack-story"])
_col = sync_collection("workspace_cases")


def _new_async_client():
    return AsyncIOMotorClient(os.environ["MONGO_URL"])


@router.get("/{incident_id}/attack-story")
async def get_attack_story(incident_id: str,
                                 user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    doc = _col.find_one({"id": incident_id}, {"_id": 0, "id": 1})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found",
                                       "id": incident_id})
    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        return await AttackStoryService.compose(async_db, incident_id)
    finally:
        client.close()
