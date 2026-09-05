"""Canonical Activity/Evidence inventory router.

Feeds the EDR Device Trajectory panels — left rail (inventory),
center canvas (trajectory events), right details (entity attributes).
Owner rule #19: one canonical object drives every panel.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import get_current_user
from services.activity.projector import build_inventory


router = APIRouter(prefix="/activity", tags=["activity"])


class InventoryBody(BaseModel):
    """Callers pass a fused Timeline (or empty for an empty inventory)."""
    case_id:  Optional[str]           = Field(None)
    timeline: Optional[Dict[str, Any]] = Field(None)


@router.post("/inventory")
async def inventory(body: InventoryBody,
                      user=Depends(get_current_user)):
    tenant_id = (user or {}).get("tenant_id") \
                    or (user or {}).get("email") \
                    or (user or {}).get("sub")
    if not tenant_id:
        raise HTTPException(status_code=401,
                              detail={"error": "tenant_context_missing"})
    inv = build_inventory(case_id=body.case_id,
                            tenant_id=tenant_id,
                            timeline=body.timeline)
    return inv.to_dict()
