"""Round 46 · Analyst Intelligence Overlay REST API.

Mounted at `/api/incidents/{incident_id}/intelligence`.

Endpoints:
  GET    /overlays
  GET    /overlays/{target_kind}/{target_id}/{field_key}
  PUT    /overlays/{target_kind}/{target_id}/{field_key}
  DELETE /overlays/{target_kind}/{target_id}/{field_key}
  GET    /overlays/{target_kind}/{target_id}/{field_key}/history

Every write requires an authenticated analyst, a non-empty ``reason``,
and returns 409 on version mismatch.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user
from services import intelligence_overlay as overlay_svc
from services.intelligence_overlay import OverlayError

router = APIRouter(prefix="/incidents/{incident_id}/intelligence",
                          tags=["intelligence-overlay"])


class OverlayWriteBody(BaseModel):
    analyst_value:     str          = Field(..., min_length=1)
    machine_value:     str          = Field(..., min_length=0)
    reason:            str          = Field(..., min_length=1)
    expected_version:  Optional[int] = None


class OverlayRevertBody(BaseModel):
    machine_value:    str            = Field(..., min_length=0)
    reason:           str            = Field(..., min_length=1)
    expected_version: Optional[int]  = None


def _handle(exc: OverlayError) -> HTTPException:
    return HTTPException(
        status_code=exc.status,
        detail={"code": exc.code, "message": exc.message, **exc.extra},
    )


@router.get("/overlays")
async def get_all_overlays(incident_id: str,
                                     user: Dict[str, Any] = Depends(get_current_user)
                                     ) -> Dict[str, Any]:
    """List every active overlay for an incident (read is open to any
    authenticated user with access to the incident)."""
    return {"incident_id": incident_id,
              "overlays": await overlay_svc.list_overlays(db, incident_id)}


@router.get("/overlays/{target_kind}/{target_id}/{field_key}")
async def get_one_overlay(incident_id: str, target_kind: str,
                                     target_id: str, field_key: str,
                                     user: Dict[str, Any] = Depends(get_current_user)
                                     ) -> Dict[str, Any]:
    try:
        doc = await overlay_svc.get_overlay(
            db, incident_id, target_kind, target_id, field_key)
    except OverlayError as e:
        raise _handle(e)
    return {"overlay": doc}


@router.put("/overlays/{target_kind}/{target_id}/{field_key}")
async def put_overlay(incident_id: str, target_kind: str,
                                target_id: str, field_key: str,
                                body: OverlayWriteBody,
                                user: Dict[str, Any] = Depends(get_current_user)
                                ) -> Dict[str, Any]:
    try:
        doc = await overlay_svc.upsert_overlay(
            db, incident_id, target_kind, target_id, field_key,
            machine_value=body.machine_value,
            analyst_value=body.analyst_value,
            reason=body.reason,
            author_id=str(user.get("id") or user.get("email")),
            author_email=user.get("email"),
            expected_version=body.expected_version)
    except OverlayError as e:
        raise _handle(e)
    return {"overlay": doc}


@router.delete("/overlays/{target_kind}/{target_id}/{field_key}")
async def revert(incident_id: str, target_kind: str,
                      target_id: str, field_key: str,
                      body: OverlayRevertBody,
                      user: Dict[str, Any] = Depends(get_current_user)
                      ) -> Dict[str, Any]:
    """Revert to machine value.  Preserves audit history — emits a
    ``reverted`` audit event; never hard-deletes."""
    try:
        doc = await overlay_svc.revert_overlay(
            db, incident_id, target_kind, target_id, field_key,
            machine_value=body.machine_value,
            reason=body.reason,
            author_id=str(user.get("id") or user.get("email")),
            author_email=user.get("email"),
            expected_version=body.expected_version)
    except OverlayError as e:
        raise _handle(e)
    return {"overlay": doc}


@router.get("/overlays/{target_kind}/{target_id}/{field_key}/history")
async def get_history(incident_id: str, target_kind: str,
                              target_id: str, field_key: str,
                              user: Dict[str, Any] = Depends(get_current_user)
                              ) -> Dict[str, Any]:
    try:
        entries = await overlay_svc.history(
            db, incident_id, target_kind, target_id, field_key)
    except OverlayError as e:
        raise _handle(e)
    return {"entries": entries}
