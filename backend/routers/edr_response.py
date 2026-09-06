"""P0-F.5/F.6 · endpoint response surfaces.

Analyst side authenticates as a user; sensor side authenticates as the
enrolled endpoint. Neither side may assert its own identity — the sensor's
endpoint_id comes from its session, never from the request body.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict

from deps import db as _db, get_current_user
from edr_plane import response as resp
from edr_plane.enrollment.identity import AuthenticatedEndpoint
from routers.edr_enrollment import get_authenticated_endpoint

router = APIRouter(prefix="/edr/response", tags=["nivxforge-edr-response"])
agent = APIRouter(prefix="/edr/agent", tags=["nivxforge-edr-agent"])


def _fail(e: resp.ResponseError):
    raise HTTPException(status_code=e.http,
                        detail={"error": e.code, "reason": e.reason})


class ActionBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    endpoint_id: str
    action: str
    target: Dict[str, Any] = {}
    reason: str = ""


class ResultBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str
    outcome: str
    detail: str = ""
    evidence: Dict[str, Any] = {}


class VerifyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_id: str
    probe: Dict[str, Any]


@router.post("/actions")
async def request_action(body: ActionBody,
                         user: dict = Depends(get_current_user)) -> dict:
    try:
        return await resp.request_action(
            _db, tenant_id=user.get("tenant_id") or "default",
            endpoint_id=body.endpoint_id, action=body.action,
            target=body.target, reason=body.reason,
            requested_by=str(user.get("sub") or user.get("email") or "user"))
    except resp.ResponseError as e:
        _fail(e)


@router.get("/actions")
async def list_actions(endpoint_id: Optional[str] = None,
                       user: dict = Depends(get_current_user)) -> dict:
    return await resp.list_commands(
        _db, tenant_id=user.get("tenant_id") or "default",
        endpoint_id=endpoint_id)


@router.get("/actions/{command_id}")
async def get_action(command_id: str,
                     user: dict = Depends(get_current_user)) -> dict:
    """The full action record for one command — the audit surface the
    console renders. Read-only; this route never mutates state."""
    try:
        return await resp.get_command(
            _db, tenant_id=user.get("tenant_id") or "default",
            command_id=command_id)
    except resp.ResponseError as e:
        _fail(e)


@agent.get("/commands")
async def poll_commands(who: AuthenticatedEndpoint = Depends(
        get_authenticated_endpoint)) -> dict:
    """The sensor claims only ITS OWN commands, scoped by its session."""
    cmds = await resp.claim_pending(_db, tenant_id=who.tenant_id,
                                   endpoint_id=who.endpoint_id)
    return {"endpoint_id": who.endpoint_id, "commands": cmds,
            "count": len(cmds)}


@agent.post("/command-result")
async def command_result(body: ResultBody,
                         who: AuthenticatedEndpoint = Depends(
                             get_authenticated_endpoint)) -> dict:
    try:
        return await resp.record_result(
            _db, tenant_id=who.tenant_id, endpoint_id=who.endpoint_id,
            command_id=body.command_id, outcome=body.outcome,
            detail=body.detail, evidence=body.evidence)
    except resp.ResponseError as e:
        _fail(e)


@agent.post("/command-verification")
async def command_verification(body: VerifyBody,
                               who: AuthenticatedEndpoint = Depends(
                                   get_authenticated_endpoint)) -> dict:
    """Post-action evidence. This is the only path to VERIFIED."""
    try:
        return await resp.verify(_db, tenant_id=who.tenant_id,
                                 endpoint_id=who.endpoint_id,
                                 command_id=body.command_id, probe=body.probe)
    except resp.ResponseError as e:
        _fail(e)
