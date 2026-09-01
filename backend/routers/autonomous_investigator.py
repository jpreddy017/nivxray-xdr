"""Round 31 · Autonomous Investigator · read-only projection API.

These endpoints are **read-only**.  There is no "Auto-Investigate"
button, no HTTP-triggered activation (§13, §16 of
AUTONOMOUS_INVESTIGATION.md).  The Orchestrator ticks are driven by
the ingestion pipeline; the UI simply *observes* the state.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorClient

from deps import get_current_user_optional, sync_collection
from services.investigator.orchestrator import InvestigatorService

router = APIRouter(prefix="/incidents", tags=["investigator"])
_col = sync_collection("workspace_cases")


def _new_async_client():
    return AsyncIOMotorClient(os.environ["MONGO_URL"])


@router.get("/{incident_id}/investigation")
async def get_investigation(incident_id: str,
                                  user=Depends(get_current_user_optional)):
    """Return the autonomous investigation state + activity feed +
    execution + finding rollups for one incident.  Read-only.
    """
    doc = _col.find_one({"id": incident_id}, {"_id": 0, "id": 1})
    if not doc:
        raise HTTPException(status_code=404,
                              detail={"error": "incident_not_found",
                                       "id": incident_id})

    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        state = await InvestigatorService.get_state(async_db, incident_id)
        activity = await InvestigatorService.get_activity(async_db, incident_id)
        executions = await InvestigatorService.get_executions(async_db, incident_id)
        findings = await InvestigatorService.get_findings(async_db, incident_id)
    finally:
        client.close()

    if not state:
        # Honest empty state — never fabricate a running investigation.
        return {
            "incident_id": incident_id,
            "state":       "WAITING_FOR_EVIDENCE",
            "state_history": [],
            "activity":    [],
            "executions":  [],
            "findings":    [],
            "counts":      {"planned": 0, "executed": 0,
                              "skipped": 0, "findings": 0},
            "honesty_note": (
                "No investigation has been registered for this incident "
                "yet.  Investigation begins autonomously when the "
                "ingestion pipeline materialises the incident."
            ),
        }

    return {
        "incident_id":       incident_id,
        "investigation_id":  state.investigation_id,
        "tenant_id":         state.tenant_id,
        "state":             state.state,
        "state_history":     state.state_history,
        "iue_fingerprint":   state.iue_fingerprint,
        "iue_version":       state.iue_version,
        "started_at":        state.started_at,
        "updated_at":        state.updated_at,
        "converged_at":      state.converged_at,
        "convergence_reason": state.convergence_reason,
        "counts": {
            "planned":  state.pivots_planned,
            "executed": state.pivots_executed,
            "skipped":  state.pivots_skipped,
            "findings": state.findings_count,
        },
        "activity":   activity,
        "executions": executions,
        "findings":   findings,
        "provenance": state.provenance,
        "honesty_note": state.honesty_note,
    }


@router.get("/{incident_id}/investigation/executions")
async def get_executions(incident_id: str,
                              user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        executions = await InvestigatorService.get_executions(async_db, incident_id)
    finally:
        client.close()
    return {"incident_id": incident_id,
              "count":       len(executions),
              "executions":  executions}


@router.get("/{incident_id}/investigation/findings")
async def get_findings(incident_id: str,
                            user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        findings = await InvestigatorService.get_findings(async_db, incident_id)
    finally:
        client.close()
    return {"incident_id": incident_id,
              "count":       len(findings),
              "findings":    findings}
