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

from deps import get_current_user, get_current_user_optional, sync_collection
from routers.incidents import authorized_incident
from services.investigator.orchestrator import InvestigatorService
from services.investigator.planner import registry_descriptor

router = APIRouter(prefix="/incidents", tags=["investigator"])
_col = sync_collection("workspace_cases")


def _new_async_client():
    return AsyncIOMotorClient(os.environ["MONGO_URL"])


# ── Registry introspection (Round 32) ───────────────────────────────
_registry_router = APIRouter(prefix="/investigator", tags=["investigator"])


@_registry_router.get("/capabilities")
async def list_capabilities(user=Depends(get_current_user_optional)):
    """Return the descriptor for every registered capability.

    Read-only.  Used by the Investigation Activity UI + tests to
    confirm the Capability Fabric surface without hitting an incident.
    """
    descs = registry_descriptor()
    counts: Dict[str, int] = {}
    for d in descs:
        counts[d["availability"]] = counts.get(d["availability"], 0) + 1
    return {
        "count":         len(descs),
        "availability":  counts,
        "capabilities":  descs,
    }


@router.get("/{incident_id}/investigation")
async def get_investigation(incident_id: str,
                                  user=Depends(get_current_user)):
    """Return the autonomous investigation state + activity feed +
    execution + finding rollups for one incident.  Read-only.

    S1 · this projection carries another customer's activity, executions and
    findings, so it is resolved through the incident record's own tenant
    authority. Anonymous is refused; cross-tenant is 404.
    """
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})

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
                              user=Depends(get_current_user)) -> Dict[str, Any]:
    # S1 · these two routes previously did not even establish that the
    # incident exists, let alone that the caller may address it.
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
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
                            user=Depends(get_current_user)) -> Dict[str, Any]:
    authorized_incident(incident_id, user, {"_id": 0, "id": 1})
    client = _new_async_client()
    try:
        async_db = client[os.environ["DB_NAME"]]
        findings = await InvestigatorService.get_findings(async_db, incident_id)
    finally:
        client.close()
    return {"incident_id": incident_id,
              "count":       len(findings),
              "findings":    findings}
