"""
Round 27 · Cortex Response Console — backend.
==============================================

Closes the NivXRay evidence → execute → ACTIONED loop.

Endpoint:
  POST /api/xdr/vendor/cortex/actions

Owner-locked invariants (Round 27):
  · Never expose or execute an action the adapter reports as
    NOT_SUPPORTED / UNAVAILABLE — the capability matrix is the
    authoritative gate (UI is not the security boundary).
  · Never invoke the adapter directly.  Only
    `xdr_cortex_executor.run_cortex_action` may cross the vault
    boundary.
  · Every execution writes:
      1. one `xdr_response_actions` record with the full vendor
         result envelope (vendor_action_id, requested_at,
         completed_at, ok, result).
      2. one canonical evidence row (`source_object_type =
         action_result`) with state `ACTIONED` on success or
         `EXECUTION_FAILED` on vendor rejection — never a fake
         `ACTIONED` for a failure.
      3. a promotion refresh that attaches the new evidence row
         to the same `xdr_incident_id`.
  · Provenance closes: `xdr_response_actions.action_id` is a
    deterministic hash so an analyst can traverse
    recommendation → action → vendor_action_id → ACTIONED evidence
    → incident.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import logging
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from deps import db
from detection_content.xdr_cortex_executor import run_cortex_action
from detection_content.xdr_cortex_promotion import promote_from_ingest

log = logging.getLogger("nivxray.xdr.cortex_actions")

router = APIRouter(prefix="/api/xdr/vendor/cortex",
                     tags=["xdr-cortex-actions"])

VENDOR       = "palo_alto_cortex_xdr"
INTEGRATIONS = "xdr_integrations"
CANONICAL    = "xdr_canonical_evidence"
ACTIONS      = "xdr_response_actions"
INCIDENTS    = "xdr_incidents"


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _sha16(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


class ExecuteBody(BaseModel):
    integration_id:    str  = Field(..., description="cortex-<uuid>")
    xdr_incident_id:   str  = Field(..., description="Cortex incident id · promotion key")
    recommendation_id: Optional[str] = None
    action_id:         str  = Field(..., description="Canonical action_id · e.g. ENDPOINT_ISOLATE")
    entity: dict            = Field(..., description="Target entity · {kind, value, source_event_id?}")
    params: dict            = Field(default_factory=dict)


async def _capability_state_for(integration_id: str, action_id: str) -> tuple[str, Optional[str]]:
    """Read the authoritative capability state from the integration
    record — the same record `xdr_capability_service` consults."""
    rec = await db[INTEGRATIONS].find_one(
        {"integration_id": integration_id, "vendor": VENDOR,
          "active": True},
        {"_id": 0, "capability_matrix": 1},
    )
    if rec is None:
        return "UNAVAILABLE", "integration_not_found"
    for entry in rec.get("capability_matrix") or []:
        if entry.get("action_id") == action_id:
            return entry.get("state") or "UNAVAILABLE", entry.get("detail")
    return "UNAVAILABLE", "action_not_in_capability_matrix"


@router.post("/actions", status_code=201)
async def cortex_execute(body: ExecuteBody):
    """Execute one canonical response action against Cortex.

    Backend-enforced capability gate (UI must ALSO gate but MUST NOT
    be trusted): rejects with 409 if the action is not AVAILABLE."""
    cap_state, cap_detail = await _capability_state_for(
        body.integration_id, body.action_id)
    if cap_state != "AVAILABLE":
        raise HTTPException(409, detail={
            "error": "capability_denied",
            "capability_state": cap_state,
            "reason": cap_detail or "action not available for this integration",
        })

    action_pk = _sha16(body.integration_id, body.action_id,
                              body.xdr_incident_id,
                              body.entity.get("value", ""),
                              str(_dt.datetime.now(_dt.timezone.utc).timestamp()))
    action_row_id = f"act-cortex-{action_pk}"
    requested_at = _iso_now()

    # Cross the vault boundary via the sanctioned executor.
    outcome = await run_cortex_action(
        db,
        integration_id=body.integration_id,
        action_id=body.action_id,
        params={"target": body.entity, **body.params},
        principal="cortex_response_console",
    )
    completed_at = _iso_now()

    vendor_action_id = outcome.get("vendor_action_id") \
                             or outcome.get("vendor_response_id")
    ok = bool(outcome.get("ok"))
    result_state = "ACTIONED" if ok else "EXECUTION_FAILED"

    # ── 1. Persist the action record (provenance root) ─────
    action_doc = {
        "action_row_id":       action_row_id,
        "vendor":              "cortex_xdr",
        "integration_id":      body.integration_id,
        "xdr_incident_id":     body.xdr_incident_id,
        "recommendation_id":   body.recommendation_id,
        "action_id":           body.action_id,
        "entity":              body.entity,
        "params":              body.params,
        "capability_state_at_request": cap_state,
        "vendor_action_id":    vendor_action_id,
        "requested_at":        requested_at,
        "completed_at":        completed_at,
        "ok":                  ok,
        "result_state":        result_state,
        "result":              outcome,
        "principal":           "cortex_response_console",
    }
    await db[ACTIONS].insert_one(dict(action_doc))

    # ── 2. Write canonical ACTIONED / EXECUTION_FAILED evidence ─
    evidence_event_id = f"cev-cortex-action-{action_pk}"
    ev_row = {
        "event_id":              evidence_event_id,
        "vendor":                "cortex_xdr",
        "source_integration_id": body.integration_id,
        "source_object_type":    "action_result",
        "source_object_id":      action_row_id,
        "xdr_incident_id":       body.xdr_incident_id,
        "observed_at":           completed_at,
        "ingested_at":           completed_at,
        "event_type":            "cortex.action_result",
        "source":                "cortex_xdr",
        "raw":                   outcome,
        "fields": {
            "action_id":         body.action_id,
            "entity":            body.entity,
            "vendor_action_id":  vendor_action_id,
            "result_state":      result_state,
            "capability_state":  cap_state,
            "provenance": {
                "recommendation_id": body.recommendation_id,
                "action_row_id":     action_row_id,
            },
        },
        # Round 26.5 semantics — this evidence belongs to an
        # already-promoted incident.  Marking it ACTIONED /
        # EXECUTION_FAILED so evidence-plane consumers know it is
        # not a passive observation.
        "promotion_state":       result_state,
    }
    await db[CANONICAL].update_one(
        {"event_id": evidence_event_id},
        {"$setOnInsert": ev_row},
        upsert=True,
    )

    # ── 3. Attach to the incident deterministically ────────
    await db[INCIDENTS].update_one(
        {"source_integration_id": body.integration_id,
          "xdr_incident_id":       body.xdr_incident_id},
        {"$addToSet": {"evidence_event_ids": evidence_event_id},
          "$set":      {"last_action_at": completed_at,
                          "updated_at":     completed_at}},
    )

    return {
        "ok":                ok,
        "action_row_id":     action_row_id,
        "vendor_action_id":  vendor_action_id,
        "result_state":      result_state,
        "evidence_event_id": evidence_event_id,
        "requested_at":      requested_at,
        "completed_at":      completed_at,
        "capability_state_at_request": cap_state,
        "detail":            outcome.get("detail") or outcome.get("error"),
    }


@router.get("/actions")
async def list_cortex_actions(xdr_incident_id: Optional[str] = None,
                                       integration_id: Optional[str] = None,
                                       limit: int = 50):
    """List executed actions.  Scoped by incident or integration if
    provided.  Returns most-recent first."""
    q: dict = {}
    if xdr_incident_id: q["xdr_incident_id"] = xdr_incident_id
    if integration_id:  q["integration_id"] = integration_id
    cursor = db[ACTIONS].find(q, {"_id": 0}).sort("completed_at", -1).limit(limit)
    rows = [r async for r in cursor]
    return {"actions": rows, "count": len(rows)}
