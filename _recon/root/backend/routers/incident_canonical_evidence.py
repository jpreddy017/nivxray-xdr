"""P1 · Evidence Namespace Bridge · incident canonical-evidence projection.

    GET /api/incidents/{id}/canonical-evidence

A READ-ONLY projection over evidence that already exists. It is not a new
evidence store and not a second evidence authority:

  * the incident is resolved through THE incident authority
    (`routers.incidents.authorized_incident`) — out of scope is
    indistinguishable from non-existent;
  * the canonical ids are then read from what the INCIDENT itself persists
    (pipeline · endpoint campaign · case-linked observations);
  * the row identity exposed to the UI is `canonical_evidence_id`
    (`xdr_canonical_evidence.event_id`) — no row id is generated.

The existing `evidence_pointers` presentation is untouched: capability
pointers and canonical evidence records are different things.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends

from deps import db, get_current_user
from routers.incidents import authorized_incident
from services.evidence_bridge import canonical_evidence_projection

router = APIRouter(prefix="/incidents", tags=["incident-canonical-evidence"])


@router.get("/{incident_id}/canonical-evidence")
async def get_canonical_evidence(incident_id: str,
                                 user=Depends(get_current_user)
                                 ) -> Dict[str, Any]:
    doc, _q = authorized_incident(
        incident_id, user,
        {"_id": 0, "id": 1, "tenant_id": 1, "xdr_pipeline": 1,
         "endpoint_campaign": 1})
    return await canonical_evidence_projection(db, doc)
