"""S2-mini · READ AUTHORITY FOR THE ENGINE-DEPTH DATA AN INCIDENT CONSUMES.

The Individual Incident workspace mounts the causal engine as collapsed
`EngineDepth` panels and reads three engine projections, all keyed on a
`case_id`:

    GET /api/v2/cases/{case_id}/investigation      (verdict · IKG · story)
    GET /api/v2/cases/{case_id}/trajectory/device  (endpoint lanes)
    GET /api/v2/cases/{case_id}/artifacts          (extracted artifacts)

All three were `require_admin`, so a tenant-scoped analyst could not read the
depth of *their own* incident. `require_admin` is right for engine-native
cases (creation, ingest, deletion, configuration) — it is wrong as the only
way to READ an incident's own analysis.

**The association problem is not solved by pretending.** `v2_cases` documents
carry NO tenant field at all, and `case_id ↔ incident_id` is not universally
valid (the 37 engine-native cases are golden fixtures with no incident). So:

  · the AUTHORITY is the incident record, never the engine case — a
    non-admin principal may read an engine projection **only** for a
    `case_id` that IS an incident they are authorized for, resolved by the
    one incident authority (`routers.incidents.authorized_incident`,
    server-resolved tenant scope, cross-tenant ⇒ 404);
  · a cross-tenant (admin) role keeps exactly the access it already has;
  · nothing is ever substituted. An engine-native / golden / foreign case id
    is simply not an incident of that tenant, so it fails closed. No
    identifier is reshaped, guessed or matched by resemblance;
  · when the principal IS authorized but the engine store holds nothing keyed
    on that incident, the answer states `NOT_ASSOCIATED` with the field it
    was read from, instead of an empty projection that reads as "no activity".

Engine MUTATION and configuration routes are untouched and remain admin-only.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import Depends

from deps import get_current_user

OBSERVATION_COLL = "v2_shadow_observations"


def engine_case_read(case_id: str,
                     user: Dict[str, Any] = Depends(get_current_user)
                     ) -> Dict[str, Any]:
    """Authorize a READ of the engine depth for one `case_id`.

    Returns the authority basis; raises 401/403/404 exactly as the incident
    plane does (existence is never disclosed to a principal out of scope).
    """
    if (user or {}).get("role") == "admin":
        return {"authority": "CROSS_TENANT_ROLE",
                "principal": (user or {}).get("email"),
                "incident_id": None}
    from routers.incidents import authorized_incident
    doc, _ = authorized_incident(case_id, user,
                                 {"_id": 0, "id": 1, "tenant_id": 1})
    return {"authority": "INCIDENT_TENANT_AUTHORITY",
            "principal": (user or {}).get("email"),
            "incident_id": doc.get("id"),
            "tenant_id": doc.get("tenant_id")}


async def engine_association(db, case_id: str,
                             grant: Dict[str, Any]) -> Dict[str, Any]:
    """State, as a recorded fact, whether engine evidence exists for this id."""
    observed = await db[OBSERVATION_COLL].count_documents(
        {"case_id": case_id}, limit=1)
    return {
        "state": "ASSOCIATED" if observed else "NOT_ASSOCIATED",
        "case_id": case_id,
        "read_from": f"{OBSERVATION_COLL}.case_id",
        "reason": None if observed else
                  ("No engine observation is keyed on this identifier. The "
                   "causal engine holds no analysis for this incident — this "
                   "is an absence of engine evidence, not an empty result."),
        "authority": grant.get("authority"),
    }
