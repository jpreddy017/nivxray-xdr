"""GATE 7 · exclusion storage and audit.

    edr_exclusion_sets   named sets that a policy version can carry
    edr_exclusions       the individual exclusions, with approval + audit

Nothing is ever deleted. Revocation is a recorded event, because the
question "what were we not looking at, between when and when" must stay
answerable.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from edr_plane.exclusions.contracts import (ApprovalState, ENFORCEABLE_STATES,
                                            ExclusionDraft, in_scope,
                                            lifecycle_state, new_exclusion_id,
                                            new_set_id)

SETS = "edr_exclusion_sets"
EXCLUSIONS = "edr_exclusions"
#: What endpoints reported their OWN engines actually enforced. This is
#: the only source `ENDPOINT_EXCLUSION_APPLIED` may be derived from.
ENFORCEMENT = "edr_endpoint_exclusion_enforcement"


class ExclusionError(Exception):
    def __init__(self, code: str, status: int, reason: str):
        self.code, self.status, self.reason = code, status, reason
        super().__init__(reason)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def ensure_indexes(db: Any) -> None:
    await db[SETS].create_index([("tenant_id", 1), ("set_id", 1)],
                                unique=True, name="uniq_tenant_set")
    await db[EXCLUSIONS].create_index([("tenant_id", 1), ("exclusion_id", 1)],
                                      unique=True, name="uniq_tenant_excl")
    await db[EXCLUSIONS].create_index([("tenant_id", 1), ("set_id", 1)],
                                      name="tenant_set")
    await db[ENFORCEMENT].create_index(
        [("tenant_id", 1), ("endpoint_id", 1), ("exclusion_id", 1)],
        unique=True, name="uniq_tenant_endpoint_exclusion")
    await db[ENFORCEMENT].create_index([("tenant_id", 1), ("exclusion_id", 1)],
                                       name="tenant_exclusion")


async def record_endpoint_enforcement(db: Any, *, tenant_id: str,
                                      endpoint_id: str, engine: str,
                                      evaluator_version: Optional[str],
                                      policy: Dict[str, Any],
                                      stale: bool,
                                      reports: List[Dict[str, Any]]
                                      ) -> Dict[str, Any]:
    """Persist what an endpoint said its own engine enforced.

    Every reported exclusion id is re-validated against THIS tenant. An
    id the tenant does not own is recorded as
    `REJECTED_NOT_IN_TENANT` and can never contribute to an enforcement
    state — a connector cannot assert enforcement of another tenant's
    exclusion by naming its id.
    """
    at = _now()
    accepted, rejected = 0, []
    for r in reports:
        exclusion_id = str(r.get("exclusion_id") or "")
        owned = await db[EXCLUSIONS].find_one(
            {"tenant_id": tenant_id, "exclusion_id": exclusion_id},
            {"_id": 0, "exclusion_id": 1})
        if not owned:
            rejected.append(exclusion_id)
            await db[ENFORCEMENT].update_one(
                {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
                 "exclusion_id": exclusion_id},
                {"$set": {"acceptance": "REJECTED_NOT_IN_TENANT",
                          "honoured_count": 0, "engine": engine,
                          "reported_at": at,
                          "basis": ("the endpoint named an exclusion this "
                                    "tenant does not own; the report is "
                                    "retained and contributes nothing")},
                 "$setOnInsert": {"created_at": at}}, upsert=True)
            continue
        accepted += 1
        await db[ENFORCEMENT].update_one(
            {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
             "exclusion_id": exclusion_id},
            {"$set": {"engine": r.get("engine") or engine,
                      "acceptance": r.get("acceptance"),
                      "honoured_count": int(r.get("honoured_count") or 0),
                      "matched_attribute": r.get("matched_attribute"),
                      "observed_value_digests":
                          list(r.get("observed_value_digests") or [])[:5],
                      "first_at": r.get("first_at"),
                      "last_at": r.get("last_at"),
                      "policy_id": r.get("policy_id") or policy.get("policy_id"),
                      "policy_version": (r.get("policy_version")
                                         or policy.get("version")),
                      "config_digest": (r.get("config_digest")
                                        or policy.get("config_digest")),
                      "evaluator_version": evaluator_version,
                      "policy_stale_at_endpoint": bool(stale),
                      "reported_at": at},
             "$setOnInsert": {"created_at": at}}, upsert=True)
    return {"recorded": accepted, "rejected_not_in_tenant": rejected,
            "reported_at": at}


async def endpoint_enforcement_map(db: Any, *, tenant_id: str,
                                   endpoint_id: Optional[str] = None
                                   ) -> Dict[str, Dict[str, Any]]:
    """`exclusion_id` -> the endpoint enforcement record.

    With no endpoint filter the records are folded across the estate:
    counts are summed and the strongest acceptance wins, so an exclusion
    is APPLIED on the estate as soon as ONE endpoint proves it enforced
    it — while the per-endpoint distribution stays available.
    """
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_id:
        q["endpoint_id"] = endpoint_id
    out: Dict[str, Dict[str, Any]] = {}
    async for r in db[ENFORCEMENT].find(q, {"_id": 0}):
        key = r["exclusion_id"]
        cur = out.get(key)
        if cur is None:
            out[key] = {**r, "endpoints_reporting": 1}
            continue
        cur["endpoints_reporting"] += 1
        cur["honoured_count"] = (int(cur.get("honoured_count") or 0)
                                 + int(r.get("honoured_count") or 0))
        if r.get("acceptance") == "HONOURED":
            cur["acceptance"] = "HONOURED"
            cur["matched_attribute"] = (cur.get("matched_attribute")
                                        or r.get("matched_attribute"))
        if str(r.get("last_at") or "") > str(cur.get("last_at") or ""):
            cur["last_at"] = r.get("last_at")
    return out


# ── sets ─────────────────────────────────────────────────────────────
async def create_set(db: Any, *, tenant_id: str, name: str,
                     description: Optional[str], os_family: str,
                     by: str) -> Dict[str, Any]:
    if await db[SETS].find_one({"tenant_id": tenant_id, "name": name}):
        raise ExclusionError("SET_NAME_IN_USE", 409,
                             "an exclusion set with this name already exists")
    doc = {"set_id": new_set_id(), "tenant_id": tenant_id, "name": name,
           "description": description or None, "os": os_family,
           "created_at": _now(), "created_by": by}
    await db[SETS].insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


async def list_sets(db: Any, *, tenant_id: str) -> List[Dict[str, Any]]:
    sets = [s async for s in db[SETS].find({"tenant_id": tenant_id},
                                           {"_id": 0})]
    for s in sets:
        s["exclusion_count"] = await db[EXCLUSIONS].count_documents(
            {"tenant_id": tenant_id, "set_id": s["set_id"]})
        s["enforceable_count"] = sum(
            1 for e in await _raw(db, tenant_id, s["set_id"])
            if lifecycle_state(e)["state"] in ENFORCEABLE_STATES)
    return sorted(sets, key=lambda r: str(r.get("name") or ""))


async def _raw(db: Any, tenant_id: str,
               set_id: Optional[str] = None) -> List[Dict[str, Any]]:
    q: Dict[str, Any] = {"tenant_id": tenant_id}
    if set_id:
        q["set_id"] = set_id
    return [e async for e in db[EXCLUSIONS].find(q, {"_id": 0})]


# ── exclusions ───────────────────────────────────────────────────────
async def create_exclusion(db: Any, *, tenant_id: str, draft: ExclusionDraft,
                           by: str) -> Dict[str, Any]:
    if not await db[SETS].find_one({"tenant_id": tenant_id,
                                    "set_id": draft.set_id}):
        raise ExclusionError("SET_NOT_FOUND", 404,
                             "an exclusion must belong to an exclusion set "
                             "that exists in this tenant")
    at = _now()
    doc = {
        "exclusion_id": new_exclusion_id(),
        "tenant_id": tenant_id,
        "set_id": draft.set_id,
        "type": draft.type,
        "value": draft.value,
        "match": draft.match,
        "reason": draft.reason,
        "affected_engines": list(draft.affected_engines),
        "scope": draft.scope.model_dump(),
        "effective_from": draft.effective_from or at,
        "expires_at": draft.expires_at,
        "review_at": draft.review_at,
        "created_by": by,
        "created_at": at,
        "approval_state": ApprovalState.PENDING_APPROVAL.value,
        "approved_by": None,
        "approved_at": None,
        "revoked_at": None,
        "revoked_by": None,
        "revoke_reason": None,
        "policy_version_bindings": [],
        "audit": [{"action": "CREATED", "by": by, "at": at,
                   "detail": "submitted for approval; inert until approved"}],
    }
    await db[EXCLUSIONS].insert_one(dict(doc))
    doc.pop("_id", None)
    return doc


async def approve(db: Any, *, tenant_id: str, exclusion_id: str, by: str,
                  decision: str, note: Optional[str]) -> Dict[str, Any]:
    doc = await db[EXCLUSIONS].find_one({"tenant_id": tenant_id,
                                         "exclusion_id": exclusion_id},
                                        {"_id": 0})
    if not doc:
        raise ExclusionError("EXCLUSION_NOT_FOUND", 404, "no such exclusion")
    if doc.get("created_by") == by:
        raise ExclusionError("SELF_APPROVAL_REFUSED", 409,
                             "the operator who created an exclusion may not "
                             "approve it; a protection blind spot requires a "
                             "second pair of eyes")
    if decision not in (ApprovalState.APPROVED.value,
                        ApprovalState.REJECTED.value):
        raise ExclusionError("DECISION_INVALID", 422,
                             "decision must be APPROVED or REJECTED")
    at = _now()
    await db[EXCLUSIONS].update_one(
        {"tenant_id": tenant_id, "exclusion_id": exclusion_id},
        {"$set": {"approval_state": decision, "approved_by": by,
                  "approved_at": at},
         "$push": {"audit": {"action": decision, "by": by, "at": at,
                             "detail": note or None}}})
    return {"exclusion_id": exclusion_id, "approval_state": decision,
            "approved_by": by, "approved_at": at}


async def revoke(db: Any, *, tenant_id: str, exclusion_id: str, by: str,
                 reason: str) -> Dict[str, Any]:
    at = _now()
    res = await db[EXCLUSIONS].update_one(
        {"tenant_id": tenant_id, "exclusion_id": exclusion_id,
         "revoked_at": None},
        {"$set": {"revoked_at": at, "revoked_by": by,
                  "revoke_reason": reason},
         "$push": {"audit": {"action": "REVOKED", "by": by, "at": at,
                             "detail": reason}}})
    if not res.matched_count:
        raise ExclusionError("EXCLUSION_NOT_REVOCABLE", 404,
                             "no such active exclusion")
    return {"exclusion_id": exclusion_id, "revoked_at": at,
            "note": ("the record is retained: what the product was not "
                     "looking at, and between when and when, stays "
                     "answerable")}


async def bind_to_policy_version(db: Any, *, tenant_id: str, set_ids: List[str],
                                 policy_id: str, version: int) -> int:
    """Record that a policy version carries these sets.

    This is what makes an endpoint-side exclusion's state derivable: an
    exclusion is only enforceable on an endpoint through a policy version
    that the endpoint has actually APPLIED.
    """
    if not set_ids:
        return 0
    at = _now()
    res = await db[EXCLUSIONS].update_many(
        {"tenant_id": tenant_id, "set_id": {"$in": set_ids}},
        {"$push": {"policy_version_bindings": {
            "policy_id": policy_id, "version": version, "at": at}}})
    return res.modified_count


async def list_exclusions(db: Any, *, tenant_id: str,
                          set_id: Optional[str] = None) -> List[Dict[str, Any]]:
    rows = await _raw(db, tenant_id, set_id)
    for r in rows:
        r["lifecycle"] = lifecycle_state(r)
        r["enforceable"] = r["lifecycle"]["state"] in ENFORCEABLE_STATES
    return sorted(rows, key=lambda r: str(r.get("created_at") or ""),
                  reverse=True)


async def enforceable_for_endpoint(db: Any, *, tenant_id: str,
                                   endpoint_id: Optional[str] = None,
                                   group_id: Optional[str] = None,
                                   set_ids: Optional[List[str]] = None
                                   ) -> List[Dict[str, Any]]:
    """The exclusions a SERVER-SIDE engine may consult for this endpoint.

    Approval, effectiveness and scope are all required. This is the only
    function the fabric calls, so "unapproved exclusions are inert" is a
    property of the code path, not a policy statement.
    """
    q: Dict[str, Any] = {"tenant_id": tenant_id,
                         "approval_state": ApprovalState.APPROVED.value,
                         "revoked_at": None}
    if set_ids is not None:
        q["set_id"] = {"$in": set_ids}
    out = []
    async for e in db[EXCLUSIONS].find(q, {"_id": 0}):
        if lifecycle_state(e)["state"] not in ENFORCEABLE_STATES:
            continue
        if not in_scope(e, endpoint_id=endpoint_id, group_id=group_id):
            continue
        out.append(e)
    return out
